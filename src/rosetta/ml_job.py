"""Génération de la configuration Elasticsearch ML (anomaly detection) qui
correspond le plus fidèlement possible aux règles ElastAlert comportementales
(`spike`, `change`, `flatline`) — celles pour lesquelles ES|QL ne peut produire
qu'une approximation (cf. converters/registry.py).

Pourquoi un module séparé plutôt qu'une simple stratégie `machine_learning`
dans `converters/registry.py` ?

Le type de règle `machine_learning` de `detection-rules` ne fait que
*référencer* un job ML déjà existant (`machine_learning_job_id`,
`anomaly_threshold`) — il ne le crée pas. Provisionner le job lui-même est une
opération Elasticsearch séparée (`PUT _ml/anomaly_detectors/...` +
`PUT _ml/datafeeds/...`), qui suppose une période d'apprentissage avant que
les scores soient fiables, et qui peut nécessiter une licence Platinum/
Enterprise. Rosetta ne peut donc pas produire cela comme un simple fichier
TOML « prêt à importer » au même titre que le reste du pipeline.

Ce module construit à la place le PLAN de ce job (dataclass `MLJobPlan`),
rendu sous forme de commandes Kibana Dev Console prêtes à copier-coller. Les
converters `spike`/`change`/`flatline` les attachent à
`ConversionResult.metadata` ; `toml_writer` les insère dans le champ `note` de
la règle migrée, à titre de recommandation optionnelle — l'approximation
ES|QL/Threshold reste la règle active par défaut.

Chaque `plan_<type>_ml_job()` documente son propre mapping et ses propres
écarts sémantiques en docstring ; le principe commun est : ne jamais deviner
silencieusement une conversion numérique qui n'a pas d'équivalent direct
(spike_height, threshold `flatline`, sémantique « transition » de `change`) —
on l'explique dans `MLJobPlan.notes` à la place.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .models import ElastAlertRule

# Score d'anomalie par défaut utilisé par Kibana pour déclencher une alerte
# (cf. doc Elastic : "anomaly_score of 75 or higher triggers the associated
# action"). Point de départ raisonnable, à ajuster après observation.
_DEFAULT_ANOMALY_THRESHOLD = 75


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return s or "rosetta_job"


def _bucket_span(rule: ElastAlertRule) -> str:
    """Dérive bucket_span du `timeframe` ElastAlert (même source que le
    lookback ES|QL, pour rester cohérent avec la fenêtre d'origine)."""
    tf = rule.get("timeframe")
    if isinstance(tf, dict):
        for unit, key in (("minutes", "m"), ("hours", "h"), ("days", "d")):
            if unit in tf:
                return f"{int(tf[unit])}{key}"
    return "15m"


def _indices(rule: ElastAlertRule) -> list[str]:
    return [i.strip() for i in (rule.index or "logs-*").split(",") if i.strip()] or ["logs-*"]


def _datafeed_query(rule: ElastAlertRule) -> dict:
    """Le `filter` ElastAlert est déjà du Query DSL Elasticsearch (term/terms/
    range/query_string) : on le réutilise tel quel, pas de traduction requise
    (contrairement à filter_to_esql / filter_to_kql)."""
    if rule.filters:
        return {"bool": {"filter": rule.filters}}
    return {"match_all": {}}


@dataclass
class MLJobPlan:
    job_id: str
    job_body: dict
    datafeed_id: str
    datafeed_body: dict
    anomaly_threshold: int
    notes: list[str] = field(default_factory=list)

    def as_console_commands(self) -> str:
        """Rendu au format Kibana Dev Console : copier-coller direct, dans
        l'ordre d'exécution (job -> datafeed -> ouverture -> démarrage)."""
        parts = [
            f"PUT _ml/anomaly_detectors/{self.job_id}\n"
            + json.dumps(self.job_body, indent=2, ensure_ascii=False),
            f"PUT _ml/datafeeds/{self.datafeed_id}\n"
            + json.dumps(self.datafeed_body, indent=2, ensure_ascii=False),
            f"POST _ml/anomaly_detectors/{self.job_id}/_open",
            f"POST _ml/datafeeds/{self.datafeed_id}/_start",
        ]
        return "\n\n".join(parts)


def _assemble(rule: ElastAlertRule, *, suffix: str, description: str,
              detectors: list[dict], influencer_keys: list[str]) -> MLJobPlan:
    """Assemble job_body/datafeed_body communs aux trois types comportementaux
    (spike/change/flatline) ; seuls les détecteurs et les notes diffèrent."""
    job_id = f"rosetta_{_slug(rule.name)}_{suffix}"
    datafeed_id = f"datafeed-{job_id}"
    job_body = {
        "description": description,
        "analysis_config": {
            "bucket_span": _bucket_span(rule),
            "detectors": detectors,
            "influencers": list(dict.fromkeys(k for k in influencer_keys if k)),
        },
        "data_description": {"time_field": "@timestamp"},
    }
    datafeed_body = {
        "job_id": job_id,
        "indices": _indices(rule),
        "query": _datafeed_query(rule),
    }
    return MLJobPlan(
        job_id=job_id, job_body=job_body, datafeed_id=datafeed_id,
        datafeed_body=datafeed_body, anomaly_threshold=_DEFAULT_ANOMALY_THRESHOLD,
    )


def plan_spike_ml_job(rule: ElastAlertRule) -> MLJobPlan:
    """Construit le plan de job ML équivalent à une règle ElastAlert `spike`."""
    query_key = rule.get("query_key")
    keys = [query_key] if isinstance(query_key, str) else list(query_key or [])
    threshold_cur = rule.get("threshold_cur")

    detector: dict = {
        "function": "high_count",
        "detector_description": (
            f"Pic du volume d'événements — migré depuis la règle ElastAlert « {rule.name} »"
        ),
    }
    notes: list[str] = []

    if keys:
        detector["partition_field_name"] = keys[0]
        if len(keys) > 1:
            notes.append(
                f"query_key ElastAlert combine plusieurs champs ({', '.join(keys)}) ; "
                f"un détecteur ML n'accepte qu'un seul partition_field_name. Seul "
                f"'{keys[0]}' a été retenu — envisagez un script_field composite pour "
                "les autres, ou un détecteur par clé."
            )

    if threshold_cur is not None:
        detector["custom_rules"] = [{
            "actions": ["skip_result"],
            "conditions": [
                {"applies_to": "actual", "operator": "lt", "value": float(threshold_cur)}
            ],
        }]

    plan = _assemble(
        rule, suffix="spike",
        description=f"Migré depuis ElastAlert (spike) : {rule.name}",
        detectors=[detector], influencer_keys=keys[:1],
    )

    notes.append(
        "spike_height (facteur multiplicatif ElastAlert) n'a pas d'équivalent direct : "
        "le job ML calcule un score d'anomalie 0-100 à partir d'une baseline apprise, "
        f"pas un ratio fixe. anomaly_threshold={_DEFAULT_ANOMALY_THRESHOLD} (valeur par "
        "défaut Kibana) est utilisé comme point de départ — ajustez-le après une "
        "période d'observation."
    )
    notes.append(
        "Le job nécessite plusieurs cycles de bucket_span pour apprendre une baseline "
        "fiable : conservez la règle ES|QL générée par ailleurs active en parallèle "
        "jusqu'à cette période d'observation passée."
    )
    notes.append(
        "Une fois le job démarré et une baseline établie, référencez-le dans une règle "
        "de détection `type = \"machine_learning\"` : "
        f'`machine_learning_job_id = ["{plan.job_id}"]`, `anomaly_threshold = '
        f"{_DEFAULT_ANOMALY_THRESHOLD}`."
    )
    plan.notes.extend(notes)
    return plan


def plan_change_ml_job(rule: ElastAlertRule) -> MLJobPlan | None:
    """Construit le plan de job ML équivalent à une règle ElastAlert `change`.

    Mapping :
        compound_compare_key / compare_key -> un détecteur `rare` par champ
            comparé (`by_field_name`), partitionné par `query_key`
        query_key                          -> partition_field_name

    Écart sémantique documenté (pas deviné) : ElastAlert `change` compare la
    valeur à l'événement PRÉCÉDENT pour la même entité et alerte à CHAQUE
    transition. `rare` alerte sur les valeurs statistiquement rares/inédites
    pour cette entité au fil du temps : une valeur qui réapparaît de temps en
    temps finit par ne plus être « rare », alors qu'ElastAlert alerterait à
    chaque fois qu'elle diffère de la précédente. C'est donc un biais vers la
    détection de PREMIÈRE apparition plutôt qu'une reproduction exacte de la
    sémantique « changement ».

    Renvoie None si aucun compare_key/compound_compare_key n'est exploitable
    (comme convert_change, mais sans détecteur `rare` inventé sur un champ
    inconnu — mieux vaut ne pas générer de job que d'en générer un faux).
    """
    compound = rule.get("compound_compare_key") or rule.get("compare_key")
    fields = compound if isinstance(compound, list) else [compound] if compound else []
    if not fields:
        return None

    query_key = rule.get("query_key")
    keys = [query_key] if isinstance(query_key, str) else list(query_key or [])

    detectors = []
    for f in fields:
        d: dict = {
            "function": "rare",
            "by_field_name": f,
            "detector_description": (
                f"Valeur rare/inédite de {f} — migré depuis la règle ElastAlert "
                f"(change) « {rule.name} »"
            ),
        }
        if keys:
            d["partition_field_name"] = keys[0]
        detectors.append(d)

    plan = _assemble(
        rule, suffix="change",
        description=f"Migré depuis ElastAlert (change) : {rule.name}",
        detectors=detectors, influencer_keys=keys[:1] + fields,
    )

    notes = [
        "ElastAlert 'change' compare la valeur à l'événement précédent et alerte à "
        "chaque transition ; la fonction ML 'rare' alerte sur les valeurs "
        "statistiquement rares/inédites pour cette entité, pas sur chaque "
        "changement pris isolément — une valeur qui réapparaît occasionnellement "
        "cesse d'être « rare ». C'est un biais vers la détection de première "
        "apparition, pas une reproduction exacte de la sémantique 'changement'."
    ]
    if len(fields) > 1:
        notes.append(
            f"{len(fields)} champs comparés (compound_compare_key) -> {len(fields)} "
            f"détecteurs 'rare' dans le même job, tous partitionnés par "
            f"'{keys[0] if keys else '—'}'."
        )
    if not keys:
        notes.append(
            "Aucun query_key : le job analyse les valeurs rares sur l'ensemble du "
            "trafic, sans isoler une baseline par entité — vérifiez que c'est bien "
            "le comportement souhaité."
        )
    plan.notes.extend(notes)
    return plan


def plan_flatline_ml_job(rule: ElastAlertRule) -> MLJobPlan:
    """Construit le plan de job ML équivalent à une règle ElastAlert `flatline`.

    Mapping :
        query_key -> partition_field_name (si présent)
        function  -> low_count (inverse de high_count utilisé pour spike :
                     détecte une baisse statistique du volume)

    Écarts sémantiques documentés (pas devinés) :
      - `threshold` ElastAlert est un plancher ABSOLU et déterministe (alerte
        si count < threshold) ; low_count détecte une baisse RELATIVE à une
        baseline apprise. Les deux sont complémentaires, pas substituables :
        la règle Threshold déjà générée reste le garde-fou déterministe du
        plancher, ce job ML n'est qu'un signal d'alerte précoce sur une
        tendance à la baisse.
      - Cas d'une entité connue devenant TOTALEMENT silencieuse (zéro
        événement, pas juste une baisse) : risque PLAUSIBLE mais NON CONFIRMÉ,
        pas un blocage établi. Ça dépend de la configuration d'agrégation du
        datafeed — le job simple généré ici n'énumère pas explicitement les
        valeurs de partition connues (min_doc_count=0 + liste 'include'), ce
        qui pourrait empêcher le modèle de recevoir un point de donnée "zéro"
        scorable pour une partition totalement absente d'un bucket. Vérifiable
        empiriquement sur un vrai job ; peut être corrigé en configurant le
        datafeed avec l'agrégation appropriée si confirmé nécessaire.
    """
    query_key = rule.get("query_key")
    keys = [query_key] if isinstance(query_key, str) else list(query_key or [])

    detector: dict = {
        "function": "low_count",
        "detector_description": (
            f"Baisse anormale du volume d'événements — migré depuis la règle "
            f"ElastAlert (flatline) « {rule.name} »"
        ),
    }
    if keys:
        detector["partition_field_name"] = keys[0]

    plan = _assemble(
        rule, suffix="flatline",
        description=f"Migré depuis ElastAlert (flatline) : {rule.name}",
        detectors=[detector], influencer_keys=keys[:1],
    )

    notes = [
        "threshold ElastAlert est un plancher ABSOLU et déterministe (alerte si "
        "count < threshold) ; low_count détecte une baisse RELATIVE à la baseline "
        "apprise. Les deux sont complémentaires : gardez la règle Threshold déjà "
        "générée comme garde-fou déterministe du plancher, ce job ML comme signal "
        "d'alerte précoce sur une tendance à la baisse.",
        "Comme pour l'approximation ES|QL, un job partitionné SANS agrégation "
        "de datafeed configurée explicitement (min_doc_count=0 + liste des "
        "valeurs de query_key connues) risque de ne pas produire de point de "
        "donnée scorable pour une entité totalement silencieuse — c'est un "
        "risque PLAUSIBLE, pas un blocage confirmé : à vérifier sur un job "
        "réel avant de trancher. Si confirmé, un datafeed avec agrégation "
        "explicite (au lieu de la simple requête générée ici) devrait le "
        "corriger — hors du périmètre de cette migration automatique.",
    ]
    if len(keys) > 1:
        notes.append(
            f"query_key combine plusieurs champs ({', '.join(keys)}) ; seul "
            f"'{keys[0]}' a été retenu comme partition_field_name."
        )
    plan.notes.extend(notes)
    return plan
