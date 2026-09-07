"""Détection de listes ElastAlert `blacklist`/`whitelist` dont les valeurs
ressemblent à de vrais IOC (hash, IP, domaine, URL) plutôt qu'à de la logique
métier (ex: liste de comptes de service, de départements...), et plan de
migration vers le type Elastic Security `threat_match` (nom UI : « Indicator
Match » — le champ TOML réel est bien `type = "threat_match"`, vérifié contre
un exemple réel du dépôt elastic/detection-rules).

Pourquoi un companion plutôt qu'un export direct ?
Comme pour ml_job.py : `threat_match` référence un `threat_index` qui doit
exister et être peuplé. Rosetta ne peut pas créer cet index depuis un simple
TOML, mais contrairement au job ML, il N'Y A PAS de période d'apprentissage
ici — on a déjà les valeurs exactes de la liste ElastAlert, donc on peut
générer directement les commandes de peuplement (bulk index), prêtes à
l'emploi, sans étape d'observation intermédiaire.

Heuristique de détection : nom du champ ET forme des valeurs doivent
correspondre à un type d'IOC connu. C'est une supposition, pas une certitude
— documentée comme telle dans le score de migration (base 0.85, -0.05 pour
le caractère heuristique de la détection de type).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .models import ElastAlertRule

_FIELD_PATTERNS: dict[str, re.Pattern[str]] = {
    "hash": re.compile(r"(^|[._])(hash|md5|sha1|sha256|sha512|imphash)([._]|$)", re.I),
    "ip": re.compile(r"(^|[._])ip([._]|$)", re.I),
    "domain": re.compile(r"(^|[._])domain([._]|$)", re.I),
    "url": re.compile(r"(^|[._])url([._]|$)", re.I),
}

_VALUE_CHECKS: dict[str, re.Pattern[str]] = {
    "hash": re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$"),
    "ip": re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    "domain": re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$"),
    "url": re.compile(r"^https?://", re.I),
}

_MIN_MATCH_RATIO = 0.7  # au moins 70% des valeurs doivent correspondre à la forme attendue


def detect_ioc_type(compare_key: str, values: list) -> str | None:  # noqa: ANN401
    """Renvoie 'hash'/'ip'/'domain'/'url' si le nom du champ ET la majorité
    des valeurs correspondent à ce type d'IOC, sinon None. Heuristique
    déclarée comme telle partout où elle est utilisée — jamais présentée
    comme une certitude."""
    if not compare_key or not values:
        return None
    for ioc_type, field_re in _FIELD_PATTERNS.items():
        if not field_re.search(compare_key):
            continue
        value_re = _VALUE_CHECKS[ioc_type]
        matches = sum(1 for v in values if value_re.match(str(v).strip()))
        if matches / len(values) >= _MIN_MATCH_RATIO:
            return ioc_type
    return None


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return s or "rosetta_ioc"


@dataclass
class IndicatorMatchPlan:
    threat_index: str
    ioc_type: str
    compare_key: str
    values: list
    notes: list[str] = field(default_factory=list)

    def as_console_commands(self) -> str:
        """Commandes Kibana Dev Console prêtes à l'emploi : création de
        l'index (mapping minimal) puis peuplement en masse avec les valeurs
        EXACTES de la liste ElastAlert — pas de période d'apprentissage
        nécessaire, contrairement au job ML."""
        bulk_lines = []
        for v in self.values:
            bulk_lines.append(json.dumps({"index": {"_index": self.threat_index}}))
            bulk_lines.append(json.dumps({"threat": {"indicator": {
                "value": v, "type": self.ioc_type,
            }}}))
        bulk_body = "\n".join(bulk_lines) + "\n"
        return (
            f"PUT {self.threat_index}\n"
            + json.dumps({
                "mappings": {"properties": {
                    "threat": {"properties": {"indicator": {"properties": {
                        "value": {"type": "keyword"},
                        "type": {"type": "keyword"},
                    }}}}
                }}
            }, indent=2, ensure_ascii=False)
            + f"\n\nPOST _bulk\n{bulk_body}"
        )


def plan_indicator_match(rule: ElastAlertRule) -> IndicatorMatchPlan | None:
    """Construit le plan threat_match pour une règle `blacklist` UNIQUEMENT
    (jamais `whitelist`), si detect_ioc_type() reconnaît un type d'IOC dans
    compare_key/values.

    threat_match alerte quand la valeur observée CORRESPOND à un indicateur
    de l'index threat intel — c'est exactement la sémantique 'blacklist'
    (alerte si la valeur EST dans la liste). Une règle 'whitelist' a la
    sémantique opposée (alerte si la valeur N'EST PAS dans la liste connue) :
    threat_match n'a pas de mode 'ne correspond à aucun indicateur' — la doc
    Elastic est explicite là-dessus ("Mapping entries that only use the DOES
    NOT MATCH condition are not supported"). Recommander indicator_match pour
    un whitelist serait donc structurellement faux, même avec des valeurs à
    forme d'IOC : ce n'est pas un problème de détection IOC, c'est un
    problème de détection de déviation par rapport à une liste de référence,
    qui reste mieux servi par le NOT IN(...) ES|QL déjà généré par défaut.
    """
    if "whitelist" in rule.raw:
        return None
    compare_key = rule.get("compare_key", "")
    values = rule.get("blacklist") or []
    ioc_type = detect_ioc_type(compare_key, values)
    if ioc_type is None:
        return None

    threat_index = f"rosetta-ioc-{_slug(rule.name)}"
    notes = [
        f"Type d'IOC détecté par heuristique (nom de champ + forme des "
        f"valeurs) : '{ioc_type}'. Vérifiez que c'est correct — Rosetta ne "
        "connaît pas la sémantique réelle de vos données.",
        "Si vous avez déjà un flux threat intel réel (intégration MISP, "
        "AbuseCH, etc.), pointez threat_index/threat_mapping dessus plutôt "
        "que sur cet index dédié généré à partir de la seule liste statique "
        "ElastAlert.",
        f"{len(values)} valeur(s) à indexer — pas de période d'apprentissage "
        "requise (contrairement au job ML) : la règle threat_match fonctionne "
        "dès que l'index est peuplé.",
    ]
    return IndicatorMatchPlan(
        threat_index=threat_index, ioc_type=ioc_type,
        compare_key=compare_key, values=list(values), notes=notes,
    )
