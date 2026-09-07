"""Converters: each function transforms an ElastAlertRule into a ConversionResult.

CONVERTERS maps the ElastAlert `type` to its converter function.
Each converter picks the best Elastic strategy and builds the query.
"""
from __future__ import annotations

from typing import Callable

import re

from ..esql.translator import filter_to_esql, filter_to_kql
from ..field_hints import check_filters, check_value
from ..indicator_match import plan_indicator_match
from ..ml_job import plan_change_ml_job, plan_flatline_ml_job, plan_spike_ml_job
from ..models import ConversionResult, ElastAlertRule, RuleStrategy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _from_clause(rule: ElastAlertRule) -> str:
    index = rule.index or "logs-*"
    return f"FROM {index} METADATA _id, _version, _index"


def _timeframe_to_lookback(rule: ElastAlertRule, default: str = "now-6m") -> str:
    """Converts the ElastAlert `timeframe` dict to an Elastic lookback string (e.g. 'now-6m').
    Adds +1 unit as a safety margin."""
    tf = rule.get("timeframe")
    if isinstance(tf, dict):
        for unit, key in (("minutes", "m"), ("hours", "h"), ("days", "d"), ("seconds", "s")):
            if unit in tf:
                return f"now-{int(tf[unit]) + 1}{key}"
    return default


def _interval_from_timeframe(rule: ElastAlertRule, default: str = "5m") -> str:
    tf = rule.get("timeframe")
    if isinstance(tf, dict):
        if "minutes" in tf:
            return f"{tf['minutes']}m"
        if "hours" in tf:
            return f"{int(tf['hours']) * 60}m"
    return default


def _base_result(rule: ElastAlertRule, strategy: RuleStrategy) -> ConversionResult:
    res = ConversionResult(source=rule, strategy=strategy)
    res.lookback = _timeframe_to_lookback(rule)
    res.interval = _interval_from_timeframe(rule)
    # Cohérence champ/valeur (heuristique de nommage, cf. field_hints.py) —
    # ici plutôt qu'en aval de chaque converter : tous y passent, et le
    # filtre source (rule.filters) est identique quelle que soit la stratégie
    # de sortie choisie ensuite.
    res.warnings.extend(check_filters(rule.filters))
    return res


def _where(rule: ElastAlertRule, res: ConversionResult) -> str:
    clause = filter_to_esql(rule.filters, res.warnings)
    return f"| WHERE {clause}" if clause else ""


def _query_keys(query_key) -> list[str]:
    """Normalise `query_key` (str | list | None) en liste de champs."""
    if not query_key:
        return []
    return [query_key] if isinstance(query_key, str) else list(query_key)


def _keep(cols: list[str]) -> str:
    """Clause finale `| KEEP …`. Requise par detection-rules pour les règles
    ES|QL : sans elle, `view-rule` rejette la requête (EsqlSemanticError)."""
    cols = [c for c in cols if c]
    return f"| KEEP {', '.join(cols)}" if cols else ""


def _attach_ml_job(res: ConversionResult, plan) -> None:
    """Attache un plan de job ML (spike/change/flatline) au résultat, si
    generé (plan_change_ml_job peut renvoyer None faute de compare_key)."""
    if plan is None:
        return
    res.metadata["ml_job_id"] = plan.job_id
    res.metadata["ml_job_commands"] = plan.as_console_commands()
    res.metadata["ml_job_notes"] = plan.notes
    res.metadata["ml_anomaly_threshold"] = plan.anomaly_threshold


# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------


def convert_any(rule: ElastAlertRule) -> ConversionResult:
    """type: any -> non-aggregating ES|QL (each matched event produces one alert)."""
    res = _base_result(rule, RuleStrategy.ESQL)
    where = _where(rule, res)
    res.esql_query = (
        f"{_from_clause(rule)}\n{where}\n"
        "| KEEP _id, _version, _index, @timestamp"
    ).replace("\n\n", "\n")
    return res


_LARGE_IOC_LIST_THRESHOLD = 20  # au-delà, IN(...) en dur devient un vrai défaut pratique, pas juste "moins bien"


def convert_blacklist_whitelist(rule: ElastAlertRule) -> ConversionResult:
    res = _base_result(rule, RuleStrategy.ESQL)
    field = rule.get("compare_key", "")
    values = rule.get("blacklist") or rule.get("whitelist") or []
    negate = "whitelist" in rule.raw
    where = _where(rule, res)
    if field and values:
        joined = ", ".join(f'"{v}"' for v in values)
        op = "NOT IN" if negate else "IN"
        listclause = f"| WHERE {field} {op} ({joined})"
        # Cohérence champ/valeur : ces valeurs ne passent pas par rule.filters
        # (compare_key/blacklist/whitelist sont des clés ElastAlert à part),
        # donc pas couvertes par le check_filters() de _base_result — vérifiées
        # ici spécifiquement. Complémentaire, pas redondant, avec la détection
        # indicator_match : celle-ci confirme une forme IOC valide, celle-là
        # détecte au contraire une incohérence.
        seen_msgs: set[str] = set()
        for v in values:
            msg = check_value(field, v)
            if msg and msg not in seen_msgs:
                seen_msgs.add(msg)
                res.warnings.append(msg)
    else:
        listclause = ""
        res.warnings.append(
            "Missing compare_key or value list — no IN/NOT IN filter clause was generated. "
            "Check your blacklist/whitelist rule definition."
        )
    res.esql_query = "\n".join(
        c for c in (
            _from_clause(rule), where, listclause,
            "| KEEP _id, _version, _index, @timestamp",
        ) if c
    )
    plan = plan_indicator_match(rule)
    if plan is not None:
        res.metadata["indicator_match_plan"] = plan
        # Champs dérivés, JSON-sérialisables : mêmes clés que le pattern
        # ml_job_* déjà utilisé pour spike/change/flatline, pour que
        # cmd_report/html_writer puissent les afficher sans toucher à l'objet
        # IndicatorMatchPlan lui-même (non sérialisable tel quel).
        res.metadata["indicator_match_commands"] = plan.as_console_commands()
        res.metadata["indicator_match_threat_index"] = plan.threat_index
        res.metadata["indicator_match_notes"] = plan.notes

        if len(plan.values) > _LARGE_IOC_LIST_THRESHOLD:
            # Passé une poignée d'entrées, IN(...) en dur n'est plus une
            # option viable du tout (pas juste "moins bien") : chaque mise à
            # jour de la liste IOC obligerait à régénérer/redéployer toute la
            # règle. indicator_match devient LE fichier livré — plus de
            # fallback ES|QL généré. Le fichier reste enabled=false tant que
            # threat_index n'est pas peuplé (pas de résultat par défaut), donc
            # c'est un vrai défaut pratique du livrable : ça pèse sur la
            # confiance, contrairement au cas <= seuil où l'ES|QL livré est
            # pleinement fonctionnel et indicator_match n'est qu'une option.
            res.strategy = RuleStrategy.THREAT_MATCH
            res.esql_query = None
            # Pour que le tiroir de détail affiche la requête (section
            # générique déjà existante, pas besoin de nouveau code) — liste de
            # warnings à part pour ne pas dupliquer ce que _where() a déjà
            # remonté plus haut sur les mêmes filtres.
            _im_kql_warnings: list[str] = []
            res.kql_query = (
                filter_to_kql(rule.filters, _im_kql_warnings) if rule.filters else "*:*"
            )
            res.warnings.append(
                f"This blacklist has {len(plan.values)} entries — too many for "
                "an inline ES|QL IN() clause to be a viable primary rule "
                "(every list update would require regenerating and "
                "redeploying it). Delivered as indicator_match instead: "
                "enabled=false until the threat_index (commands in this "
                "rule's note) is populated — nothing fires until then."
            )
    return res


def convert_frequency(rule: ElastAlertRule) -> ConversionResult:
    """type: frequency -> ES|QL STATS COUNT() BY <query_key> | WHERE count >= num_events."""
    res = _base_result(rule, RuleStrategy.ESQL)
    num_events = rule.get("num_events", 1)
    query_key = rule.get("query_key")
    where = _where(rule, res)
    keys = _query_keys(query_key)
    by = (" BY " + ", ".join(keys)) if keys else ""
    res.esql_query = "\n".join(
        c for c in (
            _from_clause(rule),
            where,
            f"| STATS event_count = COUNT(*){by}",
            f"| WHERE event_count >= {num_events}",
            _keep(keys + ["event_count"]),
        ) if c
    )
    res.metadata["num_events"] = num_events
    return res


def convert_cardinality(rule: ElastAlertRule) -> ConversionResult:
    """type: cardinality -> ES|QL COUNT_DISTINCT(cardinality_field)."""
    card_field = rule.get("cardinality_field")
    if not card_field:
        # cardinality_field est requis par ElastAlert lui-même pour ce type :
        # sans lui, il n'y a aucun champ sur lequel calculer une cardinalité.
        # Contrairement à COUNT, COUNT_DISTINCT n'accepte pas '*' en ES|QL —
        # il n'existe donc PAS de fallback syntaxiquement valide qui préserve
        # la sémantique "cardinalité". Générer quand même une requête produirait
        # soit du ES|QL invalide, soit une règle silencieusement différente
        # (un simple COUNT) déguisée en cardinalité. Mieux vaut ne rien
        # générer que générer une requête cassée ou trompeuse.
        res = _base_result(rule, RuleStrategy.MANUAL)
        res.warnings.append(
            "cardinality_field is missing: this ElastAlert rule is incomplete "
            "(the field is required by ElastAlert itself for this type). No "
            "valid ES|QL query can be generated without it — COUNT_DISTINCT "
            "has no '*' fallback in ES|QL (unlike COUNT). Set cardinality_field "
            "in the source rule, or migrate this one manually."
        )
        return res
    query_key = rule.get("query_key")
    max_c = rule.get("max_cardinality")
    min_c = rule.get("min_cardinality")
    keys = _query_keys(query_key)

    if max_c is not None and keys:
        # Threshold.cardinality natif : le seul sens qu'il sait exprimer est
        # "au moins N valeurs distinctes" (confirmé par un ticket réel du
        # dépôt : elastic/detection-rules#3617, "Threshold rule only supports
        # greater than"). ElastAlert déclenche quand cardinality >
        # max_cardinality (strictement) ; Threshold quand cardinality >=
        # value : +1 pour reproduire fidèlement la borne, pas une approximation
        # au hasard.
        #
        # Nécessite AUSSI un query_key (donc `keys` non vide) : la doc Elastic
        # est ambiguë sur le fait qu'un `field` de groupement vide soit valide
        # pour une agrégation globale sans groupement ("Optionally... one or
        # more fields" — pas de confirmation claire dans un sens ou l'autre).
        # Plutôt que deviner, on reste sur l'ES|QL déjà éprouvé dans ce cas.
        res = _base_result(rule, RuleStrategy.THRESHOLD)
        res.kql_query = filter_to_kql(rule.filters, res.warnings)
        res.threshold = {
            "field": keys,
            # ElastAlert cardinality n'a pas de seuil de COMPTE minimum,
            # seulement un seuil de cardinalité — 1 est la valeur la moins
            # contraignante possible pour ce champ requis par le schéma Threshold.
            "value": 1,
            "cardinality": {"field": card_field, "value": int(max_c) + 1},
        }
        if min_c is not None:
            res.warnings.append(
                "Both max_cardinality and min_cardinality were set — only "
                "max_cardinality maps to native Threshold; min_cardinality is "
                "ignored in this strategy (Threshold has no 'fewer than N "
                "values' mode, confirmed by elastic/detection-rules#3617). "
                "Verify this rule only needs the max_cardinality behavior, or "
                "migrate the min_cardinality case separately."
            )
        return res

    # min_cardinality (pas d'équivalent natif Threshold, même ticket #3617),
    # ou max_cardinality SANS query_key (ambiguïté doc sur un `field` de
    # groupement vide, cf. commentaire ci-dessus — on ne devine pas) : reste
    # en ES|QL, qui exprime les deux cas librement.
    res = _base_result(rule, RuleStrategy.ESQL)
    where = _where(rule, res)
    by = (" BY " + ", ".join(keys)) if keys else ""
    cmp = ""
    if min_c is not None:
        cmp = f"| WHERE distinct_count < {min_c}"
        res.warnings.append(
            "min_cardinality has no native Threshold equivalent ('at least N "
            "values' only, confirmed by elastic/detection-rules#3617) — kept "
            "as an ES|QL approximation instead."
        )
    elif max_c is not None:
        cmp = f"| WHERE distinct_count > {max_c}"
        res.warnings.append(
            "max_cardinality without a query_key: native Threshold requires a "
            "group-by field and the docs are ambiguous about an empty one for "
            "a global (ungrouped) aggregate — kept as an ES|QL approximation "
            "instead of guessing."
        )
    res.esql_query = "\n".join(
        c for c in (
            _from_clause(rule),
            where,
            f"| STATS distinct_count = COUNT_DISTINCT({card_field}){by}",
            cmp,
            _keep(keys + ["distinct_count"]),
        ) if c
    )
    return res


def convert_metric_aggregation(rule: ElastAlertRule) -> ConversionResult:
    """type: metric_aggregation -> ES|QL AVG/SUM/MIN/MAX/COUNT_DISTINCT(metric_agg_key)."""
    agg_key = rule.get("metric_agg_key")
    if not agg_key:
        # Même situation que cardinality_field pour 'cardinality' : sans champ
        # sur lequel agréger, la seule alternative à une requête cassée
        # (AVG(), SUM()... avec des parenthèses vides — ES|QL invalide) est de
        # ne rien générer et de signaler la règle source comme incomplète.
        res = _base_result(rule, RuleStrategy.MANUAL)
        res.warnings.append(
            "metric_agg_key is missing: this ElastAlert rule is incomplete "
            "(the field is required by ElastAlert itself for this type). No "
            "valid ES|QL query can be generated without a target field — "
            "AVG()/SUM()/MIN()/MAX() with no argument is not valid ES|QL. "
            "Set metric_agg_key in the source rule, or migrate this one manually."
        )
        return res
    res = _base_result(rule, RuleStrategy.ESQL)
    agg_type = str(rule.get("metric_agg_type", "avg")).upper()
    query_key = rule.get("query_key")
    max_t = rule.get("max_threshold")
    min_t = rule.get("min_threshold")
    esql_agg = {"AVG": "AVG", "SUM": "SUM", "MIN": "MIN", "MAX": "MAX",
                "CARDINALITY": "COUNT_DISTINCT", "VALUE_COUNT": "COUNT"}.get(agg_type)
    if esql_agg is None:
        # Type d'agrégation ElastAlert non mappé (ex: 'percentiles', qui exige
        # percentile_range et renvoie plusieurs valeurs, pas un scalaire) :
        # ne jamais retomber silencieusement sur AVG comme avant — c'est une
        # agrégation sémantiquement différente, pas une approximation neutre.
        res.warnings.append(
            f"metric_agg_type '{rule.get('metric_agg_type')}' has no direct ES|QL "
            "equivalent (e.g. 'percentiles' needs a percentile_range and returns "
            "multiple values) — AVG used as an approximate fallback, verify manually."
        )
        esql_agg = "AVG"
    where = _where(rule, res)
    keys = _query_keys(query_key)
    by = (" BY " + ", ".join(keys)) if keys else ""
    cmp = ""
    if max_t is not None:
        cmp = f"| WHERE metric_value > {max_t}"
    elif min_t is not None:
        cmp = f"| WHERE metric_value < {min_t}"
    res.esql_query = "\n".join(
        c for c in (
            _from_clause(rule),
            where,
            f"| STATS metric_value = {esql_agg}({agg_key}){by}",
            cmp,
            _keep(keys + ["metric_value"]),
        ) if c
    )
    return res


def convert_new_term(rule: ElastAlertRule) -> ConversionResult:
    """type: new_term -> native New Terms rule (not ES|QL)."""
    res = _base_result(rule, RuleStrategy.NEW_TERMS)
    fields = rule.get("fields", [])
    if isinstance(fields, str):
        fields = [fields]
    res.new_terms_fields = fields
    res.kql_query = filter_to_kql(rule.filters, res.warnings)
    # ElastAlert terms_window_size defaults to 30 days
    window = rule.get("terms_window_size", {"days": 30})
    if isinstance(window, dict) and "days" in window:
        res.history_window = f"now-{window['days']}d"
    else:
        res.history_window = "now-14d"
    if not fields:
        res.warnings.append(
            "No 'fields' defined for this new_term rule — "
            "the New Terms rule will have no tracked fields."
        )
    return res


def convert_spike(rule: ElastAlertRule) -> ConversionResult:
    """type: spike -> approximate ES|QL with two time windows + ratio.

    ElastAlert compares the current window against a reference window (spike_height).
    Scheduled ES|QL rules cannot natively compare two sliding windows, so this
    produces a DATE_TRUNC-based approximation and flags the semantic difference.
    """
    res = _base_result(rule, RuleStrategy.ESQL)
    query_key = rule.get("query_key")
    spike_height = rule.get("spike_height", 2)
    threshold_cur = rule.get("threshold_cur", 0)
    where = _where(rule, res)
    keys = _query_keys(query_key)
    by = (", " + ", ".join(keys)) if keys else ""
    res.esql_query = "\n".join(
        c for c in (
            _from_clause(rule),
            where,
            "| EVAL bucket = DATE_TRUNC(1 hour, @timestamp)",
            f"| STATS event_count = COUNT(*) BY bucket{by}",
            f"| WHERE event_count >= {max(threshold_cur, 1)}",
            _keep(["bucket"] + keys + ["event_count"]),
        ) if c
    )
    res.warnings.append(
        f"'spike' converted approximately: the current-window vs reference-window "
        f"comparison (spike_height={spike_height}) cannot be reproduced exactly in ES|QL. "
        "A ready-to-run Elasticsearch ML anomaly-detection job (faithful to "
        "spike_height/threshold_cur) is included in this rule's note field as an "
        "optional, more accurate alternative."
    )
    res.metadata["spike_height"] = spike_height
    _attach_ml_job(res, plan_spike_ml_job(rule))
    return res


def convert_flatline(rule: ElastAlertRule) -> ConversionResult:
    """type: flatline -> absence detection, mapped to a native Threshold rule.
    ES|QL cannot trivially detect absence of events within a time window."""
    res = _base_result(rule, RuleStrategy.THRESHOLD)
    threshold = rule.get("threshold", 1)
    query_key = rule.get("query_key")
    res.kql_query = filter_to_kql(rule.filters, res.warnings)
    res.threshold = {
        "field": [query_key] if isinstance(query_key, str) else (query_key or []),
        "value": int(threshold),
    }
    res.warnings.append(
        "'flatline' alert logic is inverted: ElastAlert fires when the event count "
        "drops BELOW the threshold; a Threshold rule fires when it EXCEEDS it. "
        "Invert the logic (e.g. use a suppression or absence-detection rule) or validate manually. "
        "An optional, complementary ML job (statistical low-count detection) is included "
        "in this rule's note field — see its caveats before relying on it alone."
    )
    _attach_ml_job(res, plan_flatline_ml_job(rule))
    return res


def convert_change(rule: ElastAlertRule) -> ConversionResult:
    """type: change -> detects a field-value change per entity (query_key).
    Approximated in ES|QL via COUNT_DISTINCT on the monitored field."""
    compound = rule.get("compound_compare_key") or rule.get("compare_key")
    fields = compound if isinstance(compound, list) else [compound] if compound else []
    if not fields:
        # Même famille de bug que cardinality_field/metric_agg_key : sans
        # compare_key/compound_compare_key, il n'y a aucun champ à comparer.
        # L'ancien fallback 'COUNT_DISTINCT(*)' n'est PAS un ES|QL valide
        # (contrairement à COUNT(*), COUNT_DISTINCT exige un champ ou littéral
        # réel) — mieux vaut ne rien générer que générer une requête cassée.
        res = _base_result(rule, RuleStrategy.MANUAL)
        res.warnings.append(
            "compare_key/compound_compare_key is missing: this ElastAlert rule is "
            "incomplete (required by ElastAlert itself for this type). No valid "
            "ES|QL query can be generated without a field to compare — "
            "COUNT_DISTINCT has no '*' fallback in ES|QL. Set compare_key in the "
            "source rule, or migrate this one manually."
        )
        return res
    res = _base_result(rule, RuleStrategy.ESQL)
    query_key = rule.get("query_key", "")
    where = _where(rule, res)
    keys = _query_keys(query_key)
    by = (" BY " + ", ".join(keys)) if keys else ""
    stats = ", ".join(
        f"changes_{i} = COUNT_DISTINCT({f})" for i, f in enumerate(fields)
    )
    change_cols = [f"changes_{i}" for i in range(len(fields))]
    where_changes = " OR ".join(f"{c} > 1" for c in change_cols)
    res.esql_query = "\n".join(
        c for c in (
            _from_clause(rule),
            where,
            f"| STATS {stats}{by}",
            f"| WHERE {where_changes}",
            _keep(keys + change_cols),
        ) if c
    )
    res.warnings.append(
        "'change' type approximated: detects >1 distinct value for the compared field "
        "within the time window — no strict temporal ordering is preserved. "
        "Verify this captures the field-change semantics you need."
    )
    _attach_ml_job(res, plan_change_ml_job(rule))
    return res


def convert_percentage_match(rule: ElastAlertRule) -> ConversionResult:
    """type: percentage_match -> match/total ratio computed via EVAL + CASE()."""
    res = _base_result(rule, RuleStrategy.ESQL)
    query_key = rule.get("query_key")
    max_pct = rule.get("max_percentage")
    min_pct = rule.get("min_percentage")
    match_filter = rule.get("match_bucket_filter", [])
    where = _where(rule, res)
    match_clause = filter_to_esql(match_filter, res.warnings) if match_filter else "true"
    keys = _query_keys(query_key)
    by = (" BY " + ", ".join(keys)) if keys else ""
    cmp = ""
    if max_pct is not None:
        cmp = f"| WHERE match_pct > {max_pct}"
    elif min_pct is not None:
        cmp = f"| WHERE match_pct < {min_pct}"
    res.esql_query = "\n".join(
        c for c in (
            _from_clause(rule),
            where,
            f"| EVAL is_match = CASE({match_clause}, 1, 0)",
            f"| STATS matched = SUM(is_match), total = COUNT(*){by}",
            "| EVAL match_pct = 100.0 * matched / total",
            cmp,
            _keep(keys + ["match_pct"]),
        ) if c
    )
    res.warnings.append(
        "'percentage_match': the match_bucket_filter was translated to an ES|QL CASE() "
        "expression — verify the generated EVAL clause matches your original intent."
    )
    return res


def convert_unknown(rule: ElastAlertRule) -> ConversionResult:
    res = _base_result(rule, RuleStrategy.MANUAL)
    res.warnings.append(
        f"ElastAlert type '{rule.rule_type}' is not supported for automatic conversion. "
        "Manual migration required."
    )
    return res


CONVERTERS: dict[str, Callable[[ElastAlertRule], ConversionResult]] = {
    "any": convert_any,
    "blacklist": convert_blacklist_whitelist,
    "whitelist": convert_blacklist_whitelist,
    "frequency": convert_frequency,
    "cardinality": convert_cardinality,
    "metric_aggregation": convert_metric_aggregation,
    "new_term": convert_new_term,
    "spike": convert_spike,
    "flatline": convert_flatline,
    "change": convert_change,
    "percentage_match": convert_percentage_match,
}


_SEQUENCE_HINT_RE = re.compile(
    r"sequence|chain|correlat|multistep|multi_step|workflow|stepwise|"
    r"ordered|stage\d|step\d",
    re.IGNORECASE,
)


def convert(rule: ElastAlertRule) -> ConversionResult:
    # Custom detection code in the rule type blocks automatic conversion entirely.
    analysis = rule.script_analysis
    if analysis is not None and analysis.blocks_detection:
        res = _base_result(rule, RuleStrategy.MANUAL)
        for f in analysis.findings:
            if f.blocks_detection:
                res.warnings.append(f.detail)
                # Heuristique PUREMENT sur le nom du module : on ne peut pas lire
                # la logique Python, seulement deviner sur le nommage. Pas de
                # migration_score ici (contrairement à ML/indicator_match, qui
                # ont un vrai mapping structurel à évaluer) — un chiffre sur une
                # supposition de nommage serait de la précision fabriquée.
                if f.category == "custom_rule_type" and _SEQUENCE_HINT_RE.search(f.reference):
                    res.metadata["migration_strategy"] = "eql"
                    res.warnings.append(
                        f"Module name ('{f.reference}') suggests a temporal "
                        "sequence/correlation pattern — EQL (event correlation) is "
                        "likely the right Elastic Security rule type. This is a "
                        "NAMING HEURISTIC ONLY (Rosetta cannot read the Python "
                        "logic) — verify against the actual code before committing."
                    )
        res.metadata["custom_detection_code"] = True
        return res

    converter = CONVERTERS.get(rule.rule_type, convert_unknown)
    result = converter(rule)

    # Propagate custom ACTION findings (don't block detection migration,
    # but the action must be recreated on the Elastic side) and ENHANCEMENT
    # findings separately. They are NOT the same kind of risk: a custom
    # alerter/command only affects notification (recreate as a connector),
    # while a match_enhancement runs *before* the match is finalized and can
    # alter what counts as a match at all (see scripts.py) — closer to a
    # detection-logic risk than an action to recreate. Keeping them in one
    # bucket labeled "connectors" mislabels the enhancement case.
    if analysis is not None and analysis.has_any:
        for f in analysis.findings:
            if not f.blocks_detection:
                result.warnings.append(f.detail)
                if f.reference and f.category == "enhancement":
                    result.metadata.setdefault("enhancements", []).append(
                        {"category": f.category, "reference": f.reference}
                    )
                elif f.reference:
                    result.metadata.setdefault("custom_actions", []).append(
                        {"category": f.category, "reference": f.reference}
                    )
    return result
