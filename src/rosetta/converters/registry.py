"""Converters: each function transforms an ElastAlertRule into a ConversionResult.

CONVERTERS maps the ElastAlert `type` to its converter function.
Each converter picks the best Elastic strategy and builds the query.
"""
from __future__ import annotations

from typing import Callable

from ..esql.translator import filter_to_esql, filter_to_kql
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
    res = _base_result(rule, RuleStrategy.ESQL)
    card_field = rule.get("cardinality_field")
    query_key = rule.get("query_key")
    max_c = rule.get("max_cardinality")
    min_c = rule.get("min_cardinality")
    where = _where(rule, res)
    keys = _query_keys(query_key)
    by = (" BY " + ", ".join(keys)) if keys else ""
    cmp = ""
    if max_c is not None:
        cmp = f"| WHERE distinct_count > {max_c}"
    elif min_c is not None:
        cmp = f"| WHERE distinct_count < {min_c}"
    if not card_field:
        res.warnings.append(
            "cardinality_field is missing — COUNT_DISTINCT(*) used as a fallback. "
            "Verify the generated query."
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
    """type: metric_aggregation -> STATS <agg>(field)."""
    res = _base_result(rule, RuleStrategy.ESQL)
    agg_type = str(rule.get("metric_agg_type", "avg")).upper()
    agg_key = rule.get("metric_agg_key", "")
    query_key = rule.get("query_key")
    max_t = rule.get("max_threshold")
    min_t = rule.get("min_threshold")
    esql_agg = {"AVG": "AVG", "SUM": "SUM", "MIN": "MIN", "MAX": "MAX",
                "CARDINALITY": "COUNT_DISTINCT"}.get(agg_type, "AVG")
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
        "Consider using an ML rule or a manually tuned threshold instead."
    )
    res.metadata["spike_height"] = spike_height
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
        "Invert the logic (e.g. use a suppression or absence-detection rule) or validate manually."
    )
    return res


def convert_change(rule: ElastAlertRule) -> ConversionResult:
    """type: change -> detects a field-value change per entity (query_key).
    Approximated in ES|QL via COUNT_DISTINCT on the monitored field."""
    res = _base_result(rule, RuleStrategy.ESQL)
    compound = rule.get("compound_compare_key") or rule.get("compare_key")
    query_key = rule.get("query_key", "")
    fields = compound if isinstance(compound, list) else [compound] if compound else []
    where = _where(rule, res)
    keys = _query_keys(query_key)
    by = (" BY " + ", ".join(keys)) if keys else ""
    stats = ", ".join(
        f"changes_{i} = COUNT_DISTINCT({f})" for i, f in enumerate(fields)
    ) or "changes_0 = COUNT_DISTINCT(*)"
    change_cols = [f"changes_{i}" for i in range(max(len(fields), 1))]
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


def convert(rule: ElastAlertRule) -> ConversionResult:
    # Custom detection code in the rule type blocks automatic conversion entirely.
    analysis = rule.script_analysis
    if analysis is not None and analysis.blocks_detection:
        res = _base_result(rule, RuleStrategy.MANUAL)
        for f in analysis.findings:
            if f.blocks_detection:
                res.warnings.append(f.detail)
        res.metadata["custom_detection_code"] = True
        return res

    converter = CONVERTERS.get(rule.rule_type, convert_unknown)
    result = converter(rule)

    # Propagate custom ACTION findings (don't block detection migration,
    # but the action must be recreated on the Elastic side).
    if analysis is not None and analysis.has_any:
        for f in analysis.findings:
            if not f.blocks_detection:
                result.warnings.append(f.detail)
                if f.reference:
                    result.metadata.setdefault("custom_actions", []).append(
                        {"category": f.category, "reference": f.reference}
                    )
    return result
