"""Confidence score: estimates how accurately a rule can be migrated automatically.

The score starts from a per-type base, then applies concrete penalties and bonuses:
translation warnings, required-field coverage, filter complexity, and semantic fidelity.
"""
from __future__ import annotations

from ..models import ConfidenceFactor, ConversionResult, RuleStrategy

# Base confidence per ElastAlert type (reflects how faithfully the semantics can be reproduced)
BASE_BY_TYPE: dict[str, float] = {
    "any": 0.95,
    "blacklist": 0.90,
    "whitelist": 0.90,
    "frequency": 0.90,
    "cardinality": 0.85,
    "metric_aggregation": 0.82,
    "new_term": 0.90,
    "percentage_match": 0.62,
    "change": 0.55,
    "spike": 0.50,
    "flatline": 0.55,
}


def score(result: ConversionResult) -> ConversionResult:
    rule = result.source
    factors: list[ConfidenceFactor] = []

    base = BASE_BY_TYPE.get(rule.rule_type, 0.20)
    factors.append(ConfidenceFactor("base_type", base,
                                    f"Base confidence for type '{rule.rule_type}'"))

    # Manual strategy = very low confidence
    if result.strategy == RuleStrategy.MANUAL:
        # Distinguish custom detection code (worst case) from unknown type.
        if result.metadata.get("custom_detection_code"):
            result.confidence = 0.05
            factors.append(ConfidenceFactor(
                "custom_detection_code", -base + 0.05,
                "Detection logic is in custom Python code — cannot be migrated automatically"))
        else:
            result.confidence = 0.10
            factors.append(ConfidenceFactor("manual", -base + 0.10,
                                            "Unknown or unsupported type — manual migration required"))
        result.factors = factors
        return result

    # Custom actions/enhancements: detection migrates but the action must be recreated.
    analysis = rule.script_analysis
    if analysis is not None and analysis.has_any:
        n_actions = sum(
            1 for f in analysis.findings
            if f.category in ("custom_alerter", "command_alerter")
        )
        n_enh = sum(1 for f in analysis.findings if f.category == "enhancement")
        if n_actions:
            pen = min(0.05 * n_actions, 0.12)
            factors.append(ConfidenceFactor(
                "custom_action", -pen,
                f"{n_actions} custom action(s) (command/alerter) must be recreated as Elastic connectors"))
        if n_enh:
            pen = min(0.06 * n_enh, 0.15)
            factors.append(ConfidenceFactor(
                "enhancement", -pen,
                f"{n_enh} Python match_enhancement(s) — must be reviewed and ported manually"))

    # Penalty per conversion warning
    n_warn = len(result.warnings)
    if n_warn:
        penalty = min(0.10 * n_warn, 0.30)
        factors.append(ConfidenceFactor(
            "warnings", -penalty, f"{n_warn} conversion warning(s)"))

    # Lucene query_string filters reduce confidence (best-effort translation)
    has_lucene = any(
        "query" in f or "query_string" in f for f in rule.filters
    )
    if has_lucene:
        factors.append(ConfidenceFactor(
            "lucene_filter", -0.05,
            "Lucene query_string filter translated on a best-effort basis — complex queries may not match exactly"))

    # Bonus: only structured filters, no Lucene
    if rule.filters and not has_lucene:
        factors.append(ConfidenceFactor(
            "structured_filter", +0.03, "Structured filters (term/terms/range) — full fidelity"))

    # Check required fields for this type
    missing = _missing_required_fields(rule)
    if missing:
        factors.append(ConfidenceFactor(
            "missing_fields", -0.15,
            f"Required ElastAlert fields missing: {', '.join(missing)}"))

    # Semantic penalty for behavioral types (approximation only)
    if rule.rule_type in ("spike", "flatline", "change"):
        factors.append(ConfidenceFactor(
            "semantic_gap", -0.05,
            "Temporal semantics not strictly equivalent — behavioral type, approximation only"))

    # Bonus: query_key correctly mapped on aggregating types
    if rule.rule_type in ("frequency", "cardinality", "metric_aggregation") \
            and rule.get("query_key"):
        factors.append(ConfidenceFactor(
            "query_key", +0.03, "query_key correctly mapped to STATS ... BY"))

    total = sum(f.delta for f in factors)
    result.confidence = max(0.0, min(1.0, total))
    result.factors = factors
    return result


def _missing_required_fields(rule) -> list[str]:  # noqa: ANN001
    req = {
        "frequency": ["num_events", "timeframe"],
        "cardinality": ["cardinality_field"],
        "metric_aggregation": ["metric_agg_key", "metric_agg_type"],
        "new_term": ["fields"],
        "blacklist": ["compare_key", "blacklist"],
        "whitelist": ["compare_key", "whitelist"],
        "spike": ["spike_height", "timeframe"],
        "flatline": ["threshold", "timeframe"],
        "change": ["compare_key", "query_key"],
        "percentage_match": ["match_bucket_filter"],
    }
    needed = req.get(rule.rule_type, [])
    return [f for f in needed if rule.get(f) is None]


def confidence_band(value: float) -> str:
    if value >= 0.85:
        return "HIGH"
    if value >= 0.60:
        return "MEDIUM"
    if value >= 0.30:
        return "LOW"
    return "VERY LOW"
