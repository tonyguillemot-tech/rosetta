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
    "metric_aggregation": 0.85,
    "new_term": 0.90,
    "percentage_match": 0.62,
    "change": 0.55,
    "spike": 0.50,
    "flatline": 0.55,
}


IM_MIGRATION_BASE = 0.85


def _score_indicator_match(rule, result: ConversionResult) -> None:  # noqa: ANN001
    """Score de migration vers threat_match (indicator_match), même principe
    que _score_ml_migration : dimension séparée, n'affecte jamais confidence.

    Ne s'applique que si threat_match est une ALTERNATIVE à ce qui est livré
    (petite liste -> ES|QL livré) — pas quand c'est DÉJÀ la stratégie livrée
    (grosse liste -> RuleStrategy.THREAT_MATCH), sinon on afficherait un badge
    'chemin recommandé : Indicator Match' à côté d'une règle qui EST déjà de
    l'Indicator Match, ce qui n'a pas de sens."""
    plan = result.metadata.get("indicator_match_plan")
    if plan is None or result.strategy == RuleStrategy.THREAT_MATCH:
        return
    factors: list[ConfidenceFactor] = [ConfidenceFactor(
        "im_base_type", IM_MIGRATION_BASE,
        f"Base threat_match mapping fidelity ('{plan.ioc_type}' IOC type detected)")]
    factors.append(ConfidenceFactor(
        "heuristic_type_detection", -0.05,
        "IOC type detected by field-name + value-shape heuristic, not a "
        "confirmed data contract — verify before relying on it"))
    total = sum(f.delta for f in factors)
    result.metadata["migration_strategy"] = "indicator_match"
    result.metadata["migration_score"] = max(0.0, min(1.0, total))
    result.metadata["migration_factors"] = [
        {"label": f.label, "delta": f.delta, "detail": f.detail} for f in factors
    ]


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

    # Penalty per conversion warning — excludes warnings already accounted for
    # above via custom_action/enhancement (registry.convert() pushes each
    # ScriptFinding.detail into result.warnings too, for visibility in the
    # note ; without this exclusion the same underlying fact would be
    # penalized twice). The warning text itself is left untouched and still
    # shown to the reviewer — only the score no longer double-counts it.
    n_script_warnings = 0
    if analysis is not None and analysis.has_any:
        n_script_warnings = sum(1 for f in analysis.findings if not f.blocks_detection)
    n_warn = max(0, len(result.warnings) - n_script_warnings)
    if n_warn:
        penalty = min(0.10 * n_warn, 0.30)
        factors.append(ConfidenceFactor(
            "warnings", -penalty, f"{n_warn} conversion warning(s)"))

    # Lucene query_string filters: on ne pénalise que si le parser a
    # explicitement signalé une construction qu'il ne peut pas traduire
    # fidèlement (regex/fuzzy/boost/proximité/terme libre) — plus une
    # pénalité systématique juste parce qu'un query_string est présent.
    # Une traduction propre reste neutre (0.0), pas bonifiée comme un filtre
    # structuré : Lucene sur un champ 'text' analysé peut matcher différemment
    # d'un '==' ES|QL exact, un risque résiduel non vérifiable sans le mapping
    # de l'index — donc pas de bonus structured_filter non plus dans ce cas.
    lucene_warning = any(
        w.startswith("Requête Lucene partiellement convertie") for w in result.warnings
    )
    has_lucene = any("query" in f or "query_string" in f for f in rule.filters)
    if lucene_warning:
        factors.append(ConfidenceFactor(
            "lucene_uncertain", -0.05,
            "Part of the Lucene query could not be translated with full fidelity "
            "(regex/fuzzy/boost/proximity/free-text term) — verify manually"))
    elif has_lucene:
        factors.append(ConfidenceFactor(
            "lucene_exact", 0.0,
            "Lucene query_string fully parsed (field:value, AND/OR/NOT, ranges, "
            "comparisons) — residual risk: analyzed-field matching semantics can't "
            "be verified without the index mapping"))

    # Bonus: only structured DSL filters (term/terms/range/...), no Lucene at all
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
    _score_ml_migration(rule, result)
    _score_indicator_match(rule, result)
    return result


# Fidélité du MAPPING vers un job ML — dimension SÉPARÉE du score de
# confiance ci-dessus, qui reste sur la règle ES|QL/native réellement livrée.
# migration_score n'est PAS une prédiction de qualité de détection une fois
# déployé (ça dépend du trafic réel et du réglage d'anomaly_threshold, qu'on
# ne connaît pas) — c'est la fidélité du CHEMIN documenté (job + datafeed,
# cf. ml_job.py) par rapport à la sémantique ElastAlert d'origine, calculée
# sur le même principe que le score de confiance (base par type + pénalités
# pour les écarts déjà documentés dans ml_job.py, pas de fabrication de
# précision sur ce qu'on ne peut pas connaître).
ML_MIGRATION_BASE_BY_TYPE: dict[str, float] = {
    "spike": 0.80,
    "change": 0.65,
    "flatline": 0.55,
}


def _score_ml_migration(rule, result: ConversionResult) -> None:  # noqa: ANN001
    """Peuple result.metadata['migration_strategy'/'migration_score'/
    'migration_factors'] quand un job ML pertinent a été généré (spike/
    change/flatline avec ml_job_commands déjà attaché par registry.py).
    N'affecte jamais result.confidence/result.factors : dimension séparée,
    pas un recalibrage du score de la règle livrée."""
    base = ML_MIGRATION_BASE_BY_TYPE.get(rule.rule_type)
    if base is None or not result.metadata.get("ml_job_commands"):
        return

    factors: list[ConfidenceFactor] = [ConfidenceFactor(
        "ml_base_type", base,
        f"Base ML job mapping fidelity for '{rule.rule_type}' "
        "(high_count/rare/low_count function, partition_field_name from query_key)")]

    if rule.rule_type == "spike":
        factors.append(ConfidenceFactor(
            "no_spike_height_equivalent", -0.05,
            "spike_height has no direct ML equivalent — anomaly_threshold default "
            "used instead of the ElastAlert ratio"))
    elif rule.rule_type == "change":
        factors.append(ConfidenceFactor(
            "first_appearance_bias", -0.10,
            "'rare' flags statistically unseen values, biased toward first "
            "appearance — not a reproduction of 'alert on every transition'"))
    elif rule.rule_type == "flatline":
        factors.append(ConfidenceFactor(
            "total_absence_uncertain", -0.05,
            "Whether a totally silent (known) entity still produces a scorable "
            "'zero' data point for its partition depends on datafeed aggregation "
            "config (min_doc_count=0 + explicit value list) — the simple job "
            "generated here doesn't set this up, so this is a plausible but "
            "UNCONFIRMED risk, not a certain blind spot"))

    total = sum(f.delta for f in factors)
    result.metadata["migration_strategy"] = "machine_learning"
    result.metadata["migration_score"] = max(0.0, min(1.0, total))
    result.metadata["migration_factors"] = [
        {"label": f.label, "delta": f.delta, "detail": f.detail} for f in factors
    ]


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
