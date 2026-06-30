"""Score de confiance : estime la probabilité qu'une règle migre correctement.

Le score part d'une base par stratégie/type, puis applique des pénalités et
bonus selon des signaux concrets (warnings de traduction, présence des champs
requis, complexité des filtres, sémantique préservée).
"""
from __future__ import annotations

from ..models import ConfidenceFactor, ConversionResult, RuleStrategy

# Base de confiance par type ElastAlert (sémantique reproductible en Elastic)
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
                                    f"Base pour type '{rule.rule_type}'"))

    # Stratégie manuelle = confiance très faible
    if result.strategy == RuleStrategy.MANUAL:
        # Distinguer le code de détection custom (le pire cas) du type inconnu.
        if result.metadata.get("custom_detection_code"):
            result.confidence = 0.05
            factors.append(ConfidenceFactor(
                "custom_detection_code", -base + 0.05,
                "Logique de détection en Python custom : non migrable automatiquement"))
        else:
            result.confidence = 0.10
            factors.append(ConfidenceFactor("manual", -base + 0.10,
                                            "Migration manuelle requise"))
        result.factors = factors
        return result

    # Actions / enhancements custom : la détection migre mais une partie du
    # comportement (l'action) devra être recréée -> pénalité graduée.
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
                f"{n_actions} action(s) custom (command/alerter) à recréer côté Elastic"))
        if n_enh:
            pen = min(0.06 * n_enh, 0.15)
            factors.append(ConfidenceFactor(
                "enhancement", -pen,
                f"{n_enh} match_enhancement(s) Python à revoir manuellement"))

    # Pénalité par warning de traduction
    n_warn = len(result.warnings)
    if n_warn:
        penalty = min(0.10 * n_warn, 0.30)
        factors.append(ConfidenceFactor(
            "warnings", -penalty, f"{n_warn} avertissement(s) de conversion"))

    # Filtres : Lucene complexe baisse la confiance
    has_lucene = any(
        "query" in f or "query_string" in f for f in rule.filters
    )
    if has_lucene:
        factors.append(ConfidenceFactor(
            "lucene_filter", -0.05,
            "Filtre Lucene/query_string converti en best-effort"))

    # Bonus : aucun filtre complexe, requête simple
    if rule.filters and not has_lucene:
        factors.append(ConfidenceFactor(
            "structured_filter", +0.03, "Filtres structurés (term/terms/range)"))

    # Vérification des champs requis selon le type
    missing = _missing_required_fields(rule)
    if missing:
        factors.append(ConfidenceFactor(
            "missing_fields", -0.15,
            f"Champs ElastAlert manquants: {', '.join(missing)}"))

    # Pénalité de sémantique pour les types comportementaux
    if rule.rule_type in ("spike", "flatline", "change"):
        factors.append(ConfidenceFactor(
            "semantic_gap", -0.05,
            "Sémantique temporelle non strictement équivalente"))

    # Query_key présent et géré -> bonus pour agrégations
    if rule.rule_type in ("frequency", "cardinality", "metric_aggregation") \
            and rule.get("query_key"):
        factors.append(ConfidenceFactor(
            "query_key", +0.03, "query_key correctement mappé sur STATS ... BY"))

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
        return "ÉLEVÉE"
    if value >= 0.60:
        return "MOYENNE"
    if value >= 0.30:
        return "FAIBLE"
    return "TRÈS FAIBLE"
