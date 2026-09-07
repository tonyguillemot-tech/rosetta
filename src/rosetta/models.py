"""Modèles de données partagés pour la migration ElastAlert -> Elastic Security."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleStrategy(str, Enum):
    """Stratégie de règle Elastic cible."""

    ESQL = "esql"           # type: esql
    QUERY = "query"         # custom query (KQL)
    EQL = "eql"             # event correlation
    THRESHOLD = "threshold"  # threshold rule native
    NEW_TERMS = "new_terms"  # new terms rule native
    THREAT_MATCH = "threat_match"  # indicator match natif (grosses listes IOC)
    MANUAL = "manual"       # nécessite une revue humaine


@dataclass
class ElastAlertRule:
    """Représentation normalisée d'une règle ElastAlert chargée depuis YAML."""

    name: str
    rule_type: str
    index: str
    raw: dict[str, Any]
    filters: list[dict[str, Any]] = field(default_factory=list)
    source_file: str | None = None
    # Analyse des scripts/code custom (renseignée par le parser).
    # Typé Any pour éviter un import circulaire avec rosetta.scripts.
    script_analysis: Any = None

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)


@dataclass
class ConfidenceFactor:
    """Un facteur individuel contribuant au score de confiance."""

    label: str
    delta: float          # contribution (négative = pénalité)
    detail: str = ""


@dataclass
class ConversionResult:
    """Résultat de la conversion d'une règle ElastAlert."""

    source: ElastAlertRule
    strategy: RuleStrategy
    esql_query: str | None = None
    kql_query: str | None = None
    threshold: dict[str, Any] | None = None
    new_terms_fields: list[str] | None = None
    history_window: str | None = None
    interval: str = "5m"
    lookback: str = "now-6m"
    confidence: float = 0.0
    factors: list[ConfidenceFactor] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def needs_review(self) -> bool:
        return self.strategy == RuleStrategy.MANUAL or self.confidence < 0.6
