"""Génération de fichiers TOML au format elastic/detection-rules (DaC).

Le schéma TOML comporte deux tables principales :
  [metadata]  -> creation_date, maturity, min_stack_version, integration, ...
  [rule]      -> author, description, name, query, type, language, risk_score, ...

Pour les règles ES|QL : type="esql", language="esql", pas de champ `index`
(la source est dans le FROM). Pour query/eql/threshold/new_terms, `index` et
`language` sont renseignés.
"""
from __future__ import annotations

import datetime as dt
import uuid

from ..models import ConversionResult, RuleStrategy
from ..scoring.confidence import confidence_band


def _toml_escape_multiline(text: str) -> str:
    return text.replace('"""', '\\"\\"\\"')


def _toml_basic_string(text: str) -> str:
    """Échappe une chaîne pour un littéral TOML basique entre guillemets."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _risk_and_severity(rule_raw: dict) -> tuple[int, str]:
    # ElastAlert n'a pas de severity standard ; on mappe priority si présent
    priority = rule_raw.get("priority", 3)
    table = {1: (21, "low"), 2: (47, "medium"), 3: (47, "medium"),
             4: (73, "high"), 5: (99, "critical")}
    return table.get(priority, (47, "medium"))


def _indices_list(index: str) -> list[str]:
    return [i.strip() for i in index.split(",") if i.strip()] or ["logs-*"]


def to_toml(result: ConversionResult, *, author: str = "Migrated from ElastAlert",
            min_stack: str = "9.0.0") -> str:
    rule = result.source
    rule_id = str(uuid.uuid4())
    today = dt.date.today().strftime("%Y/%m/%d")
    risk, severity = _risk_and_severity(rule.raw)
    band = confidence_band(result.confidence)

    description = rule.get("description") or f"Règle migrée depuis ElastAlert ({rule.rule_type})."

    lines: list[str] = []
    # --- metadata ---
    lines.append("[metadata]")
    lines.append(f'creation_date = "{today}"')
    lines.append(f'updated_date = "{today}"')
    lines.append('maturity = "development"')
    lines.append(f'min_stack_version = "{min_stack}"')
    lines.append('min_stack_comments = "Migré automatiquement depuis ElastAlert"')
    lines.append("")
    # --- rule ---
    lines.append("[rule]")
    lines.append(f'author = ["{author}"]')
    lines.append('description = """')
    lines.append(_toml_escape_multiline(description))
    lines.append('"""')
    lines.append(f'name = "{rule.name}"')
    lines.append(f'rule_id = "{rule_id}"')
    lines.append('license = "Elastic License v2"')
    lines.append(f'risk_score = {risk}')
    lines.append(f'severity = "{severity}"')
    lines.append(f'from = "{result.lookback}"')
    lines.append(f'interval = "{result.interval}"')

    # Les sous-tables ([rule.threshold], [rule.new_terms]) sont collectées à
    # part et émises EN DERNIER : en TOML, toute clé scalaire (note, tags…)
    # placée après un en-tête de table lui serait rattachée par erreur.
    strat = result.strategy
    subtables: list[str] = []
    if strat == RuleStrategy.ESQL:
        lines.append('type = "esql"')
        lines.append('language = "esql"')
        lines.append('query = """')
        lines.append(result.esql_query or "")
        lines.append('"""')
    elif strat == RuleStrategy.QUERY:
        lines.append('type = "query"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_indices_list(rule.index)!r}".replace("'", '"'))
        lines.append(f'query = "{_toml_basic_string(result.kql_query or "*:*")}"')
    elif strat == RuleStrategy.EQL:
        lines.append('type = "eql"')
        lines.append('language = "eql"')
        lines.append(f"index = {_indices_list(rule.index)!r}".replace("'", '"'))
        lines.append('query = """')
        lines.append(result.esql_query or "")
        lines.append('"""')
    elif strat == RuleStrategy.THRESHOLD:
        lines.append('type = "threshold"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_indices_list(rule.index)!r}".replace("'", '"'))
        lines.append(f'query = "{_toml_basic_string(result.kql_query or "*:*")}"')
        th = result.threshold or {}
        subtables.append("")
        subtables.append("[rule.threshold]")
        subtables.append(f"field = {th.get('field', [])!r}".replace("'", '"'))
        subtables.append(f"value = {th.get('value', 1)}")
    elif strat == RuleStrategy.NEW_TERMS:
        lines.append('type = "new_terms"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_indices_list(rule.index)!r}".replace("'", '"'))
        lines.append(f'query = "{_toml_basic_string(result.kql_query or "*:*")}"')
        subtables.append("")
        subtables.append("[rule.new_terms]")
        subtables.append('field = "new_terms_fields"')
        subtables.append(f"value = {result.new_terms_fields or []!r}".replace("'", '"'))
        subtables.append("")
        subtables.append("[[rule.new_terms.history_window_start]]")
        subtables.append('field = "history_window_start"')
        subtables.append(f'value = "{result.history_window or "now-14d"}"')
    else:  # MANUAL
        lines.append('type = "query"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_indices_list(rule.index)!r}".replace("'", '"'))
        lines.append('query = "*:*"')
        lines.append('enabled = false')

    # --- note de migration (champ note, markdown) ---
    note_lines = [
        f"## Migration ElastAlert",
        f"- Type source : `{rule.rule_type}`",
        f"- Stratégie Elastic : `{strat.value}`",
        f"- Score de confiance : **{result.confidence:.0%} ({band})**",
    ]
    if result.warnings:
        note_lines.append("- Avertissements :")
        note_lines.extend(f"  - {w}" for w in result.warnings)

    # Section dédiée : actions custom à recréer côté Elastic
    custom_actions = result.metadata.get("custom_actions")
    if custom_actions:
        note_lines.append("")
        note_lines.append("### Actions custom à recréer (connectors Elastic)")
        for a in custom_actions:
            note_lines.append(f"- `{a['category']}` : `{a['reference']}`")

    lines.append("")
    lines.append('note = """')
    lines.extend(note_lines)
    lines.append('"""')

    # --- tags ---
    lines.append("")
    tags = ['"Migrated: ElastAlert"', f'"Confidence: {band}"',
            f'"Source Type: {rule.rule_type}"']
    if custom_actions:
        tags.append('"Review: Custom Action"')
    if result.metadata.get("custom_detection_code"):
        tags.append('"Review: Custom Detection Code"')
    lines.append(f"tags = [{', '.join(tags)}]")

    # Sous-tables en dernier (cf. commentaire plus haut) : elles doivent suivre
    # toutes les clés scalaires de [rule], note et tags compris.
    lines.extend(subtables)

    return "\n".join(lines) + "\n"
