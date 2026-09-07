"""Tests unitaires pour rosetta."""
from __future__ import annotations

import re
import tomllib

import pytest

from rosetta.converters.registry import convert
from rosetta.detection_rule.toml_writer import to_toml, to_toml_indicator_match_companion, to_toml_ml_companion
from rosetta.esql.translator import filter_to_esql, filter_to_kql
from rosetta.models import RuleStrategy
from rosetta.parser.elastalert import parse_rule_dict
from rosetta.sanitize import rule_fingerprint, sanitize_result
from rosetta.scoring.confidence import confidence_band, score


def _conv(raw: dict):
    rule = parse_rule_dict(raw)
    return score(convert(rule))


def test_frequency_to_esql():
    res = _conv({
        "name": "freq", "type": "frequency", "index": "logs-*",
        "num_events": 10, "timeframe": {"minutes": 5}, "query_key": "user.name",
    })
    assert res.strategy == RuleStrategy.ESQL
    assert "STATS event_count = COUNT(*) BY user.name" in res.esql_query
    assert "WHERE event_count >= 10" in res.esql_query
    assert res.confidence >= 0.6


def test_any_non_aggregating_keeps_metadata():
    res = _conv({"name": "any", "type": "any", "index": "logs-*"})
    assert res.strategy == RuleStrategy.ESQL
    assert "METADATA _id, _version, _index" in res.esql_query
    assert "KEEP _id" in res.esql_query


def test_blacklist_in_clause():
    res = _conv({
        "name": "bl", "type": "blacklist", "index": "logs-*",
        "compare_key": "user.name", "blacklist": ["a", "b"],
    })
    assert "user.name IN" in res.esql_query


def test_whitelist_negates():
    res = _conv({
        "name": "wl", "type": "whitelist", "index": "logs-*",
        "compare_key": "user.name", "whitelist": ["a"],
    })
    assert "user.name NOT IN" in res.esql_query


def test_cardinality_max_uses_native_threshold():
    """max_cardinality -> Threshold.cardinality natif (Threshold sait exprimer
    'au moins N valeurs' — le seul sens qu'il supporte, confirmé par
    elastic/detection-rules#3617). +1 pour reproduire fidèlement 'strictement
    supérieur à' (ElastAlert) via 'au moins' (Threshold)."""
    res = _conv({
        "name": "c", "type": "cardinality", "index": "logs-*",
        "cardinality_field": "host.name", "max_cardinality": 5,
        "query_key": "user.name",
    })
    assert res.strategy == RuleStrategy.THRESHOLD
    assert res.threshold["cardinality"] == {"field": "host.name", "value": 6}
    assert res.threshold["field"] == ["user.name"]


def test_cardinality_min_stays_esql_no_native_equivalent():
    """min_cardinality -> pas d'équivalent Threshold natif (confirmé par
    elastic/detection-rules#3617, 'only supports greater than') — reste en
    ES|QL, avec avertissement honnête plutôt que forcé vers un mapping faux."""
    res = _conv({
        "name": "c min", "type": "cardinality", "index": "logs-*",
        "cardinality_field": "host.name", "min_cardinality": 3,
        "query_key": "user.name",
    })
    assert res.strategy == RuleStrategy.ESQL
    assert "distinct_count < 3" in res.esql_query
    assert any("no native Threshold equivalent" in w for w in res.warnings)


def test_cardinality_both_min_and_max_warns_about_dropped_min():
    res = _conv({
        "name": "c both", "type": "cardinality", "index": "logs-*",
        "cardinality_field": "host.name", "max_cardinality": 5, "min_cardinality": 1,
        "query_key": "user.name",
    })
    assert res.strategy == RuleStrategy.THRESHOLD
    assert any("min_cardinality is ignored" in w for w in res.warnings)


def test_metric_aggregation_avg():
    res = _conv({
        "name": "m", "type": "metric_aggregation", "index": "logs-*",
        "metric_agg_key": "bytes", "metric_agg_type": "avg", "max_threshold": 100,
    })
    assert "AVG(bytes)" in res.esql_query


def test_new_term_uses_native_rule():
    res = _conv({
        "name": "nt", "type": "new_term", "index": "logs-*",
        "fields": ["process.name"], "terms_window_size": {"days": 30},
    })
    assert res.strategy == RuleStrategy.NEW_TERMS
    assert res.new_terms_fields == ["process.name"]
    assert res.history_window == "now-30d"


def test_flatline_uses_threshold():
    res = _conv({
        "name": "fl", "type": "flatline", "index": "logs-*",
        "threshold": 1, "query_key": "agent.id", "timeframe": {"minutes": 10},
    })
    assert res.strategy == RuleStrategy.THRESHOLD
    assert res.threshold["value"] == 1
    assert res.warnings  # avertissement sur l'inversion de logique


def test_spike_low_confidence_and_warned():
    res = _conv({
        "name": "sp", "type": "spike", "index": "logs-*",
        "spike_height": 3, "threshold_cur": 50, "timeframe": {"hours": 1},
    })
    assert res.confidence < 0.6
    assert res.warnings


def test_spike_includes_ml_job_plan():
    """La règle 'spike' doit être accompagnée d'un plan de job ML fidèle."""
    res = _conv({
        "name": "Spike in auth failures", "type": "spike", "index": "logs-auth-*",
        "spike_height": 3, "threshold_cur": 50, "timeframe": {"hours": 1},
        "query_key": "user.name",
        "filter": [{"term": {"event.outcome": "failure"}}],
    })
    commands = res.metadata.get("ml_job_commands")
    assert commands and "PUT _ml/anomaly_detectors/" in commands
    assert "PUT _ml/datafeeds/" in commands
    assert '"partition_field_name": "user.name"' in commands
    # threshold_cur -> custom_rules (skip_result sous le seuil), pas juste un warning
    assert '"applies_to": "actual"' in commands and '"value": 50.0' in commands
    # Le filtre ElastAlert (déjà du DSL ES) est réutilisé tel quel dans le datafeed
    assert '"event.outcome": "failure"' in commands
    # spike_height n'a pas d'équivalent direct : documenté, pas deviné
    assert any("spike_height" in n for n in res.metadata.get("ml_job_notes", []))


def test_spike_ml_job_commands_land_in_toml_note():
    res = _conv({
        "name": "sp2", "type": "spike", "index": "logs-*",
        "spike_height": 2, "threshold_cur": 10, "timeframe": {"hours": 1},
    })
    parsed = tomllib.loads(to_toml(res))
    note = parsed["rule"]["note"]
    assert "_ml/anomaly_detectors" in note
    assert "Job Machine Learning associé" in note


def test_spike_without_query_key_omits_partition_field():
    """Sans query_key ElastAlert, pas de partition_field_name halluciné."""
    res = _conv({
        "name": "sp3", "type": "spike", "index": "logs-*",
        "spike_height": 2, "threshold_cur": 10, "timeframe": {"hours": 1},
    })
    commands = res.metadata["ml_job_commands"]
    assert "partition_field_name" not in commands


def test_change_includes_ml_job_plan_with_rare_function():
    res = _conv({
        "name": "User changed geolocation", "type": "change", "index": "logs-*",
        "compare_key": "source.geo.country_name", "query_key": "user.name",
        "timeframe": {"hours": 24},
    })
    commands = res.metadata.get("ml_job_commands")
    assert commands and '"function": "rare"' in commands
    assert '"by_field_name": "source.geo.country_name"' in commands
    assert '"partition_field_name": "user.name"' in commands
    # Écart sémantique documenté, pas deviné
    assert any("chaque transition" in n or "rare" in n.lower()
               for n in res.metadata.get("ml_job_notes", []))


def test_change_compound_compare_key_yields_one_detector_per_field():
    res = _conv({
        "name": "multi change", "type": "change", "index": "logs-*",
        "compound_compare_key": ["a.field", "b.field"], "query_key": "user.name",
    })
    commands = res.metadata["ml_job_commands"]
    assert commands.count('"function": "rare"') == 2
    assert '"by_field_name": "a.field"' in commands
    assert '"by_field_name": "b.field"' in commands


def test_change_without_compare_key_has_no_ml_job():
    """Pas de compare_key exploitable -> pas de job ML halluciné."""
    res = _conv({"name": "no compare", "type": "change", "index": "logs-*"})
    assert "ml_job_commands" not in res.metadata


def test_flatline_includes_ml_job_plan_with_low_count():
    res = _conv({
        "name": "Agent heartbeat flatline", "type": "flatline", "index": "logs-*",
        "threshold": 1, "query_key": "agent.id", "timeframe": {"minutes": 10},
    })
    commands = res.metadata.get("ml_job_commands")
    assert commands and '"function": "low_count"' in commands
    assert '"partition_field_name": "agent.id"' in commands
    # L'écart entre plancher absolu et détection relative doit être documenté
    assert any("plancher" in n.lower() for n in res.metadata.get("ml_job_notes", []))
    # Et le risque (plausible, pas confirmé) sur l'absence totale également
    assert any("plausible" in n.lower() and "silencieuse" in n.lower()
               for n in res.metadata.get("ml_job_notes", []))


def test_filter_to_kql_supports_range():
    """Bug corrigé : filter_to_kql ignorait 'range', générant un avertissement
    évitable (et donc une pénalité de confiance) pour un filtre pourtant simple."""
    warnings: list[str] = []
    kql = filter_to_kql([{"range": {"bytes": {"gt": 500, "lte": 1000}}}], warnings)
    assert warnings == []
    assert "bytes > 500" in kql and "bytes <= 1000" in kql


def test_filter_to_kql_supports_exists_and_match():
    warnings: list[str] = []
    kql = filter_to_kql(
        [{"exists": {"field": "user.name"}}, {"match": {"event.action": "logon"}}],
        warnings,
    )
    assert warnings == []
    assert "user.name: *" in kql
    assert 'event.action:"logon"' in kql


def test_filter_to_kql_supports_nested_bool():
    warnings: list[str] = []
    kql = filter_to_kql([{
        "bool": {
            "must": [{"term": {"a": "1"}}],
            "should": [{"term": {"b": "2"}}, {"term": {"b": "3"}}],
            "must_not": [{"term": {"c": "4"}}],
        }
    }], warnings)
    assert warnings == []
    assert 'a:"1"' in kql
    assert "not (" in kql


def test_flatline_range_filter_no_longer_warns():
    """Cas concret rencontré dans le corpus : flatline + filtre range ne doit
    plus générer d'avertissement KQL superflu."""
    res = _conv({
        "name": "fl range", "type": "flatline", "index": "logs-*",
        "threshold": 2, "timeframe": {"minutes": 15},
        "filter": [{"range": {"network.bytes": {"gt": 500}}}],
    })
    assert not any("non transcrit en KQL" in w for w in res.warnings)


def test_lucene_range_bracket():
    """[a TO b] -> comparaisons ES|QL correctes, plus de corruption silencieuse."""
    from rosetta.esql.translator import _lucene_to_esql
    w: list[str] = []
    out = _lucene_to_esql("bytes:[1 TO 10]", w)
    assert w == []
    assert out == "(bytes >= 1 AND bytes <= 10)"


def test_lucene_range_exclusive_bracket():
    from rosetta.esql.translator import _lucene_to_esql
    w: list[str] = []
    out = _lucene_to_esql("bytes:{1 TO 10]", w)
    assert w == []
    assert out == "(bytes > 1 AND bytes <= 10)"


def test_lucene_comparison_operators():
    from rosetta.esql.translator import _lucene_to_esql
    for expr, expected in [
        ("bytes:>5", "bytes > 5"), ("bytes:>=5", "bytes >= 5"),
        ("bytes:<5", "bytes < 5"), ("bytes:<=5", "bytes <= 5"),
    ]:
        w: list[str] = []
        assert _lucene_to_esql(expr, w) == expected
        assert w == []


def test_lucene_nested_parens_precedence():
    """Bug corrigé : les parenthèses de précédence mangeaient la parenthèse
    fermante dans la valeur citée, produisant du ES|QL syntaxiquement invalide."""
    from rosetta.esql.translator import _lucene_to_esql
    w: list[str] = []
    out = _lucene_to_esql("(a:1 OR b:2) AND c:3", w)
    assert w == []
    assert out == '(a == "1" OR b == "2") AND c == "3"'
    assert out.count("(") == out.count(")")


def test_lucene_deeply_nested_parens():
    from rosetta.esql.translator import _lucene_to_esql
    w: list[str] = []
    out = _lucene_to_esql("((x:1 OR y:2) AND z:3) OR w:4", w)
    assert w == []
    assert out.count("(") == out.count(")") == 2


def test_lucene_fuzzy_boost_proximity_are_flagged_not_silent():
    """Ni corrompues silencieusement, ni acceptées comme si elles étaient exactes."""
    from rosetta.esql.translator import _lucene_to_esql
    for expr in ['host.name:srv*^2', 'host.name:srv~', 'message:"exact phrase"~2']:
        w: list[str] = []
        _lucene_to_esql(expr, w)
        assert w, f"{expr!r} aurait dû être signalé comme incertain"


def test_lucene_bare_regex_is_flagged():
    from rosetta.esql.translator import _lucene_to_esql
    w: list[str] = []
    _lucene_to_esql("/regex.*/", w)
    assert w


def test_cardinality_simple_lucene_and_no_longer_flagged():
    """Cas concret du rapport (Cardinality rule 10) : un AND simple de deux
    field:value doit être traduit sans aucun avertissement."""
    res = _conv({
        "name": "Cardinality rule 10", "type": "cardinality", "index": "logs-*",
        "cardinality_field": "process.command_line", "max_cardinality": 10,
        "query_key": "agent.id", "timeframe": {"hours": 24},
        "filter": [{"query": {"query_string": {
            "query": "event.category:network AND event.outcome:unknown"
        }}}],
    })
    assert res.warnings == []


def test_custom_alerter_not_double_counted_in_score():
    """Le fait 'alerteur Python custom' ne doit être pénalisé qu'une fois
    (via custom_action), pas une seconde fois via le facteur générique
    'warnings' — même si le warning reste bien affiché dans le note."""
    res = _conv({
        "name": "Rule with custom alerter", "type": "blacklist", "index": "logs-*",
        "compare_key": "user.name", "blacklist": ["baduser"],
        "alert": ["elastalert_modules.custom_alerts.MyAlerter"],
    })
    labels = [f.label for f in res.factors]
    assert "custom_action" in labels
    assert "warnings" not in labels  # plus de pénalité générique redondante
    # Le warning reste bien présent (visible dans la note), seul le score change
    assert any("Custom Python alerter" in w for w in res.warnings)
    toml_note = to_toml(res)
    assert "Custom Python alerter" in toml_note


def test_warning_unrelated_to_script_finding_still_counted():
    """Un vrai avertissement structurel (ex: approximation flatline) doit
    continuer à peser sur le score normalement."""
    res = _conv({
        "name": "fl plain", "type": "flatline", "index": "logs-*",
        "threshold": 1, "timeframe": {"minutes": 5},
    })
    labels = [f.label for f in res.factors]
    assert "warnings" in labels


def test_cardinality_missing_field_is_manual_not_broken_query():
    """Bug corrigé : cardinality_field manquant générait 'COUNT_DISTINCT(None)',
    un ES|QL invalide, avec une confiance MEDIUM trompeuse. COUNT_DISTINCT n'a
    pas de fallback '*' valide en ES|QL (contrairement à COUNT) : mieux vaut
    ne pas générer de requête que d'en générer une cassée."""
    res = _conv({
        "name": "Degenerate cardinality 21", "type": "cardinality", "index": "logs-*",
        "filter": [{"term": {"host.name": "4624"}}], "timeframe": {"hours": 2},
    })
    assert res.strategy == RuleStrategy.MANUAL
    assert res.esql_query is None
    assert "None" not in (res.esql_query or "")
    assert any("cardinality_field is missing" in w for w in res.warnings)


def test_metric_aggregation_missing_field_is_manual_not_broken_query():
    """Même bug, même famille : metric_agg_key manquant générait 'AVG()' —
    ES|QL invalide — sans même un avertissement."""
    res = _conv({
        "name": "metric no key", "type": "metric_aggregation", "index": "logs-*",
        "metric_agg_type": "avg", "max_threshold": 10, "timeframe": {"hours": 1},
    })
    assert res.strategy == RuleStrategy.MANUAL
    assert res.esql_query is None
    assert any("metric_agg_key is missing" in w for w in res.warnings)


def test_cardinality_with_field_still_works_normally():
    """Non-régression : le cas nominal (max_cardinality + champ présent) migre
    maintenant vers Threshold natif — le TOML doit rester valide."""
    res = _conv({
        "name": "Cardinality rule 10", "type": "cardinality", "index": "logs-*",
        "cardinality_field": "process.command_line", "max_cardinality": 10,
        "query_key": "agent.id", "timeframe": {"hours": 24},
    })
    assert res.strategy == RuleStrategy.THRESHOLD
    assert res.threshold["cardinality"]["field"] == "process.command_line"
    parsed = tomllib.loads(to_toml(res))
    assert parsed["rule"]["threshold"]["cardinality"][0]["value"] == 11


def test_metric_aggregation_value_count_maps_to_count_not_avg():
    """Bug corrigé : 'value_count' (compte des valeurs non-nulles) tombait
    silencieusement sur AVG(field) — une agrégation différente, sans warning."""
    res = _conv({
        "name": "vc", "type": "metric_aggregation", "index": "logs-*",
        "metric_agg_key": "session.id", "metric_agg_type": "value_count",
        "max_threshold": 100, "timeframe": {"hours": 1},
    })
    assert "COUNT(session.id)" in res.esql_query
    assert "AVG(" not in res.esql_query
    assert res.warnings == []


def test_metric_aggregation_percentiles_warns_instead_of_silent_avg():
    """'percentiles' n'a pas d'équivalent scalaire direct : on le signale
    au lieu de deviner silencieusement AVG comme avant."""
    res = _conv({
        "name": "pct", "type": "metric_aggregation", "index": "logs-*",
        "metric_agg_key": "response.time", "metric_agg_type": "percentiles",
        "max_threshold": 500, "timeframe": {"hours": 1},
    })
    assert "AVG(response.time)" in res.esql_query  # fallback, mais assumé
    assert any("percentiles" in w or "metric_agg_type" in w for w in res.warnings)


def test_metric_aggregation_avg_still_exact_no_warning():
    """Non-régression : le cas courant (avg/sum/min/max/cardinality) reste
    sans avertissement."""
    res = _conv({
        "name": "avg ok", "type": "metric_aggregation", "index": "logs-*",
        "metric_agg_key": "event.duration", "metric_agg_type": "avg",
        "max_threshold": 100, "timeframe": {"minutes": 5},
    })
    assert res.warnings == []
    assert "AVG(event.duration)" in res.esql_query


def test_toml_survives_quote_in_rule_name():
    """Bug corrigé : name = "{rule.name}" n'était pas échappé du tout — un
    guillemet dans le nom cassait le TOML."""
    res = _conv({
        "name": 'Alert for "suspicious" logins', "type": "any", "index": "logs-*",
        "filter": [{"term": {"host.name": "srv01"}}],
    })
    parsed = tomllib.loads(to_toml(res))
    assert parsed["rule"]["name"] == 'Alert for "suspicious" logins'


def test_toml_survives_apostrophe_in_index_and_fields():
    """Bug corrigé : repr()+replace("'", '"') corrompait toute apostrophe à
    l'intérieur d'un index/champ (ex: 'logs-o'brien-*' -> guillemet parasite),
    car repr() choisit lui-même des guillemets doubles comme délimiteur dès
    qu'une apostrophe est présente, et le replace aveugle touchait alors le
    caractère interne, pas le délimiteur."""
    res = _conv({
        "name": "NT test", "type": "new_term", "index": "logs-o'brien-*",
        "fields": ["user's.name"],
    })
    parsed = tomllib.loads(to_toml(res))
    assert parsed["rule"]["index"] == ["logs-o'brien-*"]
    assert parsed["rule"]["new_terms"]["value"] == ["user's.name"]


def test_toml_survives_apostrophe_in_threshold_field():
    res = _conv({
        "name": "Threshold apostrophe", "type": "blacklist", "index": "logs-o'brien-*",
        "compare_key": "user's_field", "blacklist": ["bad"], "query_key": "a'b",
    })
    # blacklist utilise esql (pas threshold) mais on vérifie au moins l'index ;
    # on force aussi un cas 'threshold' réel via metric_aggregation manquant -> non,
    # testons directement via un flatline (-> RuleStrategy.THRESHOLD)
    res2 = _conv({
        "name": "fl apostrophe", "type": "flatline", "index": "logs-o'brien-*",
        "threshold": 1, "query_key": "agent's.id", "timeframe": {"minutes": 5},
    })
    parsed = tomllib.loads(to_toml(res2))
    assert parsed["rule"]["index"] == ["logs-o'brien-*"]
    assert parsed["rule"]["threshold"]["field"] == ["agent's.id"]


def test_toml_survives_backslash_and_unicode_in_name():
    res = _conv({"name": "Back\\slash été 日本語 test", "type": "any", "index": "logs-*"})
    parsed = tomllib.loads(to_toml(res))
    assert parsed["rule"]["name"] == "Back\\slash été 日本語 test"


def test_windows_path_filter_value_round_trips_through_toml():
    """Cas réaliste critique (EDR) : un chemin Windows dans une valeur de
    filtre doit survivre intact à la fois l'échappement ES|QL et l'échappement
    TOML — avant le fix, le backslash n'était échappé à AUCUN des deux niveaux
    ('Unescaped backslash in a string' au parsing TOML)."""
    res = _conv({
        "name": "Suspicious binary", "type": "any", "index": "logs-endpoint.events.process-*",
        "filter": [{"term": {"process.executable": "C:\\Users\\Public\\evil.exe"}}],
    })
    parsed = tomllib.loads(to_toml(res))
    esql_literal = parsed["rule"]["query"]
    # Le littéral ES|QL doit contenir le backslash doublé (échappement ES|QL) ;
    # en le "désé-échappant" comme le ferait le parseur ES|QL, on doit
    # retrouver exactement la valeur d'origine.
    m = re.search(r'process\.executable == "([^"]*)"', esql_literal)
    assert m is not None
    decoded = m.group(1).replace("\\\\", "\x00").replace('\\"', '"').replace("\x00", "\\")
    assert decoded == "C:\\Users\\Public\\evil.exe"


def test_new_terms_field_with_backslash_round_trips():
    res = _conv({
        "name": "NT backslash", "type": "new_term", "index": "logs-*",
        "fields": ["a\\b.field"],
    })
    parsed = tomllib.loads(to_toml(res))
    assert parsed["rule"]["new_terms"]["value"] == ["a\\b.field"]


def test_lone_carriage_return_in_description_does_not_break_toml():
    """Bug corrigé : un '\\r' isolé (hors CRLF) est illégal même dans une
    chaîne TOML multi-ligne — 'Illegal character' au parsing sinon."""
    res = _conv({
        "name": "cr test", "type": "any", "index": "logs-*",
        "description": "line one\rline two",
    })
    parsed = tomllib.loads(to_toml(res))
    assert "line one" in parsed["rule"]["description"]


def test_change_missing_compare_key_is_manual_not_broken_query():
    """Troisième occurrence du même bug (déjà trouvé sur cardinality et
    metric_aggregation) : sans compare_key, l'ancien code produisait
    'COUNT_DISTINCT(*)' — pas un ES|QL valide. Trouvé en vérifiant le regex
    officiel de validation ES|QL du dépôt elastic/detection-rules."""
    res = _conv({
        "name": "change no compare key", "type": "change", "index": "logs-*",
        "query_key": "user.name", "timeframe": {"hours": 1},
    })
    assert res.strategy == RuleStrategy.MANUAL
    assert res.esql_query is None
    assert "COUNT_DISTINCT(*)" not in (res.esql_query or "")
    assert any("compare_key/compound_compare_key is missing" in w for w in res.warnings)


def test_kql_query_string_and_or_normalized_to_lowercase():
    """Bug corrigé (trouvé via validation réelle detection-rules) : KQL exige
    and/or/not en minuscules, contrairement à Lucene/ES|QL. Le passthrough
    query_string->KQL recopiait AND/OR tels quels, invalides pour le vrai
    parser KQL ('Error at line:1,column:N' pile sur le AND)."""
    res = _conv({
        "name": "fl kql and", "type": "flatline", "index": "logs-*",
        "threshold": 2, "timeframe": {"hours": 24},
        "filter": [{"query": {"query_string": {
            "query": "event.category:configuration AND event.outcome:unknown"
        }}}],
    })
    assert res.kql_query == "(event.category:configuration and event.outcome:unknown)"
    assert "AND" not in res.kql_query


def test_report_and_share_fingerprints_match_with_same_secret():
    """Le pont central du workflow client : rapport complet (report) et
    rapport anonymisé (share), avec le même --hmac-secret, doivent produire
    la MÊME empreinte pour la même règle — sans jamais faire transiter son
    nom par le canal anonymisé."""
    res = _conv({
        "name": "Flatline rule 106", "type": "flatline", "index": "auditbeat-*",
        "filter": [{"term": {"source.ip": "login"}}],
        "threshold": 5, "timeframe": {"minutes": 5}, "query_key": "host.name",
    })
    secret = b"secret-partage-client-X"
    fp_direct = rule_fingerprint(res, secret)
    fp_via_sanitize = sanitize_result(res, secret)["fingerprint"]
    assert fp_direct == fp_via_sanitize
    # Une autre règle (nom différent) doit avoir une empreinte différente
    res2 = _conv({"name": "Une autre règle", "type": "any", "index": "logs-*"})
    assert rule_fingerprint(res2, secret) != fp_direct
    # Un secret différent doit changer l'empreinte (pas de fuite via un secret devinable)
    assert rule_fingerprint(res, b"autre-secret") != fp_direct


def test_migration_score_spike_higher_than_confidence():
    """spike : le score de migration ML doit dépasser nettement la confiance
    ES|QL livrée — c'est le cas justifiant qu'on recommande le chemin ML."""
    res = _conv({
        "name": "spike ml", "type": "spike", "index": "logs-*",
        "spike_height": 3, "threshold_cur": 50, "timeframe": {"hours": 1},
        "query_key": "user.name",
    })
    assert res.metadata["migration_strategy"] == "machine_learning"
    assert res.metadata["migration_score"] > res.confidence
    assert abs(res.metadata["migration_score"] - 0.75) < 1e-9


def test_migration_score_flatline_reflects_uncertainty_not_certainty():
    """flatline : après révision (le blocage 'absence totale' n'est pas
    confirmé, juste plausible), la pénalité est plus modeste (-0.05, pas
    -0.15) — honnête sur ce qu'on sait vs ce qu'on suppose."""
    res = _conv({
        "name": "flatline ml", "type": "flatline", "index": "logs-*",
        "threshold": 1, "timeframe": {"minutes": 5}, "query_key": "agent.id",
    })
    assert res.metadata["migration_strategy"] == "machine_learning"
    assert abs(res.metadata["migration_score"] - 0.50) < 1e-9
    factor_labels = [f["label"] for f in res.metadata["migration_factors"]]
    assert "total_absence_uncertain" in factor_labels
    assert "total_absence_blind_spot" not in factor_labels


def test_migration_score_absent_when_no_ml_job():
    """Types sans job ML pertinent (ex: frequency) -> pas de migration_score."""
    res = _conv({
        "name": "freq plain", "type": "frequency", "index": "logs-*",
        "num_events": 5, "timeframe": {"minutes": 5},
    })
    assert "migration_strategy" not in res.metadata
    assert "migration_score" not in res.metadata


def test_ml_companion_toml_is_valid_and_disabled():
    """Le fichier compagnon machine_learning : job_id préempli, désactivé par
    défaut, note explicite sur la marche à suivre."""
    res = _conv({
        "name": "Spike companion test", "type": "spike", "index": "logs-*",
        "spike_height": 3, "threshold_cur": 50, "timeframe": {"hours": 1},
        "query_key": "user.name",
    })
    ml_toml = to_toml_ml_companion(res)
    assert ml_toml is not None
    parsed = tomllib.loads(ml_toml)
    r = parsed["rule"]
    assert r["type"] == "machine_learning"
    assert r["enabled"] is False
    assert r["machine_learning_job_id"] == [res.metadata["ml_job_id"]]
    assert "NE PAS ACTIVER" in r["note"]
    assert f"{res.metadata['migration_score']:.0%}" in r["note"]


def test_ml_companion_toml_none_when_not_applicable():
    res = _conv({
        "name": "freq plain 2", "type": "frequency", "index": "logs-*",
        "num_events": 5, "timeframe": {"minutes": 5},
    })
    assert to_toml_ml_companion(res) is None


def test_eql_sequence_hint_from_custom_module_name():
    """Heuristique de nommage : un module custom au nom évocateur de séquence
    doit recommander EQL, SANS score numérique (pure supposition sur le nom,
    pas un mapping structurel vérifiable)."""
    res = _conv({
        "name": "chained rule", "type": "elastalert_modules.custom_rules.ChainedLoginAttempts",
        "index": "logs-*",
    })
    assert res.strategy == RuleStrategy.MANUAL
    assert res.metadata.get("migration_strategy") == "eql"
    assert "migration_score" not in res.metadata
    assert any("naming heuristic" in w.lower() for w in res.warnings)


def test_no_eql_hint_for_generic_custom_module_name():
    res = _conv({
        "name": "generic custom", "type": "elastalert_modules.custom_rules.MyWeirdRule",
        "index": "logs-*",
    })
    assert res.metadata.get("migration_strategy") is None


def test_indicator_match_detected_for_real_hash_list():
    """blacklist avec des valeurs qui ressemblent à de vrais hashs SHA256 sur
    un champ nommé en conséquence -> recommandation indicator_match, SANS
    pénaliser la confiance de la règle IN() livrée (elle reste parfaite)."""
    import hashlib
    values = [hashlib.sha256(f"malware{i}".encode()).hexdigest() for i in range(5)]
    res = _conv({
        "name": "Known bad hashes", "type": "blacklist", "index": "logs-*",
        "compare_key": "process.hash.sha256", "blacklist": values,
    })
    assert res.confidence == 0.90  # inchangée : la règle IN() est parfaitement fidèle
    assert res.warnings == []      # pas de pénalité pour une recommandation, pas un défaut
    assert res.metadata["migration_strategy"] == "indicator_match"
    assert abs(res.metadata["migration_score"] - 0.80) < 1e-9


def test_indicator_match_not_detected_for_business_values():
    """blacklist de valeurs métier (pas des IOC) -> aucune fausse recommandation."""
    res = _conv({
        "name": "Restricted departments", "type": "blacklist", "index": "logs-*",
        "compare_key": "user.department", "blacklist": ["finance", "legal", "hr"],
    })
    assert "migration_strategy" not in res.metadata
    assert to_toml_indicator_match_companion(res) is None


def test_indicator_match_companion_toml_valid_and_disabled():
    import hashlib
    values = [hashlib.sha256(f"bad{i}".encode()).hexdigest() for i in range(3)]
    res = _conv({
        "name": "IM companion test", "type": "blacklist", "index": "logs-*",
        "compare_key": "file.hash.sha256", "blacklist": values,
    })
    im_toml = to_toml_indicator_match_companion(res)
    assert im_toml is not None
    parsed = tomllib.loads(im_toml)
    r = parsed["rule"]
    assert r["type"] == "threat_match"
    assert r["enabled"] is False
    assert r["threat_mapping"][0]["entries"][0]["field"] == "file.hash.sha256"
    assert r["threat_mapping"][0]["entries"][0]["value"] == "threat.indicator.value"
    assert "NE PAS ACTIVER" in r["note"]


def test_indicator_match_companion_reuses_other_filters():
    """Bug corrigé : le compagnon utilisait 'query = \"*:*\"' en dur, ignorant
    les AUTRES filtres de la règle d'origine (au-delà du seul compare_key qui
    migre vers threat_mapping) — comparait alors TOUS les événements à l'index
    threat intel au lieu de scoper comme la règle ES|QL principale."""
    import hashlib
    values = [hashlib.sha256(f"bad{i}".encode()).hexdigest() for i in range(3)]
    res = _conv({
        "name": "IM scoped", "type": "blacklist", "index": "logs-*",
        "compare_key": "process.hash.sha256", "blacklist": values,
        "filter": [{"term": {"event.category": "process"}}],
    })
    im_toml = to_toml_indicator_match_companion(res)
    parsed = tomllib.loads(im_toml)
    assert parsed["rule"]["query"] != "*:*"
    assert "event.category" in parsed["rule"]["query"]
    assert parsed["rule"]["language"] == "kuery"  # jamais esql, threat_match ne le supporte pas


def test_indicator_match_ip_type_detection():
    res = _conv({
        "name": "Known bad IPs", "type": "blacklist", "index": "logs-*",
        "compare_key": "source.ip",
        "blacklist": ["1.2.3.4", "10.0.0.1", "192.168.1.1", "8.8.8.8"],
    })
    assert res.metadata.get("migration_strategy") == "indicator_match"


def test_indicator_match_never_recommended_for_whitelist():
    """Bug corrigé : threat_match n'a pas de mode 'ne correspond à aucun
    indicateur' (confirmé par la doc Elastic) — recommander indicator_match
    pour un whitelist serait structurellement faux, même avec des valeurs à
    forme d'IOC parfaite."""
    res = _conv({
        "name": "Known good IPs", "type": "whitelist", "index": "logs-*",
        "compare_key": "source.ip",
        "whitelist": ["1.2.3.4", "10.0.0.1", "192.168.1.1", "8.8.8.8"],
    })
    assert res.metadata.get("migration_strategy") is None
    assert to_toml_indicator_match_companion(res) is None


def test_ecs_field_hint_catches_ip_field_with_non_ip_value():
    """Cas réel trouvé en session avec le vrai validateur KQL
    (source.ip:"login") — désormais détecté par Rosetta lui-même, hors ligne."""
    res = _conv({
        "name": "bad ip value", "type": "any", "index": "logs-*",
        "filter": [{"term": {"source.ip": "login"}}],
    })
    assert any("naming heuristic" in w and "source.ip" in w for w in res.warnings)


def test_ecs_field_hint_silent_on_normal_values():
    """Ne doit RIEN dire sur des champs/valeurs cohérents — silence par
    défaut plutôt que deviner, c'est le principe du module."""
    res = _conv({
        "name": "normal ip", "type": "any", "index": "logs-*",
        "filter": [
            {"term": {"source.ip": "10.0.0.5"}},
            {"term": {"destination.port": 443}},
            {"term": {"event.category": "authentication"}},
        ],
    })
    assert not any("naming heuristic" in w for w in res.warnings)


def test_ecs_field_hint_silent_on_wildcard():
    res = _conv({
        "name": "wildcard ip", "type": "any", "index": "logs-*",
        "filter": [{"term": {"source.ip": "10.0.*"}}],
    })
    assert not any("naming heuristic" in w for w in res.warnings)


def test_ecs_field_hint_on_blacklist_compare_key():
    """compare_key/blacklist ne passent pas par rule.filters — vérifiés à
    part dans convert_blacklist_whitelist."""
    res = _conv({
        "name": "bad blacklist ips", "type": "blacklist", "index": "logs-*",
        "compare_key": "source.ip", "blacklist": ["not-an-ip", "also-bad"],
    })
    assert any("naming heuristic" in w and "source.ip" in w for w in res.warnings)


def test_indicator_match_commands_exposed_in_metadata_for_report():
    """Bug corrigé : indicator_match_plan restait piégé dans les métadonnées
    internes (objet non sérialisable), jamais exposé pour le rapport/tiroir —
    même trou que celui déjà corrigé pour ml_job_commands."""
    import hashlib
    values = [hashlib.sha256(f"bad{i}".encode()).hexdigest() for i in range(3)]
    res = _conv({
        "name": "IM exposed", "type": "blacklist", "index": "logs-*",
        "compare_key": "process.hash.sha256", "blacklist": values,
    })
    commands = res.metadata.get("indicator_match_commands")
    assert commands and "PUT rosetta-ioc-" in commands
    assert "POST _bulk" in commands
    assert isinstance(res.metadata.get("indicator_match_threat_index"), str)
    assert isinstance(res.metadata.get("indicator_match_notes"), list)


def test_large_ioc_list_switches_strategy_to_threat_match():
    """Passé un certain volume, IN(...) en dur n'est plus juste 'moins bien'
    qu'indicator_match : il n'est plus livré du tout — indicator_match (type
    TOML réel: threat_match) devient LA stratégie livrée, enabled=false tant
    que threat_index n'est pas peuplé."""
    import hashlib
    small = [hashlib.sha256(f"m{i}".encode()).hexdigest() for i in range(5)]
    large = [hashlib.sha256(f"m{i}".encode()).hexdigest() for i in range(500)]

    res_small = _conv({
        "name": "small list", "type": "blacklist", "index": "logs-*",
        "compare_key": "process.hash.sha256", "blacklist": small,
    })
    res_large = _conv({
        "name": "large list", "type": "blacklist", "index": "logs-*",
        "compare_key": "process.hash.sha256", "blacklist": large,
    })
    assert res_small.warnings == []  # petite liste : ES|QL livré, aucun défaut
    assert res_small.strategy == RuleStrategy.ESQL
    assert res_large.strategy == RuleStrategy.THREAT_MATCH
    assert res_large.esql_query is None
    assert any("too many for an inline ES|QL" in w for w in res_large.warnings)
    assert res_large.confidence < res_small.confidence
    # Petite liste : ES|QL livré + Indicator Match en ALTERNATIVE recommandée
    assert res_small.metadata.get("migration_strategy") == "indicator_match"
    # Grosse liste : Indicator Match EST déjà la stratégie livrée -> pas de
    # badge "alternative recommandée" redondant (cf. test dédié séparé)
    assert res_large.metadata.get("migration_strategy") is None


def test_large_ioc_list_toml_is_primary_threat_match_disabled():
    import hashlib
    large = [hashlib.sha256(f"m{i}".encode()).hexdigest() for i in range(500)]
    res = _conv({
        "name": "Large IOC feed", "type": "blacklist", "index": "logs-*",
        "compare_key": "process.hash.sha256", "blacklist": large,
        "filter": [{"term": {"event.category": "process"}}],
    })
    toml_text = to_toml(res)
    parsed = tomllib.loads(toml_text)
    r = parsed["rule"]
    assert r["type"] == "threat_match"
    assert r["enabled"] is False
    assert "event.category" in r["query"]
    assert r["threat_mapping"][0]["entries"][0]["field"] == "process.hash.sha256"
    assert "NE PAS ACTIVER" in r["note"]
    # Pas de fichier compagnon distinct nécessaire : le principal EST déjà le threat_match
    assert to_toml_indicator_match_companion(res) is not None  # la fonction reste utilisable
    # mais cmd_convert (testé séparément) ne doit pas l'écrire en plus


def test_no_redundant_migration_badge_when_already_threat_match():
    """Quand indicator_match EST déjà la stratégie livrée (grosse liste), pas
    de badge 'chemin recommandé : Indicator Match' redondant à côté."""
    import hashlib
    large = [hashlib.sha256(f"m{i}".encode()).hexdigest() for i in range(500)]
    res = _conv({
        "name": "no redundant badge", "type": "blacklist", "index": "logs-*",
        "compare_key": "process.hash.sha256", "blacklist": large,
    })
    assert res.strategy == RuleStrategy.THREAT_MATCH
    assert res.metadata.get("migration_strategy") is None
    assert res.metadata.get("migration_score") is None


def test_cardinality_max_without_query_key_stays_esql():
    """max_cardinality SANS query_key : la doc Threshold est ambiguë sur un
    'field' de groupement vide pour une agrégation globale — pas de certitude,
    donc pas de pari : reste en ES|QL plutôt que deviner (bug réel trouvé via
    l'audit structurel : 'threshold: empty field list' sur 5 règles du corpus)."""
    res = _conv({
        "name": "c global", "type": "cardinality", "index": "logs-*",
        "cardinality_field": "host.name", "max_cardinality": 5,
    })
    assert res.strategy == RuleStrategy.ESQL
    assert "distinct_count > 5" in res.esql_query
    assert any("ambiguous about an empty" in w for w in res.warnings)


def test_prebuilt_category_detection():
    """Détection de catégorie prebuilt Elastic à partir du pattern d'index —
    partie hors-ligne, testable sans réseau. Ne devine RIEN si aucun motif
    connu ne correspond, plutôt qu'une catégorie fausse."""
    from rosetta.prebuilt_match import guess_category
    assert guess_category("winlogbeat-*") == "windows"
    assert guess_category("logs-endpoint.events.process-*") == "windows"
    assert guess_category("auditbeat-*") == "linux"
    assert guess_category("packetbeat-*") == "network"
    assert guess_category("logs-aws.cloudtrail-*") == "integrations/aws"
    assert guess_category("logs-custom-app-*") is None  # rien à deviner, silence


def test_prebuilt_hint_degrades_gracefully_without_network():
    """Sans réseau (ou en cas d'échec), fetch_prebuilt_hint ne doit JAMAIS
    lever d'exception — la fonctionnalité est strictement optionnelle et ne
    doit jamais faire échouer une conversion."""
    from rosetta.prebuilt_match import fetch_prebuilt_hint
    hint = fetch_prebuilt_hint("winlogbeat-*", "Suspicious Rule", ["process.command_line"])
    assert hint is not None
    assert hint.category == "windows"
    # Dans cet environnement de test (pas d'accès réseau), un échec est
    # attendu et doit être capturé proprement, pas propagé.
    assert hint.error is not None or hint.candidates is not None


def test_prebuilt_hint_none_when_no_category_guessed():
    from rosetta.prebuilt_match import fetch_prebuilt_hint
    assert fetch_prebuilt_hint("logs-custom-app-*", "Some Rule", []) is None


def test_unknown_type_is_manual():
    res = _conv({"name": "x", "type": "totally_unknown", "index": "logs-*"})
    assert res.strategy == RuleStrategy.MANUAL
    assert res.confidence <= 0.2


def test_filter_translation_terms_and_range():
    warns: list[str] = []
    clause = filter_to_esql([
        {"terms": {"src.ip": ["1.1.1.1", "2.2.2.2"]}},
        {"range": {"bytes": {"gt": 100}}},
    ], warns)
    assert "src.ip IN" in clause
    assert "bytes > 100" in clause


def test_confidence_band():
    assert confidence_band(0.9) == "HIGH"
    assert confidence_band(0.7) == "MEDIUM"
    assert confidence_band(0.4) == "LOW"
    assert confidence_band(0.1) == "VERY LOW"


@pytest.mark.parametrize("rtype", [
    "any", "frequency", "blacklist", "cardinality",
    "metric_aggregation", "new_term", "spike", "flatline",
    "change", "percentage_match",
])
def test_toml_output_parses(rtype):
    raw = {
        "name": f"rule {rtype}", "type": rtype, "index": "logs-*",
        "num_events": 5, "timeframe": {"minutes": 5}, "compare_key": "user.name",
        "blacklist": ["a"], "whitelist": ["a"], "cardinality_field": "host.name",
        "max_cardinality": 5, "metric_agg_key": "b", "metric_agg_type": "avg",
        "max_threshold": 1, "fields": ["process.name"], "spike_height": 2,
        "threshold": 1, "query_key": "user.name",
        "match_bucket_filter": [{"term": {"x": 1}}], "max_percentage": 30,
    }
    res = _conv(raw)
    toml_text = to_toml(res)
    parsed = tomllib.loads(toml_text)
    assert parsed["rule"]["name"] == f"rule {rtype}"
    assert "type" in parsed["rule"]
    # note et tags doivent rester au niveau [rule], pas être absorbés par une
    # éventuelle sous-table ([rule.threshold] / [rule.new_terms]).
    assert isinstance(parsed["rule"]["note"], str)
    assert isinstance(parsed["rule"]["tags"], list)


def test_threshold_subtable_does_not_absorb_note_tags():
    res = _conv({
        "name": "fl", "type": "flatline", "index": "logs-*",
        "threshold": 1, "query_key": "agent.id", "timeframe": {"minutes": 10},
    })
    parsed = tomllib.loads(to_toml(res))
    assert "note" in parsed["rule"] and "tags" in parsed["rule"]
    assert "note" not in parsed["rule"]["threshold"]
    assert "tags" not in parsed["rule"]["threshold"]


def test_new_terms_subtable_does_not_absorb_note_tags():
    res = _conv({
        "name": "nt", "type": "new_term", "index": "logs-*",
        "fields": ["process.name"],
    })
    parsed = tomllib.loads(to_toml(res))
    assert "note" in parsed["rule"] and "tags" in parsed["rule"]
    assert "note" not in parsed["rule"]["new_terms"]


@pytest.mark.parametrize("rtype,extra", [
    ("frequency", {"num_events": 5, "timeframe": {"minutes": 5}}),
    ("cardinality", {"cardinality_field": "host.name", "min_cardinality": 5}),
    ("metric_aggregation", {"metric_agg_key": "b", "metric_agg_type": "avg",
                            "max_threshold": 1}),
    ("percentage_match", {"match_bucket_filter": [{"term": {"x": 1}}],
                          "max_percentage": 30}),
    ("spike", {"spike_height": 2, "threshold_cur": 10, "timeframe": {"hours": 1}}),
    ("change", {"compare_key": "geo.country", "query_key": "user.name"}),
])
def test_aggregating_esql_ends_with_keep(rtype, extra):
    """detection-rules rejette une requête ES|QL agrégeante sans clause KEEP."""
    res = _conv({"name": rtype, "type": rtype, "index": "logs-*", **extra})
    assert res.strategy == RuleStrategy.ESQL
    assert "| KEEP" in res.esql_query


# --- Détection de scripts / code custom -----------------------------------

def test_custom_rule_type_is_manual_and_disabled():
    res = _conv({
        "name": "custom", "type": "elastalert_modules.mod.MyRule",
        "index": "logs-*",
    })
    assert res.strategy == RuleStrategy.MANUAL
    assert res.confidence <= 0.10
    assert res.metadata.get("custom_detection_code")
    # La règle TOML doit être désactivée
    toml_text = to_toml(res)
    parsed = tomllib.loads(toml_text)
    assert parsed["rule"]["enabled"] is False


def test_command_alerter_keeps_detection_but_flags_action():
    res = _conv({
        "name": "cmd", "type": "frequency", "index": "logs-*",
        "num_events": 10, "timeframe": {"minutes": 5},
        "alert": ["command"], "command": ["/opt/notify.sh", "%(rule_name)s"],
    })
    # La détection migre toujours en ES|QL
    assert res.strategy == RuleStrategy.ESQL
    assert res.esql_query and "STATS" in res.esql_query
    # Mais l'action est signalée
    assert res.metadata.get("custom_actions")
    assert any("command" in w.lower() for w in res.warnings)
    # Confiance dégradée mais pas effondrée
    assert 0.6 <= res.confidence < 0.9


def test_custom_alerter_module_flagged():
    res = _conv({
        "name": "ca", "type": "blacklist", "index": "logs-*",
        "compare_key": "user.name", "blacklist": ["x"],
        "alert": "elastalert_modules.my_alerts.MyAlerter",
    })
    assert res.strategy == RuleStrategy.ESQL
    actions = res.metadata.get("custom_actions", [])
    assert any(a["category"] == "custom_alerter" for a in actions)


def test_match_enhancement_flagged():
    res = _conv({
        "name": "enh", "type": "frequency", "index": "logs-*",
        "num_events": 5, "timeframe": {"minutes": 5},
        "match_enhancements": ["elastalert_modules.enh.GeoEnrich"],
        "alert": ["slack"],
    })
    assert res.strategy == RuleStrategy.ESQL
    assert any("enhancement" in w.lower() for w in res.warnings)


def test_enhancement_not_mislabeled_as_custom_action():
    """Bug corrigé : un match_enhancement finissait dans metadata['custom_actions'],
    rendu sous « Actions custom à recréer (connectors Elastic) » dans le TOML —
    trompeur, une enhancement n'est pas un connector à recréer mais du code
    qui peut modifier le match avant l'alerte."""
    res = _conv({
        "name": "Rule with enhancement 277", "type": "frequency", "index": "logs-okta*",
        "num_events": 5, "timeframe": {"minutes": 5},
        "match_enhancements": ["elastalert_modules.enh.GeoEnrich"],
        "alert": ["pagerduty"],
    })
    assert "custom_actions" not in res.metadata
    enh = res.metadata.get("enhancements", [])
    assert any(e["reference"] == "elastalert_modules.enh.GeoEnrich" for e in enh)
    note = to_toml(res)
    assert "### Enrichissements Python à examiner" in note
    assert "elastalert_modules.enh.GeoEnrich" in note
    # Pas de section 'connectors' du tout ici (aucun custom_alerter/command)
    assert "### Actions custom à recréer" not in note


def test_custom_alerter_and_enhancement_together_stay_separate():
    """Un rule avec les deux (alerter custom + enhancement) doit produire
    deux sections distinctes, pas une seule liste mélangée."""
    res = _conv({
        "name": "both", "type": "frequency", "index": "logs-*",
        "num_events": 5, "timeframe": {"minutes": 5},
        "alert": ["elastalert_modules.custom_alerts.MyAlerter"],
        "match_enhancements": ["elastalert_modules.enh.GeoEnrich"],
    })
    assert any(a["category"] == "custom_alerter" for a in res.metadata.get("custom_actions", []))
    assert any(e["category"] == "enhancement" for e in res.metadata.get("enhancements", []))
    note = to_toml(res)
    assert "### Actions custom à recréer" in note
    assert "### Enrichissements Python à examiner" in note


def test_builtin_alerter_not_flagged_as_script():
    res = _conv({
        "name": "plain", "type": "frequency", "index": "logs-*",
        "num_events": 5, "timeframe": {"minutes": 5},
        "alert": ["email", "slack"],
    })
    assert not res.metadata.get("custom_actions")
    assert res.confidence >= 0.8


# --- Robustesse du parser --------------------------------------------------

def test_parser_recovers_from_parasitic_indentation(tmp_path):
    """Une clé top-level mal indentée (cas Yelp ssh.yaml) doit être réparée."""
    from rosetta.parser.elastalert import parse_file
    rule_yaml = (
        "# commentaire\n"
        "  name: SSH abuse\n"   # indentation parasite
        "type: frequency\n"
        "num_events: 20\n"
        "timeframe:\n"
        "  minutes: 60\n"
        "index: auditbeat-*\n"
        "filter:\n"
        "  - query:\n"
        "      query_string:\n"
        "        query: \"event.type:authentication_failure\"\n"
    )
    f = tmp_path / "ssh.yaml"
    f.write_text(rule_yaml)
    rule = parse_file(f)
    assert rule.name == "SSH abuse"
    assert rule.rule_type == "frequency"


# --- Sanitisation : garantie de non-fuite ----------------------------------

def _sanitize_one(raw: dict):
    from rosetta.sanitize import sanitize_result
    res = _conv(raw)
    return sanitize_result(res, secret=b"test-secret")


def test_sanitize_no_leak_of_sensitive_values():
    """Aucune valeur sensible de la règle ne doit apparaître dans la sortie."""
    import json
    raw = {
        "name": "SENTINEL_NAME_xyz",
        "type": "frequency",
        "index": "SENTINEL_INDEX_abc-*",
        "num_events": 4242,
        "timeframe": {"minutes": 7},
        "query_key": "SENTINEL_FIELD_ssn",
        "description": "SENTINEL_DESC monitors 10.13.37.99",
        "filter": [
            {"query": {"query_string": {
                "query": "user.name:SENTINEL_USER AND source.ip:10.13.37.99"}}},
            {"terms": {"SENTINEL_FIELD2": ["SENTINEL_V1", "SENTINEL_V2"]}},
        ],
        "alert": ["command"],
        "command": ["/SENTINEL_PATH/script.sh"],
    }
    blob = json.dumps(_sanitize_one(raw), ensure_ascii=False)
    for needle in ["SENTINEL", "10.13.37.99", "4242", "ssn", "script.sh"]:
        assert needle not in blob, f"FUITE: {needle!r} présent dans la sortie sanitisée"


def test_sanitize_no_leak_of_ml_job_plan():
    """Le plan de job ML (index, champs, seuils réels) ne doit jamais fuiter
    dans la sortie 'share' — seul un booléen ('recommandé ou non') en sort."""
    import json
    raw = {
        "name": "SENTINEL_SPIKE", "type": "spike", "index": "SENTINEL_INDEX-*",
        "spike_height": 3, "threshold_cur": 4242, "timeframe": {"hours": 1},
        "query_key": "SENTINEL_FIELD_user",
        "filter": [{"term": {"SENTINEL_FIELD2": "SENTINEL_VALUE"}}],
    }
    out = _sanitize_one(raw)
    blob = json.dumps(out, ensure_ascii=False)
    for needle in ["SENTINEL", "4242", "high_count", "_ml/anomaly_detectors"]:
        assert needle not in blob, f"FUITE: {needle!r} présent dans la sortie sanitisée"
    assert out["ml_job_recommended"] is True


def test_sanitize_no_leak_of_ml_job_plan_change_and_flatline():
    """Même garantie que pour spike, mais pour change/flatline."""
    import json
    for raw in [
        {
            "name": "SENTINEL_CHANGE", "type": "change", "index": "SENTINEL_INDEX-*",
            "compare_key": "SENTINEL_FIELD_geo", "query_key": "SENTINEL_FIELD_user",
        },
        {
            "name": "SENTINEL_FLATLINE", "type": "flatline", "index": "SENTINEL_INDEX-*",
            "threshold": 4242, "query_key": "SENTINEL_FIELD_agent",
        },
    ]:
        out = _sanitize_one(raw)
        blob = json.dumps(out, ensure_ascii=False)
        for needle in ["SENTINEL", "4242", "rare", "low_count", "_ml/anomaly_detectors"]:
            assert needle not in blob, f"FUITE ({raw['type']}): {needle!r} présent"
        assert out["ml_job_recommended"] is True


def test_sanitize_no_leak_of_indicator_match_plan():
    """Les valeurs IOC réelles (hashs, champ) ne doivent jamais fuiter dans
    la sortie sanitisée — seuls migration_strategy/migration_score en sortent."""
    import hashlib, json
    values = [hashlib.sha256(f"SENTINEL{i}".encode()).hexdigest() for i in range(3)]
    raw = {
        "name": "SENTINEL_BLACKLIST", "type": "blacklist", "index": "SENTINEL_INDEX-*",
        "compare_key": "SENTINEL_FIELD.hash.sha256", "blacklist": values,
    }
    out = _sanitize_one(raw)
    blob = json.dumps(out, ensure_ascii=False)
    for needle in ["SENTINEL"] + values:
        assert needle not in blob, f"FUITE: {needle!r} présent dans la sortie sanitisée"
    assert out["migration_strategy"] == "indicator_match"


def test_sanitize_preserves_debug_info():
    """La sortie doit garder ce qui sert à débugger : type, stratégie, structure."""
    raw = {
        "name": "x", "type": "frequency", "index": "logs-*",
        "num_events": 10, "timeframe": {"minutes": 5}, "query_key": "user.name",
        "filter": [{"terms": {"f": ["a", "b", "c"]}}],
    }
    out = _sanitize_one(raw)
    assert out["source_type"] == "frequency"
    assert out["strategy"] == "esql"
    assert out["esql_skeleton"]["pipeline"] == ["FROM", "WHERE", "STATS", "WHERE", "KEEP"]
    assert out["filter_shapes"][0]["kind"] == "terms"
    assert out["filter_shapes"][0]["arity"] == 3  # arité OK, valeurs absentes
    assert out["uses_query_key"] is True


def test_sanitize_custom_type_becomes_generic_label():
    """Un type custom (module.file.Class) ne doit pas exposer le chemin module."""
    out = _sanitize_one({
        "name": "x", "type": "secret_modules.internal.MyRule", "index": "logs-*",
    })
    assert out["source_type"] == "custom_module"
    assert "secret_modules" not in str(out)
    assert out["has_custom_detection_code"] is True


def test_sanitize_fingerprint_stable_with_fixed_secret():
    from rosetta.sanitize import sanitize_result
    raw = {"name": "same", "type": "any", "index": "logs-*"}
    r1 = sanitize_result(_conv(raw), secret=b"fixed")
    r2 = sanitize_result(_conv(raw), secret=b"fixed")
    assert r1["fingerprint"] == r2["fingerprint"]
    # Secret différent -> empreinte différente (non corrélable)
    r3 = sanitize_result(_conv(raw), secret=b"other")
    assert r3["fingerprint"] != r1["fingerprint"]


def test_sanitize_command_path_not_leaked():
    """Le chemin du script command ne doit jamais apparaître."""
    import json
    out = _sanitize_one({
        "name": "x", "type": "frequency", "index": "logs-*",
        "num_events": 5, "timeframe": {"minutes": 5},
        "alert": ["command"], "command": ["/very/secret/path.sh", "%(rule_name)s"],
    })
    blob = json.dumps(out)
    assert "/very/secret/path.sh" not in blob
    assert "command_alerter" in out["custom_action_categories"]
