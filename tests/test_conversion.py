"""Tests unitaires pour rosetta."""
from __future__ import annotations

import tomllib

import pytest

from rosetta.converters.registry import convert
from rosetta.detection_rule.toml_writer import to_toml
from rosetta.esql.translator import filter_to_esql
from rosetta.models import RuleStrategy
from rosetta.parser.elastalert import parse_rule_dict
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


def test_cardinality_count_distinct():
    res = _conv({
        "name": "c", "type": "cardinality", "index": "logs-*",
        "cardinality_field": "host.name", "max_cardinality": 5,
        "query_key": "user.name",
    })
    assert "COUNT_DISTINCT(host.name)" in res.esql_query
    assert "distinct_count > 5" in res.esql_query


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
    assert confidence_band(0.9) == "ÉLEVÉE"
    assert confidence_band(0.7) == "MOYENNE"
    assert confidence_band(0.4) == "FAIBLE"
    assert confidence_band(0.1) == "TRÈS FAIBLE"


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
    ("cardinality", {"cardinality_field": "host.name", "max_cardinality": 5}),
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
