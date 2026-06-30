#!/usr/bin/env python3
"""Génère un grand corpus de règles ElastAlert variées pour éprouver rosetta.

Produit des règles de tous les types, avec des filtres de complexité variable,
des cas de scripts, et quelques cas volontairement dégénérés (champs manquants,
YAML limite) pour tester la robustesse.

Usage: python generate_corpus.py <dossier_sortie> [nombre]
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

random.seed(42)  # reproductible

INDICES = ["logs-*", "logs-endpoint.events.*", "logs-system.security-*",
           "auditbeat-*", "filebeat-*", "logs-network-*", "logs-okta*",
           "logs-aws.cloudtrail-*", "winlogbeat-*"]

FIELDS = ["user.name", "source.ip", "host.name", "process.name", "event.action",
          "destination.ip", "service.name", "agent.id", "url.domain",
          "file.hash.sha256", "process.command_line", "user.id"]

CATEGORIES = ["authentication", "process", "network", "file", "iam",
              "configuration", "session", "web"]

OUTCOMES = ["success", "failure", "unknown"]

ALERTERS = ["email", "slack", "pagerduty", "jira", "ms_teams", "opsgenie"]

PRIORITIES = [1, 2, 3, 4, 5]


def rand_timeframe():
    unit = random.choice(["minutes", "hours", "days"])
    val = random.choice([1, 5, 10, 15, 30]) if unit == "minutes" else \
        random.choice([1, 2, 6, 12, 24]) if unit == "hours" else \
        random.choice([1, 7, 14, 30])
    return {unit: val}


def rand_lucene_filter():
    cat = random.choice(CATEGORIES)
    out = random.choice(OUTCOMES)
    return [{"query": {"query_string": {
        "query": f"event.category:{cat} AND event.outcome:{out}"}}}]


def rand_term_filter():
    return [{"term": {random.choice(FIELDS): random.choice(
        ["admin", "root", "svc_app", "4624", "login", "powershell.exe"])}}]


def rand_terms_filter():
    f = random.choice(FIELDS)
    n = random.randint(2, 4)
    vals = random.sample(["a", "b", "c", "d", "e", "admin", "guest", "test"], n)
    return [{"terms": {f: vals}}]


def rand_range_filter():
    f = random.choice(["network.bytes", "event.duration", "http.response.status_code"])
    return [{"range": {f: {"gt": random.choice([100, 500, 1000, 10000])}}}]


def rand_filter():
    return random.choice([
        rand_lucene_filter, rand_term_filter,
        rand_terms_filter, rand_range_filter,
    ])()


def base(name, rtype, idx=None):
    d = {
        "name": name,
        "type": rtype,
        "index": idx or random.choice(INDICES),
        "priority": random.choice(PRIORITIES),
        "filter": rand_filter(),
        "alert": [random.choice(ALERTERS)],
    }
    return d


def gen_frequency(i):
    d = base(f"Frequency rule {i}", "frequency")
    d["num_events"] = random.choice([5, 10, 20, 50, 100])
    d["timeframe"] = rand_timeframe()
    if random.random() < 0.7:
        d["query_key"] = random.choice(FIELDS)
    return d


def gen_any(i):
    return base(f"Any match rule {i}", "any")


def gen_blacklist(i):
    d = base(f"Blacklist rule {i}", "blacklist")
    d["compare_key"] = random.choice(FIELDS)
    d["blacklist"] = random.sample(["bad1", "bad2", "evil", "malware", "c2"], 3)
    return d


def gen_whitelist(i):
    d = base(f"Whitelist rule {i}", "whitelist")
    d["compare_key"] = random.choice(FIELDS)
    d["whitelist"] = random.sample(["ok1", "ok2", "trusted", "internal"], 2)
    d["ignore_null"] = True
    return d


def gen_cardinality(i):
    d = base(f"Cardinality rule {i}", "cardinality")
    d["cardinality_field"] = random.choice(FIELDS)
    d["timeframe"] = rand_timeframe()
    if random.random() < 0.5:
        d["max_cardinality"] = random.choice([5, 10, 50])
    else:
        d["min_cardinality"] = random.choice([1, 2, 3])
    if random.random() < 0.6:
        d["query_key"] = random.choice(FIELDS)
    return d


def gen_metric(i):
    d = base(f"Metric aggregation rule {i}", "metric_aggregation")
    d["metric_agg_key"] = random.choice(["network.bytes", "event.duration", "cpu.pct"])
    d["metric_agg_type"] = random.choice(["avg", "max", "min", "sum"])
    d["timeframe"] = rand_timeframe()
    if random.random() < 0.5:
        d["max_threshold"] = random.choice([100, 1000, 0.9])
    else:
        d["min_threshold"] = random.choice([1, 10])
    if random.random() < 0.5:
        d["query_key"] = random.choice(FIELDS)
    return d


def gen_new_term(i):
    d = base(f"New term rule {i}", "new_term")
    d["fields"] = random.sample(FIELDS, random.randint(1, 2))
    d["terms_window_size"] = {"days": random.choice([7, 14, 30, 90])}
    return d


def gen_spike(i):
    d = base(f"Spike rule {i}", "spike")
    d["spike_height"] = random.choice([2, 3, 5])
    d["spike_type"] = random.choice(["up", "down", "both"])
    d["timeframe"] = rand_timeframe()
    d["threshold_cur"] = random.choice([10, 50, 100])
    if random.random() < 0.6:
        d["query_key"] = random.choice(FIELDS)
    return d


def gen_flatline(i):
    d = base(f"Flatline rule {i}", "flatline")
    d["threshold"] = random.choice([1, 2, 5])
    d["timeframe"] = rand_timeframe()
    if random.random() < 0.5:
        d["query_key"] = random.choice(FIELDS)
    return d


def gen_change(i):
    d = base(f"Change rule {i}", "change")
    d["compare_key"] = random.choice(FIELDS)
    d["query_key"] = random.choice(FIELDS)
    d["timeframe"] = rand_timeframe()
    d["ignore_null"] = True
    return d


def gen_percentage(i):
    d = base(f"Percentage match rule {i}", "percentage_match")
    d["match_bucket_filter"] = rand_term_filter()
    d["timeframe"] = rand_timeframe()
    if random.random() < 0.5:
        d["max_percentage"] = random.choice([10, 30, 50])
    else:
        d["min_percentage"] = random.choice([70, 90])
    if random.random() < 0.6:
        d["query_key"] = random.choice(FIELDS)
    return d


# --- Cas spéciaux / scripts -------------------------------------------------

def gen_command(i):
    d = gen_frequency(i)
    d["name"] = f"Frequency with command action {i}"
    d["alert"] = ["command"]
    d["command"] = ["/opt/scripts/notify.sh", "%(rule_name)s", f"%({random.choice(FIELDS)})s"]
    return d


def gen_custom_alerter(i):
    d = gen_blacklist(i)
    d["name"] = f"Rule with custom alerter {i}"
    d["alert"] = "elastalert_modules.custom_alerts.MyAlerter"
    return d


def gen_custom_type(i):
    d = base(f"Custom detection type {i}", "elastalert_modules.custom_rules.MyRule")
    d["some_param"] = random.randint(1, 100)
    return d


def gen_enhancement(i):
    d = gen_frequency(i)
    d["name"] = f"Rule with enhancement {i}"
    d["match_enhancements"] = ["elastalert_modules.enh.GeoEnrich"]
    return d


def gen_missing_fields(i):
    # cardinality sans cardinality_field -> doit baisser le score
    d = base(f"Degenerate cardinality {i}", "cardinality")
    d["timeframe"] = rand_timeframe()
    return d


GENERATORS = [
    (gen_frequency, 0.20),
    (gen_any, 0.08),
    (gen_blacklist, 0.10),
    (gen_whitelist, 0.05),
    (gen_cardinality, 0.10),
    (gen_metric, 0.08),
    (gen_new_term, 0.08),
    (gen_spike, 0.07),
    (gen_flatline, 0.05),
    (gen_change, 0.05),
    (gen_percentage, 0.04),
    (gen_command, 0.04),
    (gen_custom_alerter, 0.02),
    (gen_custom_type, 0.02),
    (gen_enhancement, 0.01),
    (gen_missing_fields, 0.01),
]


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus")
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    out.mkdir(parents=True, exist_ok=True)

    import yaml
    gens, weights = zip(*GENERATORS)
    for i in range(n):
        gen = random.choices(gens, weights=weights, k=1)[0]
        rule = gen(i)
        fname = out / f"rule_{i:04d}_{rule['type'].split('.')[-1][:20]}.yml"
        fname.write_text(yaml.safe_dump(rule, sort_keys=False, allow_unicode=True))
    print(f"{n} règles générées dans {out}/")


if __name__ == "__main__":
    main()
