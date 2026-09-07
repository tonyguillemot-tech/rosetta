# Rosetta — ElastAlert → Elastic Security Migration

Rosetta converts **ElastAlert** detection rules (YAML) into **Elastic Security** rules,
targeting **ES|QL** as the primary output format. Rules are written to **TOML** files
compatible with [`elastic/detection-rules`](https://github.com/elastic/detection-rules),
enabling a **Detection-as-Code (DaC)** workflow. Every migrated rule receives an
**explainable confidence score** so you know exactly what needs manual review.

## Why ES|QL first

ES|QL natively expresses the "filter → aggregate (`STATS … BY`) → filter on the
computed value" pattern that underlies most ElastAlert rule types (frequency,
cardinality, metric). When ES|QL is not the right fit, Rosetta falls back to the
most semantically faithful native Elastic Security rule type.

## ElastAlert type coverage

| ElastAlert type        | Elastic strategy (delivered rule)                              | Base confidence |
|-------------------------|------------------------------------------------------------------|------------------|
| `any`                   | ES\|QL (non-aggregating)                                          | 95 % |
| `frequency`             | ES\|QL `STATS COUNT()`                                            | 90 % |
| `blacklist`             | ES\|QL `IN` (small list) or **`threat_match` native** (> 20 IOC-shaped values) | 90 % |
| `whitelist`             | ES\|QL `NOT IN` (never `threat_match` — see below)                | 90 % |
| `cardinality`           | ES\|QL `COUNT_DISTINCT()`, or **Threshold rule native** (`max_cardinality` + `query_key`) | 85 % |
| `metric_aggregation`    | ES\|QL `AVG`/`SUM`/`MIN`/`MAX`/`COUNT`                            | 85 % |
| `new_term`              | New Terms rule (native)                                           | 90 % |
| `percentage_match`      | ES\|QL ratio via `EVAL`                                           | 62 % |
| `change`                | ES\|QL `COUNT_DISTINCT` approximation                             | 55 % |
| `flatline`              | Threshold rule (native, inverted logic)                           | 55 % |
| `spike`                 | ES\|QL approximation                                              | 50 % |
| *(custom type)*         | `manual` (detection logic in code, `enabled = false`)             | 5 % |
| *(unknown type)*        | `manual` (review required)                                        | 10 % |

These are base scores before per-rule adjustments (filter translation warnings,
missing required fields, `query_key` mapping, etc.) — see [Confidence score](#confidence-score).

Behavioral types (`spike`, `flatline`, `change`) have no strict semantic equivalent
in ES|QL/native rules. Rosetta produces an approximation, lowers the confidence
score, and adds an explicit warning in the rule's `note` field.

### Migration suggestions (separate from the delivered rule's confidence)

For a few source types, Rosetta also detects a **more semantically faithful migration
path** than the rule it actually delivers, and reports it as a separate `migration_strategy`
/ `migration_score` — this never affects the delivered rule's own confidence score,
it's an independent "have you considered…" signal:

| Source type(s)              | Suggested path      | Fidelity score | Why it's only a suggestion |
|------------------------------|----------------------|----------------|------------------------------|
| `spike`                      | Machine Learning (`high_count`/`rare` job) | ~75 % | No equivalent of `spike_height`; uses the ML job's default anomaly threshold instead |
| `change`                      | Machine Learning (`rare` job)              | ~55 % | Biased toward "first appearance", not a true reproduction of "alert on every value change" |
| `flatline`                    | Machine Learning (`low_count` job)          | ~50 % | Whether a silent entity still produces a scorable zero data point depends on datafeed config not set up by the generated job |
| `blacklist` (small list)      | Indicator Match (`threat_match`)            | ~80 % | IOC type (hash/IP/domain/URL) is detected by a field-name + value-shape heuristic, not a confirmed data contract |
| custom type (module name)     | EQL (event sequence)                        | *(no score)* | Pure naming heuristic (module name suggests `sequence`/`chain`/`stage1`/…) — Rosetta cannot read the Python logic, so no confidence figure is fabricated |

When a suggestion applies, `convert` also writes a ready-to-import **companion TOML
file** next to the main rule (`*_ml_job.toml` or `*_indicator_match.toml`), generated
with `enabled = false` and prefilled fields (`machine_learning_job_id`, or
`threat_index` / `threat_mapping`) — review before enabling.
`whitelist` never gets an Indicator Match suggestion: `threat_match` has no "does
not match" mode in Elastic Security, so it structurally cannot express whitelist
semantics ("alert if NOT in list").

### Optional: cross-checking against Elastic prebuilt rules

`report --check-prebuilt` and `convert --check-prebuilt` make a **live, opt-in** call
to the GitHub API to look for existing Elastic prebuilt detection rules that might
already cover the same use case (matched by index pattern + field names). This is
purely informational, never a certain match, never enabled by default, and never
fatal if the network call fails.

## Custom scripts and code in ElastAlert

ElastAlert allows injecting Python or external scripts at several points. Rosetta
detects them and adjusts the confidence score depending on whether the **detection
logic** or only the **alerting action** is in code:

| ElastAlert case | Detected as | Migration impact |
|---|---|---|
| `type: module.file.RuleName` (custom type) | `custom_rule_type` | **Blocking**: detection logic is in code → `manual` strategy, rule generated with `enabled = false`, confidence ~5 % |
| `alert: command` + `command: [...]` | `command_alerter` | Detection migrates; the action script is listed in `note` for recreation via connector. Moderate penalty |
| `alert: module.file.AlertName` (custom alerter) | `custom_alerter` | Same as command: detection migrates, action to recreate |
| `match_enhancements: [module.file.Enh]` | `enhancement` | Detection migrates, Python enhancement to review. Moderate penalty |

Built-in alerters (`email`, `slack`, `jira`, `pagerduty`, …) are never treated as
custom code. Affected rules receive `Review: Custom Action` or
`Review: Custom Detection Code` tags and a dedicated section in their `note` field.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

### Preview the migration (no files written)

```bash
python -m rosetta report /path/to/elastalert_rules

# Machine-readable formats
python -m rosetta report /path/to/elastalert_rules --json      # output JSON
python -m rosetta report /path/to/elastalert_rules --html      # interactive HTML (stdout)
python -m rosetta report /path/to/elastalert_rules --html report.html  # save to file
```

The HTML report features an interactive table with sortable columns, confidence band filters,
search by rule name, and a side panel that opens when you click a rule — showing confidence
breakdown, warnings, ES|QL query, source YAML, score factors, and recommended migration paths.

### Generate TOML rule files

```bash
# Convert all rules
python -m rosetta convert /path/to/elastalert_rules -o output/rules/

# Only write rules above a confidence threshold
python -m rosetta convert /path/to/elastalert_rules -o output/rules/ --min-confidence 0.6
```

### Import into Elastic Security

The generated TOML files follow the `[metadata]` / `[rule]` schema expected by
`elastic/detection-rules`. To validate and deploy them:

```bash
# Local schema validation
python -m detection_rules view-rule output/rules/my_rule.toml

# Import into Kibana (custom rules)
python -m detection_rules kibana import-rules -d output/rules/ --overwrite
```

Place the files in your configured `CUSTOM_RULES_DIR`, then use
`kibana import-rules` / `export-rules` to synchronize with Elastic Security.

## Confidence score

The score starts from a per-type base (reflecting how faithfully the semantics can
be reproduced), then adjusts with concrete penalties and bonuses: filter translation
warnings, Lucene `query_string` queries (converted on a best-effort basis), missing
required fields, semantic gap on temporal rule types, and correct mapping of
`query_key` onto `STATS … BY`.

Confidence bands:

| Band | Score |
|------|-------|
| **HIGH** | ≥ 85 % |
| **MEDIUM** | ≥ 60 % |
| **LOW** | ≥ 30 % |
| **VERY LOW** | < 30 % |

A rule is flagged for review when its strategy is `manual` or its confidence is
below 60 %.

## Sharing diagnostic data without exposing sensitive rules

If your rules are confidential but you need to share diagnostic information (e.g.,
when reporting a conversion issue), use the `share` command. It produces a sanitized
report designed for debugging — **no business data is included**:

```bash
# JSON output (default)
python -m rosetta share /path/to/your/rules -o shared_report.json

# Interactive HTML report with the same data
python -m rosetta share /path/to/your/rules --html shared_report.html
```

For each rule the report contains: the source type, the Elastic strategy, the score
and its factors, **categories** of warnings, the **shape** of filters
(term/terms/range/lucene + arity), the **skeleton** of the ES|QL query (command
sequence, functions, operators — no identifiers or values), and an HMAC fingerprint
to reference a rule without naming it.

The HTML format offers the same interactive features as the `report` HTML output:
sortable columns, confidence filtering, search by rule ID (fingerprint), and a
detailed side panel for each rule. This is ideal for visual analysis without exposing
sensitive rule metadata.

What **never appears** in the output: rule names and descriptions, field and index
names, filter values (IPs, users, hostnames, hashes), business thresholds, script
paths, or raw queries. A field omitted from the safe-list cannot leak by design.

To produce stable fingerprints across multiple runs (useful for tracking a specific
rule over time), set a shared secret:

```bash
export ROSETTA_HMAC_SECRET="your-shared-secret"
python -m rosetta share /path/to/your/rules -o shared_report.json
```

## Testing with a synthetic corpus

To test on a large volume of rules, a generator creates varied ElastAlert rules
covering all supported types, filters of varying complexity, custom script cases,
and degenerate inputs:

```bash
python tools/generate_corpus.py /tmp/corpus 300
python -m rosetta report /tmp/corpus
```

You can also point Rosetta at real public rules — for example, the `example_rules/`
folder from the [Yelp/elastalert](https://github.com/Yelp/elastalert) repository,
or Sigma rules converted to ElastAlert format.

The parser tolerates common YAML malformations (spurious top-level indentation) and
repairs them automatically, reporting the operation on `stderr`.

On a synthetic corpus of 300 rules, ~82 % migrate to ES|QL with a median confidence
around 88 %; behavioral types (spike, flatline, change) and custom Python code are
correctly isolated with low confidence.

## Known limitations

- `query_string` Lucene query conversion is best-effort (booleans, `field:value`,
  lists, wildcards → `LIKE`). Complex queries are flagged for manual review.
- `spike` does not reproduce the current-window / reference-window comparison;
  consider an ML rule instead.
- `flatline` detects absence; a Threshold rule detects a count exceeding a value —
  the logic must be inverted and validated manually.
- The `priority` → `severity` / `risk_score` mapping is heuristic.

## Architecture

```
src/rosetta/
├── parser/elastalert.py           # YAML ElastAlert → normalized model
├── scripts.py                     # custom script / code detection
├── esql/translator.py             # DSL/Lucene filters → ES|QL WHERE & KQL
├── converters/registry.py         # one converter per ElastAlert type
├── scoring/confidence.py          # explainable confidence score
├── detection_rule/toml_writer.py  # model → detection-rules TOML
└── __main__.py                    # CLI (convert / report / share)
```

## License

Apache-2.0 for the tool. Generated rules carry `Elastic License v2`
(configurable in `toml_writer.py`).
