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

| ElastAlert type      | Elastic strategy         | Typical confidence |
|----------------------|--------------------------|--------------------|
| `any`                | ES\|QL (non-aggregating) | ~90 % |
| `frequency`          | ES\|QL `STATS COUNT()`   | ~88 % |
| `blacklist`/`whitelist` | ES\|QL `IN` / `NOT IN` | ~90 % |
| `cardinality`        | ES\|QL `COUNT_DISTINCT()`| ~90 % |
| `metric_aggregation` | ES\|QL `AVG/SUM/MIN/MAX` | ~85 % |
| `new_term`           | New Terms rule (native)  | ~90 % |
| `percentage_match`   | ES\|QL ratio via `EVAL`  | ~55 % |
| `change`             | ES\|QL `COUNT_DISTINCT`  | ~45 % |
| `flatline`           | Threshold rule (native)  | ~45 % |
| `spike`              | ES\|QL approx. / ML      | ~30 % |
| *(unknown)*          | `manual` (review required) | ~10 % |

Behavioral types (`spike`, `flatline`, `change`) have no strict semantic equivalent.
Rosetta produces an approximation, lowers the confidence score, and adds an explicit
warning in the rule's `note` field.

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
python -m rosetta report /path/to/elastalert_rules --json   # machine-readable output
```

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
when reporting a conversion issue), use the `share` command. It produces a JSON
report designed for debugging — **no business data is included**:

```bash
python -m rosetta share /path/to/your/rules -o shared_report.json
```

For each rule the report contains: the source type, the Elastic strategy, the score
and its factors, **categories** of warnings, the **shape** of filters
(term/terms/range/lucene + arity), the **skeleton** of the ES|QL query (command
sequence, functions, operators — no identifiers or values), and an HMAC fingerprint
to reference a rule without naming it.

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
