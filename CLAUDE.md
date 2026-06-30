# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Aperçu

Rosetta convertit des règles de détection **ElastAlert** (YAML) en règles **Elastic Security**, en privilégiant **ES|QL**, avec une sortie **TOML** compatible `elastic/detection-rules` (Detection-as-Code). Chaque règle migrée reçoit un **score de confiance explicable**.

## Commandes

```bash
# Installation (éditable, avec les outils de dev)
pip install -e ".[dev]"

# Tests
python -m pytest tests/ -v                                   # toute la suite
python -m pytest tests/test_conversion.py::test_frequency_to_esql  # un seul test
python -m pytest -k sanitize                                 # par mot-clé

# CLI (3 sous-commandes ; package exécutable via python -m rosetta)
python -m rosetta report   examples/elastalert_rules [--json]
python -m rosetta convert  examples/elastalert_rules -o rules/ [--min-confidence 0.6]
python -m rosetta share    /chemin/regles -o rapport.json     # sortie sanitisée

# Corpus de test synthétique (tous les types + cas dégénérés)
python tools/generate_corpus.py /tmp/corpus 300
```

Il n'y a **pas de linter ni de formatter configuré** (pas de ruff/flake8/black dans `pyproject.toml`) ; certains `# noqa` sont présents par anticipation mais aucune commande de lint n'est attendue en CI. La CI (`.github/workflows/ci.yml`) lance pytest, génère les TOML depuis `examples/`, vérifie leur parsabilité, puis les valide via la CLI officielle `detection_rules view-rule`.

## Architecture

Le cœur est un **pipeline à quatre étapes** orchestré dans [src/rosetta/__main__.py](src/rosetta/__main__.py) (`_process`) :

```
parse → convert → score → (to_toml | sanitize)
```

1. **parse** ([parser/elastalert.py](src/rosetta/parser/elastalert.py)) — YAML → `ElastAlertRule` normalisée. Tolère certaines malformations (indentation parasite de premier niveau) et répare en signalant sur `stderr`. Appelle `scripts.analyze()` et stocke le résultat dans `rule.script_analysis`.
2. **convert** ([converters/registry.py](src/rosetta/converters/registry.py)) — `ElastAlertRule` → `ConversionResult`. Le dict `CONVERTERS` mappe chaque `type` ElastAlert vers une fonction `convert_*`. La fonction `convert()` court-circuite vers la stratégie `manual` si la **détection** est en code custom, sinon délègue au converter et propage les findings d'**action** custom.
3. **score** ([scoring/confidence.py](src/rosetta/scoring/confidence.py)) — remplit `result.confidence` et `result.factors` à partir de `BASE_BY_TYPE` plus pénalités/bonus concrets. Chaque contribution est un `ConfidenceFactor` (label, delta, detail) → score **traçable**.
4. **sortie** — [detection_rule/toml_writer.py](src/rosetta/detection_rule/toml_writer.py) (`to_toml`, schéma `[metadata]`/`[rule]`) ou [sanitize.py](src/rosetta/sanitize.py) (`sanitize_result`) pour la commande `share`.

Modèles partagés dans [models.py](src/rosetta/models.py) : `RuleStrategy` (enum esql/query/eql/threshold/new_terms/manual), `ElastAlertRule`, `ConversionResult`, `ConfidenceFactor`. La traduction des filtres DSL/Lucene → `WHERE` ES|QL et KQL vit dans [esql/translator.py](src/rosetta/esql/translator.py) (`filter_to_esql`, `filter_to_kql`), qui **accumule ses avertissements dans une liste passée par référence** (`res.warnings`).

### Stratégie de conversion

ES|QL est priorisé car il exprime nativement « filtrer → `STATS … BY` → re-filtrer ». Quand ES|QL n'est pas le bon outil, on retombe sur le type natif le plus fidèle (`new_term` → New Terms rule, `flatline` → Threshold rule). Les types comportementaux (`spike`, `flatline`, `change`) n'ont **pas** d'équivalent sémantique strict : le converter produit une approximation, ajoute un warning explicite, et le scorer applique une pénalité `semantic_gap`.

### Détection de code custom ([scripts.py](src/rosetta/scripts.py))

Distinction centrale : un **type** custom (`type: module.file.RuleName`) met la *logique de détection* en code → bloquant (`blocks_detection=True`, stratégie `manual`, règle générée `enabled=false`, confiance ~5 %). Un **alerter/command/enhancement** custom ne touche que l'*action* → la détection migre, l'action est listée dans le champ `note` pour recréation, pénalité modérée. Les alerters intégrés (`BUILTIN_ALERTERS`) ne sont jamais traités comme du code custom.

### Sanitisation « privacy by design » ([sanitize.py](src/rosetta/sanitize.py))

La commande `share` produit un JSON pour débogage **sans aucune donnée métier** : la sortie ne reconstruit que des champs explicitement sûrs (type, stratégie, score+facteurs, *forme* des filtres, *squelette* de la requête ES|QL, empreinte HMAC), donc une donnée non listée ne peut pas fuiter. **Cette garantie est testée** : les tests `test_sanitize_*` vérifient qu'aucune valeur sentinelle (noms, IP, champs, chemins de scripts) n'apparaît dans la sortie. Toute modification de `sanitize.py` doit conserver ces tests verts.

## Ajouter un nouveau type ElastAlert

Modifier de façon cohérente ces points (sinon le type tombe en `manual`/confiance 0.20) :
1. Écrire `convert_<type>` dans [converters/registry.py](src/rosetta/converters/registry.py) et l'enregistrer dans `CONVERTERS`.
2. Ajouter une base dans `BASE_BY_TYPE` et, si besoin, les champs requis dans `_missing_required_fields` ([scoring/confidence.py](src/rosetta/scoring/confidence.py)).
3. Déclarer le type dans `BUILTIN_RULE_TYPES` ([scripts.py](src/rosetta/scripts.py)) pour qu'il ne soit pas pris pour un type custom.
4. Ajouter un cas au test paramétré `test_toml_output_parses` et un test ciblé.

## Conventions

- Python ≥ 3.11, layout `src/`, `from __future__ import annotations` en tête de chaque module, type hints modernes (`list[...]`, `X | None`).
- **Docstrings et commentaires en français** ; suivre ce style.
- Dataclasses pour les structures de données ; les enums de stratégie héritent de `str` pour la sérialisation directe.
- Les warnings de conversion s'accumulent dans `ConversionResult.warnings` ; le scoring les traduit en pénalités — ne pas avaler une situation dégradée silencieusement, ajouter un warning.
- Les converters construisent les requêtes ES|QL par jointure de fragments non vides (`"\n".join(c for c in (...) if c)`).
