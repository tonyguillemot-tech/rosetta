# Rosetta — Migration ElastAlert → Elastic Security

> Traduit fidèlement vos règles de détection d'un langage à l'autre, avec un
> score de confiance pour chaque migration.

Convertit des règles **ElastAlert** (YAML) en règles **Elastic Security**, en
privilégiant **ES|QL**, avec sortie au format **TOML** compatible
[`elastic/detection-rules`](https://github.com/elastic/detection-rules) pour
une approche **Detection-as-Code (DaC)**. Chaque règle migrée reçoit un
**score de confiance**.

## Pourquoi ES|QL en priorité

ES|QL exprime nativement la logique « filtrer → agréger (`STATS … BY`) →
re-filtrer sur la valeur calculée » qui sous-tend la majorité des règles
ElastAlert (frequency, cardinality, metric). Les règles ES|QL sont un type de
règle de détection à part entière dans Elastic Security (`type = "esql"`).
Quand ES|QL n'est pas le bon outil, `rosetta` retombe sur le type natif le plus
fidèle.

## Couverture des types ElastAlert

| Type ElastAlert      | Stratégie Elastic        | Confiance typique |
|----------------------|--------------------------|-------------------|
| `any`                | ES\|QL (non-agrégeante)  | ~90 % |
| `frequency`          | ES\|QL `STATS COUNT()`   | ~88 % |
| `blacklist`/`whitelist` | ES\|QL `IN` / `NOT IN` | ~90 % |
| `cardinality`        | ES\|QL `COUNT_DISTINCT()`| ~90 % |
| `metric_aggregation` | ES\|QL `AVG/SUM/MIN/MAX` | ~85 % |
| `new_term`           | New Terms rule (native)  | ~90 % |
| `percentage_match`   | ES\|QL ratio via `EVAL`  | ~55 % |
| `change`             | ES\|QL `COUNT_DISTINCT`  | ~45 % |
| `flatline`           | Threshold rule (native)  | ~45 % |
| `spike`              | ES\|QL approx. / ML       | ~30 % |
| *(inconnu)*          | `manual` (revue requise) | ~10 % |

Les types comportementaux (`spike`, `flatline`, `change`) n'ont **pas**
d'équivalent sémantique strict : `rosetta` produit une approximation, baisse le
score et ajoute un avertissement explicite dans le champ `note` de la règle.

## Scripts et code custom ElastAlert

ElastAlert permet d'injecter du Python ou des scripts externes à plusieurs
endroits. `rosetta` les détecte et ajuste le score selon que c'est la **détection**
ou seulement l'**action** qui est en code :

| Cas ElastAlert | Détecté comme | Impact migration |
|---|---|---|
| `type: module.file.RuleName` (type custom) | `custom_rule_type` | **Bloquant** : la logique de détection est en code → stratégie `manual`, règle générée `enabled = false`, confiance ~5 % |
| `alert: command` + `command: [...]` | `command_alerter` | La détection migre ; le script d'action est listé dans `note` pour recréation via connector. Pénalité modérée |
| `alert: module.file.AlertName` (alerter custom) | `custom_alerter` | Idem command : détection migrée, action à recréer |
| `match_enhancements: [module.file.Enh]` | `enhancement` | Détection migrée, enhancement Python à revoir. Pénalité modérée |

Les alerters intégrés (`email`, `slack`, `jira`, `pagerduty`, …) ne sont **pas**
considérés comme du code custom. Les règles concernées reçoivent des tags
`Review: Custom Action` ou `Review: Custom Detection Code` et une section
dédiée dans leur champ `note`.

## Installation

```bash
pip install -e ".[dev]"
```

## Utilisation

Rapport de confiance (sans écriture) :

```bash
python -m rosetta report examples/elastalert_rules
python -m rosetta report examples/elastalert_rules --json   # pour l'automatisation
```

Génération des fichiers TOML :

```bash
# Tout convertir
python -m rosetta convert examples/elastalert_rules -o rules/

# N'écrire que les règles au-dessus d'un seuil de confiance
python -m rosetta convert examples/elastalert_rules -o rules/ --min-confidence 0.6
```

## Collaboration sans partage de données sensibles

Si tu améliores l'outil avec un client qui ne peut pas transmettre ses règles
(confidentielles), il utilise la commande `share`. Elle produit un JSON conçu
pour le débogage de l'outil, **sans aucune donnée métier** :

```bash
# Côté client (sur ses règles confidentielles)
python -m rosetta share /ses/regles/ -o rapport_partage.json
```

Le client garde tout son détail en local. Le fichier `rapport_partage.json`
qu'il t'envoie contient, par règle : le type source, la stratégie Elastic, le
score et ses facteurs, les **catégories** d'avertissements, la **forme** des
filtres (term/terms/range/lucene + arité), le **squelette** de la requête ES|QL
(séquence des commandes, fonctions, opérateurs — sans identifiants ni valeurs),
et une empreinte HMAC pour référencer une règle sans la nommer.

Ce qui **ne sort jamais** : noms et descriptions de règles, noms de champs et
d'index, valeurs des filtres (IP, utilisateurs, hosts, hashes), seuils métier,
chemins de scripts, requêtes en clair. Le principe est « privacy by design » :
la sortie ne reconstruit que des champs explicitement sûrs, donc une donnée
non listée ne peut pas fuiter. Cinq tests automatisés (`test_sanitize_*`)
vérifient l'absence de fuite à chaque exécution de la suite.

Pour des empreintes stables entre deux envois (suivre une règle précise dans
le temps), le client fixe un secret partagé :

```bash
export ROSETTA_HMAC_SECRET="un-secret-convenu-entre-vous"
python -m rosetta share /ses/regles/ -o rapport_partage.json
```

Avec ce JSON, tu peux reproduire un cas (recréer une règle ayant la même forme),
comprendre pourquoi un score est bas, et corriger un bug de génération — le tout
sans jamais voir les données du client.

## Éprouver l'outil (corpus de test)

Pour tester sur un grand volume, un générateur produit des règles ElastAlert
variées (tous les types, filtres de complexité diverse, cas de scripts, et
quelques cas dégénérés) :

```bash
python tools/generate_corpus.py /tmp/corpus 300
python -m rosetta report /tmp/corpus
```

Tu peux aussi pointer l'outil vers de vraies règles publiques, par exemple le
dossier `example_rules/` du dépôt [Yelp/elastalert](https://github.com/Yelp/elastalert)
ou des règles Sigma converties au format ElastAlert. Le parser tolère certaines
malformations YAML courantes (indentation parasite de premier niveau) et
répare automatiquement quand c'est possible, en signalant l'opération sur
`stderr`.

Sur un corpus synthétique de 300 règles, ~82 % migrent en ES|QL, avec une
confiance médiane autour de 88 % ; les types comportementaux (spike, flatline,
change) et le code Python custom sont correctement isolés en confiance faible.

## Score de confiance

Le score combine une base par type (sémantique reproductible ou non) puis des
pénalités/bonus concrets : avertissements de traduction de filtres, requêtes
Lucene/`query_string` (converties en best-effort), champs requis manquants,
écart sémantique des règles temporelles, et bon mappage de `query_key` sur
`STATS … BY`. Bandes : **ÉLEVÉE** (≥85 %), **MOYENNE** (≥60 %), **FAIBLE**
(≥30 %), **TRÈS FAIBLE** (<30 %).

Une règle est marquée *à revoir* si elle est `manual` ou sous 60 %.

## Intégration detection-rules (DaC)

Les TOML produits suivent le schéma `[metadata]` / `[rule]` attendu par
`elastic/detection-rules`. Pour les valider et les déployer :

```bash
# Validation de schéma locale
python -m detection_rules view-rule rules/ma_regle.toml

# Import dans Kibana (custom rules)
python -m detection_rules kibana import-rules -d rules/ --overwrite
```

Place les fichiers dans ton dossier `CUSTOM_RULES_DIR` configuré, puis utilise
les commandes `kibana import-rules` / `export-rules` pour synchroniser avec
Elastic Security.

## CI GitHub Actions

`.github/workflows/ci.yml` exécute :
1. **unit-tests** — pytest + génération TOML + vérification de parsabilité ;
2. **detection-rules-validation** — validation de chaque règle via la CLI
   officielle Elastic ;
3. **esql-live-validation** — placeholder pour la validation ES|QL contre une
   stack éphémère (Elastic Container Project), à activer avec des secrets de
   cluster.

## Architecture

```
src/rosetta/
├── parser/elastalert.py       # YAML ElastAlert -> modèle normalisé
├── scripts.py                 # détection des scripts / code custom
├── esql/translator.py         # filtres DSL/Lucene -> WHERE ES|QL & KQL
├── converters/registry.py     # 1 converter par type ElastAlert
├── scoring/confidence.py      # score de confiance explicable
├── detection_rule/toml_writer.py  # modèle -> TOML detection-rules
└── __main__.py                # CLI (convert / report)
```

## Limites connues

- La conversion des requêtes `query_string` Lucene est best-effort (booléens,
  `field:value`, listes, wildcards → `LIKE`). Les requêtes très complexes sont
  signalées pour revue manuelle.
- `spike` ne reproduit pas la comparaison fenêtre courante/référence ;
  envisager une règle ML.
- `flatline` détecte une absence ; une Threshold rule détecte un dépassement —
  la logique doit être inversée et validée manuellement.
- Le mapping `priority` ElastAlert → `severity`/`risk_score` est heuristique.

## Licence

Apache-2.0 pour l'outil. Les règles générées portent `Elastic License v2`
(modifiable dans `toml_writer.py`).
