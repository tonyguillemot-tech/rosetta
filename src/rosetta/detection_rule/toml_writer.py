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
import re
import uuid

from ..esql.translator import filter_to_kql
from ..models import ConversionResult, RuleStrategy
from ..scoring.confidence import confidence_band


_CONTROL_ESCAPES = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t",
                     "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _toml_escape_multiline(text: str) -> str:
    """Échappe une chaîne pour une TOML multi-line basic string (\"\"\"...\"\"\").

    Les retours à la ligne réels restent tels quels (c'est la sémantique
    voulue d'une chaîne multi-ligne : description/query/note en ont besoin).
    En revanche il faut échapper :
    - le backslash : sinon toute donnée contenant un backslash littéral (ex:
      chemin Windows 'C:\\Users\\...', très courant dans les valeurs de règles
      de sécurité EDR) produit un TOML invalide ('Unescaped backslash').
    - toute série de 3+ guillemets consécutifs : romprait le délimiteur
      fermant sinon.
    - tout caractère de contrôle autre que '\\n'/'\\t' (notamment '\\r' isolé,
      hors CRLF) : illégal tel quel même dans une chaîne multi-ligne TOML.
    Le backslash doit être échappé EN PREMIER, avant les guillemets, sinon on
    ré-échapperait les '\\\"' qu'on vient d'insérer.
    """
    text = text.replace("\\", "\\\\")
    text = re.sub(r'"{3,}', lambda m: '\\"' * len(m.group(0)), text)
    out = []
    for ch in text:
        if ch in ("\n", "\t"):
            out.append(ch)
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def _toml_basic_string(text: str) -> str:
    """Échappe une chaîne pour un littéral TOML basique MONO-LIGNE entre
    guillemets (contrairement à _toml_escape_multiline, ici tout caractère de
    contrôle — y compris un retour à la ligne réel — est illégal tel quel et
    doit être échappé)."""
    out = []
    for ch in text:
        esc = _CONTROL_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def _toml_string_array(items: list[str]) -> str:
    """Sérialise une liste de chaînes en tableau TOML, avec échappement
    correct de CHAQUE élément. Ne jamais utiliser repr()+replace(\"'\", '\"')
    pour ça : ça casse dès qu'une valeur contient une apostrophe (le
    délimiteur choisi par repr() varie selon le contenu, et le replace
    aveugle corrompt alors le caractère à l'intérieur de la valeur, pas
    seulement le délimiteur — ex: repr([\"logs-o'brien-*\"]) donne déjà des
    guillemets doubles, et le replace transforme l'apostrophe interne en
    guillemet parasite)."""
    return "[" + ", ".join(f'"{_toml_basic_string(str(i))}"' for i in items) + "]"


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
    lines.append(f'author = {_toml_string_array([author])}')
    lines.append('description = """')
    lines.append(_toml_escape_multiline(description))
    lines.append('"""')
    lines.append(f'name = "{_toml_basic_string(rule.name)}"')
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
        lines.append(_toml_escape_multiline(result.esql_query or ""))
        lines.append('"""')
    elif strat == RuleStrategy.QUERY:
        lines.append('type = "query"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_toml_string_array(_indices_list(rule.index))}")
        lines.append(f'query = "{_toml_basic_string(result.kql_query or "*:*")}"')
    elif strat == RuleStrategy.EQL:
        lines.append('type = "eql"')
        lines.append('language = "eql"')
        lines.append(f"index = {_toml_string_array(_indices_list(rule.index))}")
        lines.append('query = """')
        lines.append(_toml_escape_multiline(result.esql_query or ""))
        lines.append('"""')
    elif strat == RuleStrategy.THRESHOLD:
        lines.append('type = "threshold"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_toml_string_array(_indices_list(rule.index))}")
        lines.append(f'query = "{_toml_basic_string(result.kql_query or "*:*")}"')
        th = result.threshold or {}
        subtables.append("")
        subtables.append("[rule.threshold]")
        subtables.append(f"field = {_toml_string_array(th.get('field', []))}")
        subtables.append(f"value = {th.get('value', 1)}")
        card = th.get("cardinality")
        if card:
            subtables.append("")
            subtables.append("[[rule.threshold.cardinality]]")
            subtables.append(f'field = "{_toml_basic_string(card["field"])}"')
            subtables.append(f"value = {card['value']}")
    elif strat == RuleStrategy.THREAT_MATCH:
        # Grosse liste IOC (> seuil, cf. registry.py) : plus de fallback
        # ES|QL du tout, indicator_match est LE fichier livré. Reste
        # enabled=false tant que threat_index n'est pas peuplé — mais
        # contrairement au job ML, pas de période d'apprentissage : les
        # commandes de peuplement (note ci-dessous) sont immédiatement
        # exécutables avec les valeurs exactes de la liste ElastAlert.
        im_plan = result.metadata.get("indicator_match_plan")
        lines.append('type = "threat_match"')
        lines.append(f"index = {_toml_string_array(_indices_list(rule.index))}")
        lines.append('language = "kuery"')
        im_warnings: list[str] = []
        event_query = filter_to_kql(rule.filters, im_warnings) if rule.filters else "*:*"
        lines.append(f'query = "{_toml_basic_string(event_query)}"')
        if im_plan is not None:
            lines.append(f"threat_index = {_toml_string_array([im_plan.threat_index])}")
        lines.append('threat_indicator_path = "threat.indicator"')
        lines.append('threat_language = "kuery"')
        lines.append('threat_query = "*:*"')
        lines.append('enabled = false')
        if im_plan is not None:
            subtables.append("")
            subtables.append("[[rule.threat_mapping]]")
            subtables.append("")
            subtables.append("[[rule.threat_mapping.entries]]")
            subtables.append(f'field = "{_toml_basic_string(im_plan.compare_key)}"')
            subtables.append('type = "mapping"')
            subtables.append('value = "threat.indicator.value"')
    elif strat == RuleStrategy.NEW_TERMS:
        lines.append('type = "new_terms"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_toml_string_array(_indices_list(rule.index))}")
        lines.append(f'query = "{_toml_basic_string(result.kql_query or "*:*")}"')
        subtables.append("")
        subtables.append("[rule.new_terms]")
        subtables.append('field = "new_terms_fields"')
        subtables.append(f"value = {_toml_string_array(result.new_terms_fields or [])}")
        subtables.append("")
        subtables.append("[[rule.new_terms.history_window_start]]")
        subtables.append('field = "history_window_start"')
        subtables.append(f'value = "{result.history_window or "now-14d"}"')
    else:  # MANUAL
        lines.append('type = "query"')
        lines.append('language = "kuery"')
        lines.append(f"index = {_toml_string_array(_indices_list(rule.index))}")
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

    # Section dédiée : indicateur de recoupement prebuilt Elastic — appel
    # réseau LIVE fait à l'exécution (--check-prebuilt), jamais un instantané
    # embarqué. Piste à vérifier manuellement, jamais une correspondance
    # confirmée (cf. prebuilt_match.py pour le détail de la méthode).
    prebuilt = result.metadata.get("prebuilt_hint")
    if prebuilt:
        note_lines.append("")
        note_lines.append("### Prebuilt Elastic potentiellement pertinents (piste, pas une certitude)")
        note_lines.append(
            "Rosetta fait le retrieval (comme la recherche sémantique côté "
            "Elastic Automatic Migration), pas le jugement final ('identique "
            "ou très proche', qu'eux confient à un LLM) — à vous (ou à un "
            "LLM sollicité séparément) de trancher sur la base du contenu "
            "ci-dessous."
        )
        if prebuilt.get("error"):
            note_lines.append(
                f"Catégorie détectée : `{prebuilt['category']}` — la vérification en direct a "
                f"échoué ({prebuilt['error']}). Vérifiez manuellement : {prebuilt['browse_url']}"
            )
        elif prebuilt.get("candidates"):
            note_lines.append(f"Catégorie détectée : `{prebuilt['category']}`.")
            for c in prebuilt["candidates"]:
                if c.get("description") or c.get("query_excerpt"):
                    note_lines.append(f"- **[{c.get('name', c['filename'])}]({c['url']})**")
                    if c.get("description"):
                        note_lines.append(f"  - Description : {c['description']}")
                    if c.get("query_excerpt"):
                        note_lines.append(f"  - Requête (extrait) : `{c['query_excerpt']}`")
                    if c.get("tags"):
                        note_lines.append(f"  - Tags : {', '.join(c['tags'])}")
                else:
                    # Enrichissement échoué pour ce candidat (bonus best-effort) :
                    # seul le nom de fichier reste disponible.
                    note_lines.append(f"- [{c['filename']}]({c['url']}) (contenu non récupéré)")
        else:
            note_lines.append(
                f"Catégorie détectée : `{prebuilt['category']}` — aucun nom de fichier "
                f"ne recoupe cette règle, mais parcourez quand même : {prebuilt['browse_url']}"
            )

    # Section dédiée : actions custom à recréer côté Elastic
    custom_actions = result.metadata.get("custom_actions")
    if custom_actions:
        note_lines.append("")
        note_lines.append("### Actions custom à recréer (connectors Elastic)")
        for a in custom_actions:
            note_lines.append(f"- `{a['category']}` : `{a['reference']}`")

    # Section dédiée : match_enhancements Python — pas des connectors à
    # recréer, mais du code qui s'exécute AVANT que le match soit finalisé
    # et qui peut donc contenir de la logique de détection cachée.
    enhancements = result.metadata.get("enhancements")
    if enhancements:
        note_lines.append("")
        note_lines.append("### Enrichissements Python à examiner")
        note_lines.append(
            "Ce code s'exécute avant l'alerte et peut modifier ou filtrer le "
            "match — il peut contenir de la logique de détection cachée, pas "
            "seulement de l'enrichissement cosmétique. À porter manuellement, "
            "par ex. via ES|QL `ENRICH` (policy) si c'est un lookup, ou une "
            "règle de suppression/pré-filtre sinon."
        )
        for e in enhancements:
            note_lines.append(f"- `{e['reference']}`")

    # Section dédiée : job ML optionnel, plus fidèle que l'approximation ES|QL
    # pour les types comportementaux (spike, ...). Voir ml_job.py : ce job doit
    # être créé manuellement (une fois) via ces commandes, Rosetta ne peut pas
    # le provisionner depuis un simple fichier TOML.
    ml_job_commands = result.metadata.get("ml_job_commands")
    if ml_job_commands:
        migration_score = result.metadata.get("migration_score")
        note_lines.append("")
        note_lines.append(
            "### Job Machine Learning associé (recommandé, plus fidèle que "
            "l'approximation ES|QL)"
        )
        if migration_score is not None:
            note_lines.append(
                f"Score de migration ML : **{migration_score:.0%}** "
                f"(vs. {result.confidence:.0%} pour la règle ES|QL ci-dessus)."
            )
        note_lines.append(
            "**Marche à suivre (dans l'ordre)** :\n"
            "1. Exécuter les commandes ci-dessous dans Kibana Dev Tools pour créer "
            f"le job `{result.metadata.get('ml_job_id', '')}` et son datafeed.\n"
            "2. Attendre une période d'apprentissage (plusieurs cycles de "
            "bucket_span) avant que les scores d'anomalie soient fiables — garder "
            "la règle ES|QL ci-dessus active pendant ce temps.\n"
            "3. Importer le fichier compagnon "
            "`<nom_du_fichier>_ml_job.toml` (généré à côté de celui-ci) : le "
            "`machine_learning_job_id` y est déjà prérempli avec l'ID exact du "
            "job créé à l'étape 1.\n"
            "4. Vérifier les scores produits, ajuster `anomaly_threshold` si besoin, "
            "puis activer cette règle et désactiver l'approximation ES|QL."
        )
        note_lines.append("```")
        note_lines.extend(ml_job_commands.splitlines())
        note_lines.append("```")
        for n in result.metadata.get("ml_job_notes", []):
            note_lines.append(f"- ⚠ {n}")

    # Section dédiée : détection heuristique d'IOC sur blacklist/whitelist.
    # Deux cas très différents selon la stratégie livrée :
    #  - strat == THREAT_MATCH (grosse liste) : c'est LE fichier livré, il faut
    #    peupler threat_index AVANT toute détection (rien ne fonctionne sans).
    #  - strat == ESQL (petite liste) : la règle IN(...) livrée est déjà
    #    pleinement fonctionnelle, ceci n'est qu'une recommandation
    #    architecturale à côté, pas un correctif.
    im_plan = result.metadata.get("indicator_match_plan")
    if im_plan is not None:
        migration_score = result.metadata.get("migration_score")
        note_lines.append("")
        if strat == RuleStrategy.THREAT_MATCH:
            note_lines.append(
                "## ⚠ NE PAS ACTIVER tant que threat_index n'est pas peuplé"
            )
            note_lines.append(
                f"Liste `{rule.rule_type}` de {len(im_plan.values)} entrées — trop "
                "volumineuse pour un IN(...) ES|QL en dur (chaque mise à jour de la "
                "liste obligerait à régénérer/redéployer toute la règle) : "
                f"`indicator_match` (champ `{im_plan.compare_key}`, type d'IOC "
                f"détecté par heuristique : **{im_plan.ioc_type}**) est livré "
                "directement comme règle principale, pas comme option à côté."
            )
            if migration_score is not None:
                note_lines.append(f"Score de fidélité du mapping : **{migration_score:.0%}**.")
            note_lines.append(
                "**Marche à suivre (rien ne fonctionne avant l'étape 1)** :\n"
                f"1. Exécuter les commandes ci-dessous pour créer et peupler l'index "
                f"threat intel `{im_plan.threat_index}` avec les valeurs exactes de "
                "la liste ElastAlert (pas de période d'apprentissage requise, "
                "contrairement à un job ML).\n"
                "2. Vérifier les résultats, ajuster `threat_mapping` si besoin.\n"
                "3. Passer `enabled = true` dans ce fichier."
            )
        else:
            note_lines.append(
                "### Alternative recommandée : Indicator Match (threat_match)"
            )
            note_lines.append(
                f"Champ `{im_plan.compare_key}` détecté comme probable IOC de type "
                f"**{im_plan.ioc_type}** ({len(im_plan.values)} valeur(s)). La règle "
                "ES|QL ci-dessus reste pleinement fidèle et fonctionnelle — ceci est "
                "une recommandation architecturale, pas un correctif."
            )
            if migration_score is not None:
                note_lines.append(f"Score de fidélité du mapping : **{migration_score:.0%}**.")
            note_lines.append(
                "**Marche à suivre** :\n"
                "1. Exécuter les commandes ci-dessous pour créer et peupler l'index "
                f"threat intel `{im_plan.threat_index}` avec les valeurs exactes de "
                "la liste ElastAlert (pas de période d'apprentissage requise).\n"
                "2. Importer le fichier compagnon `<nom_du_fichier>_indicator_match.toml` "
                "(généré à côté de celui-ci) : `threat_index`/`threat_mapping` y sont "
                "déjà préremplis.\n"
                "3. Vérifier les résultats, puis désactiver la règle ES|QL ci-dessus "
                "pour éviter les doublons."
            )
        note_lines.append("```")
        note_lines.extend(im_plan.as_console_commands().splitlines())
        note_lines.append("```")
        for n in im_plan.notes:
            note_lines.append(f"- ⚠ {n}")

    lines.append("")
    lines.append('note = """')
    lines.append(_toml_escape_multiline("\n".join(note_lines)))
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


def to_toml_ml_companion(result: ConversionResult, *,
                          author: str = "Migrated from ElastAlert",
                          min_stack: str = "9.0.0") -> str | None:
    """Génère le fichier TOML compagnon `type = "machine_learning"`, quand un
    job ML pertinent existe (spike/change/flatline — voir ml_job.py). Le
    machine_learning_job_id est déjà prérempli avec l'ID EXACT que produisent
    les commandes de la note de la règle principale : rien à deviner, il faut
    seulement avoir réellement créé et entraîné ce job avant d'importer ce
    fichier — d'où `enabled = false` et l'avertissement en tête de note.

    Renvoie None si aucun job ML n'est pertinent pour cette règle.
    """
    job_id = result.metadata.get("ml_job_id")
    if not job_id:
        return None

    rule = result.source
    rule_id = str(uuid.uuid4())
    today = dt.date.today().strftime("%Y/%m/%d")
    risk, severity = _risk_and_severity(rule.raw)
    threshold = result.metadata.get("ml_anomaly_threshold", 75)
    migration_score = result.metadata.get("migration_score")
    name = f"{rule.name} (ML anomaly detection)"

    lines: list[str] = []
    lines.append("[metadata]")
    lines.append(f'creation_date = "{today}"')
    lines.append(f'updated_date = "{today}"')
    lines.append('maturity = "development"')
    lines.append(f'min_stack_version = "{min_stack}"')
    lines.append(
        'min_stack_comments = "Compagnon ML d\'une règle migrée ElastAlert — '
        'ne pas activer avant d\'avoir créé et entraîné le job (voir la règle '
        'principale)."'
    )
    lines.append("")
    lines.append("[rule]")
    lines.append(f'author = {_toml_string_array([author])}')
    lines.append('description = """')
    desc = (
        f"Job Machine Learning compagnon de la règle migrée « {rule.name} » "
        f"(type ElastAlert d'origine : {rule.rule_type}). Plus fidèle que "
        "l'approximation ES|QL de la règle principale, mais nécessite le job "
        "ci-dessous créé et entraîné avant activation."
    )
    lines.append(_toml_escape_multiline(desc))
    lines.append('"""')
    lines.append(f'name = "{_toml_basic_string(name)}"')
    lines.append(f'rule_id = "{rule_id}"')
    lines.append('license = "Elastic License v2"')
    lines.append(f'risk_score = {risk}')
    lines.append(f'severity = "{severity}"')
    lines.append('from = "now-16m"')
    lines.append('interval = "15m"')
    lines.append('type = "machine_learning"')
    lines.append(f'machine_learning_job_id = {_toml_string_array([job_id])}')
    lines.append(f'anomaly_threshold = {threshold}')
    lines.append('enabled = false')

    note_lines = [
        "## ⚠ NE PAS ACTIVER tant que le job ML n'est pas créé et entraîné",
        f"- Job requis : `{job_id}` — commandes de création dans la note de la "
        "règle ES|QL migrée correspondante.",
        f"- `anomaly_threshold = {threshold}` : valeur par défaut Kibana, à "
        "ajuster après une période d'observation.",
    ]
    if migration_score is not None:
        note_lines.append(
            f"- Score de fidélité du mapping ML : **{migration_score:.0%}** "
            "— voir la note de la règle ES|QL pour le détail des écarts "
            "documentés (ex: spike_height sans équivalent direct)."
        )
    note_lines.append(
        "- Une fois activée, désactiver la règle ES|QL correspondante pour "
        "éviter les doublons d'alerte."
    )
    lines.append("")
    lines.append('note = """')
    lines.append(_toml_escape_multiline("\n".join(note_lines)))
    lines.append('"""')

    lines.append("")
    tags = ['"Migrated: ElastAlert"', '"Type: ML companion — do not enable yet"',
            f'"Source Type: {rule.rule_type}"']
    lines.append(f"tags = [{', '.join(tags)}]")

    return "\n".join(lines) + "\n"


def to_toml_indicator_match_companion(result: ConversionResult, *,
                                       author: str = "Migrated from ElastAlert",
                                       min_stack: str = "9.0.0") -> str | None:
    """Génère le fichier TOML compagnon `type = "threat_match"` (nom UI :
    indicator_match), quand une liste blacklist/whitelist a été détectée
    comme probable IOC (voir indicator_match.py). threat_index/threat_mapping
    sont déjà préremplis avec les valeurs exactes de la liste ElastAlert —
    contrairement au job ML, pas de période d'apprentissage : la règle
    fonctionne dès que l'index (commandes dans la note de la règle ES|QL
    principale) est peuplé. `enabled = false` en attendant.

    Renvoie None si aucune détection IOC n'est pertinente pour cette règle.
    """
    plan = result.metadata.get("indicator_match_plan")
    if plan is None:
        return None

    rule = result.source
    rule_id = str(uuid.uuid4())
    today = dt.date.today().strftime("%Y/%m/%d")
    risk, severity = _risk_and_severity(rule.raw)
    migration_score = result.metadata.get("migration_score")
    name = f"{rule.name} (Indicator Match)"

    lines: list[str] = []
    lines.append("[metadata]")
    lines.append(f'creation_date = "{today}"')
    lines.append(f'updated_date = "{today}"')
    lines.append('maturity = "development"')
    lines.append(f'min_stack_version = "{min_stack}"')
    lines.append(
        'min_stack_comments = "Compagnon indicator_match d\'une règle migrée '
        'ElastAlert — ne pas activer avant d\'avoir peuplé threat_index (voir '
        'la règle principale)."'
    )
    lines.append("")
    lines.append("[rule]")
    lines.append(f'author = {_toml_string_array([author])}')
    lines.append('description = """')
    desc = (
        f"Règle Indicator Match compagnon de la règle migrée « {rule.name} » "
        f"(liste {rule.rule_type} d'origine). IOC de type '{plan.ioc_type}' "
        f"détecté sur le champ '{plan.compare_key}'. Nécessite threat_index "
        "peuplé avant activation (voir la note de la règle ES|QL correspondante)."
    )
    lines.append(_toml_escape_multiline(desc))
    lines.append('"""')
    lines.append(f'name = "{_toml_basic_string(name)}"')
    lines.append(f'rule_id = "{rule_id}"')
    lines.append('license = "Elastic License v2"')
    lines.append(f'risk_score = {risk}')
    lines.append(f'severity = "{severity}"')
    lines.append('from = "now-6m"')
    lines.append('interval = "5m"')
    lines.append('type = "threat_match"')
    lines.append(f"index = {_toml_string_array(_indices_list(rule.index))}")
    lines.append('language = "kuery"')
    # Réutilise les AUTRES filtres de la règle d'origine (au-delà du seul
    # compare_key, qui migre vers threat_mapping) — un exemple réel du dépôt
    # elastic/detection-rules montre que 'query' doit scoper les événements
    # comparés (ex: event.category:"network"), pas juste '*:*' qui comparerait
    # TOUS les événements à l'index threat intel, bien trop large.
    im_warnings: list[str] = []
    event_query = filter_to_kql(rule.filters, im_warnings) if rule.filters else "*:*"
    lines.append(f'query = "{_toml_basic_string(event_query)}"')
    lines.append(f"threat_index = {_toml_string_array([plan.threat_index])}")
    lines.append('threat_indicator_path = "threat.indicator"')
    lines.append('threat_language = "kuery"')
    lines.append('threat_query = "*:*"')
    lines.append('enabled = false')

    note_lines = [
        "## ⚠ NE PAS ACTIVER tant que threat_index n'est pas peuplé",
        f"- Index requis : `{plan.threat_index}` — commandes de création/peuplement "
        "dans la note de la règle ES|QL migrée correspondante.",
        f"- Type d'IOC détecté par heuristique : **{plan.ioc_type}** — à vérifier, "
        "pas une certitude.",
    ]
    if migration_score is not None:
        note_lines.append(f"- Score de fidélité du mapping : **{migration_score:.0%}**.")
    note_lines.append(
        "- Une fois activée, désactiver la règle ES|QL correspondante pour "
        "éviter les doublons d'alerte."
    )
    lines.append("")
    lines.append('note = """')
    lines.append(_toml_escape_multiline("\n".join(note_lines)))
    lines.append('"""')

    lines.append("")
    tags = ['"Migrated: ElastAlert"',
            '"Type: Indicator Match companion — do not enable yet"',
            f'"Source Type: {rule.rule_type}"']
    lines.append(f"tags = [{', '.join(tags)}]")

    # Sous-table EN DERNIER (cf. commentaire de to_toml) : toute clé scalaire
    # placée après serait rattachée à [rule.threat_mapping.entries] par erreur.
    lines.append("")
    lines.append("[[rule.threat_mapping]]")
    lines.append("")
    lines.append("[[rule.threat_mapping.entries]]")
    lines.append(f'field = "{_toml_basic_string(plan.compare_key)}"')
    lines.append('type = "mapping"')
    lines.append('value = "threat.indicator.value"')

    return "\n".join(lines) + "\n"
