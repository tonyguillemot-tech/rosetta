"""Chargement et normalisation des règles ElastAlert depuis des fichiers YAML."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

from ..models import ElastAlertRule
from ..scripts import analyze as analyze_scripts


def _extract_index(raw: dict[str, Any]) -> str:
    idx = raw.get("index", "")
    # ElastAlert autorise un index ou une liste
    if isinstance(idx, list):
        return ",".join(idx)
    return str(idx)


def _extract_filters(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Renvoie la liste de filtres ElastAlert (filter:) telle quelle."""
    flt = raw.get("filter", [])
    if isinstance(flt, dict):
        return [flt]
    if isinstance(flt, list):
        return flt
    return []


def parse_rule_dict(raw: dict[str, Any], source_file: str | None = None) -> ElastAlertRule:
    if "type" not in raw:
        raise ValueError("Règle ElastAlert invalide : champ 'type' manquant")
    if "name" not in raw:
        raise ValueError("Règle ElastAlert invalide : champ 'name' manquant")
    return ElastAlertRule(
        name=str(raw["name"]),
        rule_type=str(raw["type"]),
        index=_extract_index(raw),
        raw=raw,
        filters=_extract_filters(raw),
        source_file=source_file,
        script_analysis=analyze_scripts(raw),
    )


def _load_yaml_lenient(text: str, path: Path):
    """Charge du YAML en tolérant une indentation parasite de premier niveau.

    Certaines règles publiques (ex. Yelp/elastalert ssh.yaml) ont des clés de
    premier niveau indentées de quelques espaces, ce qui casse le parsing
    strict. On tente d'abord un chargement normal, puis une récupération en
    désindentant les lignes de premier niveau si nécessaire.
    """
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        pass

    # Récupération : retirer une indentation parasite homogène sur les clés
    # de premier niveau (lignes "  key:" alors que d'autres sont à la colonne 0).
    fixed_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip(" ")
        # Ligne de commentaire ou vide : conservée telle quelle
        if not stripped or stripped.startswith("#"):
            fixed_lines.append(line)
            continue
        indent = len(line) - len(stripped)
        # Désindente seulement les clés top-level mal indentées (1-3 espaces)
        # qui ressemblent à "clef:" ou "clef: valeur" et ne font pas partie
        # d'une liste (pas de '- ' devant).
        if 0 < indent <= 3 and ":" in stripped and not stripped.startswith("- "):
            fixed_lines.append(stripped)
        else:
            fixed_lines.append(line)
    repaired = "\n".join(fixed_lines)
    result = yaml.safe_load(repaired)  # peut encore lever : on laisse remonter
    print(f"[INFO] {path.name} : YAML réparé (indentation parasite corrigée).", file=sys.stderr)
    return result


def parse_file(path: str | Path) -> ElastAlertRule:
    path = Path(path)
    raw = _load_yaml_lenient(path.read_text(encoding="utf-8"), path)
    if not isinstance(raw, dict):
        raise ValueError(f"{path} ne contient pas un mapping YAML valide")
    return parse_rule_dict(raw, source_file=str(path))


def parse_directory(directory: str | Path) -> list[ElastAlertRule]:
    directory = Path(directory)
    rules: list[ElastAlertRule] = []
    for ext in ("*.yml", "*.yaml"):
        for path in sorted(directory.rglob(ext)):
            try:
                rules.append(parse_file(path))
            except Exception as exc:  # noqa: BLE001
                # On collecte les erreurs sans interrompre tout le batch
                print(f"[WARN] Impossible de parser {path}: {exc}", file=sys.stderr)
    return rules
