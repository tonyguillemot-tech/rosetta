"""Sanitisation : produit une sortie partageable d'un ConversionResult sans
aucune donnée métier confidentielle.

Principe « privacy by design » : on ne copie PAS le détail puis on nettoie ;
on (re)construit uniquement des champs sûrs. Tout ce qui n'est pas explicitement
listé comme sûr n'est jamais émis.

Ce qui SORT (utile pour améliorer le code) :
  - type source, stratégie Elastic
  - score et facteurs de confiance (labels + deltas, pas le detail libre)
  - catégories d'avertissements (normalisées, pas le texte brut)
  - forme des filtres (term/terms/range/lucene + arité, pas les champs/valeurs)
  - squelette de la requête générée (opérations ES|QL, pas les identifiants)
  - empreinte HMAC stable de la règle (pour en parler sans la nommer)

Ce qui NE SORT JAMAIS :
  - noms/descriptions de règles, noms de champs/index réels
  - valeurs des filtres (IP, users, hosts, hashes...)
  - chemins de scripts, requêtes en clair, commandes
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from .models import ConversionResult

# Version du schéma de sortie sanitisée (pour que les deux côtés s'accordent).
SANITIZED_SCHEMA_VERSION = "1.0"

# Catégories d'avertissements normalisées : on mappe le texte libre vers un
# code stable. Toute nouvelle formulation tombe dans "other".
_WARNING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("lucene_partial", re.compile(r"lucene", re.I)),
    ("spike_approx", re.compile(r"spike", re.I)),
    ("flatline_inversion", re.compile(r"flatline", re.I)),
    ("change_approx", re.compile(r"\bchange\b|valeur distincte", re.I)),
    ("percentage_match", re.compile(r"percentage|match_bucket", re.I)),
    ("custom_detection_code", re.compile(r"détection.*code|logique de détection", re.I)),
    ("command_alerter", re.compile(r"command.*script|alerter 'command'", re.I)),
    ("custom_alerter", re.compile(r"alerter python|connector", re.I)),
    ("enhancement", re.compile(r"enhancement", re.I)),
    ("missing_field", re.compile(r"manquant|absente?", re.I)),
    ("unsupported_type", re.compile(r"non support|migration manuelle", re.I)),
]


def _classify_warning(text: str) -> str:
    for code, pat in _WARNING_PATTERNS:
        if pat.search(text):
            return code
    return "other"


def _rule_fingerprint(result: ConversionResult, secret: bytes) -> str:
    """Empreinte HMAC stable d'une règle, sans révéler son nom.

    Utilise le nom + le fichier source comme entrée, mais ne renvoie que le
    digest tronqué : irréversible côté destinataire.
    """
    src = result.source
    base = f"{src.name}|{src.source_file or ''}".encode("utf-8")
    return hmac.new(secret, base, hashlib.sha256).hexdigest()[:12]


# --- Squelette de requête ES|QL --------------------------------------------

# On garde uniquement les commandes/opérateurs ES|QL, jamais les identifiants.
_ESQL_COMMANDS = ["FROM", "WHERE", "STATS", "EVAL", "KEEP", "SORT", "LIMIT",
                  "DROP", "RENAME", "DISSECT", "GROK", "ENRICH", "MV_EXPAND"]
_ESQL_FUNCS = ["COUNT", "COUNT_DISTINCT", "AVG", "SUM", "MIN", "MAX", "CASE",
               "DATE_TRUNC", "DATE_DIFF", "COALESCE", "VALUES"]
_ESQL_OPS = ["==", "!=", ">=", "<=", ">", "<", "IN", "NOT IN", "LIKE",
             "IS NOT NULL", "IS NULL", "AND", "OR", "NOT"]


def _esql_skeleton(query: str | None) -> dict[str, Any] | None:
    """Extrait la structure d'une requête ES|QL sans aucun identifiant/valeur.

    Renvoie la séquence des commandes par pipe, les fonctions et opérateurs
    utilisés, et des compteurs — utile pour repérer un bug de génération.
    """
    if not query:
        return None
    # Découpe par pipe en gardant l'ordre des commandes
    stages = []
    for raw_stage in query.replace("\n", " ").split("|"):
        stage = raw_stage.strip()
        if not stage:
            continue
        cmd = stage.split(None, 1)[0].upper()
        stages.append(cmd if cmd in _ESQL_COMMANDS else "UNKNOWN")
    funcs = sorted({f for f in _ESQL_FUNCS if re.search(rf"\b{f}\s*\(", query)})
    ops = sorted({o for o in _ESQL_OPS if o in query})
    return {
        "pipeline": stages,                       # ex: ["FROM","WHERE","STATS","WHERE"]
        "functions": funcs,                       # ex: ["COUNT"]
        "operators": ops,                         # ex: ["==","AND",">="]
        "is_aggregating": "STATS" in stages,
        "stage_count": len(stages),
    }


# --- Forme des filtres source ----------------------------------------------

def _filter_shapes(filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Décrit la FORME de chaque filtre ElastAlert sans champs ni valeurs."""
    shapes: list[dict[str, Any]] = []
    for flt in filters:
        for key, body in flt.items():
            shape: dict[str, Any] = {"kind": key}
            if key in ("query", "query_string"):
                # On indique seulement la présence d'opérateurs booléens/wildcards
                inner = body.get("query_string", body) if isinstance(body, dict) else {}
                q = str(inner.get("query", "")) if isinstance(inner, dict) else ""
                shape["has_boolean"] = bool(re.search(r"\b(AND|OR|NOT)\b", q, re.I))
                shape["has_wildcard"] = "*" in q or "?" in q
                shape["has_grouping"] = "(" in q
            elif key == "terms" and isinstance(body, dict):
                # arité = nombre de valeurs, sans les valeurs
                first = next(iter(body.values()), [])
                shape["arity"] = len(first) if isinstance(first, list) else 1
            elif key == "range" and isinstance(body, dict):
                conds = next(iter(body.values()), {})
                shape["bounds"] = sorted(conds.keys()) if isinstance(conds, dict) else []
            shapes.append(shape)
    return shapes


# --- Entrée principale ------------------------------------------------------

def sanitize_result(result: ConversionResult, secret: bytes) -> dict[str, Any]:
    """Construit le dict sanitisé d'UNE règle (champs sûrs uniquement)."""
    src = result.source

    # Avertissements -> codes normalisés + comptage (pas le texte brut)
    warn_codes: dict[str, int] = {}
    for w in result.warnings:
        code = _classify_warning(w)
        warn_codes[code] = warn_codes.get(code, 0) + 1

    # Facteurs : on garde label + delta (numérique), pas le detail libre qui
    # pourrait contenir un nom de champ.
    factors = [{"label": f.label, "delta": round(f.delta, 3)} for f in result.factors]

    # Actions custom : on garde la CATÉGORIE, jamais la référence (chemin/module)
    custom_actions = result.metadata.get("custom_actions", [])
    action_categories = sorted({a["category"] for a in custom_actions}) if custom_actions else []

    return {
        "fingerprint": _rule_fingerprint(result, secret),
        "source_type": src.rule_type if "." not in src.rule_type else "custom_module",
        "strategy": result.strategy.value,
        "confidence": round(result.confidence, 3),
        "needs_review": result.needs_review,
        "factors": factors,
        "warning_codes": warn_codes,
        "filter_shapes": _filter_shapes(src.filters),
        "filter_count": len(src.filters),
        "esql_skeleton": _esql_skeleton(result.esql_query),
        "uses_query_key": bool(src.get("query_key")),
        "has_timeframe": src.get("timeframe") is not None,
        "custom_action_categories": action_categories,
        "has_custom_detection_code": bool(result.metadata.get("custom_detection_code")),
    }


def sanitize_report(results: list[ConversionResult], secret: bytes,
                    *, parse_errors: int = 0) -> dict[str, Any]:
    """Construit le rapport sanitisé complet, prêt à transmettre."""
    rules = [sanitize_result(r, secret) for r in results]
    return {
        "schema_version": SANITIZED_SCHEMA_VERSION,
        "tool_version": _tool_version(),
        "rule_count": len(rules),
        "parse_errors": parse_errors,
        "rules": rules,
    }


def _tool_version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"
