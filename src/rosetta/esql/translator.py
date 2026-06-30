"""Traduction des filtres ElastAlert (Elasticsearch query DSL / Lucene) en
clauses ES|QL `WHERE` et en KQL.

ElastAlert exprime ses filtres sous la forme d'une liste d'objets query DSL,
par ex:
    filter:
      - query:
          query_string:
            query: "event.category:authentication AND event.outcome:failure"
      - term:
          host.name: "srv01"
      - terms:
          source.ip: ["10.0.0.1", "10.0.0.2"]
      - range:
          bytes: {gt: 1000}

On gère les formes les plus courantes. Toute forme inconnue produit un
avertissement et est ignorée (signalé au scorer).
"""
from __future__ import annotations

import re
from typing import Any


class TranslationWarning(str):
    pass


def _esql_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    # échappement des guillemets
    escaped = str(value).replace('"', '\\"')
    return f'"{escaped}"'


def _lucene_to_esql(query: str, warnings: list[str]) -> str:
    """Conversion best-effort d'une requête Lucene/query_string vers ES|QL.

    Couvre: field:value, AND/OR/NOT, parenthèses, field:(a OR b),
    wildcards (* -> LIKE). Les requêtes trop complexes lèvent un warning.
    """
    q = query.strip()

    # Opérateurs booléens -> majuscules ES|QL
    q = re.sub(r"\bAND\b", "AND", q, flags=re.IGNORECASE)
    q = re.sub(r"\bOR\b", "OR", q, flags=re.IGNORECASE)
    q = re.sub(r"\bNOT\b", "NOT", q, flags=re.IGNORECASE)

    def repl_field(match: re.Match[str]) -> str:
        field = match.group("field")
        value = match.group("value").strip()
        # liste field:(a OR b)
        if value.startswith("(") and value.endswith(")"):
            inner = value[1:-1]
            parts = re.split(r"\s+OR\s+", inner, flags=re.IGNORECASE)
            vals = ", ".join(_esql_value(p.strip().strip('"')) for p in parts)
            return f"{field} IN ({vals})"
        # wildcard -> LIKE
        if "*" in value or "?" in value:
            return f'{field} LIKE {_esql_value(value)}'
        return f"{field} == {_esql_value(value.strip(chr(34)))}"

    field_pattern = re.compile(
        r"(?P<field>[a-zA-Z_][\w.]*)\s*:\s*(?P<value>\([^)]*\)|\"[^\"]*\"|\S+)"
    )
    converted = field_pattern.sub(repl_field, q)

    if ":" in converted:
        warnings.append(
            f"Requête Lucene partiellement convertie, vérifier manuellement: {query!r}"
        )
    return converted


def filter_to_esql(filters: list[dict[str, Any]], warnings: list[str]) -> str:
    """Retourne une clause WHERE ES|QL (sans le mot-clé WHERE)."""
    clauses: list[str] = []
    for flt in filters:
        clauses.extend(_single_filter_to_esql(flt, warnings))
    return " AND ".join(c for c in clauses if c)


def _single_filter_to_esql(flt: dict[str, Any], warnings: list[str]) -> list[str]:
    out: list[str] = []
    for key, body in flt.items():
        if key == "query" and isinstance(body, dict):
            qs = body.get("query_string", {})
            if isinstance(qs, dict) and "query" in qs:
                out.append("(" + _lucene_to_esql(str(qs["query"]), warnings) + ")")
            else:
                warnings.append(f"Filtre 'query' non géré: {body}")
        elif key == "query_string" and isinstance(body, dict) and "query" in body:
            out.append("(" + _lucene_to_esql(str(body["query"]), warnings) + ")")
        elif key == "term" and isinstance(body, dict):
            for f, v in body.items():
                out.append(f"{f} == {_esql_value(v)}")
        elif key == "terms" and isinstance(body, dict):
            for f, vals in body.items():
                if isinstance(vals, list):
                    joined = ", ".join(_esql_value(v) for v in vals)
                    out.append(f"{f} IN ({joined})")
        elif key == "match" and isinstance(body, dict):
            for f, v in body.items():
                out.append(f"{f} == {_esql_value(v)}")
        elif key == "range" and isinstance(body, dict):
            for f, conds in body.items():
                if isinstance(conds, dict):
                    op_map = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
                    for op, v in conds.items():
                        if op in op_map:
                            out.append(f"{f} {op_map[op]} {_esql_value(v)}")
        elif key == "exists" and isinstance(body, dict):
            f = body.get("field")
            if f:
                out.append(f"{f} IS NOT NULL")
        elif key == "bool":
            out.extend(_bool_to_esql(body, warnings))
        else:
            warnings.append(f"Type de filtre non géré '{key}', ignoré.")
    return out


def _bool_to_esql(body: dict[str, Any], warnings: list[str]) -> list[str]:
    out: list[str] = []
    for must in body.get("must", []):
        out.extend(_single_filter_to_esql(must, warnings))
    for should in body.get("should", []):
        sub = _single_filter_to_esql(should, warnings)
        if sub:
            out.append("(" + " OR ".join(sub) + ")")
    for mustnot in body.get("must_not", []):
        sub = _single_filter_to_esql(mustnot, warnings)
        for c in sub:
            out.append(f"NOT ({c})")
    return out


def filter_to_kql(filters: list[dict[str, Any]], warnings: list[str]) -> str:
    """Reconstruit une requête KQL approximative pour les règles 'query'."""
    clauses: list[str] = []
    for flt in filters:
        for key, body in flt.items():
            if key in ("query", "query_string"):
                inner = body.get("query_string", body) if isinstance(body, dict) else {}
                if isinstance(inner, dict) and "query" in inner:
                    clauses.append(f"({inner['query']})")
            elif key == "term" and isinstance(body, dict):
                for f, v in body.items():
                    clauses.append(f'{f}:"{v}"')
            elif key == "terms" and isinstance(body, dict):
                for f, vals in body.items():
                    if isinstance(vals, list):
                        joined = " or ".join(f'"{v}"' for v in vals)
                        clauses.append(f"{f}:({joined})")
            else:
                warnings.append(f"Filtre '{key}' non transcrit en KQL.")
    return " and ".join(clauses) if clauses else "*"
