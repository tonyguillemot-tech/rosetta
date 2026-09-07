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


_ESQL_STRING_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _escape_string_literal(s: str) -> str:
    """Échappement caractère par caractère (backslash, guillemet, contrôles) —
    une seule passe, donc pas de risque d'ordre d'application incorrect
    (contrairement à des .replace() enchaînés)."""
    return "".join(_ESQL_STRING_ESCAPES.get(ch, ch) for ch in s)


def _esql_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    # ES|QL utilise le backslash comme caractère d'échappement dans les
    # littéraux de chaîne (confirmé par la doc Elastic et
    # elastic/elasticsearch#118932) — un backslash littéral non échappé (ex:
    # chemin Windows 'C:\Users\...', courant en sécurité EDR) doit être
    # doublé, sous peine de requête invalide ou mal interprétée.
    return f'"{_escape_string_literal(str(value))}"'


def _esql_range_bound(v: str) -> str:
    """Une borne de range Lucene ([1 TO 10]) : nombre nu si numérique, sinon
    chaîne échappée. Évite de citer '10' en "10" alors qu'un WHERE numérique
    ES|QL attend une valeur nue."""
    try:
        float(v)
        return v
    except ValueError:
        return _esql_value(v)


class _LuceneParser:
    """Parser récursif descendant pour un sous-ensemble de la syntaxe Lucene
    query_string : field:value, AND/OR/NOT, parenthèses de précédence,
    field:(a OR b), plages field:[a TO b] / field:{a TO b}, opérateurs de
    comparaison field:>N, wildcards (* ? -> LIKE).

    Principe : toute construction non couverte (regex /…/, fuzzy ~, boost
    ^N, proximité "…"~N, entrée malformée) doit produire un avertissement
    plutôt qu'un ES|QL syntaxiquement invalide ou sémantiquement faux généré
    en silence. `self.ok` reste True tant qu'aucune construction douteuse
    n'a été rencontrée ; sinon un avertissement générique est levé une fois,
    à la fin, par `_lucene_to_esql`.
    """

    _BOOL_RE = re.compile(r"[A-Za-z]+")

    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.ok = True

    def _skip_ws(self) -> None:
        while self.i < self.n and self.s[self.i].isspace():
            self.i += 1

    def _peek_bool_kw(self) -> str | None:
        m = self._BOOL_RE.match(self.s, self.i)
        if m and m.group(0).upper() in ("AND", "OR", "NOT"):
            return m.group(0).upper()
        return None

    def parse_expr(self) -> str:
        left = self.parse_term()
        while True:
            self._skip_ws()
            kw = self._peek_bool_kw()
            if kw in ("AND", "OR"):
                self.i += len(kw)
                right = self.parse_term()
                left = f"{left} {kw} {right}"
            else:
                break
        return left

    def parse_term(self) -> str:
        self._skip_ws()
        if self._peek_bool_kw() == "NOT":
            self.i += 3
            self._skip_ws()
            return f"NOT {self.parse_factor()}"
        return self.parse_factor()

    def _find_matching_paren(self, start: int) -> int:
        """Renvoie l'index du ')' fermant celui en `start`, en ignorant les
        parenthèses à l'intérieur de guillemets. -1 si non trouvé."""
        depth = 0
        j = start
        in_quotes = False
        while j < self.n:
            c = self.s[j]
            if c == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        return j
            j += 1
        return -1

    def parse_factor(self) -> str:
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == "(":
            end = self._find_matching_paren(self.i)
            if end == -1:
                self.ok = False
                inner_text = self.s[self.i + 1:]
                self.i = self.n
                return _esql_value(inner_text)
            sub = _LuceneParser(self.s[self.i + 1:end])
            inner = sub.parse_expr()
            sub._skip_ws()
            if sub.i < sub.n or not sub.ok:
                self.ok = False
            self.i = end + 1
            return f"({inner})"
        return self.parse_field_value()

    def parse_field_value(self) -> str:
        self._skip_ws()
        m = re.match(r"[A-Za-z_][\w.]*\s*:\s*", self.s[self.i:])
        if not m:
            # Terme "libre" sans field: (recherche plein texte implicite en
            # Lucene) : pas de champ ES|QL cible évident -> on ne devine pas.
            tok = re.match(r"\S+", self.s[self.i:])
            token = tok.group(0) if tok else self.s[self.i:self.i + 1] or " "
            self.i += max(len(token), 1)
            self.ok = False
            return _esql_value(token)
        field = m.group(0).split(":", 1)[0].strip()
        self.i += m.end()
        return self._parse_value(field)

    def _parse_value(self, field: str) -> str:
        self._skip_ws()
        if self.i >= self.n:
            self.ok = False
            return f'{field} == ""'
        c = self.s[self.i]

        # Plage : [a TO b] (inclusive) / {a TO b} (exclusive) / bornes mixtes
        if c in "[{":
            lo_incl = c == "["
            end = -1
            hi_incl = True
            for j in range(self.i + 1, self.n):
                if self.s[j] in "]}":
                    end = j
                    hi_incl = self.s[j] == "]"
                    break
            if end == -1:
                self.ok = False
                self.i = self.n
                return f'{field} == ""'
            body = self.s[self.i + 1:end]
            self.i = end + 1
            rm = re.match(r"\s*(\S+)\s+TO\s+(\S+)\s*$", body, re.IGNORECASE)
            if not rm:
                self.ok = False
                return f"{field} == {_esql_value(body)}"
            lo, hi = rm.group(1), rm.group(2)
            parts = []
            if lo != "*":
                parts.append(f"{field} {'>=' if lo_incl else '>'} {_esql_range_bound(lo)}")
            if hi != "*":
                parts.append(f"{field} {'<=' if hi_incl else '<'} {_esql_range_bound(hi)}")
            if not parts:
                self.ok = False
                return f"{field} IS NOT NULL"
            return "(" + " AND ".join(parts) + ")" if len(parts) > 1 else parts[0]

        # Comparaison courte : field:>5, field:>=5, field:<5, field:<=5
        for op in (">=", "<=", ">", "<"):
            if self.s.startswith(op, self.i):
                self.i += len(op)
                self._skip_ws()
                vm = re.match(r"\S+", self.s[self.i:])
                val = vm.group(0) if vm else ""
                self.i += len(val)
                return f"{field} {op} {_esql_range_bound(val)}"

        # Liste : field:(a OR b OR c)
        if c == "(":
            end = self._find_matching_paren(self.i)
            if end == -1:
                self.ok = False
                self.i = self.n
                return f'{field} == ""'
            inner = self.s[self.i + 1:end]
            self.i = end + 1
            if re.search(r"\bAND\b|\bNOT\b", inner, re.IGNORECASE):
                self.ok = False
                return f"{field} == {_esql_value(inner)}"
            parts = re.split(r"\s+OR\s+", inner.strip(), flags=re.IGNORECASE)
            vals = ", ".join(_esql_value(p.strip().strip('"')) for p in parts if p.strip())
            return f"{field} IN ({vals})" if len(parts) > 1 else f"{field} == {_esql_value(parts[0])}"

        # Phrase entre guillemets, avec suffixe fuzzy/proximité éventuel ("a"~2)
        if c == '"':
            end = self.s.find('"', self.i + 1)
            if end == -1:
                self.ok = False
                val = self.s[self.i + 1:]
                self.i = self.n
            else:
                val = self.s[self.i + 1:end]
                self.i = end + 1
                suffix = re.match(r"[~^]\d*", self.s[self.i:])
                if suffix:
                    self.i += suffix.end()
                    self.ok = False  # proximité/boost non représentable
            return f"{field} == {_esql_value(val)}"

        # Regex Lucene /…/ : pas d'équivalent ES|QL direct fiable
        if c == "/":
            end = self.s.find("/", self.i + 1)
            if end != -1:
                self.i = end + 1
                self.ok = False
                return f'{field} == ""'

        # Mot nu, avec wildcard (* ?) -> LIKE, ou suffixe fuzzy/boost (~ ^N)
        tok = re.match(r"\S+", self.s[self.i:])
        token = tok.group(0) if tok else ""
        self.i += len(token)
        core = token
        fm = re.match(r"^(.*?)([~^]\d*)$", token)
        if fm and fm.group(2) and fm.group(1):
            core = fm.group(1)
            self.ok = False  # fuzzy/boost tronqué, pas représenté
        if "*" in core or "?" in core:
            return f"{field} LIKE {_esql_value(core)}"
        return f"{field} == {_esql_value(core.strip(chr(34)))}"


def _lucene_to_esql(query: str, warnings: list[str]) -> str:
    """Conversion d'une requête Lucene/query_string vers ES|QL.

    Couvre : field:value, AND/OR/NOT, parenthèses de précédence imbriquées,
    field:(a OR b), plages field:[a TO b]/{a TO b}, comparaisons field:>N,
    wildcards (* ? -> LIKE). Toute construction non couverte (regex, fuzzy,
    boost, proximité, terme libre sans field:) lève UN avertissement — jamais
    silencieusement une clause ES|QL fausse ou syntaxiquement invalide."""
    parser = _LuceneParser(query.strip())
    result = parser.parse_expr()
    parser._skip_ws()
    if parser.i < parser.n:
        parser.ok = False
    if not parser.ok:
        warnings.append(
            f"Requête Lucene partiellement convertie, vérifier manuellement: {query!r}"
        )
    return result


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


def _kql_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return f'"{_escape_string_literal(str(value))}"'


def filter_to_kql(filters: list[dict[str, Any]], warnings: list[str]) -> str:
    """Reconstruit une requête KQL approximative pour les règles 'query'/'new_term'/
    'flatline'. Couvre les mêmes formes que filter_to_esql (term/terms/match/range/
    exists/bool imbriqué) pour éviter des avertissements évitables sur des filtres
    pourtant simples à traduire."""
    clauses: list[str] = []
    for flt in filters:
        clauses.extend(_single_filter_to_kql(flt, warnings))
    return " and ".join(clauses) if clauses else "*"


_KQL_BOOL_RE = re.compile(r"\b(AND|OR|NOT)\b", re.IGNORECASE)


def _normalize_kql_bool_ops(query: str) -> str:
    """KQL exige and/or/not en minuscules — contrairement à Lucene/ES|QL, où
    AND/OR/NOT en majuscules est la convention courante. Un query_string
    ElastAlert repris tel quel (passthrough) casse donc le parsing KQL réel
    dès qu'il contient un opérateur booléen en majuscules. Remplacement par
    mot entier, insensible à la casse — ne touche pas un 'AND' qui ferait
    partie d'un nom de champ ou d'une valeur non-opérateur accidentellement
    identique (limite acceptée du passthrough, qui ne reparse pas la chaîne)."""
    return _KQL_BOOL_RE.sub(lambda m: m.group(0).lower(), query)


def _single_filter_to_kql(flt: dict[str, Any], warnings: list[str]) -> list[str]:
    out: list[str] = []
    for key, body in flt.items():
        if key in ("query", "query_string"):
            inner = body.get("query_string", body) if isinstance(body, dict) else {}
            if isinstance(inner, dict) and "query" in inner:
                out.append(f"({_normalize_kql_bool_ops(str(inner['query']))})")
            else:
                warnings.append(f"Filtre 'query' non géré en KQL: {body}")
        elif key == "term" and isinstance(body, dict):
            for f, v in body.items():
                out.append(f"{f}:{_kql_value(v)}")
        elif key == "match" and isinstance(body, dict):
            for f, v in body.items():
                out.append(f"{f}:{_kql_value(v)}")
        elif key == "terms" and isinstance(body, dict):
            for f, vals in body.items():
                if isinstance(vals, list):
                    joined = " or ".join(_kql_value(v) for v in vals)
                    out.append(f"{f}:({joined})")
        elif key == "range" and isinstance(body, dict):
            for f, conds in body.items():
                if isinstance(conds, dict):
                    op_map = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
                    sub = [f"{f} {op_map[op]} {_kql_value(v)}"
                           for op, v in conds.items() if op in op_map]
                    if len(sub) > 1:
                        out.append("(" + " and ".join(sub) + ")")
                    elif sub:
                        out.append(sub[0])
        elif key == "exists" and isinstance(body, dict):
            f = body.get("field")
            if f:
                out.append(f"{f}: *")
        elif key == "bool":
            out.extend(_bool_to_kql(body, warnings))
        else:
            warnings.append(f"Filtre '{key}' non transcrit en KQL.")
    return out


def _bool_to_kql(body: dict[str, Any], warnings: list[str]) -> list[str]:
    out: list[str] = []
    for must in body.get("must", []):
        out.extend(_single_filter_to_kql(must, warnings))
    for should in body.get("should", []):
        sub = _single_filter_to_kql(should, warnings)
        if sub:
            out.append("(" + " or ".join(sub) + ")")
    for mustnot in body.get("must_not", []):
        sub = _single_filter_to_kql(mustnot, warnings)
        for c in sub:
            out.append(f"not ({c})")
    return out
