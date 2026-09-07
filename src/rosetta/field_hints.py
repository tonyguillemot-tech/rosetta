"""Vérification heuristique de cohérence champ/valeur pour un jeu restreint
de champs de sécurité à convention de nommage bien connue.

Rosetta n'embarque PAS le vrai schéma ECS (fichiers etc/*.json du dépôt
elastic/detection-rules — trop lourd à maintenir à jour, et la validation
ECS complète nécessite de toute façon un vrai cluster, cf. les échanges
précédents sur elastic/elasticsearch#5222). Ce module attrape à la place,
localement et sans dépendance, exactement la classe de problème qu'on a vue
passer le vrai validateur KQL en conditions réelles : `source.ip:"login"` —
un champ dont le NOM indique sans ambiguïté un type (IP, hash, port...) mais
dont la VALEUR ne correspond visiblement pas à ce type.

Volontairement conservateur : seuls les motifs de champs sans ambiguïté
raisonnable sont vérifiés (contient '.ip.', '.hash.', etc.) ; tout le reste
est ignoré plutôt que deviné, pour ne pas produire de faux positifs sur des
champs dont on ne peut rien dire avec ce niveau d'information.
"""
from __future__ import annotations

import re
from typing import Any

_FIELD_TYPE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(^|[._])ip($|[._])", re.I), "ip"),
    (re.compile(r"(^|[._])mac($|[._])", re.I), "mac"),
    (re.compile(r"(^|[._])(md5|sha1|sha256|sha512|imphash)($|[._])", re.I), "hash"),
    (re.compile(r"(^|[._])port($|[._])", re.I), "port"),
    (re.compile(r"(^|[._])(bytes|duration|risk_score)($|[._])", re.I), "number"),
]


def _looks_like_ip(v: Any) -> bool:
    s = str(v).strip()
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", s)
    if m:
        return all(0 <= int(g) <= 255 for g in m.groups())
    # IPv6 : vérification best-effort (au moins 2 groupes hex séparés par ':')
    return bool(re.match(r"^[0-9a-fA-F:]*:[0-9a-fA-F:]*$", s)) and s.count(":") >= 2


def _looks_like_mac(v: Any) -> bool:
    return bool(re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", str(v).strip()))


def _looks_like_hash(v: Any) -> bool:
    s = str(v).strip()
    return bool(re.match(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", s))


def _looks_like_port(v: Any) -> bool:
    s = str(v).strip()
    return bool(re.match(r"^\d+$", s)) and 0 <= int(s) <= 65535


def _looks_like_number(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return True
    return bool(re.match(r"^-?\d+(\.\d+)?$", str(v).strip()))


_VALUE_CHECKS = {
    "ip": _looks_like_ip, "mac": _looks_like_mac, "hash": _looks_like_hash,
    "port": _looks_like_port, "number": _looks_like_number,
}


def guess_field_type(field: str) -> str | None:
    for pattern, ftype in _FIELD_TYPE_PATTERNS:
        if pattern.search(field):
            return ftype
    return None


def check_value(field: str, value: Any) -> str | None:
    """Avertissement si `value` ne correspond visiblement pas au type attendu
    pour `field`, sinon None. Ne se prononce QUE sur les motifs de champs
    connus — silence sur tout le reste plutôt que deviner."""
    ftype = guess_field_type(field)
    if ftype is None:
        return None
    if isinstance(value, str) and ("*" in value or "?" in value):
        return None  # wildcard : pas de valeur concrète à vérifier
    if _VALUE_CHECKS[ftype](value):
        return None
    return (
        f"Field '{field}' looks like a '{ftype}' field by naming convention, "
        f"but its value ({value!r}) doesn't match that shape — verify this "
        "isn't a data/mapping mismatch (Rosetta doesn't have the real ECS "
        "schema, this is a naming heuristic only, not a certainty)."
    )


def _extract_one(flt: dict[str, Any]) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for key, body in flt.items():
        if key in ("term", "match") and isinstance(body, dict):
            out.extend(body.items())
        elif key == "terms" and isinstance(body, dict):
            for f, vals in body.items():
                if isinstance(vals, list):
                    out.extend((f, v) for v in vals)
        elif key == "range" and isinstance(body, dict):
            for f, conds in body.items():
                if isinstance(conds, dict):
                    out.extend((f, v) for v in conds.values())
        elif key == "bool" and isinstance(body, dict):
            for sub_key in ("must", "should", "must_not"):
                for sub in body.get(sub_key, []):
                    out.extend(_extract_one(sub))
    return out


def check_filters(filters: list[dict[str, Any]]) -> list[str]:
    """Avertissements de cohérence champ/valeur pour un jeu de filtres
    ElastAlert (term/terms/match/range, bool imbriqué)."""
    warnings: list[str] = []
    for flt in filters:
        for field, value in _extract_one(flt):
            msg = check_value(field, value)
            if msg:
                warnings.append(msg)
    return warnings
