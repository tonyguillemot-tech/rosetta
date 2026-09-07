"""Indicateur (pas une correspondance certaine) de recoupement possible avec
le catalogue de règles prebuilt Elastic Security (dépôt public
elastic/detection-rules), interrogé EN DIRECT via l'API GitHub au moment de
l'exécution — jamais un instantané embarqué dans Rosetta, qui se périmerait
immédiatement (le dépôt change quotidiennement).

Architecture alignée sur celle du vrai outil « Automatic Migration »
d'Elastic (vérifié via leur doc/blog) : ILS utilisent une recherche
SÉMANTIQUE (ELSER) sur titre+description+requête pour trouver des candidats,
PUIS un LLM tranche si c'est "identique ou très proche". Rosetta ne peut pas
répliquer ELSER (pas de modèle d'embedding embarqué), mais reprend la même
architecture EN DEUX ÉTAGES :
1. Retrieval bon marché : la catégorie du dépôt est devinée depuis l'index
   ElastAlert, puis les noms de fichiers de cette catégorie sont filtrés par
   mots-clés (1 appel API).
2. Enrichissement pour jugement : pour les quelques meilleurs candidats
   (borné à 3, pour rester dans des limites de taux raisonnables), le
   contenu réel (nom, description, extrait de requête, tags) est récupéré
   (1 appel API par candidat enrichi) — assez de matière pour qu'un humain,
   ou un LLM sollicité séparément, puisse juger la correspondance
   SÉMANTIQUE, pas juste la ressemblance du nom de fichier.

Rosetta s'arrête au retrieval + enrichissement : le jugement final
("identique ou très proche", comme le fait le LLM côté Elastic) reste hors
périmètre — Rosetta n'invente jamais de verdict de correspondance confirmée.
"""
from __future__ import annotations

import base64
import json
import re
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field

_API_BASE = "https://api.github.com/repos/elastic/detection-rules/contents/rules"
_TIMEOUT_S = 8
_USER_AGENT = "rosetta-elastalert-migration-tool"
_MAX_ENRICHED = 3  # candidats dont on récupère le contenu réel (étage 2)

# Catégories confirmées par la structure réelle du dépôt (README du dossier
# rules/, vérifié) — volontairement restreint à ce qui a été vérifié plutôt
# que deviné sur les sous-dossiers integrations/ (il y en a beaucoup d'autres,
# mais je ne veux pas en inventer sans confirmation).
_INDEX_TO_CATEGORY: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"winlogbeat|sysmon|logs-windows", re.I), "windows"),
    (re.compile(r"logs-endpoint", re.I), "windows"),  # Endpoint couvre surtout Windows/macOS/Linux, windows en 1er filtre large
    (re.compile(r"auditbeat|logs-linux|syslog", re.I), "linux"),
    (re.compile(r"packetbeat|suricata|zeek|logs-network", re.I), "network"),
    (re.compile(r"aws\.cloudtrail|aws\.", re.I), "integrations/aws"),
    (re.compile(r"azure", re.I), "integrations/azure"),
    (re.compile(r"o365|office365", re.I), "integrations/o365"),
    (re.compile(r"\bgcp\b|google_cloud", re.I), "integrations/gcp"),
    (re.compile(r"google_workspace|gsuite", re.I), "integrations/google_workspace"),
    (re.compile(r"macos", re.I), "macos"),
]


@dataclass
class PrebuiltHint:
    category: str
    candidates: list[dict] = field(default_factory=list)
    error: str | None = None

    @property
    def browse_url(self) -> str:
        return f"https://github.com/elastic/detection-rules/tree/main/rules/{self.category}"


def guess_category(index_pattern: str) -> str | None:
    """Devine la catégorie du dépôt à partir du pattern d'index ElastAlert.
    Renvoie None si aucun motif connu ne correspond — mieux vaut ne rien
    suggérer que deviner à tort."""
    for pattern, category in _INDEX_TO_CATEGORY:
        if pattern.search(index_pattern or ""):
            return category
    return None


def _rule_keywords(rule_name: str, fields: list[str]) -> list[str]:
    """Mots-clés tirés du nom de la règle et des noms de champs utilisés,
    pour filtrer les noms de fichiers du dépôt — heuristique volontairement
    simple (correspondance de sous-chaîne), pas de NLP/fuzzy matching qui
    donnerait une fausse impression de précision."""
    words = re.findall(r"[a-zA-Z]{4,}", rule_name.lower())
    stop = {"rule", "alert", "elastalert", "test", "detect", "detection"}
    kws = [w for w in words if w not in stop]
    for f in fields:
        kws.extend(w for w in re.findall(r"[a-zA-Z]{4,}", f.lower()) if w not in stop)
    return list(dict.fromkeys(kws))[:8]  # dédupliqué, borné


def _fetch_rule_content(category: str, filename: str) -> dict | None:
    """Étage 2 (enrichissement) : récupère le contenu RÉEL d'une règle
    candidate — nom, description, extrait de requête, tags — pour permettre
    un jugement de correspondance sémantique, comme le fait Elastic via
    ELSER + LLM. Renvoie None en cas d'échec (silencieux : c'est un bonus,
    pas un besoin critique — le candidat reste utilisable avec son seul nom
    de fichier si l'enrichissement échoue)."""
    url = f"{_API_BASE}/{category}/{filename}"
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": _USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        raw = base64.b64decode(payload["content"]).decode("utf-8", errors="replace")
        parsed = tomllib.loads(raw)
        r = parsed.get("rule", {})
        return {
            "name": r.get("name", filename),
            "description": (r.get("description") or "")[:300].strip(),
            "query_excerpt": (r.get("query") or "")[:200].strip(),
            "tags": r.get("tags", []),
        }
    except Exception:  # noqa: BLE001 — bonus best-effort, jamais bloquant
        return None


def fetch_prebuilt_hint(index_pattern: str, rule_name: str,
                         extra_fields: list[str] | None = None) -> PrebuiltHint | None:
    """Appel réseau LIVE (pas de cache, pas d'instantané) à l'API GitHub.
    Renvoie None si aucune catégorie n'a pu être devinée. En cas d'échec
    réseau (pas de connexion, timeout, rate limit...), renvoie un PrebuiltHint
    avec `error` renseigné plutôt que de lever une exception — la conversion
    ne doit JAMAIS échouer à cause de cette fonctionnalité optionnelle."""
    category = guess_category(index_pattern)
    if category is None:
        return None

    keywords = _rule_keywords(rule_name, extra_fields or [])
    url = f"{_API_BASE}/{category}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": _USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        return PrebuiltHint(category=category, error=str(e))
    except (json.JSONDecodeError, ValueError) as e:
        return PrebuiltHint(category=category, error=f"Réponse GitHub inattendue: {e}")

    if not isinstance(payload, list):
        # Ex: rate limit -> GitHub renvoie un objet {"message": "API rate limit exceeded..."}
        msg = payload.get("message", "réponse inattendue") if isinstance(payload, dict) else "réponse inattendue"
        return PrebuiltHint(category=category, error=msg)

    candidates = []
    for f in payload:
        name = f.get("name", "")
        if not name.endswith(".toml"):
            continue
        lname = name.lower()
        if any(kw in lname for kw in keywords):
            candidates.append({"filename": name, "url": f.get("html_url", "")})
    candidates = candidates[:10]

    # Étage 2 : enrichir les MEILLEURS candidats avec leur contenu réel, pour
    # un vrai jugement sémantique possible — pas juste un nom de fichier qui
    # ressemble. Borné à _MAX_ENRICHED pour rester dans des limites de taux
    # raisonnables (1 appel API supplémentaire par candidat enrichi).
    for c in candidates[:_MAX_ENRICHED]:
        detail = _fetch_rule_content(category, c["filename"])
        if detail:
            c.update(detail)

    return PrebuiltHint(category=category, candidates=candidates)
