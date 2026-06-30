"""Détection et classification des scripts / code custom dans une règle ElastAlert.

ElastAlert permet d'injecter du code Python ou des scripts externes à plusieurs
endroits, ce qui impacte fortement la migrabilité :

1. TYPE custom        -> `type: module.file.RuleName`
   La *logique de détection* est en Python. Non convertible automatiquement.
   => migration manuelle obligatoire.

2. ALERTER custom     -> `alert: module.file.AlertName`
   L'*action* d'alerte est en Python. La détection peut migrer, mais l'action
   doit être recréée côté Elastic (connector/action). Pénalité modérée.

3. COMMAND alerter    -> `alert: command` + `command: [...]`
   Exécute un script/binaire externe. Même cas que l'alerter custom : la
   détection migre, l'action est à recréer (souvent via un webhook/connector).

4. ENHANCEMENTS       -> `match_enhancements: [module.file.Enh]`
   Modules Python qui modifient le match avant alerte. Peuvent contenir de la
   logique de détection déguisée. Pénalité modérée à forte.

Le scorer consomme ScriptFindings pour ajuster la confiance et décider si la
règle doit basculer en stratégie `manual`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Types de règles natifs (non-custom). Tout `type` contenant un point et ne
# figurant pas ici est considéré comme un type custom (module.file.RuleName).
BUILTIN_RULE_TYPES = {
    "any", "blacklist", "whitelist", "frequency", "cardinality",
    "metric_aggregation", "spike", "spike_aggregation", "flatline",
    "new_term", "change", "percentage_match",
}

# Alerters intégrés (non-custom).
BUILTIN_ALERTERS = {
    "email", "jira", "opsgenie", "sns", "hipchat", "slack", "mattermost",
    "telegram", "googlechat", "debug", "stomp", "thehive", "command",
    "pagerduty", "pagertree", "exotel", "twilio", "victorops", "gitter",
    "servicenow", "alerta", "post", "http_post", "http_post2", "ms_teams",
    "discord", "dingtalk", "chatwork", "datadog", "zabbix", "rocketchat",
    "command_alerter", "webhook",
}

# Heuristique : un identifiant ressemblant à module.file.ClassName
_MODULE_PATH = re.compile(r"^[a-zA-Z_][\w]*(\.[a-zA-Z_][\w]*){2,}$")


@dataclass
class ScriptFinding:
    """Un usage de script/code custom détecté dans la règle."""

    category: str          # "custom_rule_type" | "custom_alerter" |
                           # "command_alerter" | "enhancement"
    detail: str
    blocks_detection: bool  # True si la LOGIQUE DE DÉTECTION est en code
    reference: str = ""     # chemin module ou commande


@dataclass
class ScriptAnalysis:
    findings: list[ScriptFinding] = field(default_factory=list)

    @property
    def has_any(self) -> bool:
        return bool(self.findings)

    @property
    def blocks_detection(self) -> bool:
        """True si au moins un finding rend la détection non-migrable."""
        return any(f.blocks_detection for f in self.findings)

    @property
    def has_custom_action(self) -> bool:
        """True si une action (alerter custom/command) devra être recréée."""
        return any(
            f.category in ("custom_alerter", "command_alerter")
            for f in self.findings
        )


def _looks_like_module_path(value: str) -> bool:
    return bool(_MODULE_PATH.match(value.strip()))


def analyze(raw: dict[str, Any]) -> ScriptAnalysis:
    analysis = ScriptAnalysis()

    # 1. Type de règle custom -------------------------------------------------
    rtype = str(raw.get("type", "")).strip()
    if rtype and rtype not in BUILTIN_RULE_TYPES and _looks_like_module_path(rtype):
        analysis.findings.append(ScriptFinding(
            category="custom_rule_type",
            detail=(f"Type de règle custom en Python ('{rtype}'). La logique de "
                    "détection est dans du code et n'est pas convertible "
                    "automatiquement."),
            blocks_detection=True,
            reference=rtype,
        ))

    # 2. & 3. Alerters --------------------------------------------------------
    alert = raw.get("alert")
    alert_list = alert if isinstance(alert, list) else [alert] if alert else []
    for a in alert_list:
        a_str = str(a).strip()
        if a_str == "command":
            cmd = raw.get("command")
            cmd_repr = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            analysis.findings.append(ScriptFinding(
                category="command_alerter",
                detail=("Alerter 'command' : exécute un script/binaire externe. "
                        "La détection migre, mais l'action doit être recréée "
                        "côté Elastic (connector / webhook)."),
                blocks_detection=False,
                reference=cmd_repr,
            ))
        elif a_str and a_str not in BUILTIN_ALERTERS and _looks_like_module_path(a_str):
            analysis.findings.append(ScriptFinding(
                category="custom_alerter",
                detail=(f"Alerter Python custom ('{a_str}'). La détection migre, "
                        "mais l'action devra être réimplémentée en connector "
                        "Elastic."),
                blocks_detection=False,
                reference=a_str,
            ))

    # 4. Enhancements ---------------------------------------------------------
    enh = raw.get("match_enhancements")
    enh_list = enh if isinstance(enh, list) else [enh] if enh else []
    for e in enh_list:
        e_str = str(e).strip()
        if e_str:
            analysis.findings.append(ScriptFinding(
                category="enhancement",
                detail=(f"Match enhancement Python ('{e_str}'). Peut contenir de "
                        "la logique modifiant le match ; à revoir manuellement."),
                blocks_detection=False,
                reference=e_str,
            ))

    return analysis
