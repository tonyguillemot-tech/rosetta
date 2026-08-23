"""Detection and classification of custom scripts/code in an ElastAlert rule.

ElastAlert allows injecting Python code or external scripts at several points,
which directly affects how automatically a rule can be migrated:

1. CUSTOM TYPE        -> `type: module.file.RuleName`
   The detection logic is in Python — cannot be converted automatically.
   => manual migration required.

2. CUSTOM ALERTER     -> `alert: module.file.AlertName`
   The alert action is in Python. Detection can migrate, but the action must
   be recreated as an Elastic connector/action. Moderate penalty.

3. COMMAND alerter    -> `alert: command` + `command: [...]`
   Runs an external script/binary. Same as custom alerter: detection migrates,
   action must be recreated (usually via a webhook/connector).

4. ENHANCEMENTS       -> `match_enhancements: [module.file.Enh]`
   Python modules that modify the match before alerting. May contain hidden
   detection logic. Moderate-to-high penalty.

The scorer consumes ScriptFindings to adjust confidence and decide whether the
rule must fall back to the `manual` strategy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Native (non-custom) rule types. Any `type` containing a dot that is not listed
# here is treated as a custom Python module type (module.file.RuleName).
BUILTIN_RULE_TYPES = {
    "any", "blacklist", "whitelist", "frequency", "cardinality",
    "metric_aggregation", "spike", "spike_aggregation", "flatline",
    "new_term", "change", "percentage_match",
}

# Built-in alerters (non-custom).
BUILTIN_ALERTERS = {
    "email", "jira", "opsgenie", "sns", "hipchat", "slack", "mattermost",
    "telegram", "googlechat", "debug", "stomp", "thehive", "command",
    "pagerduty", "pagertree", "exotel", "twilio", "victorops", "gitter",
    "servicenow", "alerta", "post", "http_post", "http_post2", "ms_teams",
    "discord", "dingtalk", "chatwork", "datadog", "zabbix", "rocketchat",
    "command_alerter", "webhook",
}

# Heuristic: an identifier that looks like module.file.ClassName
_MODULE_PATH = re.compile(r"^[a-zA-Z_][\w]*(\.[a-zA-Z_][\w]*){2,}$")


@dataclass
class ScriptFinding:
    """Un usage de script/code custom détecté dans la règle."""

    category: str          # "custom_rule_type" | "custom_alerter" |
                           # "command_alerter" | "enhancement"
    detail: str
    blocks_detection: bool  # True if the DETECTION LOGIC itself is in code
    reference: str = ""     # module path or command


@dataclass
class ScriptAnalysis:
    findings: list[ScriptFinding] = field(default_factory=list)

    @property
    def has_any(self) -> bool:
        return bool(self.findings)

    @property
    def blocks_detection(self) -> bool:
        """True if at least one finding makes the detection non-migratable."""
        return any(f.blocks_detection for f in self.findings)

    @property
    def has_custom_action(self) -> bool:
        """True if a custom action (alerter or command) must be recreated."""
        return any(
            f.category in ("custom_alerter", "command_alerter")
            for f in self.findings
        )


def _looks_like_module_path(value: str) -> bool:
    return bool(_MODULE_PATH.match(value.strip()))


def analyze(raw: dict[str, Any]) -> ScriptAnalysis:
    analysis = ScriptAnalysis()

    # 1. Custom rule type -----------------------------------------------------
    rtype = str(raw.get("type", "")).strip()
    if rtype and rtype not in BUILTIN_RULE_TYPES and _looks_like_module_path(rtype):
        analysis.findings.append(ScriptFinding(
            category="custom_rule_type",
            detail=(f"Custom Python rule type ('{rtype}'): detection logic is in code "
                    "and cannot be migrated automatically."),
            blocks_detection=True,
            reference=rtype,
        ))

    # 2. & 3. Alerters (built-in alerters are ignored) ------------------------
    alert = raw.get("alert")
    alert_list = alert if isinstance(alert, list) else [alert] if alert else []
    for a in alert_list:
        a_str = str(a).strip()
        if a_str == "command":
            cmd = raw.get("command")
            cmd_repr = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            analysis.findings.append(ScriptFinding(
                category="command_alerter",
                detail=("'command' alerter runs an external script/binary. "
                        "Detection migrates, but the action must be recreated "
                        "as an Elastic connector or webhook."),
                blocks_detection=False,
                reference=cmd_repr,
            ))
        elif a_str and a_str not in BUILTIN_ALERTERS and _looks_like_module_path(a_str):
            analysis.findings.append(ScriptFinding(
                category="custom_alerter",
                detail=(f"Custom Python alerter ('{a_str}'): detection migrates, "
                        "but the action must be reimplemented as an Elastic connector."),
                blocks_detection=False,
                reference=a_str,
            ))

    # 4. Match enhancements ---------------------------------------------------
    enh = raw.get("match_enhancements")
    enh_list = enh if isinstance(enh, list) else [enh] if enh else []
    for e in enh_list:
        e_str = str(e).strip()
        if e_str:
            analysis.findings.append(ScriptFinding(
                category="enhancement",
                detail=(f"Python match_enhancement ('{e_str}'): may contain logic "
                        "that modifies the match — must be reviewed and ported manually."),
                blocks_detection=False,
                reference=e_str,
            ))

    return analysis
