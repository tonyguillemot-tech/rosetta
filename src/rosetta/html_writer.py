"""HTML rendering for Rosetta reports (report and share commands)."""
from __future__ import annotations

import html as _html
import json as _json
from datetime import datetime, timezone
from typing import Any

_BAND_COLOR: dict[str, tuple[str, str]] = {
    "HIGH":      ("#15803d", "#dcfce7"),
    "MEDIUM":    ("#b45309", "#fef3c7"),
    "LOW":       ("#c2410c", "#ffedd5"),
    "VERY LOW":  ("#b91c1c", "#fee2e2"),
}

_BAND_BG_FILL = {
    "HIGH":     "#15803d",
    "MEDIUM":   "#d97706",
    "LOW":      "#ea580c",
    "VERY LOW": "#dc2626",
}

_STRATEGY_LABEL = {
    "esql":       "ES|QL",
    "query":      "Query (KQL)",
    "eql":        "EQL",
    "threshold":  "Threshold",
    "new_terms":  "New Terms",
    "threat_match": "Indicator Match",
    "manual":     "Manual review",
}


def _e(s: object) -> str:
    return _html.escape(str(s))


def _conf_to_band(c: float) -> str:
    if c >= 0.85:
        return "HIGH"
    if c >= 0.60:
        return "MEDIUM"
    if c >= 0.30:
        return "LOW"
    return "VERY LOW"


def _badge(band: str) -> str:
    fg, bg = _BAND_COLOR.get(band, ("#374151", "#f3f4f6"))
    return f'<span class="badge" style="color:{fg};background:{bg}">{_e(band)}</span>'


def _conf_bar(value: float, band: str) -> str:
    pct = round(value * 100)
    fg = _BAND_BG_FILL.get(band, "#6b7280")
    return (
        f'<div class="conf-cell">'
        f'<div class="conf-bar"><div class="conf-fill" style="width:{pct}%;background:{fg}"></div></div>'
        f'<span>{pct}%</span>'
        f'</div>'
    )


def _dist_bar(by_band: dict[str, int], total: int) -> str:
    html = ""
    for name in ("HIGH", "MEDIUM", "LOW", "VERY LOW"):
        count = by_band.get(name, 0)
        if count and total:
            pct = count / total * 100
            html += (f'<div class="dist-seg" title="{name}: {count}"'
                     f' style="width:{pct:.1f}%;background:{_BAND_BG_FILL[name]}"></div>')
    return html


def _pattern_breakdown(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Regroupe les règles par source_type pour l'analyse de tendances :
    combien, confiance moyenne, % à revoir, avertissements les plus
    fréquents, suggestion de migration dominante. Utilisée par report_to_html
    ET share_to_html — les deux ont les mêmes clés agrégeables (source_type,
    confidence, needs_review, warning_codes, migration_strategy), donc aucune
    info supplémentaire n'est nécessaire côté sanitisé pour ça : c'est
    justement le genre d'usage que l'anonymisation ne bloque pas."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in rules:
        groups.setdefault(r.get("source_type", "?"), []).append(r)

    out = []
    for source_type, rs in groups.items():
        n = len(rs)
        avg_conf = sum(r["confidence"] for r in rs) / n
        needs_review = sum(1 for r in rs if r.get("needs_review"))
        warn_counts: dict[str, int] = {}
        for r in rs:
            codes = r.get("warning_codes")
            if codes is None:
                # rapport complet (non sanitisé) : pas de warning_codes,
                # seulement 'warnings' en texte libre — on compte juste leur présence.
                if r.get("warnings"):
                    warn_counts["(warnings)"] = warn_counts.get("(warnings)", 0) + len(r["warnings"])
                continue
            for code, count in codes.items():
                warn_counts[code] = warn_counts.get(code, 0) + count
        top_warnings = sorted(warn_counts.items(), key=lambda kv: -kv[1])[:3]

        # Suggestion de migration dominante pour ce type source (ex: spike ->
        # Machine Learning sur 100% des règles). Compte à la fois les
        # suggestions (migration_strategy, alternative à côté d'ES|QL) ET les
        # cas où indicator_match EST DÉJÀ la stratégie livrée (grosse liste
        # IOC -> threat_match, cf. registry.py) : sinon ces règles disparaissent
        # de l'agrégation alors qu'elles sont le résultat direct de la même
        # détection heuristique — juste déjà appliquée plutôt que suggérée.
        mig_counts: dict[str, list] = {}
        mig_delivered: dict[str, int] = {}
        for r in rs:
            strat = r.get("migration_strategy")
            if strat:
                mig_counts.setdefault(strat, []).append(r.get("migration_score"))
            elif r.get("strategy") == "threat_match":
                mig_counts.setdefault("indicator_match", []).append(None)
                mig_delivered["indicator_match"] = mig_delivered.get("indicator_match", 0) + 1
        migration_summary = None
        if mig_counts:
            top_strat, scores = max(mig_counts.items(), key=lambda kv: len(kv[1]))
            valid_scores = [s for s in scores if s is not None]
            migration_summary = {
                "strategy": top_strat,
                "count": len(scores),
                "delivered": mig_delivered.get(top_strat, 0),
                "avg_score": (sum(valid_scores) / len(valid_scores)) if valid_scores else None,
            }

        out.append({
            "source_type": source_type,
            "count": n,
            "avg_confidence": avg_conf,
            "needs_review": needs_review,
            "top_warnings": top_warnings,
            "migration_summary": migration_summary,
        })
    out.sort(key=lambda x: x["avg_confidence"])
    return out


def _pattern_table_html(rules: list[dict[str, Any]]) -> str:
    breakdown = _pattern_breakdown(rules)
    if not breakdown:
        return ""
    rows = ""
    for row in breakdown:
        pct = row["avg_confidence"]
        band = _conf_to_band(pct)
        bc, _ = _BAND_COLOR.get(band, ("#374151", ""))
        review_pct = (row["needs_review"] / row["count"] * 100) if row["count"] else 0
        warn_html = ", ".join(
            f'{_e(code)} ×{count}' for code, count in row["top_warnings"]
        ) or "—"
        mig = row.get("migration_summary")
        if mig:
            label = _MIGRATION_LABELS.get(mig["strategy"], mig["strategy"])
            score_txt = f" {mig['avg_score']:.0%}" if mig["avg_score"] is not None else ""
            delivered = mig.get("delivered", 0)
            delivered_txt = (
                f' <span style="font-size:11px;color:#15803d">({delivered} already delivered)</span>'
                if delivered else ""
            )
            mig_html = (
                f'<span class="tag mig-tag">{_e(label)}{_e(score_txt)}</span> '
                f'<span style="font-size:11px;color:#9ca3af">{mig["count"]}/{row["count"]}</span>'
                f'{delivered_txt}'
            )
        else:
            mig_html = "—"
        rows += (
            f'<tr>'
            f'<td><span class="tag">{_e(row["source_type"])}</span></td>'
            f'<td data-val="{row["count"]}">{row["count"]}</td>'
            f'<td data-val="{pct}" style="color:{bc};font-weight:600">{pct:.0%}</td>'
            f'<td data-val="{row["needs_review"]}">{row["needs_review"]} ({review_pct:.0f}%)</td>'
            f'<td style="font-size:12px;color:#6b7280">{warn_html}</td>'
            f'<td>{mig_html}</td>'
            f'</tr>'
        )
    return (
        '<details class="patterns" open>'
        '<summary>Patterns by source type — click to collapse</summary>'
        '<table class="patterns-table">'
        '<thead><tr>'
        '<th data-col="0">Source type<span class="arrow"></span></th>'
        '<th data-col="1">Count<span class="arrow"></span></th>'
        '<th data-col="2">Avg confidence<span class="arrow"></span></th>'
        '<th data-col="3">Needs review<span class="arrow"></span></th>'
        '<th data-col="4">Top warnings<span class="arrow"></span></th>'
        '<th data-col="5">Migration suggestion<span class="arrow"></span></th>'
        '</tr></thead>'
        f'<tbody>{rows}</tbody>'
        '</table>'
        '</details>'
    )


_MIGRATION_LABELS = {
    "machine_learning": "ML",
    "eql": "EQL",
    "indicator_match": "Indicator Match",
}


def _migration_badge(r: dict[str, Any]) -> str:
    """Petit badge « → <stratégie> [N%] » quand un chemin de migration plus
    fidèle que la règle livrée par défaut a été détecté (ML pour spike/change/
    flatline, EQL pour les modules custom au nom évocateur de séquence,
    indicator_match pour blacklist/whitelist aux valeurs de type IOC). Le
    score est optionnel : une pure heuristique de nommage (EQL) n'en a pas —
    inventer un chiffre dessus serait fabriquer de la précision."""
    strat = r.get("migration_strategy")
    if not strat:
        return ""
    label = _MIGRATION_LABELS.get(strat, strat)
    score = r.get("migration_score")
    pct = f" {score:.0%}" if score is not None else ""
    return (
        f' <span class="tag mig-tag" title="Recommended migration path: '
        f'{_e(label)}{pct} — see the rule note / drawer for details">'
        f'→ {_e(label)}{pct}</span>'
    )


def _stat_card(val: object, label: str, color: str = "", band_filter: str = "") -> str:
    style = f' style="color:{color}"' if color else ""
    cls = "stat-card"
    attr = ""
    if band_filter:
        cls += " stat-card-filterable"
        attr = f' data-band-filter="{_e(band_filter)}" title="Filtrer sur ce statut"'
    return (f'<div class="{cls}"{attr}>'
            f'<div class="val"{style}>{_e(val)}</div>'
            f'<div class="lbl">{_e(label)}</div>'
            f'</div>')


def _css() -> str:
    return (
        "* { box-sizing: border-box; margin: 0; padding: 0; }"
        "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;"
        "       font-size: 14px; color: #1f2937; background: #f9fafb; padding: 24px; }"
        "h1 { font-size: 22px; font-weight: 700; color: #111827; margin-bottom: 4px; }"
        ".subtitle { color: #6b7280; font-size: 13px; margin-bottom: 24px; }"
        ".stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }"
        ".stat-card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;"
        "             padding: 12px 20px; min-width: 110px; }"
        ".stat-card-filterable { cursor: pointer; transition: box-shadow .12s ease; }"
        ".stat-card-filterable:hover { box-shadow: 0 0 0 2px #d1d5db; }"
        ".stat-card-filterable.active { box-shadow: 0 0 0 2px #3730a3; background: #eef2ff; }"
        ".toolbar { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }"
        ".search-input { flex: 0 1 320px; padding: 8px 12px; border: 1px solid #e5e7eb;"
        "                border-radius: 8px; font-size: 13px; color: #1f2937; background: #fff; }"
        ".search-input:focus { outline: 2px solid #93c5fd; outline-offset: -1px; }"
        ".filter-hint { font-size: 12px; color: #6b7280; }"
        ".filter-hint button { border: none; background: none; color: #3730a3; cursor: pointer;"
        "                      font-size: 12px; text-decoration: underline; padding: 0; }"
        ".stat-card .val { font-size: 26px; font-weight: 700; line-height: 1.2; }"
        ".stat-card .lbl { font-size: 12px; color: #6b7280; margin-top: 2px; }"
        ".dist-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden;"
        "            background: #e5e7eb; margin-bottom: 24px; }"
        ".dist-seg { height: 100%; }"
        "table { width: 100%; border-collapse: collapse; background: #fff;"
        "        border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; }"
        "th { background: #f3f4f6; font-weight: 600; text-align: left;"
        "     padding: 10px 14px; cursor: pointer; user-select: none;"
        "     border-bottom: 1px solid #e5e7eb; white-space: nowrap; }"
        "th:hover { background: #e5e7eb; }"
        ".arrow { margin-left: 4px; color: #9ca3af; font-size: 11px; }"
        "td { padding: 9px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: middle; }"
        "tr:last-child td { border-bottom: none; }"
        "tr:hover td { background: #f9fafb; }"
        ".badge { display: inline-block; padding: 2px 8px; border-radius: 9999px;"
        "         font-size: 12px; font-weight: 600; }"
        ".tag { display: inline-block; background: #e0e7ff; color: #3730a3;"
        "       border-radius: 4px; padding: 1px 6px; font-size: 12px; }"
        ".warn-tag { background: #fef3c7; color: #92400e; }"
        ".rev-yes { color: #b45309; font-weight: 600; }"
        ".rev-no  { color: #9ca3af; }"
        ".conf-cell { display: flex; align-items: center; gap: 8px; }"
        ".fp-code { font-family: ui-monospace,'Cascadia Code',monospace; font-size: 12px;"
        "           color: #6b7280; background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }"
        ".mig-tag { background: #ede9fe; color: #6d28d9; font-weight: 600; }"
        ".conf-bar { width: 80px; height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; }"
        ".conf-fill { height: 100%; border-radius: 4px; }"
        ".patterns { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;"
        "            padding: 4px 16px 14px; margin-bottom: 16px; }"
        ".patterns summary { cursor: pointer; padding: 10px 0; font-size: 13px; font-weight: 600;"
        "                     color: #374151; user-select: none; }"
        ".patterns-table { width: 100%; border-collapse: collapse; font-size: 13px; }"
        ".patterns-table th { text-align: left; padding: 6px 10px; color: #6b7280;"
        "                      font-weight: 600; border-bottom: 1px solid #e5e7eb; }"
        ".patterns-table td { padding: 6px 10px; border-bottom: 1px solid #f3f4f6; }"
        ".patterns-table tbody tr { cursor: pointer; }"
        ".patterns-table tbody tr:hover { background: #f9fafb; }"
        ".patterns-table tbody tr.active-pattern { background: #eef2ff; }"
        ".section { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;"
        "           margin-bottom: 16px; overflow: hidden; }"
        ".sec-hdr { padding: 11px 16px; background: #f9fafb;"
        "           border-bottom: 1px solid #e5e7eb; font-weight: 600;"
        "           display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }"
        ".grid2 { display: grid; grid-template-columns: 1fr 1fr; }"
        ".cell { padding: 9px 16px; border-bottom: 1px solid #f3f4f6; }"
        ".cell:nth-child(odd) { border-right: 1px solid #f3f4f6; }"
        ".key { font-size: 11px; color: #9ca3af; text-transform: uppercase;"
        "       letter-spacing: .04em; margin-bottom: 3px; }"
        ".skel { padding: 10px 16px; background: #f9fafb; border-top: 1px solid #f3f4f6; }"
        ".factors-hdr { padding: 7px 16px 4px; font-size: 11px; color: #9ca3af;"
        "               border-top: 1px solid #f3f4f6; font-weight: 600;"
        "               text-transform: uppercase; letter-spacing: .04em; }"
        ".factor { padding: 6px 16px; border-bottom: 1px solid #f3f4f6;"
        "          display: flex; align-items: baseline; gap: 8px; }"
        ".factor:last-child { border-bottom: none; }"
        ".delta { font-weight: 600; min-width: 52px; text-align: right; font-variant-numeric: tabular-nums; }"
        ".pos { color: #15803d; } .neg { color: #b91c1c; } .neu { color: #6b7280; }"
        "tr[data-rule] { cursor: pointer; }"
        "tr[data-rule]:hover td { background: #eff6ff !important; }"
        ".d-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.35);"
        "             z-index: 100; display: none; }"
        ".d-overlay.open { display: block; }"
        ".d-panel { position: fixed; right: 0; top: 0; height: 100vh; width: min(580px,100vw);"
        "           background: #fff; z-index: 101; transform: translateX(100%);"
        "           transition: transform .25s ease; overflow: hidden;"
        "           box-shadow: -4px 0 32px rgba(0,0,0,.15);"
        "           display: flex; flex-direction: column; }"
        ".d-panel.open { transform: translateX(0); }"
        ".d-hdr { padding: 16px 20px; border-bottom: 1px solid #e5e7eb;"
        "         display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }"
        ".d-hdr-left { flex: 1; min-width: 0; }"
        ".d-name { font-size: 15px; font-weight: 700; margin-bottom: 6px;"
        "          word-break: break-word; }"
        ".d-close { background: none; border: none; font-size: 18px; cursor: pointer;"
        "           color: #9ca3af; padding: 2px 6px; border-radius: 4px; line-height: 1; }"
        ".d-close:hover { background: #f3f4f6; color: #374151; }"
        ".d-body { padding: 16px 20px; flex: 1; overflow-y: auto; }"
        ".d-conf { margin-bottom: 16px; }"
        ".d-sec { margin-bottom: 18px; }"
        ".d-sec-title { font-size: 11px; font-weight: 600; text-transform: uppercase;"
        "               letter-spacing: .04em; color: #9ca3af; margin-bottom: 8px; }"
        ".warn-list { list-style: none; display: flex; flex-direction: column; gap: 4px; }"
        ".warn-list li { background: #fffbeb; border: 1px solid #fde68a; border-radius: 4px;"
        "                padding: 6px 10px; font-size: 13px; color: #92400e; }"
        "pre.esql { background: #1e1e2e; color: #cdd6f4; padding: 14px 16px; border-radius: 6px;"
        "           font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-word;"
        "           margin: 0; font-family: ui-monospace,'Cascadia Code',monospace; line-height: 1.6; }"
        ".factor-row { display: flex; align-items: baseline; gap: 8px; padding: 5px 0;"
        "              border-bottom: 1px solid #f3f4f6; font-size: 13px; flex-wrap: wrap; }"
        ".factor-row:last-child { border-bottom: none; }"
        ".factor-detail { color: #6b7280; font-size: 12px; }"
    )


def _js_sort() -> str:
    return (
        "(function(){"
        "document.querySelectorAll('th[data-col]').forEach(function(th){"
        "  th.addEventListener('click',function(){"
        "    var tb=th.closest('table').querySelector('tbody');"
        "    var col=+th.dataset.col,asc=th.dataset.asc!=='1';"
        "    th.dataset.asc=asc?'1':'0';"
        "    th.closest('table').querySelectorAll('.arrow').forEach(function(a){a.textContent='';});"
        "    th.querySelector('.arrow').textContent=asc?' ▲':' ▼';"
        "    Array.from(tb.rows).sort(function(a,b){"
        "      var av=a.cells[col].dataset.val||a.cells[col].textContent.trim();"
        "      var bv=b.cells[col].dataset.val||b.cells[col].textContent.trim();"
        "      var an=parseFloat(av),bn=parseFloat(bv);"
        "      if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;"
        "      return asc?av.localeCompare(bv):bv.localeCompare(av);"
        "    }).forEach(function(r){tb.appendChild(r);});"
        "  });"
        "});"
        "})();"
    )


def _drawer_html() -> str:
    """Static HTML skeleton for the side panel (content populated by JS)."""
    return (
        '<div class="d-overlay" id="d-overlay"></div>'
        '<div class="d-panel" id="d-panel">'
        '  <div class="d-hdr">'
        '    <div class="d-hdr-left">'
        '      <div class="d-name" id="d-name"></div>'
        '      <div id="d-badges"></div>'
        '    </div>'
        '    <button class="d-close" id="d-close" aria-label="Close">&#x2715;</button>'
        '  </div>'
        '  <div class="d-body">'
        '    <div class="d-conf d-sec" id="d-conf"></div>'
        '    <div class="d-sec" id="d-migration"></div>'
        '    <div class="d-sec" id="d-prebuilt"></div>'
        '    <div class="d-sec" id="d-warns"></div>'
        '    <div class="d-sec" id="d-query"></div>'
        '    <div class="d-sec" id="d-source"></div>'
        '    <div class="d-sec" id="d-mljob"></div>'
        '    <div class="d-sec" id="d-factors"></div>'
        '  </div>'
        '</div>'
    )


def _js_drawer() -> str:
    return (
        "(function(){"
        "var BC={HIGH:'#15803d',MEDIUM:'#d97706',LOW:'#ea580c','VERY LOW':'#dc2626'};"
        "var BB={HIGH:'#dcfce7',MEDIUM:'#fef3c7',LOW:'#ffedd5','VERY LOW':'#fee2e2'};"
        "var SL={esql:'ES|QL',query:'Query (KQL)',eql:'EQL',threshold:'Threshold',"
        "        new_terms:'New Terms',threat_match:'Indicator Match',manual:'Manual review'};"
        "function esc(s){"
        "  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')"
        "    .replace(/>/g,'&gt;').replace(/\"/g,'&quot;');"
        "}"
        "var ov=document.getElementById('d-overlay');"
        "var pn=document.getElementById('d-panel');"
        "function open(r){"
        "  var band=r.band||'VERY LOW';"
        "  var bc=BC[band]||'#6b7280', bb=BB[band]||'#f3f4f6';"
        "  var strat=SL[r.strategy]||r.strategy;"
        "  var pct=Math.round(r.confidence*100);"
        "  document.getElementById('d-name').textContent=r.name;"
        "  document.getElementById('d-badges').innerHTML="
        "    (r.fingerprint?'<code style=\"color:#9ca3af;font-size:11px;margin-right:6px\">'+esc(r.fingerprint)+'</code>':'')"
        "    +'<span class=\"badge\" style=\"color:'+bc+';background:'+bb+'\">'+esc(band)+'</span> '"
        "    +'<span class=\"tag\">'+esc(r.source_type)+'</span> '"
        "    +'<span class=\"tag\">'+esc(strat)+'</span>';"
        "  document.getElementById('d-conf').innerHTML="
        "    '<div class=\"d-sec-title\">Confidence</div>'"
        "    +'<div class=\"conf-cell\">'"
        "    +'<div class=\"conf-bar\"><div class=\"conf-fill\" style=\"width:'+pct+'%;background:'+bc+'\"></div></div>'"
        "    +'<span>'+pct+'%</span>'"
        "    +(r.needs_review"
        "      ?'<span style=\"color:#b45309;font-weight:600;margin-left:10px\">⚠ Review needed</span>'"
        "      :'<span style=\"color:#15803d;margin-left:10px\">✓ OK</span>')"
        "    +'</div>';"
        "  var MIGL={machine_learning:'Machine Learning',eql:'EQL (event correlation)',"
        "            indicator_match:'Indicator Match'};"
        "  var MIGHINT={"
        "    machine_learning:'Separate file, not shown above. References an ML job "
        "(no query language) — requires manual job setup + training. See the ML job "
        "section below and the companion _ml_job.toml file.',"
        "    eql:'Naming heuristic only (module name suggests a sequence/chain "
        "pattern) — Rosetta cannot read the Python logic, verify manually before "
        "committing to EQL.',"
        "    indicator_match:'Separate file, not shown above — uses KQL "
        "(language=\"kuery\"), never ES|QL. Requires a threat intel index "
        "populated with the listed values — see the companion "
        "_indicator_match.toml file and its populate script.'"
        "  };"
        "  var msec=document.getElementById('d-migration');"
        "  if(r.migration_strategy){"
        "    var mlabel=MIGL[r.migration_strategy]||r.migration_strategy;"
        "    var mhint=MIGHINT[r.migration_strategy]||'';"
        "    var hasScore=(r.migration_score!==null&&r.migration_score!==undefined);"
        "    var mpct=hasScore?Math.round(r.migration_score*100):0;"
        "    msec.innerHTML='<div class=\"d-sec-title\">Recommended migration path "
        "(separate companion file)</div>'"
        "      +'<div class=\"conf-cell\">'"
        "      +'<span class=\"tag mig-tag\">'+esc(mlabel)+'</span>'"
        "      +(hasScore"
        "        ?('<div class=\"conf-bar\"><div class=\"conf-fill\" style=\"width:'+mpct+'%;background:#6d28d9\"></div></div>'"
        "          +'<span>'+mpct+'% mapping fidelity</span>')"
        "        :'<span style=\"color:#9ca3af;font-size:12px\">heuristic — no fidelity score</span>')"
        "      +'</div>'"
        "      +(mhint?'<div style=\"font-size:12px;color:#6b7280;margin-top:6px\">'+esc(mhint)+'</div>':'');"
        "    msec.style.display='';"
        "  } else { msec.style.display='none'; }"
        "  var pbsec=document.getElementById('d-prebuilt');"
        "  if(r.prebuilt_hint){"
        "    var ph=r.prebuilt_hint;"
        "    var phBody;"
        "    if(ph.error){"
        "      phBody='<div style=\"font-size:12px;color:#6b7280\">Category guessed: <b>'+esc(ph.category)+"
        "        '</b> — live lookup failed ('+esc(ph.error)+'). <a href=\"'+esc(ph.browse_url)+'\" target=\"_blank\">Browse manually</a>.</div>';"
        "    } else if(ph.candidates&&ph.candidates.length){"
        "      phBody='<div style=\"font-size:12px;color:#6b7280;margin-bottom:4px\">Category: <b>'+esc(ph.category)+"
        "        '</b> — Rosetta retrieves candidates (like the semantic search step in Elastic\\'s own "
        "Automatic Migration for Splunk/QRadar); judging \"same intent\" is on you (or an LLM), not Rosetta:</div>'"
        "        +'<ul class=\"warn-list\">'+ph.candidates.map(function(c){"
        "          var title=c.name?esc(c.name):esc(c.filename);"
        "          var extra='';"
        "          if(c.description){extra+='<div style=\"color:#6b7280;margin-top:2px\">'+esc(c.description)+'</div>';}"
        "          if(c.query_excerpt){extra+='<div style=\"font-family:ui-monospace,monospace;font-size:11px;color:#9ca3af;margin-top:2px\">'+esc(c.query_excerpt)+'</div>';}"
        "          return '<li><a href=\"'+esc(c.url)+'\" target=\"_blank\">'+title+'</a>'+extra+'</li>';"
        "        }).join('')+'</ul>';"
        "    } else {"
        "      phBody='<div style=\"font-size:12px;color:#6b7280\">Category: <b>'+esc(ph.category)+"
        "        '</b> — no filename overlap found, but worth a look: <a href=\"'+esc(ph.browse_url)+'\" target=\"_blank\">browse</a>.</div>';"
        "    }"
        "    pbsec.innerHTML='<div class=\"d-sec-title\">Possible Elastic prebuilt overlap (live GitHub lookup, informational only)</div>'+phBody;"
        "    pbsec.style.display='';"
        "  } else { pbsec.style.display='none'; }"
        "  var wsec=document.getElementById('d-warns');"
        "  if(r.warnings&&r.warnings.length){"
        "    wsec.innerHTML='<div class=\"d-sec-title\">Warnings ('+r.warnings.length+')</div>'"
        "      +'<ul class=\"warn-list\">'+r.warnings.map(function(w){"
        "          return '<li>'+esc(w)+'</li>';}).join('')+'</ul>';"
        "    wsec.style.display='';"
        "  } else { wsec.style.display='none'; }"
        "  var qsec=document.getElementById('d-query');"
        "  var q=r.esql_query||r.kql_query||'';"
        "  if(q){"
        "    var lang=r.esql_query?'ES|QL Query — delivered rule (this file)':'KQL Query — delivered rule (this file)';"
        "    qsec.innerHTML='<div class=\"d-sec-title\">'+lang+'</div>'"
        "      +'<pre class=\"esql\">'+esc(q)+'</pre>';"
        "    qsec.style.display='';"
        "  } else { qsec.style.display='none'; }"
        "  var ssec=document.getElementById('d-source');"
        "  if(r.source_yaml){"
        "    ssec.innerHTML='<div class=\"d-sec-title\">Source ElastAlert rule (YAML)</div>'"
        "      +'<pre class=\"esql\" style=\"color:#a6e3a1\">'+esc(r.source_yaml)+'</pre>';"
        "    ssec.style.display='';"
        "  } else { ssec.style.display='none'; }"
        "  var msec3=document.getElementById('d-mljob');"
        "  if(r.ml_job_commands){"
        "    msec3.innerHTML='<div class=\"d-sec-title\">Optional ML anomaly-detection job (ready to run)</div>'"
        "      +'<pre class=\"esql\">'+esc(r.ml_job_commands)+'</pre>';"
        "    msec3.style.display='';"
        "  } else if(r.indicator_match_commands){"
        "    msec3.innerHTML='<div class=\"d-sec-title\">Optional Indicator Match setup (ready to run — creates &amp; populates the threat index)</div>'"
        "      +'<pre class=\"esql\">'+esc(r.indicator_match_commands)+'</pre>';"
        "    msec3.style.display='';"
        "  } else { msec3.style.display='none'; }"
        "  var fsec=document.getElementById('d-factors');"
        "  if(r.factors&&r.factors.length){"
        "    var rows=r.factors.map(function(f){"
        "      var d=f.delta,cls=d>0?'pos':d<0?'neg':'neu',sign=d>0?'+':'';"
        "      return '<div class=\"factor-row\">'"
        "        +'<span class=\"delta '+cls+'\">'+sign+d.toFixed(3)+'</span>'"
        "        +'<span>'+esc(f.label)+'</span>'"
        "        +(f.detail?'<span class=\"factor-detail\">— '+esc(f.detail)+'</span>':'')"
        "        +'</div>';"
        "    }).join('');"
        "    fsec.innerHTML='<div class=\"d-sec-title\">Score factors</div>'+rows;"
        "    fsec.style.display='';"
        "  } else { fsec.style.display='none'; }"
        "  ov.classList.add('open'); pn.classList.add('open');"
        "  document.body.style.overflow='hidden';"
        "}"
        "function close(){"
        "  ov.classList.remove('open'); pn.classList.remove('open');"
        "  document.body.style.overflow='';"
        "}"
        "ov.addEventListener('click',close);"
        "document.getElementById('d-close').addEventListener('click',close);"
        "document.addEventListener('keydown',function(e){if(e.key==='Escape')close();});"
        "document.querySelectorAll('tr[data-rule]').forEach(function(row){"
        "  row.addEventListener('click',function(){"
        "    open(JSON.parse(row.dataset.rule));"
        "  });"
        "});"
        "})();"
    )


def _js_filter() -> str:
    """Barre de recherche (nom/ID de règle) + cartes stat cliquables (bande de
    confiance) + lignes de la table 'Patterns by source type' cliquables
    (filtre par source_type). Les trois filtres se combinent (ET)."""
    return (
        "(function(){"
        "var activeBand=null;"
        "var activeType=null;"
        "var search=document.getElementById('search-name');"
        "var hint=document.getElementById('filter-hint');"
        "var rows=Array.from(document.querySelectorAll('table tbody tr[data-rule]'));"
        "var cards=Array.from(document.querySelectorAll('.stat-card-filterable'));"
        "var patternRows=Array.from(document.querySelectorAll('.patterns-table tbody tr'));"
        "function apply(){"
        "  var q=search?search.value.trim().toLowerCase():'';"
        "  var shown=0;"
        "  rows.forEach(function(r){"
        "    var nameOk=!q||r.cells[0].textContent.toLowerCase().indexOf(q)!==-1"
        "      ||r.cells[1].textContent.toLowerCase().indexOf(q)!==-1;"
        "    var band=r.dataset.band;"
        "    var bandOk=!activeBand||band===activeBand"
        "      ||(activeBand==='LOW_VERYLOW'&&(band==='LOW'||band==='VERY LOW'));"
        "    var typeOk=!activeType||r.dataset.sourceType===activeType;"
        "    var visible=nameOk&&bandOk&&typeOk;"
        "    r.style.display=visible?'':'none';"
        "    if(visible)shown++;"
        "  });"
        "  if(hint){"
        "    if(activeBand||q||activeType){"
        "      hint.style.display='';"
        "      hint.querySelector('span').textContent=shown+' / '+rows.length+' rule(s)'"
        "        +(activeType?' · type: '+activeType:'');"
        "    } else { hint.style.display='none'; }"
        "  }"
        "}"
        "if(search)search.addEventListener('input',apply);"
        "cards.forEach(function(c){"
        "  c.addEventListener('click',function(){"
        "    var b=c.dataset.bandFilter;"
        "    if(activeBand===b){activeBand=null;c.classList.remove('active');}"
        "    else{"
        "      cards.forEach(function(x){x.classList.remove('active');});"
        "      activeBand=b;c.classList.add('active');"
        "    }"
        "    apply();"
        "  });"
        "});"
        "patternRows.forEach(function(pr){"
        "  pr.addEventListener('click',function(){"
        "    var t=pr.cells[0].textContent.trim();"
        "    if(activeType===t){activeType=null;pr.classList.remove('active-pattern');}"
        "    else{"
        "      patternRows.forEach(function(x){x.classList.remove('active-pattern');});"
        "      activeType=t;pr.classList.add('active-pattern');"
        "    }"
        "    apply();"
        "  });"
        "});"
        "if(hint){"
        "  var clearBtn=hint.querySelector('button');"
        "  if(clearBtn)clearBtn.addEventListener('click',function(){"
        "    activeBand=null; activeType=null; if(search)search.value='';"
        "    cards.forEach(function(x){x.classList.remove('active');});"
        "    patternRows.forEach(function(x){x.classList.remove('active-pattern');});"
        "    apply();"
        "  });"
        "}"
        "})();"
    )


def _js_share_drawer() -> str:
    """Variante de _js_drawer() pour les données SANITISÉES (pas de nom, pas de
    requête en clair) : le Rule ID tient lieu de titre, et les emplacements
    'query'/'source' du tiroir affichent le squelette ES|QL et la forme des
    filtres plutôt que du texte en clair."""
    return (
        "(function(){"
        "var BC={HIGH:'#15803d',MEDIUM:'#d97706',LOW:'#ea580c','VERY LOW':'#dc2626'};"
        "var BB={HIGH:'#dcfce7',MEDIUM:'#fef3c7',LOW:'#ffedd5','VERY LOW':'#fee2e2'};"
        "var SL={esql:'ES|QL',query:'Query (KQL)',eql:'EQL',threshold:'Threshold',"
        "        new_terms:'New Terms',threat_match:'Indicator Match',manual:'Manual review'};"
        "function esc(s){"
        "  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')"
        "    .replace(/>/g,'&gt;').replace(/\"/g,'&quot;');"
        "}"
        "var ov=document.getElementById('d-overlay');"
        "var pn=document.getElementById('d-panel');"
        "function open(r){"
        "  var c=r.confidence;"
        "  var band=c>=0.85?'HIGH':c>=0.6?'MEDIUM':c>=0.3?'LOW':'VERY LOW';"
        "  var bc=BC[band]||'#6b7280', bb=BB[band]||'#f3f4f6';"
        "  var strat=SL[r.strategy]||r.strategy;"
        "  var pct=Math.round(r.confidence*100);"
        "  document.getElementById('d-name').textContent=r.fingerprint||'(no id)';"
        "  document.getElementById('d-badges').innerHTML="
        "    '<span class=\"badge\" style=\"color:'+bc+';background:'+bb+'\">'+esc(band)+'</span> '"
        "    +'<span class=\"tag\">'+esc(r.source_type)+'</span> '"
        "    +'<span class=\"tag\">'+esc(strat)+'</span>';"
        "  document.getElementById('d-conf').innerHTML="
        "    '<div class=\"d-sec-title\">Confidence</div>'"
        "    +'<div class=\"conf-cell\">'"
        "    +'<div class=\"conf-bar\"><div class=\"conf-fill\" style=\"width:'+pct+'%;background:'+bc+'\"></div></div>'"
        "    +'<span>'+pct+'%</span>'"
        "    +(r.needs_review"
        "      ?'<span style=\"color:#b45309;font-weight:600;margin-left:10px\">⚠ Review needed</span>'"
        "      :'<span style=\"color:#15803d;margin-left:10px\">✓ OK</span>')"
        "    +'</div>';"
        "  var MIGL2={machine_learning:'Machine Learning',eql:'EQL (event correlation)',"
        "             indicator_match:'Indicator Match'};"
        "  var msec2=document.getElementById('d-migration');"
        "  if(r.migration_strategy){"
        "    var mlabel2=MIGL2[r.migration_strategy]||r.migration_strategy;"
        "    var hasScore2=(r.migration_score!==null&&r.migration_score!==undefined);"
        "    var mpct2=hasScore2?Math.round(r.migration_score*100):0;"
        "    msec2.innerHTML='<div class=\"d-sec-title\">Recommended migration path "
        "(separate companion file)</div>'"
        "      +'<div class=\"conf-cell\">'"
        "      +'<span class=\"tag mig-tag\">'+esc(mlabel2)+'</span>'"
        "      +(hasScore2"
        "        ?('<div class=\"conf-bar\"><div class=\"conf-fill\" style=\"width:'+mpct2+'%;background:#6d28d9\"></div></div>'"
        "          +'<span>'+mpct2+'% mapping fidelity</span>')"
        "        :'<span style=\"color:#9ca3af;font-size:12px\">heuristic — no fidelity score</span>')"
        "      +'</div>'"
        "      +'<div style=\"font-size:12px;color:#6b7280;margin-top:6px\">Not shown above "
        "(different query language than the delivered rule) — see the full report "
        "for ready-to-run commands and the companion file.</div>';"
        "    msec2.style.display='';"
        "  } else { msec2.style.display='none'; }"
        "  var pbsec2=document.getElementById('d-prebuilt');"
        "  if(r.prebuilt_hint){"
        "    var ph2=r.prebuilt_hint;"
        "    var phBody2;"
        "    if(ph2.error){"
        "      phBody2='<div style=\"font-size:12px;color:#6b7280\">Category guessed: <b>'+esc(ph2.category)+"
        "        '</b> — live lookup failed. <a href=\"'+esc(ph2.browse_url)+'\" target=\"_blank\">Browse manually</a>.</div>';"
        "    } else if(ph2.candidates&&ph2.candidates.length){"
        "      phBody2='<div style=\"font-size:12px;color:#6b7280;margin-bottom:4px\">Category: <b>'+esc(ph2.category)+"
        "        '</b> — retrieval candidates (judgment is on you, not Rosetta):</div>'"
        "        +'<ul class=\"warn-list\">'+ph2.candidates.map(function(c){"
        "          var title=c.name?esc(c.name):esc(c.filename);"
        "          var extra='';"
        "          if(c.description){extra+='<div style=\"color:#6b7280;margin-top:2px\">'+esc(c.description)+'</div>';}"
        "          if(c.query_excerpt){extra+='<div style=\"font-family:ui-monospace,monospace;font-size:11px;color:#9ca3af;margin-top:2px\">'+esc(c.query_excerpt)+'</div>';}"
        "          return '<li><a href=\"'+esc(c.url)+'\" target=\"_blank\">'+title+'</a>'+extra+'</li>';"
        "        }).join('')+'</ul>';"
        "    } else {"
        "      phBody2='<div style=\"font-size:12px;color:#6b7280\">Category: <b>'+esc(ph2.category)+"
        "        '</b> — no filename overlap found: <a href=\"'+esc(ph2.browse_url)+'\" target=\"_blank\">browse</a>.</div>';"
        "    }"
        "    pbsec2.innerHTML='<div class=\"d-sec-title\">Possible Elastic prebuilt overlap (live GitHub lookup, informational only)</div>'+phBody2;"
        "    pbsec2.style.display='';"
        "  } else { pbsec2.style.display='none'; }"
        "  var wsec=document.getElementById('d-warns');"
        "  var codes=r.warning_codes||{};"
        "  var codeKeys=Object.keys(codes);"
        "  if(codeKeys.length){"
        "    wsec.innerHTML='<div class=\"d-sec-title\">Warning categories</div>'"
        "      +'<ul class=\"warn-list\">'+codeKeys.map(function(k){"
        "          return '<li>'+esc(k)+' \u00d7'+codes[k]+'</li>';}).join('')+'</ul>';"
        "    wsec.style.display='';"
        "  } else { wsec.style.display='none'; }"
        "  var qsec=document.getElementById('d-query');"
        "  var skel=r.esql_skeleton;"
        "  if(skel){"
        "    qsec.innerHTML='<div class=\"d-sec-title\">ES|QL skeleton</div>'"
        "      +'<code style=\"font-size:13px\">'+esc((skel.pipeline||[]).join(' | '))+'</code>'"
        "      +'<div style=\"display:flex;gap:20px;margin-top:8px;font-size:13px;flex-wrap:wrap\">'"
        "      +'<span><b>Functions:</b> '+esc((skel.functions||[]).join(', ')||'\u2014')+'</span>'"
        "      +'<span><b>Operators:</b> '+esc((skel.operators||[]).join(', ')||'\u2014')+'</span>'"
        "      +'<span><b>Aggregating:</b> '+(skel.is_aggregating?'Yes':'No')+'</span>'"
        "      +'</div>';"
        "    qsec.style.display='';"
        "  } else { qsec.style.display='none'; }"
        "  var ssec=document.getElementById('d-source');"
        "  var shapes=r.filter_shapes||[];"
        "  if(shapes.length){"
        "    ssec.innerHTML='<div class=\"d-sec-title\">Filter shapes ('+shapes.length+')</div>'"
        "      +shapes.map(function(s){"
        "        var parts=Object.keys(s).filter(function(k){return k!=='kind';})"
        "          .map(function(k){return k+'='+JSON.stringify(s[k]);}).join(', ');"
        "        return '<div class=\"factor-row\"><span>'+esc(s.kind)+'</span>'"
        "          +(parts?'<span class=\"factor-detail\">\u2014 '+esc(parts)+'</span>':'')+'</div>';"
        "      }).join('');"
        "    ssec.style.display='';"
        "  } else { ssec.style.display='none'; }"
        "  var msec=document.getElementById('d-mljob');"
        "  if(r.ml_job_recommended){"
        "    msec.innerHTML='<div class=\"d-sec-title\">ML anomaly-detection job</div>'"
        "      +'<div style=\"font-size:13px;color:#6b7280\">Recommended for this rule — the "
        "ready-to-run commands are not included here (sanitized report). See the full report "
        "for this rule\\'s note field.</div>';"
        "    msec.style.display='';"
        "  } else { msec.style.display='none'; }"
        "  var fsec=document.getElementById('d-factors');"
        "  var rowsHtml='';"
        "  if(r.factors&&r.factors.length){"
        "    rowsHtml=r.factors.map(function(f){"
        "      var d=f.delta,cls=d>0?'pos':d<0?'neg':'neu',sign=d>0?'+':'';"
        "      return '<div class=\"factor-row\">'"
        "        +'<span class=\"delta '+cls+'\">'+sign+d.toFixed(3)+'</span>'"
        "        +'<span>'+esc(f.label)+'</span>'"
        "        +'</div>';"
        "    }).join('');"
        "  }"
        "  var flags=[];"
        "  if(r.uses_query_key)flags.push('uses query_key');"
        "  if(r.has_timeframe)flags.push('has timeframe');"
        "  if(r.has_custom_detection_code)flags.push('custom detection code');"
        "  if(r.ml_job_recommended)flags.push('ML job recommended');"
        "  if((r.custom_action_categories||[]).length)flags.push('custom actions: '+r.custom_action_categories.join(', '));"
        "  var extras=flags.length"
        "    ?'<div class=\"factor-row\"><span class=\"factor-detail\">'+esc(flags.join(' \u00b7 '))+'</span></div>'"
        "    :'';"
        "  if(rowsHtml||extras){"
        "    fsec.innerHTML='<div class=\"d-sec-title\">Score factors</div>'+rowsHtml+extras;"
        "    fsec.style.display='';"
        "  } else { fsec.style.display='none'; }"
        "  ov.classList.add('open'); pn.classList.add('open');"
        "  document.body.style.overflow='hidden';"
        "}"
        "function close(){"
        "  ov.classList.remove('open'); pn.classList.remove('open');"
        "  document.body.style.overflow='';"
        "}"
        "ov.addEventListener('click',close);"
        "document.getElementById('d-close').addEventListener('click',close);"
        "document.addEventListener('keydown',function(e){if(e.key==='Escape')close();});"
        "document.querySelectorAll('tr[data-rule]').forEach(function(row){"
        "  row.addEventListener('click',function(){"
        "    open(JSON.parse(row.dataset.rule));"
        "  });"
        "});"
        "})();"
    )


def _html_page(title: str, subtitle: str, body: str) -> str:
    return (
        f'<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        f'<meta charset="utf-8">\n'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f'<title>{_e(title)}</title>\n'
        f'<style>{_css()}</style>\n'
        f'</head>\n<body>\n'
        f'<h1>{_e(title)}</h1>\n'
        f'<p class="subtitle">{subtitle}</p>\n'
        f'{body}'
        f'</body>\n</html>'
    )


# ---------------------------------------------------------------------------
# report_to_html
# ---------------------------------------------------------------------------

def report_to_html(report: list[dict[str, Any]], source_paths: str = "") -> str:
    """Generates an HTML page from the report produced by cmd_report."""
    total = len(report)
    by_band: dict[str, int] = {}
    for r in report:
        by_band[r["band"]] = by_band.get(r["band"], 0) + 1

    needs_review = sum(1 for r in report if r["needs_review"])
    esql_count = sum(1 for r in report if r["strategy"] == "esql")
    avg_conf = sum(r["confidence"] for r in report) / total if total else 0.0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    stats = (
        _stat_card(total, "Total rules")
        + _stat_card(by_band.get("HIGH", 0), "High confidence", "#15803d", band_filter="HIGH")
        + _stat_card(by_band.get("MEDIUM", 0), "Medium confidence", "#d97706", band_filter="MEDIUM")
        + _stat_card(by_band.get("LOW", 0) + by_band.get("VERY LOW", 0),
                     "Low / Very Low", "#b91c1c", band_filter="LOW_VERYLOW")
        + _stat_card(needs_review, "Need review",
                     "#b45309" if needs_review else "#6b7280")
        + _stat_card(f"{esql_count}/{total}", "Migrate to ES|QL")
        + _stat_card(f"{avg_conf:.0%}", "Avg confidence")
    )

    rows = []
    for r in report:
        band = r["band"]
        strat = _STRATEGY_LABEL.get(r["strategy"], r["strategy"])
        rev_cls = "rev-yes" if r["needs_review"] else "rev-no"
        rev_txt = "⚠ Review" if r["needs_review"] else "—"
        nw = len(r.get("warnings", []))
        fp = r.get("fingerprint", "")
        rule_json = _html.escape(_json.dumps(r, ensure_ascii=False), quote=True)
        rows.append(
            f'<tr data-rule="{rule_json}" data-band="{_e(band)}" data-source-type="{_e(r["source_type"])}">'
            f'<td>{_e(r["name"])}</td>'
            f'<td><code class="fp-code">{_e(fp) if fp else "—"}</code></td>'
            f'<td><span class="tag">{_e(r["source_type"])}</span></td>'
            f'<td><span class="tag">{_e(strat)}</span>{_migration_badge(r)}</td>'
            f'<td data-val="{r["confidence"]}">{_conf_bar(r["confidence"], band)}</td>'
            f'<td data-val="{1 if r["needs_review"] else 0}" class="{rev_cls}">{rev_txt}</td>'
            f'<td data-val="{nw}">{nw or "—"}</td>'
            f'</tr>'
        )

    subtitle_src = f" · Source: {_e(source_paths)}" if source_paths else ""
    subtitle = f"Generated {now}{subtitle_src}"

    body = (
        f'<div class="stats">{stats}</div>'
        f'<div class="dist-bar">{_dist_bar(by_band, total)}</div>'
        f'{_pattern_table_html(report)}'
        f'<div class="toolbar">'
        f'<input id="search-name" class="search-input" type="text" '
        f'placeholder="Filter by rule name or ID…" />'
        f'<span class="filter-hint" id="filter-hint" style="display:none">'
        f'<span></span> · <button type="button">Reset</button>'
        f'</span>'
        f'</div>'
        f'<table>'
        f'<thead><tr>'
        f'<th data-col="0">Rule name<span class="arrow"></span></th>'
        f'<th data-col="1">Rule ID<span class="arrow"></span></th>'
        f'<th data-col="2">Source type<span class="arrow"></span></th>'
        f'<th data-col="3">Strategy<span class="arrow"></span></th>'
        f'<th data-col="4">Confidence<span class="arrow"></span></th>'
        f'<th data-col="5">Review<span class="arrow"></span></th>'
        f'<th data-col="6">Warnings<span class="arrow"></span></th>'
        f'</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table>'
        f'{_drawer_html()}'
        f'<script>{_js_sort()}{_js_drawer()}{_js_filter()}</script>'
    )

    return _html_page("Rosetta Migration Report", subtitle, body)


# ---------------------------------------------------------------------------
# share_to_html
# ---------------------------------------------------------------------------

def share_to_html(report: dict[str, Any]) -> str:
    """Generates an HTML page from the sanitized report produced by cmd_share.

    Same table + click-to-open detail panel pattern as report_to_html, adapted
    to sanitized fields: Rule ID (fingerprint) stands in for the rule name
    everywhere a name would normally appear, and the detail panel shows the
    ES|QL skeleton / filter shapes / warning categories instead of literal
    query text, field names, or values.
    """
    rules: list[dict[str, Any]] = report.get("rules", [])
    total = report.get("rule_count", len(rules))
    tool_version = report.get("tool_version", "unknown")
    parse_errors = report.get("parse_errors", 0)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    by_band: dict[str, int] = {}
    for r in rules:
        band = _conf_to_band(r["confidence"])
        by_band[band] = by_band.get(band, 0) + 1

    needs_review = sum(1 for r in rules if r.get("needs_review"))
    avg_conf = sum(r["confidence"] for r in rules) / total if total else 0.0

    stats = (
        _stat_card(total, "Rules")
        + _stat_card(by_band.get("HIGH", 0), "High confidence", "#15803d", band_filter="HIGH")
        + _stat_card(by_band.get("MEDIUM", 0), "Medium confidence", "#d97706", band_filter="MEDIUM")
        + _stat_card(by_band.get("LOW", 0) + by_band.get("VERY LOW", 0),
                     "Low / Very Low", "#b91c1c", band_filter="LOW_VERYLOW")
        + _stat_card(needs_review, "Need review",
                     "#b45309" if needs_review else "#6b7280")
        + _stat_card(f"{avg_conf:.0%}", "Avg confidence")
    )
    if parse_errors:
        stats += _stat_card(parse_errors, "Parse errors", "#b91c1c")

    rows = []
    for r in rules:
        band = _conf_to_band(r["confidence"])
        strat = _STRATEGY_LABEL.get(r["strategy"], r["strategy"])
        rev_cls = "rev-yes" if r.get("needs_review") else "rev-no"
        rev_txt = "⚠ Review" if r.get("needs_review") else "—"
        nw = sum(r.get("warning_codes", {}).values())
        fp = r.get("fingerprint", "")
        rule_json = _html.escape(_json.dumps(r, ensure_ascii=False), quote=True)
        rows.append(
            f'<tr data-rule="{rule_json}" data-band="{_e(band)}" data-source-type="{_e(r.get("source_type", ""))}">'
            f'<td><code class="fp-code">{_e(fp) if fp else "—"}</code></td>'
            f'<td><span class="tag">{_e(r.get("source_type", ""))}</span></td>'
            f'<td><span class="tag">{_e(strat)}</span>{_migration_badge(r)}</td>'
            f'<td data-val="{r["confidence"]}">{_conf_bar(r["confidence"], band)}</td>'
            f'<td data-val="{1 if r.get("needs_review") else 0}" class="{rev_cls}">{rev_txt}</td>'
            f'<td data-val="{nw}">{nw or "—"}</td>'
            f'</tr>'
        )

    subtitle = (
        f"Generated {now} · "
        f"Tool version {_e(tool_version)} · "
        f"No sensitive data included"
    )
    body = (
        f'<div class="stats">{stats}</div>'
        f'<div class="dist-bar">{_dist_bar(by_band, total)}</div>'
        f'{_pattern_table_html(rules)}'
        f'<div class="toolbar">'
        f'<input id="search-name" class="search-input" type="text" '
        f'placeholder="Filter by rule ID…" />'
        f'<span class="filter-hint" id="filter-hint" style="display:none">'
        f'<span></span> · <button type="button">Reset</button>'
        f'</span>'
        f'</div>'
        f'<table>'
        f'<thead><tr>'
        f'<th data-col="0">Rule ID<span class="arrow"></span></th>'
        f'<th data-col="1">Source type<span class="arrow"></span></th>'
        f'<th data-col="2">Strategy<span class="arrow"></span></th>'
        f'<th data-col="3">Confidence<span class="arrow"></span></th>'
        f'<th data-col="4">Review<span class="arrow"></span></th>'
        f'<th data-col="5">Warnings<span class="arrow"></span></th>'
        f'</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table>'
        f'{_drawer_html()}'
        f'<script>{_js_sort()}{_js_share_drawer()}{_js_filter()}</script>'
    )

    return _html_page("Rosetta Sanitized Share Report", subtitle, body)
