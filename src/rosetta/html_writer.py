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


def _stat_card(val: object, label: str, color: str = "") -> str:
    style = f' style="color:{color}"' if color else ""
    return (f'<div class="stat-card">'
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
        ".conf-bar { width: 80px; height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; }"
        ".conf-fill { height: 100%; border-radius: 4px; }"
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
        '    <div class="d-sec" id="d-warns"></div>'
        '    <div class="d-sec" id="d-query"></div>'
        '    <div class="d-sec" id="d-source"></div>'
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
        "        new_terms:'New Terms',manual:'Manual review'};"
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
        "    var lang=r.esql_query?'ES|QL Query':'KQL Query';"
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
        + _stat_card(by_band.get("HIGH", 0), "High confidence", "#15803d")
        + _stat_card(by_band.get("MEDIUM", 0), "Medium confidence", "#d97706")
        + _stat_card(by_band.get("LOW", 0) + by_band.get("VERY LOW", 0),
                     "Low / Very Low", "#b91c1c")
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
        rule_json = _html.escape(_json.dumps(r, ensure_ascii=False), quote=True)
        rows.append(
            f'<tr data-rule="{rule_json}">'
            f'<td>{_e(r["name"])}</td>'
            f'<td><span class="tag">{_e(r["source_type"])}</span></td>'
            f'<td><span class="tag">{_e(strat)}</span></td>'
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
        f'<table>'
        f'<thead><tr>'
        f'<th data-col="0">Rule name<span class="arrow"></span></th>'
        f'<th data-col="1">Source type<span class="arrow"></span></th>'
        f'<th data-col="2">Strategy<span class="arrow"></span></th>'
        f'<th data-col="3">Confidence<span class="arrow"></span></th>'
        f'<th data-col="4">Review<span class="arrow"></span></th>'
        f'<th data-col="5">Warnings<span class="arrow"></span></th>'
        f'</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table>'
        f'{_drawer_html()}'
        f'<script>{_js_sort()}{_js_drawer()}</script>'
    )

    return _html_page("Rosetta Migration Report", subtitle, body)


# ---------------------------------------------------------------------------
# share_to_html
# ---------------------------------------------------------------------------

def share_to_html(report: dict[str, Any]) -> str:
    """Generates an HTML page from the sanitized report produced by cmd_share."""
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
        + _stat_card(by_band.get("HIGH", 0), "High confidence", "#15803d")
        + _stat_card(by_band.get("MEDIUM", 0), "Medium confidence", "#d97706")
        + _stat_card(by_band.get("LOW", 0) + by_band.get("VERY LOW", 0),
                     "Low / Very Low", "#b91c1c")
        + _stat_card(needs_review, "Need review",
                     "#b45309" if needs_review else "#6b7280")
        + _stat_card(f"{avg_conf:.0%}", "Avg confidence")
    )
    if parse_errors:
        stats += _stat_card(parse_errors, "Parse errors", "#b91c1c")

    sections: list[str] = []
    for i, r in enumerate(rules, 1):
        band = _conf_to_band(r["confidence"])
        fg_rev, _ = _BAND_COLOR.get(band, ("#374151", ""))
        strat = _STRATEGY_LABEL.get(r["strategy"], r["strategy"])
        fp = _e(r.get("fingerprint", ""))
        rev_label = "⚠ Review" if r.get("needs_review") else "OK"
        rev_color = "#b45309" if r.get("needs_review") else "#15803d"

        # Warnings
        warn_codes = r.get("warning_codes", {})
        warn_html = " ".join(
            f'<span class="badge warn-tag">{_e(code)} ×{count}</span>'
            for code, count in warn_codes.items()
        ) or "—"

        # ES|QL skeleton
        skel = r.get("esql_skeleton")
        if skel:
            pipeline = " | ".join(_e(s) for s in skel.get("pipeline", []))
            funcs = ", ".join(_e(f) for f in skel.get("functions", [])) or "—"
            ops = ", ".join(_e(o) for o in skel.get("operators", [])) or "—"
            agg = "Yes" if skel.get("is_aggregating") else "No"
            skel_block = (
                f'<div class="skel">'
                f'<div class="key" style="margin-bottom:5px">ES|QL skeleton</div>'
                f'<code style="font-size:13px">{pipeline}</code>'
                f'<div style="display:flex;gap:20px;margin-top:6px;font-size:13px">'
                f'<span><b>Functions:</b> {funcs}</span>'
                f'<span><b>Operators:</b> {ops}</span>'
                f'<span><b>Aggregating:</b> {agg}</span>'
                f'</div></div>'
            )
        else:
            skel_block = ""

        # Score factors
        factors_rows = ""
        for f in r.get("factors", []):
            delta = f["delta"]
            dcls = "pos" if delta > 0 else ("neg" if delta < 0 else "neu")
            sign = "+" if delta > 0 else ""
            factors_rows += (
                f'<div class="factor">'
                f'<span class="delta {dcls}">{sign}{delta:.3f}</span>'
                f'<span>{_e(f["label"])}</span>'
                f'</div>'
            )

        no_factors = '<div class="factor"><span style="color:#9ca3af">—</span></div>'
        sections.append(
            f'<div class="section">'
            f'<div class="sec-hdr">'
            f'<span style="color:#9ca3af">#{i}</span>'
            f'<code style="color:#6b7280;font-size:12px">{fp}</code>'
            f'{_badge(band)}'
            f'<span style="color:{rev_color};font-size:13px;font-weight:600">{rev_label}</span>'
            f'</div>'
            f'<div class="grid2">'
            f'<div class="cell"><div class="key">Source type</div>'
            f'<span class="tag">{_e(r.get("source_type", ""))}</span></div>'
            f'<div class="cell"><div class="key">Strategy</div>'
            f'<span class="tag">{_e(strat)}</span></div>'
            f'<div class="cell"><div class="key">Confidence</div>'
            f'<div style="margin-top:4px">{_conf_bar(r["confidence"], band)}</div></div>'
            f'<div class="cell"><div class="key">Filter count</div>'
            f'{r.get("filter_count", 0)}</div>'
            f'<div class="cell"><div class="key">Warnings</div>{warn_html}</div>'
            f'<div class="cell"><div class="key">Custom detection</div>'
            f'{"Yes" if r.get("has_custom_detection_code") else "No"}</div>'
            f'</div>'
            f'{skel_block}'
            f'<div class="factors-hdr">Score factors</div>'
            f'{factors_rows or no_factors}'
            f'</div>'
        )

    subtitle = (
        f"Generated {now} · "
        f"Tool version {_e(tool_version)} · "
        f"No sensitive data included"
    )
    body = (
        f'<div class="stats">{stats}</div>'
        f'<div class="dist-bar">{_dist_bar(by_band, total)}</div>'
        + "".join(sections)
    )

    return _html_page("Rosetta Sanitized Share Report", subtitle, body)
