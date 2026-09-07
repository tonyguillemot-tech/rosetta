"""Interface en ligne de commande pour la migration ElastAlert -> Elastic Security.

Exemples :
    python -m rosetta convert examples/elastalert_rules -o rules/
    python -m rosetta report examples/elastalert_rules
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

from .converters.registry import convert
from .detection_rule.toml_writer import to_toml, to_toml_indicator_match_companion, to_toml_ml_companion
from .html_writer import report_to_html, share_to_html
from .models import RuleStrategy
from .parser.elastalert import parse_directory, parse_file
from .sanitize import rule_fingerprint, sanitize_report
from .scoring.confidence import confidence_band, score


def _slug(name: str) -> str:
    s = re.sub(r"[^\w]+", "_", name.lower()).strip("_")
    return s or "rule"


def _process(paths: list[Path], check_prebuilt: bool = False):
    rules = []
    for p in paths:
        if p.is_dir():
            rules.extend(parse_directory(p))
        else:
            rules.append(parse_file(p))
    results = []
    for rule in rules:
        res = convert(rule)
        res = score(res)
        if check_prebuilt:
            _attach_prebuilt_hint(res)
        results.append(res)
    return results


def _attach_prebuilt_hint(res) -> None:
    """Appel réseau LIVE, optionnel — jamais activé par défaut, jamais fatal
    si le réseau est indisponible (cf. prebuilt_match.py)."""
    from .field_hints import _extract_one
    from .prebuilt_match import fetch_prebuilt_hint

    rule = res.source
    fields = []
    for flt in rule.filters:
        fields.extend(f for f, _ in _extract_one(flt))
    for k in ("query_key", "compare_key"):
        v = rule.get(k)
        if isinstance(v, str):
            fields.append(v)
    hint = fetch_prebuilt_hint(rule.index or "", rule.name, fields)
    if hint is None:
        return
    res.metadata["prebuilt_hint"] = {
        "category": hint.category,
        "browse_url": hint.browse_url,
        "candidates": hint.candidates,
        "error": hint.error,
    }


def cmd_convert(args: argparse.Namespace) -> int:
    results = _process([Path(p) for p in args.inputs], check_prebuilt=args.check_prebuilt)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    threshold = args.min_confidence

    written = skipped = ml_written = 0
    for res in results:
        if res.confidence < threshold:
            skipped += 1
            band = confidence_band(res.confidence)
            print(f"[SKIP] {res.source.name} — confiance {res.confidence:.0%} ({band}) "
                  f"< seuil {threshold:.0%}")
            continue
        toml = to_toml(res, min_stack=args.min_stack)
        fname = f"{_slug(res.source.name)}.toml"
        (out_dir / fname).write_text(toml, encoding="utf-8")
        written += 1
        print(f"[OK]   {res.source.name} -> {fname} "
              f"({res.strategy.value}, {res.confidence:.0%})")

        ml_toml = to_toml_ml_companion(res, min_stack=args.min_stack)
        if ml_toml:
            ml_fname = f"{_slug(res.source.name)}_ml_job.toml"
            (out_dir / ml_fname).write_text(ml_toml, encoding="utf-8")
            ml_written += 1
            mig_score = res.metadata.get("migration_score")
            mig_txt = f", migration {mig_score:.0%}" if mig_score is not None else ""
            print(f"       + {ml_fname} (machine_learning, enabled=false{mig_txt} "
                  f"— voir sa note avant activation)")

        im_toml = to_toml_indicator_match_companion(res, min_stack=args.min_stack)
        if im_toml and res.strategy != RuleStrategy.THREAT_MATCH:
            # Si la stratégie EST déjà THREAT_MATCH (grosse liste IOC), le
            # fichier principal contient déjà tout ceci — un compagnon serait
            # redondant.
            im_fname = f"{_slug(res.source.name)}_indicator_match.toml"
            (out_dir / im_fname).write_text(im_toml, encoding="utf-8")
            ml_written += 1
            mig_score = res.metadata.get("migration_score")
            mig_txt = f", migration {mig_score:.0%}" if mig_score is not None else ""
            print(f"       + {im_fname} (threat_match, enabled=false{mig_txt} "
                  f"— voir sa note avant activation)")
    print(f"\n{written} règle(s) écrite(s), {skipped} ignorée(s) sous le seuil, "
          f"{ml_written} fichier(s) compagnon (ML/indicator_match).")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    results = _process([Path(p) for p in args.inputs], check_prebuilt=args.check_prebuilt)

    # Même logique de secret que `share` : avec --hmac-secret (ou
    # ROSETTA_HMAC_SECRET) IDENTIQUE des deux côtés, l'empreinte d'une règle
    # est la MÊME dans ce rapport complet et dans le rapport anonymisé
    # produit par `share` — le pont entre les deux sans jamais faire
    # transiter le nom de la règle par le canal anonymisé.
    secret_str = args.hmac_secret or os.environ.get("ROSETTA_HMAC_SECRET")
    secret = secret_str.encode("utf-8") if secret_str else secrets.token_bytes(32)
    if not secret_str:
        print("Avertissement : pas de --hmac-secret/ROSETTA_HMAC_SECRET — l'empreinte "
              "de ce rapport ne correspondra à aucun rapport 'share' généré séparément. "
              "Utilisez le même secret des deux côtés pour pouvoir les recouper.",
              file=sys.stderr)

    report = []
    for res in results:
        report.append({
            "fingerprint": rule_fingerprint(res, secret),
            "name": res.source.name,
            "source_type": res.source.rule_type,
            "strategy": res.strategy.value,
            "confidence": round(res.confidence, 3),
            "band": confidence_band(res.confidence),
            "needs_review": res.needs_review,
            "warnings": res.warnings,
            "esql_query": res.esql_query,
            "kql_query": res.kql_query,
            "migration_strategy": res.metadata.get("migration_strategy"),
            "migration_score": res.metadata.get("migration_score"),
            "prebuilt_hint": res.metadata.get("prebuilt_hint"),
            "ml_job_commands": res.metadata.get("ml_job_commands"),
            "indicator_match_commands": res.metadata.get("indicator_match_commands"),
            "source_yaml": yaml.dump(
                res.source.raw, allow_unicode=True,
                default_flow_style=False, sort_keys=False,
            ),
            "factors": [
                {"label": f.label, "delta": round(f.delta, 3), "detail": f.detail}
                for f in res.factors
            ],
        })
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.html:
        source_str = ", ".join(args.inputs)
        html = report_to_html(report, source_paths=source_str)
        if args.html is True:
            print(html)
        else:
            Path(args.html).write_text(html, encoding="utf-8")
            print(f"Rapport HTML écrit dans {args.html} ({len(report)} règle(s)).",
                  file=sys.stderr)
    else:
        _print_table(report)
    return 0


def _print_table(report: list[dict]) -> None:
    print(f"{'RÈGLE':<40} {'TYPE':<18} {'STRATÉGIE':<12} {'CONFIANCE':<14} REVUE")
    print("-" * 100)
    for r in report:
        review = "⚠ OUI" if r["needs_review"] else "non"
        print(f"{r['name'][:39]:<40} {r['source_type']:<18} {r['strategy']:<12} "
              f"{r['confidence']:.0%} ({r['band']})".ljust(14) + f"   {review}")
    avg = sum(r["confidence"] for r in report) / len(report) if report else 0
    print("-" * 100)
    print(f"Total : {len(report)} règle(s) — confiance moyenne {avg:.0%}")


def _count_yaml_files(paths: list[Path]) -> int:
    total = 0
    for p in paths:
        if p.is_dir():
            total += sum(1 for _ in p.rglob("*.yml")) + sum(1 for _ in p.rglob("*.yaml"))
        else:
            total += 1
    return total


def cmd_share(args: argparse.Namespace) -> int:
    """Produit une sortie sanitisée, partageable sans données sensibles.

    Le client lance cette commande sur ses règles confidentielles. La sortie
    ne contient AUCUN nom, valeur, champ, index ou requête en clair : seulement
    des types, scores, facteurs, et la structure des règles. Sûre à transmettre.
    """
    paths = [Path(p) for p in args.inputs]
    results = _process(paths)

    # Échecs de parsing = fichiers présents - règles chargées avec succès
    parse_errors = max(0, _count_yaml_files(paths) - len(results))

    # Secret HMAC pour les empreintes. Par défaut : aléatoire (empreintes
    # comparables seulement DANS ce rapport). Avec --hmac-secret ou la variable
    # ROSETTA_HMAC_SECRET : stable entre exécutions (suivi d'une règle dans le temps).
    secret_str = args.hmac_secret or os.environ.get("ROSETTA_HMAC_SECRET")
    secret = secret_str.encode("utf-8") if secret_str else secrets.token_bytes(32)

    report = sanitize_report(results, secret, parse_errors=parse_errors)

    if args.html:
        output = share_to_html(report)
        dest = args.html if args.html is not True else args.output
        if dest:
            Path(dest).write_text(output, encoding="utf-8")
            print(f"Rapport HTML sanitisé écrit dans {dest} "
                  f"({report['rule_count']} règle(s), {parse_errors} erreur(s) de parsing).",
                  file=sys.stderr)
        else:
            print(output)
    else:
        text = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"Rapport sanitisé écrit dans {args.output} "
                  f"({report['rule_count']} règle(s), {parse_errors} erreur(s) de parsing).",
                  file=sys.stderr)
            print("Aucune donnée sensible : noms, valeurs, champs et requêtes sont exclus.",
                  file=sys.stderr)
        else:
            print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rosetta",
                                description="Migration ElastAlert -> Elastic Security")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("convert", help="Convertir et écrire les fichiers TOML")
    c.add_argument("inputs", nargs="+", help="Fichiers ou dossiers de règles ElastAlert")
    c.add_argument("-o", "--output", default="rules", help="Dossier de sortie TOML")
    c.add_argument("--min-confidence", type=float, default=0.0,
                   help="Seuil de confiance minimal pour écrire (0..1)")
    c.add_argument("--min-stack", default="9.0.0", help="min_stack_version")
    c.add_argument("--check-prebuilt", action="store_true",
                   help="Interroge l'API GitHub (en direct, à l'exécution) pour "
                        "repérer des règles prebuilt Elastic potentiellement "
                        "déjà couvrantes — nécessite un accès réseau, jamais "
                        "activé par défaut, indicatif seulement (jamais une "
                        "correspondance certaine)")
    c.set_defaults(func=cmd_convert)

    r = sub.add_parser("report", help="Afficher un rapport de confiance sans écrire")
    r.add_argument("inputs", nargs="+")
    r.add_argument("--json", action="store_true", help="Sortie JSON")
    r.add_argument("--check-prebuilt", action="store_true",
                    help="Interroge l'API GitHub (en direct, à l'exécution) pour "
                         "repérer des règles prebuilt Elastic potentiellement "
                         "déjà couvrantes — nécessite un accès réseau, jamais "
                         "activé par défaut, indicatif seulement (jamais une "
                         "correspondance certaine)")
    r.add_argument("--hmac-secret", default=None,
                    help="Secret pour l'empreinte de règle (même valeur que "
                         "`share` pour recouper les deux rapports ; sinon via "
                         "ROSETTA_HMAC_SECRET, sinon aléatoire à chaque exécution)")
    r.add_argument("--html", nargs="?", const=True, metavar="FILE",
                   help="Sortie HTML (optionnel : chemin du fichier, sinon stdout)")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser(
        "share",
        help="Produire une sortie sanitisée partageable (sans données sensibles)")
    s.add_argument("inputs", nargs="+",
                   help="Fichiers ou dossiers de règles ElastAlert")
    s.add_argument("-o", "--output", default=None,
                   help="Fichier de sortie JSON (défaut : stdout)")
    s.add_argument("--hmac-secret", default=None,
                   help="Secret pour des empreintes stables entre exécutions "
                        "(sinon aléatoire ; aussi via ROSETTA_HMAC_SECRET)")
    s.add_argument("--html", nargs="?", const=True, metavar="FILE",
                   help="Sortie HTML au lieu de JSON (optionnel : chemin du fichier)")
    s.set_defaults(func=cmd_share)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
