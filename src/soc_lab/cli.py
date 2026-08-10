from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze, render_markdown
from .reporting import render_html


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Windows/Sysmon JSONL telemetry for a simulated SOC incident."
    )
    parser.add_argument("events", type=Path, help="Path to the JSONL event file")
    parser.add_argument("--json", type=Path, dest="json_output", help="Write JSON findings")
    parser.add_argument(
        "--markdown", type=Path, dest="markdown_output", help="Write Markdown findings"
    )
    parser.add_argument("--html", type=Path, dest="html_output", help="Write interactive HTML dashboard")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    result = analyze(args.events)

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(render_markdown(result), encoding="utf-8")
    if args.html_output:
        args.html_output.parent.mkdir(parents=True, exist_ok=True)
        args.html_output.write_text(render_html(result), encoding="utf-8")

    print(json.dumps(result, indent=2))
    return 0
