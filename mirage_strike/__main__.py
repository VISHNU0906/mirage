"""CLI entry point: ``python -m mirage_strike --target http://localhost:8000``.

Runs every exploit module against a live MIRAGE server and writes a Markdown +
SARIF report.  Prints a per-module VULNERABLE/blocked summary and exits 1 if
any exploit succeeded (so it can gate CI on a known-good baseline).
"""

from __future__ import annotations

import argparse
import sys

from .client import TargetClient
from .report import write_reports
from .runner import run_all


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mirage-strike")
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Base URL of the running MIRAGE app.",
    )
    parser.add_argument("--md", default="mirage-strike-report.md", help="Markdown out")
    parser.add_argument("--sarif", default="mirage-strike-report.sarif", help="SARIF out")
    parser.add_argument(
        "--mode",
        default="auto",
        help="Label for the report (insecure / secure / auto). "
        "'auto' asks the target's /healthz which mode it is in.",
    )
    args = parser.parse_args(argv)

    def make_client():
        return TargetClient(base_url=args.target)

    mode = args.mode
    if mode == "auto":
        # Detect the target's actual mode so the report label is never wrong.
        try:
            probe = make_client().get("/healthz").json()
            mode = "secure" if probe.get("secure") else "insecure"
        except Exception:
            mode = "unknown"

    print(f"[mirage-strike] target = {args.target} (mode: {mode})")
    results = run_all(make_client)

    exploited = 0
    for r in results:
        status = "VULNERABLE" if r.success else "blocked"
        marker = "[!]" if r.success else "[ ]"
        print(f"  {marker} {r.vuln_id:18s} {status:11s} {r.name}")
        if r.success:
            exploited += 1

    write_reports(results, args.target, mode, args.md, args.sarif)
    print(
        f"[mirage-strike] {exploited}/{len(results)} exploits succeeded. "
        f"Reports: {args.md}, {args.sarif}"
    )
    return 1 if exploited else 0


if __name__ == "__main__":
    raise SystemExit(main())
