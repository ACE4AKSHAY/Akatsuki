"""ECDAT CLI — python -m backend.scanners <path> [--scan-target-id ID] [--out file.json]

Wired up fully in T14. Defined now so the package layout from T0 is complete.
"""
from __future__ import annotations

import json
import sys

import click

from backend.scanners.binary_deps.scanner import scan_path as m2_scan
from backend.scanners.infra.scanner import scan_path as m3_scan
from backend.scanners.source.scanner import scan_repository as m1_scan


def _utc_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("scan_%Y_%m_%d_%H%M%S")


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("--scan-target-id", default=None, help="Override generated scan id.")
@click.option("--out", "-o", type=click.Path(dir_okay=False), default=None,
              help="Write findings JSON to this file (defaults to stdout).")
def main(path: str, scan_target_id: str | None, out: str | None) -> None:
    """Run M1/M2/M3 over PATH and emit raw findings JSON."""
    target_id = scan_target_id or _utc_timestamp()
    findings = []
    findings.extend(m1_scan(path, target_id))
    findings.extend(m2_scan(path, target_id))
    findings.extend(m3_scan(path, target_id))
    payload = json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=False)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.write("\n")
    else:
        click.echo(payload)
    sys.exit(0)


if __name__ == "__main__":
    main()