#!/usr/bin/env python3
"""Fail if docs/spec-pins holds anything beyond link/version/hash metadata.

Allowed: spec-pins.json (list of objects with a fixed key set and short string
values) and README.md (short lines, links and metadata only). Any other file,
key, long value or long prose line is treated as possibly copied spec text.
Usage: scripts/check_spec_pins.py [DIR]
"""
import json, re, sys
from pathlib import Path

KEYS = {"id", "title", "canonical_url", "version_date_status", "retrieved", "sha256", "license_terms", "notes"}
MAX_VALUE = 600       # characters per metadata value
MAX_README_LINE = 240  # characters per README line
SHA = re.compile(r"^[0-9a-f]{64}$")


def check(d: Path):
    errs = []
    for f in sorted(p for p in d.rglob("*") if p.is_file()):
        rel = f.relative_to(d)
        if f.name == "spec-pins.json":
            try:
                pins = json.loads(f.read_text())
            except ValueError as e:
                errs.append(f"{rel}: invalid JSON: {e}"); continue
            if not isinstance(pins, list):
                errs.append(f"{rel}: top level must be a list"); continue
            for i, p in enumerate(pins):
                if not isinstance(p, dict):
                    errs.append(f"{rel}[{i}]: not an object"); continue
                extra = set(p) - KEYS
                if extra:
                    errs.append(f"{rel}[{i}]: unexpected keys {sorted(extra)}")
                for k, v in p.items():
                    if not isinstance(v, str):
                        errs.append(f"{rel}[{i}].{k}: must be a string")
                    elif len(v) > MAX_VALUE:
                        errs.append(f"{rel}[{i}].{k}: {len(v)} chars > {MAX_VALUE} (possible copied text)")
                if not SHA.match(str(p.get("sha256", ""))):
                    errs.append(f"{rel}[{i}]: sha256 missing or malformed")
                if not str(p.get("canonical_url", "")).startswith("https://"):
                    errs.append(f"{rel}[{i}]: canonical_url must be https")
        elif f.name == "README.md":
            for n, line in enumerate(f.read_text().splitlines(), 1):
                if len(line) > MAX_README_LINE:
                    errs.append(f"{rel}:{n}: line longer than {MAX_README_LINE} chars")
        else:
            errs.append(f"{rel}: only spec-pins.json and README.md are allowed")
    return errs


if __name__ == "__main__":
    d = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/spec-pins")
    errs = check(d)
    for e in errs:
        print("FAIL", e)
    print(f"spec-pins check: {'FAIL' if errs else 'PASS'} ({len(errs)} problems)")
    sys.exit(1 if errs else 0)
