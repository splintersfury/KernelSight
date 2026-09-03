"""Scan __ksnav technique entries in mitigation pages for required verdict fields.

The configs are JS object literals inside markdown, so this parses by regex
rather than by evaluating them. Each technique entry is recognised by its
`name:` key; the three required fields are read from the same object body.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES = sorted((ROOT / "docs" / "mitigations").glob("*.md"))

VALID_LAYERS = {"kernel", "user"}
VALID_BASIS = {"tested", "cited", "inferred"}
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")

# One technique object: from `{ name:` up to the `ev:` key that closes the
# metadata run. Non-greedy so adjacent entries do not merge.
TECHNIQUE = re.compile(r"\{\s*name\s*:\s*(['\"])(?P<name>.*?)\1(?P<body>.*?)ev\s*:", re.S)


def _field(body, key):
    match = re.search(rf"{key}\s*:\s*(['\"])(.*?)\1", body, re.S)
    return match.group(2) if match else None


def scan():
    records = []
    for page in PAGES:
        text = page.read_text(encoding="utf-8")
        if "__ksnav" not in text:
            continue
        for match in TECHNIQUE.finditer(text):
            body = match.group("body")
            records.append({
                "file": page.name,
                "name": match.group("name"),
                "layer": _field(body, "layer"),
                "asOf": _field(body, "asOf"),
                "basis": _field(body, "basis"),
            })
    return records


def check(records):
    errors = []
    for record in records:
        where = f"{record['file']}: {record['name']}"
        if record["layer"] not in VALID_LAYERS:
            errors.append(f"{where}: layer must be one of {sorted(VALID_LAYERS)}, got {record['layer']!r}")
        if record["basis"] not in VALID_BASIS:
            errors.append(f"{where}: basis must be one of {sorted(VALID_BASIS)}, got {record['basis']!r}")
        if not record["asOf"] or not ISO_DATE.fullmatch(record["asOf"]):
            errors.append(f"{where}: asOf must be an ISO date, got {record['asOf']!r}")
    return errors


def main():
    records = scan()
    errors = check(records)
    for error in errors:
        print(f"ERROR {error}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} problems across {len(records)} techniques", file=sys.stderr)
        return 1
    print(f"verdicts ok: {len(records)} techniques, all carrying layer, asOf and basis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
