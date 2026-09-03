"""Validate index/defenses.yaml. Exit non-zero on any error."""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROSTER = ROOT / "index" / "defenses.yaml"

VALID_LAYERS = {"kernel", "user"}
VALID_ENFORCERS = {"kernel", "hypervisor", "hardware"}
VALID_STATUS = {"current", "planned", "historical"}
REQUIRED = ("id", "name", "layer", "enforced_by", "protects", "page", "status")


def load_roster():
    with ROSTER.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)["defenses"]


def check(roster):
    errors = []
    seen = set()
    for entry in roster:
        did = entry.get("id", "<missing id>")
        for field in REQUIRED:
            if field not in entry:
                errors.append(f"{did}: missing required field '{field}'")
        if did in seen:
            errors.append(f"{did}: duplicate id")
        seen.add(did)
        if entry.get("layer") not in VALID_LAYERS:
            errors.append(f"{did}: layer must be one of {sorted(VALID_LAYERS)}")
        if entry.get("enforced_by") not in VALID_ENFORCERS:
            errors.append(f"{did}: enforced_by must be one of {sorted(VALID_ENFORCERS)}")
        if entry.get("status") not in VALID_STATUS:
            errors.append(f"{did}: status must be one of {sorted(VALID_STATUS)}")
        page = entry.get("page")
        if page is None:
            if entry.get("status") != "planned":
                errors.append(f"{did}: page is null so status must be 'planned'")
        elif not (ROOT / page).exists():
            errors.append(f"{did}: page does not exist: {page}")
    return errors


def main():
    errors = check(load_roster())
    for error in errors:
        print(f"ERROR {error}", file=sys.stderr)
    if errors:
        return 1
    roster = load_roster()
    kernel = sum(1 for d in roster if d["layer"] == "kernel")
    user = len(roster) - kernel
    written = sum(1 for d in roster if d["page"])
    print(f"roster ok: {len(roster)} defenses ({kernel} kernel, {user} user), {written} with pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
