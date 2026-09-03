"""Generate the homepage hardening curve from the real verdict functions.

The per-technique logic lives in JavaScript ev() functions inside the
mitigation pages. Rather than restate those numbers by hand, where they would
drift the moment a verdict changed, this evaluates them with node against a
fixed set of platform configurations.

Each navigator config declares fromPlatform(), which projects the canonical
platform descriptor onto that page's own control names. Configs were authored
independently and their control ids share no namespace, so this projection is
what makes cross-page evaluation correct.
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
from html import unescape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES = sorted((ROOT / "docs" / "mitigations").glob("*.md"))
OUT = ROOT / "docs" / "assets" / "hero-curve.json"

sys.path.insert(0, str(ROOT / "scripts"))
from check_roster import load_roster  # noqa: E402

PUSH = re.compile(
    r"\(window\.__ksnav\s*=\s*window\.__ksnav\s*\|\|\s*\[\]\)\.push\((.*?)\);\s*</script>",
    re.S,
)

# The five configurations the homepage curve reports.
CONFIGS = [
    ("Windows 10 2004", dict(build=19041, hlat=False, kcet=False, hvci=False, admin=True, prims=True)),
    ("11 22H2, kCET", dict(build=22621, hlat=False, kcet=True, hvci=True, admin=True, prims=True)),
    ("11 24H2, pre-11th gen", dict(build=26100, hlat=False, kcet=True, hvci=True, admin=True, prims=True)),
    ("11 24H2, HLAT", dict(build=26100, hlat=True, kcet=True, hvci=True, admin=True, prims=True)),
    ("11 25H2, HLAT", dict(build=26200, hlat=True, kcet=True, hvci=True, admin=True, prims=True)),
]

HARNESS = """
var window = {};
%(configs)s
var CONFIGS = %(platforms)s;
var out = [];
CONFIGS.forEach(function (pair) {
  var o = 0, g = 0, c = 0, errors = 0;
  window.__ksnav.forEach(function (cfg) {
    if (typeof cfg.fromPlatform !== 'function') return;
    var st = cfg.fromPlatform(pair[1]);
    (cfg.techniques || []).forEach(function (t) {
      try {
        var r = t.ev(st);
        if (r[0] === 'open') o++; else if (r[0] === 'gated') g++; else c++;
      } catch (e) { errors++; }
    });
  });
  out.push({ label: pair[0], open: o, gated: g, closed: c, errors: errors });
});
console.log(JSON.stringify(out));
"""


def extract_configs():
    blocks, skipped = [], []
    for page in PAGES:
        text = page.read_text(encoding="utf-8")
        match = PUSH.search(text)
        if not match:
            continue
        if "fromPlatform" not in match.group(1):
            skipped.append(page.name)
            continue
        blocks.append("(window.__ksnav = window.__ksnav || []).push(" + unescape(match.group(1)) + ");")
    return blocks, skipped


def main():
    if not shutil.which("node"):
        print("ERROR node is required to evaluate the verdict functions", file=sys.stderr)
        return 1

    blocks, skipped = extract_configs()
    if not blocks:
        print("ERROR no navigator configs with fromPlatform found", file=sys.stderr)
        return 1
    for name in skipped:
        print(f"WARNING {name} registers a navigator but declares no fromPlatform, "
              f"so it is absent from the curve", file=sys.stderr)

    script = HARNESS % {
        "configs": "\n".join(blocks),
        "platforms": json.dumps([[label, plat] for label, plat in CONFIGS]),
    }
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
        fh.write(script)
        path = fh.name
    try:
        result = subprocess.run(["node", path], capture_output=True, text=True, check=True)
    finally:
        Path(path).unlink(missing_ok=True)

    configs = json.loads(result.stdout.strip().splitlines()[-1])

    total_errors = sum(c["errors"] for c in configs)
    if total_errors:
        print(f"ERROR {total_errors} verdict functions threw during evaluation", file=sys.stderr)
        return 1

    totals = {c["open"] + c["gated"] + c["closed"] for c in configs}
    if len(totals) != 1:
        print(f"ERROR configurations disagree on the technique total: {totals}", file=sys.stderr)
        return 1

    roster = load_roster()
    data = {
        "generated": "computed from the ev() functions, not hand maintained",
        "techniques": totals.pop(),
        "configs": [{k: c[k] for k in ("label", "open", "gated", "closed")} for c in configs],
        "roster": {
            "total": len(roster),
            "kernel": sum(1 for d in roster if d["layer"] == "kernel"),
            "user": sum(1 for d in roster if d["layer"] == "user"),
            "with_inventory": sum(1 for d in roster if d["page"]),
        },
    }
    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("hero curve: " + ", ".join(f'{c["label"]}={c["open"]}' for c in data["configs"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
