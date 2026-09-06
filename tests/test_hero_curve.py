import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "hero-curve.json"

_cache = {}


def build():
    if "data" not in _cache:
        subprocess.run([sys.executable, "scripts/build_hero_curve.py"], cwd=ROOT, check=True,
                       stdout=subprocess.DEVNULL)
        _cache["data"] = json.loads(OUT.read_text(encoding="utf-8"))
    return _cache["data"]


def test_curve_has_five_configurations():
    assert len(build()["configs"]) == 5


def test_each_configuration_sums_to_the_technique_total():
    data = build()
    totals = {c["open"] + c["gated"] + c["closed"] for c in data["configs"]}
    assert len(totals) == 1, f"configurations disagree on the total: {totals}"
    assert totals.pop() == data["techniques"]


def test_open_count_never_rises_as_the_platform_hardens():
    # Equal is fine and currently expected: nothing on the site models HLAT
    # yet, so the last three configurations are indistinguishable. A RISE
    # would mean a verdict function has its logic inverted.
    opens = [c["open"] for c in build()["configs"]]
    assert opens == sorted(opens, reverse=True), opens


def test_roster_block_matches_the_roster_file():
    roster = build()["roster"]
    assert (roster["total"], roster["kernel"], roster["user"]) == (30, 19, 11)


def test_every_navigator_config_declares_a_platform_projection():
    """A config without fromPlatform is silently absent from the curve."""
    pages = sorted((ROOT / "docs" / "mitigations").glob("*.md"))
    for page in pages:
        text = page.read_text(encoding="utf-8")
        if "__ksnav" in text:
            assert "fromPlatform" in text, f"{page.name} registers a navigator but declares no fromPlatform"
