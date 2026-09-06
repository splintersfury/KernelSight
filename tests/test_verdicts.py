import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_verdicts import scan, check

VALID_BASIS = {"tested", "cited", "inferred"}


def test_scan_finds_every_shipping_technique():
    """Cross-check the regex scanner against an independent count.

    A hardcoded total went stale on every new defense page, which taught
    nothing when it failed. This counts ev: handlers directly instead, so the
    test catches what it is actually for: the scanner silently missing entries
    because a page was authored in a shape the regex does not match.
    """
    pages = sorted((ROOT / "docs" / "mitigations").glob("*.md"))
    independent = sum(
        p.read_text(encoding="utf-8").count("ev:function")
        for p in pages if "__ksnav" in p.read_text(encoding="utf-8"))
    found = len(scan())
    assert found == independent, (
        f"scanner found {found} techniques, counting ev: handlers gives "
        f"{independent}; the regex is missing some page's authoring style")
    assert found > 40, f"only {found} techniques; a navigator page may have stopped registering"


def test_every_navigator_page_contributes():
    """A page whose config the scanner cannot read is worse than no page."""
    from collections import Counter
    seen = Counter(r["file"] for r in scan())
    for page in sorted((ROOT / "docs" / "mitigations").glob("*.md")):
        if "__ksnav" in page.read_text(encoding="utf-8"):
            assert seen.get(page.name, 0) > 0, f"{page.name} registers a navigator but yielded no techniques"


def test_every_technique_has_the_three_required_fields():
    for record in scan():
        assert record["layer"] in {"kernel", "user"}, record
        assert record["basis"] in VALID_BASIS, record
        assert record["asOf"], record


def test_asof_is_an_iso_date():
    for record in scan():
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", record["asOf"]), record


def test_check_reports_no_errors():
    assert check(scan()) == []


def test_check_catches_a_missing_basis():
    bad = [{"file": "x.md", "name": "t", "layer": "kernel", "asOf": "2026-01-01", "basis": None}]
    assert any("basis" in e for e in check(bad))


def test_check_catches_a_bad_layer():
    bad = [{"file": "x.md", "name": "t", "layer": "firmware", "asOf": "2026-01-01", "basis": "cited"}]
    assert any("layer" in e for e in check(bad))
