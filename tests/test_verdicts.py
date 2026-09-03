import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_verdicts import scan, check

VALID_BASIS = {"tested", "cited", "inferred"}


def test_scan_finds_every_shipping_technique():
    assert len(scan()) == 37


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
