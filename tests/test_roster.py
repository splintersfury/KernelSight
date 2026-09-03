import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_roster import load_roster, check


def test_roster_has_29_defenses():
    assert len(load_roster()) == 29


def test_layer_split_is_19_kernel_10_user():
    roster = load_roster()
    kernel = [d for d in roster if d["layer"] == "kernel"]
    user = [d for d in roster if d["layer"] == "user"]
    assert (len(kernel), len(user)) == (19, 10)


def test_every_id_is_unique():
    ids = [d["id"] for d in load_roster()]
    assert len(ids) == len(set(ids))


def test_ppl_is_user_layer_enforced_by_kernel():
    ppl = next(d for d in load_roster() if d["id"] == "protected-process")
    assert ppl["layer"] == "user"
    assert ppl["enforced_by"] == "kernel"


def test_roster_check_reports_no_errors():
    assert check(load_roster()) == []


def test_check_catches_a_page_that_does_not_exist():
    bad = [{
        "id": "ghost", "name": "Ghost", "layer": "kernel",
        "enforced_by": "kernel", "protects": "nothing",
        "page": "docs/mitigations/does-not-exist.md", "status": "current",
    }]
    errors = check(bad)
    assert any("does-not-exist" in e for e in errors)


def test_check_catches_a_bad_layer_value():
    bad = [{
        "id": "ghost", "name": "Ghost", "layer": "hypervisor",
        "enforced_by": "kernel", "protects": "nothing",
        "page": None, "status": "planned",
    }]
    assert any("layer" in e for e in check(bad))


def test_protected_process_page_exists_and_registers_a_navigator():
    page = ROOT / "docs" / "mitigations" / "protected-process.md"
    assert page.exists()
    text = page.read_text(encoding="utf-8")
    assert "__ksnav" in text
    assert text.count("layer:'user'") == 3
