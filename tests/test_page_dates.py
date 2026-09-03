"""Page dates must reflect substance, not punctuation.

A site-wide em-dash sweep touched 27 files without changing what any of them
said. Dating pages by their last commit reset 53 of them to "today", which
would have made a feature built to expose staleness hide it instead.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_page_dates as bpd  # noqa: E402

OUT = ROOT / "docs" / "assets" / "page-dates.json"

_cache = {}


def data():
    if "d" not in _cache:
        subprocess.run([sys.executable, "scripts/build_page_dates.py"], cwd=ROOT,
                       check=True, stdout=subprocess.DEVNULL)
        _cache["d"] = json.loads(OUT.read_text(encoding="utf-8"))
    return _cache["d"]


def test_every_tracked_page_has_a_date():
    d = data()
    assert d["pages_total"] > 200
    assert all(v for v in d["pages"].values())


def test_urls_match_the_shape_the_template_looks_up():
    """The theme reads page.url, which is '' for home and 'a/b/' otherwise."""
    keys = data()["pages"]
    assert "" in keys, "homepage key missing"
    assert "overview/" in keys
    assert "mitigations/protected-process/" in keys
    assert not any(k.startswith("/") or k.endswith(".md") for k in keys)


def test_punctuation_only_changes_are_treated_as_cosmetic():
    before = "| **Status** | Blocklisted — included in the blocklist |"
    after = "| **Status** | Blocklisted: included in the blocklist |"
    assert bpd.normalise(before) == bpd.normalise(after)


def test_figure_renumbering_is_treated_as_cosmetic():
    assert bpd.normalise('<span>FIG_003 — Title</span>') == bpd.normalise('<span>FIG_003: Title</span>')
    assert bpd.normalise('<span>FIG — Title</span>') == bpd.normalise('<span>FIG_010: Title</span>')


def test_a_real_content_change_is_not_cosmetic():
    assert bpd.normalise("documents 147 CVEs") != bpd.normalise("documents 156 CVEs")
    assert bpd.normalise("the exploitation pipeline") != bpd.normalise("the two halves")


def test_most_pages_still_show_their_march_date():
    """If a sweep ever resets the whole corpus again, this fails loudly."""
    d = data()
    march = sum(1 for v in d["pages"].values() if v.startswith("2026-03"))
    assert march > 150, f"only {march} pages still carry a March date; a sweep may have masked staleness"
