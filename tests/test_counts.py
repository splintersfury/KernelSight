"""Corpus totals stated in prose must match the generated data.

Three different totals were live at once here (134, 147 and 156) because every
page restated the number from memory. This makes the generated dashboard data
the single source of truth.

The guard is deliberately narrow. Per-driver tallies are everywhere and are
correct ("AFD accounts for 13 CVEs in the KernelSight corpus"), so matching on
proximity to the word "corpus" produces false positives. Instead this matches
only the canonical whole-corpus phrasings, where the number can mean nothing
else. A narrow guard that is right beats a broad one that cries wolf.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

STATS = json.loads((DOCS / "assets" / "dashboard-data.json").read_text(encoding="utf-8"))["stats"]

# "156 CVEs across 64 drivers" and friends: both numbers are corpus totals.
ACROSS = re.compile(r"\b(\d+)\s+(?:real\s+)?CVEs?\s+across\s+(\d+)\s+(?:unique\s+)?drivers\b", re.I)

# "all 156 CVEs", "visualize all 156 CVEs": "all" makes it the whole corpus.
ALL_OF = re.compile(r"\ball\s+(\d+)\s+(?:real\s+)?CVEs?\b", re.I)

# "57 exploited in the wild" only counts when paired with a corpus total nearby.
ITW_WITH_TOTAL = re.compile(
    r"\b" + str(STATS["total_cves"]) + r"\b[^.]{0,120}?\b(\d+)\s+exploited in the wild", re.I)


def offences():
    bad = []
    for md in sorted(DOCS.rglob("*.md")):
        for n, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
            where = f"{md.relative_to(ROOT)}:{n}"
            for m in ACROSS.finditer(line):
                if int(m.group(1)) != STATS["total_cves"]:
                    bad.append(f"{where} says {m.group(1)} CVEs, data says {STATS['total_cves']}")
                if int(m.group(2)) != STATS["total_drivers"]:
                    bad.append(f"{where} says {m.group(2)} drivers, data says {STATS['total_drivers']}")
            for m in ALL_OF.finditer(line):
                if int(m.group(1)) != STATS["total_cves"]:
                    bad.append(f"{where} says all {m.group(1)} CVEs, data says {STATS['total_cves']}")
            for m in ITW_WITH_TOTAL.finditer(line):
                if int(m.group(1)) != STATS["itw_count"]:
                    bad.append(f"{where} says {m.group(1)} exploited ITW, data says {STATS['itw_count']}")
    return bad


def test_whole_corpus_totals_match_the_generated_data():
    bad = offences()
    assert not bad, "corpus totals drifted:\n  " + "\n  ".join(bad)


def test_the_data_itself_is_sane():
    assert STATS["total_cves"] > 0
    assert STATS["itw_count"] <= STATS["total_cves"]
    assert STATS["poc_count"] <= STATS["total_cves"]


def test_the_guard_would_actually_catch_drift():
    """A guard nobody has seen fail is a guard nobody should trust."""
    assert ACROSS.search("documents 147 CVEs across 64 drivers")
    assert int(ACROSS.search("documents 147 CVEs across 64 drivers").group(1)) == 147
    assert ALL_OF.search("visualize all 147 CVEs")
    # and it must NOT fire on a legitimate per-driver tally
    assert not ACROSS.search("With 13 CVEs in the KernelSight corpus")
    assert not ALL_OF.search("With 13 CVEs in the KernelSight corpus")


def test_figure_labels_use_one_consistent_format():
    """Three separators were in use at once: ':', '--' and an em-dash."""
    bad = []
    for md in sorted(DOCS.rglob("*.md")):
        for n, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
            if "ks-figure-label" not in line:
                continue
            if not re.search(r">FIG(?:_\d+)?: \S", line):
                bad.append(f"{md.relative_to(ROOT)}:{n}: {line.strip()[:80]}")
    assert not bad, "figure labels must read 'FIG_00N: Title':\n  " + "\n  ".join(bad)


def test_no_em_dashes_anywhere_in_the_docs():
    """House rule. They had crept into 27 files.

    Checks the HTML entity too: an SVG label written as &mdash; renders as an
    em-dash and passes a naive character scan. That is exactly how three of
    them survived the first sweep.
    """
    bad = []
    for f in sorted(list(DOCS.rglob("*.md")) + list(DOCS.rglob("*.html"))):
        text = f.read_text(encoding="utf-8")
        if "\u2014" in text or "&mdash;" in text:
            bad.append(str(f.relative_to(ROOT)))
    assert not bad, "em-dashes found in: " + ", ".join(bad)
