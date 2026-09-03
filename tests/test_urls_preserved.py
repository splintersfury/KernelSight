"""The nav regrouping must not change a single published URL.

MkDocs derives a page URL from its path under docs/, not from its position
in the nav tree, so a pure regrouping must leave the built URL set intact.
tests/url_baseline.txt is a snapshot of every URL the site produced before
the regroup. Regenerate it deliberately, never to make this test pass.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests" / "url_baseline.txt"

_cache = {}


def built_pages():
    if "pages" not in _cache:
        subprocess.run([sys.executable, "scripts/build_dashboard_data.py"], cwd=ROOT,
                       check=True, stdout=subprocess.DEVNULL)
        # Capture rather than discard: a strict-mode failure here is the whole
        # point of the test, so the warning that caused it must reach the report.
        result = subprocess.run(["mkdocs", "build", "--strict"], cwd=ROOT,
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(
                "mkdocs build --strict failed:\n"
                + "\n".join(l for l in (result.stdout + result.stderr).splitlines()
                             if any(k in l.lower() for k in ("warning", "error", "aborted")))
            )
        site = ROOT / "site"
        _cache["pages"] = {str(p.relative_to(site)) for p in site.rglob("*.html")}
    return _cache["pages"]


def baseline():
    return {line.strip() for line in BASELINE.read_text(encoding="utf-8").splitlines() if line.strip()}


def test_no_published_url_disappeared():
    lost = sorted(baseline() - built_pages())
    assert not lost, f"{len(lost)} URLs disappeared, first few: {lost[:10]}"


def test_the_whole_case_study_corpus_still_builds():
    studies = [p for p in built_pages() if p.startswith("case-studies/")]
    assert len(studies) >= 161, len(studies)


def test_the_new_pages_are_present():
    pages = built_pages()
    for page in ("bypasses/index.html", "mitigations/protected-process/index.html"):
        assert page in pages, page
