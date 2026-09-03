"""Record when each documentation page was last actually changed.

Page age is the same discipline the bypass inventories use: a claim without a
date reads as current whether or not it is. This walks git for the last commit
that touched each page and writes the dates out for the theme to render, so a
reader can see that a page has not moved in six months rather than assuming it
has.

Deliberately dependency free. The obvious alternative,
mkdocs-git-revision-date-localized-plugin, would need a new package on the
runner; git is already there.
"""
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "assets" / "page-dates.json"


def tracked_pages():
    result = subprocess.run(
        ["git", "ls-files", "docs/**/*.md", "docs/*.md"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return [line for line in result.stdout.splitlines() if line.endswith(".md")]


def last_changed(paths):
    """One git call per page is slow over 250 files, so read the whole log once."""
    result = subprocess.run(
        ["git", "log", "--name-only", "--pretty=format:%x00%ad", "--date=short", "--", "docs/"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    seen, current = {}, None
    for line in result.stdout.splitlines():
        if line.startswith("\x00"):
            current = line[1:].strip()
        elif line.strip() and current and line not in seen:
            seen[line] = current
    return seen


def url_for(path):
    """docs/a/b.md -> a/b/ ; docs/a/index.md -> a/ ; docs/index.md -> ''"""
    rel = path[len("docs/"):]
    if rel == "index.md":
        return ""
    if rel.endswith("/index.md"):
        return rel[: -len("index.md")]
    return rel[:-3] + "/"


def main():
    pages = tracked_pages()
    if not pages:
        print("ERROR no tracked pages found; is this a shallow clone?", file=sys.stderr)
        return 1

    dates = last_changed(pages)
    missing = [p for p in pages if p not in dates]
    if missing:
        print(f"WARNING {len(missing)} pages have no commit touching them, "
              f"first: {missing[0]}", file=sys.stderr)

    mapping = {url_for(p): dates[p] for p in pages if p in dates}
    newest = max(mapping.values())
    stale_cutoff = str(date.today().replace(year=date.today().year - 1))
    stale = sum(1 for d in mapping.values() if d < stale_cutoff)

    OUT.write_text(json.dumps({
        "generated": str(date.today()),
        "newest_page": newest,
        "pages_total": len(mapping),
        "pages_over_a_year_old": stale,
        "pages": mapping,
    }, indent=0, sort_keys=True) + "\n", encoding="utf-8")

    print(f"page dates: {len(mapping)} pages, newest {newest}, {stale} older than a year")
    return 0


if __name__ == "__main__":
    sys.exit(main())
