"""Record when each documentation page last changed in substance.

Page age is the same discipline the bypass inventories use: a claim without a
date reads as current whether or not it is.

The subtlety is that a site-wide punctuation sweep touches many files without
changing what any of them say. Dating a page by its last commit would let such
a sweep reset 53 pages to "today" and hide that their content is six months
old, which is the precise failure this feature exists to prevent. So each
commit touching a page is inspected: if the added and removed lines are equal
once punctuation and whitespace are normalised, the commit is cosmetic and the
search continues to the one before it.

Deliberately dependency free. mkdocs-git-revision-date-localized-plugin would
need a new package on the runner and would date pages the naive way anyway.
"""
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "assets" / "page-dates.json"

# Differences that do not change what a page says.
COSMETIC = [
    (re.compile(r"[—]|&mdash;"), ":"),      # em-dash recast
    (re.compile(r"FIG(?:_\d+)?\s*[:,-]+\s*"), "FIG: "),  # figure label renumbering
    (re.compile(r"\s+"), " "),                    # reflowed lines
    (re.compile(r"[ ]*([:,;])[ ]*"), r"\1"),      # spacing around punctuation
]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, check=True).stdout


def normalise(text):
    for pattern, repl in COSMETIC:
        text = pattern.sub(repl, text)
    return text.strip().lower()


def commits_for(path):
    out = git("log", "--format=%H %ad", "--date=short", "--", path)
    return [line.split(" ", 1) for line in out.splitlines() if line.strip()]


def is_cosmetic(sha, path):
    """True when the patch changes only punctuation, spacing or figure numbers."""
    try:
        patch = git("show", "--format=", "--unified=0", sha, "--", path)
    except subprocess.CalledProcessError:
        return False
    added, removed = [], []
    for line in patch.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    if not added and not removed:
        return False
    return normalise("\n".join(added)) == normalise("\n".join(removed))


def url_for(path):
    """docs/a/b.md -> a/b/ ; docs/a/index.md -> a/ ; docs/index.md -> ''"""
    rel = path[len("docs/"):]
    if rel == "index.md":
        return ""
    if rel.endswith("/index.md"):
        return rel[: -len("index.md")]
    return rel[:-3] + "/"


def substantive_date(path):
    history = commits_for(path)
    for sha, when in history:
        if not is_cosmetic(sha, path):
            return when
    return history[-1][1] if history else None


def main():
    pages = [p for p in git("ls-files", "docs/").splitlines() if p.endswith(".md")]
    if not pages:
        print("ERROR no tracked pages found; is this a shallow clone?", file=sys.stderr)
        return 1

    mapping, cosmetic_only = {}, 0
    for path in pages:
        when = substantive_date(path)
        if not when:
            continue
        mapping[url_for(path)] = when
        newest = commits_for(path)[0][1]
        if newest != when:
            cosmetic_only += 1

    if not mapping:
        print("ERROR no dates resolved", file=sys.stderr)
        return 1

    today = date.today()
    six_months = str(today.replace(month=today.month - 6) if today.month > 6
                     else today.replace(year=today.year - 1, month=today.month + 6))
    stale = sum(1 for d in mapping.values() if d < six_months)

    OUT.write_text(json.dumps({
        "generated": str(today),
        "newest_page": max(mapping.values()),
        "pages_total": len(mapping),
        "pages_over_six_months_old": stale,
        "pages": mapping,
    }, indent=0, sort_keys=True) + "\n", encoding="utf-8")

    print(f"page dates: {len(mapping)} pages, newest {max(mapping.values())}, "
          f"{stale} older than six months, "
          f"{cosmetic_only} looked newer until cosmetic commits were discounted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
