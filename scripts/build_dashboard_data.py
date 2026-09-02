#!/usr/bin/env python3
"""Build dashboard-data.json from KernelSight YAML index files.

Reads index/cve_index.yaml, index/techniques.yaml, and index/driver_index.yaml,
then outputs docs/assets/dashboard-data.json for the interactive JS dashboard.

Usage:
    python scripts/build_dashboard_data.py
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
INDEX_DIR = ROOT / "index"
OUTPUT = ROOT / "docs" / "assets" / "dashboard-data.json"


def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# Maps the product-build number (3rd octet of 10.0.<N>.<rev>) to a Windows
# release label. Extend as the corpus grows into new branches.
WIN_VERSION_MAP = {
    "26200": "Win11 25H2",
    "26100": "Win11 24H2",
    "22631": "Win11 23H2",
    "22621": "Win11 22H2",
    "22000": "Win11 21H2",
    "25398": "Server 23H2",
    "20348": "Server 2022",
    "19045": "Win10 22H2",
    "19044": "Win10 21H2",
    "19043": "Win10 21H1",
    "19042": "Win10 20H2",
    "19041": "Win10 2004",
    "18363": "Win10 1909",
    "17763": "Win10 1809",
    "14393": "Server 2016",
}

# Matches a summary-table row such as:  | **Vulnerable Build** | `10.0.22621.608` (KB..) |
_BUILD_ROW_RE = re.compile(
    r"\|\s*\*\*(?P<field>Vulnerable Build|Fixed Build)\*\*\s*\|\s*`?(?P<build>10\.0\.\d+\.\d+)",
    re.IGNORECASE,
)


def win_version_for(build: str) -> str:
    """Derive a Windows release label from a full build string, or '' if unknown."""
    if not build:
        return ""
    parts = build.split(".")
    if len(parts) >= 3:
        return WIN_VERSION_MAP.get(parts[2], f"Build {parts[2]}")
    return ""


def parse_case_study_builds(case_study_raw: str) -> dict:
    """Read a case-study markdown file and pull vulnerable/fixed build numbers
    from its summary table. Returns {'vuln_build': str, 'fix_build': str}."""
    out = {"vuln_build": "", "fix_build": ""}
    if not case_study_raw:
        return out
    path = case_study_raw
    if not path.startswith("docs/"):
        path = "docs/" + path.lstrip("/")
    md = ROOT / path
    if not md.exists():
        return out
    try:
        text = md.read_text(encoding="utf-8")
    except OSError:
        return out
    for m in _BUILD_ROW_RE.finditer(text):
        field = m.group("field").lower()
        build = m.group("build")
        if field.startswith("vulnerable") and not out["vuln_build"]:
            out["vuln_build"] = build
        elif field.startswith("fixed") and not out["fix_build"]:
            out["fix_build"] = build
    return out


def resolve_build_info(entry: dict) -> dict:
    """Best-effort build + Windows-version metadata for one CVE.

    Prefers the case-study markdown table (what the reader sees and the richest
    source), falling back to the YAML vuln_version/fix_version fields.
    """
    info = parse_case_study_builds(entry.get("case_study", ""))
    if not info["vuln_build"]:
        vv = entry.get("vuln_version")
        if isinstance(vv, dict) and vv.get("build"):
            info["vuln_build"] = str(vv["build"])
    if not info["fix_build"]:
        fv = entry.get("fix_version")
        if isinstance(fv, dict) and fv.get("build"):
            info["fix_build"] = str(fv["build"])
    info["win_version"] = win_version_for(info["vuln_build"] or info["fix_build"])
    return info


def normalize_case_study(raw: str) -> str:
    """Strip 'docs/' prefix from case_study path and ensure trailing slash for MkDocs."""
    if not raw:
        return ""
    path = raw
    if path.startswith("docs/"):
        path = path[5:]
    if path.endswith(".md"):
        path = path[:-3] + "/"
    if not path.endswith("/"):
        path += "/"
    return path


def build_cve_list(cve_data: list) -> list:
    """Build the flat CVE list for the dashboard."""
    result = []
    for entry in cve_data:
        refs = entry.get("references", {})
        build = resolve_build_info(entry)
        cve = {
            "id": entry.get("cve_id", ""),
            "driver": entry.get("driver", ""),
            "description": entry.get("description", ""),
            "vuln_class": entry.get("vuln_class", ""),
            "itw": bool(entry.get("itw", False)),
            "has_poc": bool(refs.get("poc", "")),
            "has_writeup": bool(refs.get("writeup", "")),
            "case_study": normalize_case_study(entry.get("case_study", "")),
            "vuln_build": build["vuln_build"],
            "fix_build": build["fix_build"],
            "win_version": build["win_version"],
            "references": {
                "msrc": refs.get("msrc", ""),
                "writeup": refs.get("writeup", ""),
                "poc": refs.get("poc", ""),
            },
        }
        if entry.get("third_party"):
            cve["third_party"] = True
        if entry.get("byovd"):
            cve["byovd"] = True
        if entry.get("vendor"):
            cve["vendor"] = entry["vendor"]
        result.append(cve)
    return result


def build_matrix(cves: list) -> dict:
    """Build the driver x vuln_class heat matrix.

    Only includes drivers with 2+ CVEs. Rows sorted by CVE count descending,
    columns sorted by CVE count descending.
    """
    driver_vuln = defaultdict(list)
    driver_itw = defaultdict(int)
    vuln_class_counts = defaultdict(int)

    for cve in cves:
        driver = cve["driver"]
        vc = cve["vuln_class"]
        if not driver or not vc:
            continue
        key = f"{driver}|{vc}"
        driver_vuln[key].append(cve["id"])
        if cve["itw"]:
            driver_itw[key] += 1
        vuln_class_counts[vc] += 1

    # Count CVEs per driver
    driver_total = defaultdict(int)
    for cve in cves:
        if cve["driver"]:
            driver_total[cve["driver"]] += 1

    # Filter to drivers with 2+ CVEs, sort descending
    rows = sorted(
        [d for d, c in driver_total.items() if c >= 2],
        key=lambda d: driver_total[d],
        reverse=True,
    )

    # Collect unique vuln classes that appear in matrix rows
    cols_in_matrix = set()
    for cve in cves:
        if cve["driver"] in rows and cve["vuln_class"]:
            cols_in_matrix.add(cve["vuln_class"])

    cols = sorted(
        cols_in_matrix,
        key=lambda vc: vuln_class_counts[vc],
        reverse=True,
    )

    cells = {}
    for key, cve_ids in driver_vuln.items():
        driver, vc = key.split("|", 1)
        if driver not in rows:
            continue
        cells[key] = {
            "count": len(cve_ids),
            "itw": driver_itw.get(key, 0),
            "cves": cve_ids,
        }

    return {"rows": rows, "cols": cols, "cells": cells}


def build_stats(cves: list) -> dict:
    """Build aggregate statistics."""
    drivers = set()
    vuln_class_counts = defaultdict(int)
    driver_counts = defaultdict(int)
    win_version_counts = defaultdict(int)
    itw_count = 0
    poc_count = 0

    for cve in cves:
        if cve["driver"]:
            drivers.add(cve["driver"])
            driver_counts[cve["driver"]] += 1
        if cve["vuln_class"]:
            vuln_class_counts[cve["vuln_class"]] += 1
        win_version_counts[cve.get("win_version") or "Unspecified"] += 1
        if cve["itw"]:
            itw_count += 1
        if cve["has_poc"]:
            poc_count += 1

    # Sort dicts by count descending
    sorted_vc = dict(sorted(vuln_class_counts.items(), key=lambda x: x[1], reverse=True))
    sorted_dc = dict(sorted(driver_counts.items(), key=lambda x: x[1], reverse=True))
    sorted_wv = dict(sorted(win_version_counts.items(), key=lambda x: x[1], reverse=True))

    return {
        "total_cves": len(cves),
        "total_drivers": len(drivers),
        "itw_count": itw_count,
        "poc_count": poc_count,
        "vuln_class_counts": sorted_vc,
        "driver_counts": sorted_dc,
        "win_version_counts": sorted_wv,
    }


def main():
    cve_index = load_yaml(INDEX_DIR / "cve_index.yaml")
    raw_cves = cve_index.get("cves", [])

    cves = build_cve_list(raw_cves)
    matrix = build_matrix(cves)
    stats = build_stats(cves)

    dashboard = {
        "cves": cves,
        "matrix": matrix,
        "stats": stats,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(dashboard, f, indent=2, ensure_ascii=False)

    print(f"Dashboard data written to {OUTPUT}")
    print(f"  CVEs: {stats['total_cves']}")
    print(f"  Drivers: {stats['total_drivers']}")
    print(f"  ITW: {stats['itw_count']}")
    print(f"  Matrix: {len(matrix['rows'])} drivers x {len(matrix['cols'])} vuln classes")


if __name__ == "__main__":
    main()
