#!/usr/bin/env python3
"""Build dashboard-data.json from KernelSight YAML index files.

Reads index/cve_index.yaml, index/techniques.yaml, and index/driver_index.yaml,
then outputs docs/assets/dashboard-data.json for the interactive JS dashboard.

Usage:
    python scripts/build_dashboard_data.py
"""

import json
import os
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
        cve = {
            "id": entry.get("cve_id", ""),
            "driver": entry.get("driver", ""),
            "description": entry.get("description", ""),
            "vuln_class": entry.get("vuln_class", ""),
            "itw": bool(entry.get("itw", False)),
            "has_poc": bool(refs.get("poc", "")),
            "has_writeup": bool(refs.get("writeup", "")),
            "case_study": normalize_case_study(entry.get("case_study", "")),
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
    itw_count = 0
    poc_count = 0

    for cve in cves:
        if cve["driver"]:
            drivers.add(cve["driver"])
            driver_counts[cve["driver"]] += 1
        if cve["vuln_class"]:
            vuln_class_counts[cve["vuln_class"]] += 1
        if cve["itw"]:
            itw_count += 1
        if cve["has_poc"]:
            poc_count += 1

    # Sort dicts by count descending
    sorted_vc = dict(sorted(vuln_class_counts.items(), key=lambda x: x[1], reverse=True))
    sorted_dc = dict(sorted(driver_counts.items(), key=lambda x: x[1], reverse=True))

    return {
        "total_cves": len(cves),
        "total_drivers": len(drivers),
        "itw_count": itw_count,
        "poc_count": poc_count,
        "vuln_class_counts": sorted_vc,
        "driver_counts": sorted_dc,
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
