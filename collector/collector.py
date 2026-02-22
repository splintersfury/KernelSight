#!/usr/bin/env python3
"""KernelSight Collector — automated intelligence gathering for the knowledge base."""

import argparse
import logging
import os
import sys
import time
from pathlib import Path

import schedule
import yaml

from analyzer import Analyzer
from pr_manager import PRManager
from sources import IntelItem
from sources.msrc import MSRCSource
from sources.project_zero import ProjectZeroSource
from sources.github_poc import GitHubPoCSource
from sources.security_blogs import SecurityBlogsSource
from sources.nvd import NVDSource

logger = logging.getLogger("collector")

# Repo root is one level up from collector/
REPO_ROOT = Path(__file__).resolve().parent.parent


def load_config(config_path: Path | None = None) -> dict:
    """Load collector configuration."""
    if config_path is None:
        config_path = Path(__file__).parent / "config.yaml"

    with open(config_path) as f:
        raw = f.read()

    # Substitute environment variables
    for key, value in os.environ.items():
        raw = raw.replace(f"${{{key}}}", value)
        raw = raw.replace(f"${{{key}:-}}", value)

    # Handle defaults for unset env vars: ${VAR:-default}
    import re
    for match in re.finditer(r"\$\{(\w+):-([^}]*)\}", raw):
        raw = raw.replace(match.group(0), match.group(2))

    return yaml.safe_load(raw)


def init_sources(config: dict) -> list:
    """Initialize enabled source scrapers."""
    sources_config = config.get("sources", {})
    active = []

    if sources_config.get("msrc", {}).get("enabled", False):
        active.append(MSRCSource(sources_config["msrc"]))

    if sources_config.get("project_zero", {}).get("enabled", False):
        active.append(ProjectZeroSource(sources_config["project_zero"]))

    if sources_config.get("github_poc", {}).get("enabled", False):
        active.append(GitHubPoCSource(sources_config["github_poc"]))

    if sources_config.get("security_blogs", {}).get("enabled", False):
        active.append(SecurityBlogsSource(sources_config["security_blogs"]))

    logger.info("Initialized %d sources", len(active))
    return active


def dedup_items(items: list[IntelItem], seen: set[str]) -> list[IntelItem]:
    """Remove already-seen items."""
    new_items = []
    for item in items:
        key = item.dedup_key
        if key not in seen:
            seen.add(key)
            new_items.append(item)
    return new_items


def try_redis_seen_set(config: dict) -> set[str] | None:
    """Try to load the seen-set from Redis. Returns None if unavailable."""
    redis_config = config.get("redis", {})
    try:
        import redis as redis_lib
        r = redis_lib.Redis(
            host=redis_config.get("host", "localhost"),
            port=redis_config.get("port", 6379),
            db=redis_config.get("db", 5),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        r.ping()
        key = redis_config.get("seen_set_key", "kernelsight:collector:seen")
        return r.smembers(key)
    except Exception:
        logger.info("Redis not available — using in-memory seen set")
        return None


def save_to_redis(config: dict, seen: set[str]):
    """Save seen-set to Redis if available."""
    redis_config = config.get("redis", {})
    try:
        import redis as redis_lib
        r = redis_lib.Redis(
            host=redis_config.get("host", "localhost"),
            port=redis_config.get("port", 6379),
            db=redis_config.get("db", 5),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        key = redis_config.get("seen_set_key", "kernelsight:collector:seen")
        if seen:
            r.sadd(key, *seen)
            ttl_days = redis_config.get("seen_set_ttl_days", 90)
            r.expire(key, ttl_days * 86400)
    except Exception:
        pass


def run_collection_cycle(
    config: dict,
    sources: list,
    analyzer: Analyzer,
    pr_manager: PRManager,
    seen: set[str],
    dry_run: bool = False,
    nvd_source: NVDSource | None = None,
):
    """Run a single collection cycle."""
    logger.info("Starting collection cycle")

    # Collect from all sources
    all_items: list[IntelItem] = []
    for source in sources:
        try:
            items = source.collect()
            all_items.extend(items)
        except Exception:
            logger.exception("Source %s failed", type(source).__name__)

    logger.info("Collected %d total items", len(all_items))

    # Deduplicate
    new_items = dedup_items(all_items, seen)
    logger.info("After dedup: %d new items", len(new_items))

    if not new_items:
        logger.info("No new items — skipping analysis")
        return

    # Enrich with NVD data
    if nvd_source:
        for item in new_items:
            for cve_id in item.cve_ids:
                enrichment = nvd_source.enrich_cve(cve_id)
                if enrichment:
                    logger.info("Enriched %s: CVSS=%s, CWE=%s",
                                cve_id, enrichment.get("cvss_score"), enrichment.get("cwe_ids"))

    # Analyze
    all_changes = []
    for item in new_items:
        try:
            changes = analyzer.analyze(item)
            all_changes.extend(changes)
        except Exception:
            logger.exception("Analysis failed for %s", item.url)

    logger.info("Proposed %d changes", len(all_changes))

    if not all_changes:
        logger.info("No changes to propose")
        return

    # Create PR (or dry-run)
    pr_url = pr_manager.create_pr(all_changes, dry_run=dry_run)
    if pr_url:
        logger.info("PR created: %s", pr_url)
    elif dry_run:
        logger.info("Dry run complete — %d changes would be proposed", len(all_changes))

    # Save seen-set
    save_to_redis(config, seen)


def main():
    parser = argparse.ArgumentParser(description="KernelSight Collector")
    parser.add_argument("--config", type=Path, help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Print proposed changes without creating PRs")
    parser.add_argument("--once", action="store_true", help="Run once and exit (don't schedule)")
    args = parser.parse_args()

    config = load_config(args.config)

    # Setup logging
    log_config = config.get("logging", {})
    logging.basicConfig(
        level=getattr(logging, log_config.get("level", "INFO")),
        format=log_config.get("format", "%(asctime)s [%(levelname)s] %(name)s: %(message)s"),
    )

    # Initialize components
    sources = init_sources(config)
    analyzer = Analyzer(REPO_ROOT)
    pr_manager = PRManager(REPO_ROOT, config)

    nvd_config = config.get("sources", {}).get("nvd", {})
    nvd_source = NVDSource(nvd_config) if nvd_config.get("enabled", False) else None

    # Load seen-set
    redis_seen = try_redis_seen_set(config)
    seen: set[str] = redis_seen if redis_seen is not None else set()

    if args.once or args.dry_run:
        run_collection_cycle(config, sources, analyzer, pr_manager, seen, dry_run=args.dry_run, nvd_source=nvd_source)
        return

    # Schedule recurring collection
    interval = config.get("schedule", {}).get("interval_hours", 6)
    logger.info("Scheduling collection every %d hours", interval)

    def job():
        run_collection_cycle(config, sources, analyzer, pr_manager, seen, nvd_source=nvd_source)

    # Run immediately on start
    job()

    schedule.every(interval).hours.do(job)

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    main()
