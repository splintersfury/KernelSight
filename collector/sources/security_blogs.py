"""Curated security blog RSS feed scraper."""

import logging
import re

import feedparser

from . import IntelItem

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DRIVER_RE = re.compile(r"\b[\w]+\.sys\b", re.IGNORECASE)


class SecurityBlogsSource:
    """Scrapes curated security blog RSS feeds for Windows kernel content."""

    def __init__(self, config: dict):
        self.feeds = config.get("feeds", [])

    def collect(self) -> list[IntelItem]:
        """Collect items from all configured RSS feeds."""
        items = []

        for feed_config in self.feeds:
            name = feed_config.get("name", "unknown")
            url = feed_config.get("url", "")
            keywords = [k.lower() for k in feed_config.get("keywords", ["windows", "kernel"])]

            if not url:
                continue

            try:
                feed = feedparser.parse(url)
                for entry in feed.entries:
                    title = entry.get("title", "")
                    summary = entry.get("summary", "")
                    link = entry.get("link", "")
                    text = f"{title} {summary}".lower()

                    if not any(kw in text for kw in keywords):
                        continue

                    cve_ids = list(set(CVE_RE.findall(f"{title} {summary}")))
                    drivers = list(set(DRIVER_RE.findall(f"{title} {summary}")))

                    items.append(IntelItem(
                        url=link,
                        title=title,
                        summary=summary[:500],
                        source=f"blog:{name}",
                        cve_ids=cve_ids,
                        drivers=drivers,
                        raw_content=summary,
                    ))

            except Exception:
                logger.exception("Failed to parse feed: %s (%s)", name, url)

        logger.info("Security Blogs: collected %d items from %d feeds", len(items), len(self.feeds))
        return items
