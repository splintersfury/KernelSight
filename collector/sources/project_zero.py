"""Google Project Zero tracker and blog scraper."""

import logging
import re

import feedparser
import httpx

from . import IntelItem

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DRIVER_RE = re.compile(r"\b[\w]+\.sys\b", re.IGNORECASE)


class ProjectZeroSource:
    """Scrapes Project Zero blog RSS for Windows kernel content."""

    def __init__(self, config: dict):
        self.blog_rss = config.get(
            "blog_rss",
            "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
        )
        self.labels = [l.lower() for l in config.get("labels", ["Windows", "Kernel"])]

    def collect(self) -> list[IntelItem]:
        """Collect Windows kernel items from Project Zero blog."""
        items = []
        try:
            feed = feedparser.parse(self.blog_rss)
            for entry in feed.entries:
                title = entry.get("title", "")
                summary = entry.get("summary", "")
                link = entry.get("link", "")
                text = f"{title} {summary}".lower()

                if not any(label in text for label in self.labels):
                    continue

                cve_ids = list(set(CVE_RE.findall(f"{title} {summary}")))
                drivers = list(set(DRIVER_RE.findall(f"{title} {summary}")))

                items.append(IntelItem(
                    url=link,
                    title=title,
                    summary=summary[:500],
                    source="project_zero",
                    cve_ids=cve_ids,
                    drivers=drivers,
                    raw_content=summary,
                ))

        except Exception:
            logger.exception("Project Zero collection failed")

        logger.info("Project Zero: collected %d items", len(items))
        return items
