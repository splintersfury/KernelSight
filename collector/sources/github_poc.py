"""GitHub PoC repository search scraper."""

import logging
import re
import subprocess

from . import IntelItem

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class GitHubPoCSource:
    """Searches GitHub for CVE PoC repositories related to Windows kernel drivers."""

    def __init__(self, config: dict):
        self.search_queries = config.get("search_queries", [
            "CVE windows kernel driver exploit",
        ])
        self.min_stars = config.get("min_stars", 2)

    def _gh_search(self, query: str) -> list[dict]:
        """Run gh search repos and return results."""
        try:
            result = subprocess.run(
                [
                    "gh", "search", "repos", query,
                    "--sort", "updated",
                    "--limit", "20",
                    "--json", "name,url,description,stargazersCount,updatedAt",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning("gh search failed: %s", result.stderr[:200])
                return []

            import json
            return json.loads(result.stdout)
        except FileNotFoundError:
            logger.warning("gh CLI not found — skipping GitHub PoC search")
            return []
        except Exception:
            logger.exception("GitHub PoC search failed for query: %s", query)
            return []

    def collect(self) -> list[IntelItem]:
        """Collect PoC repos from GitHub."""
        items = []
        seen_urls = set()

        for query in self.search_queries:
            repos = self._gh_search(query)
            for repo in repos:
                url = repo.get("url", "")
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                stars = repo.get("stargazersCount", 0)
                if stars < self.min_stars:
                    continue

                name = repo.get("name", "")
                desc = repo.get("description", "") or ""
                text = f"{name} {desc}"

                cve_ids = list(set(CVE_RE.findall(text)))
                if not cve_ids:
                    # Try to extract CVE from repo name
                    cve_ids = list(set(CVE_RE.findall(name)))
                if not cve_ids:
                    continue

                items.append(IntelItem(
                    url=url,
                    title=name,
                    summary=desc[:500],
                    source="github_poc",
                    cve_ids=cve_ids,
                ))

        logger.info("GitHub PoC: collected %d items", len(items))
        return items
