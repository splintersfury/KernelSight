"""MSRC Security Update Guide scraper."""

import logging
import re
from datetime import datetime, timedelta

import httpx

from . import IntelItem

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DRIVER_RE = re.compile(r"\b[\w]+\.sys\b", re.IGNORECASE)


class MSRCSource:
    """Scrapes MSRC CVRF API for kernel driver CVEs."""

    def __init__(self, config: dict):
        self.api_url = config.get("api_url", "https://api.msrc.microsoft.com/cvrf/v3.0")
        self.keywords = [k.lower() for k in config.get("keywords", ["Kernel", "Driver"])]
        self.lookback_months = config.get("lookback_months", 3)
        rate = config.get("rate_limit", {})
        self.rate_limit = rate.get("requests_per_minute", 10)

    def _get_recent_update_ids(self, client: httpx.Client) -> list[str]:
        """Get MSRC update IDs for recent months."""
        ids = []
        now = datetime.utcnow()
        for i in range(self.lookback_months):
            dt = now - timedelta(days=30 * i)
            ids.append(dt.strftime("%Y-%b"))
        return ids

    def _is_kernel_related(self, vuln: dict) -> bool:
        """Check if a vulnerability entry is kernel/driver related."""
        title = vuln.get("Title", {}).get("Value", "").lower()
        notes = " ".join(
            n.get("Value", "") for n in vuln.get("Notes", [])
        ).lower()
        text = f"{title} {notes}"
        return any(kw in text for kw in self.keywords)

    def collect(self) -> list[IntelItem]:
        """Collect kernel driver CVEs from MSRC."""
        items = []
        try:
            with httpx.Client(timeout=30) as client:
                update_ids = self._get_recent_update_ids(client)
                for update_id in update_ids:
                    try:
                        resp = client.get(
                            f"{self.api_url}/cvrf/{update_id}",
                            headers={"Accept": "application/json"},
                        )
                        if resp.status_code != 200:
                            logger.warning("MSRC API returned %d for %s", resp.status_code, update_id)
                            continue

                        data = resp.json()
                        vulns = data.get("Vulnerability", [])

                        for vuln in vulns:
                            if not self._is_kernel_related(vuln):
                                continue

                            cve_id = vuln.get("CVE", "")
                            if not CVE_RE.match(cve_id):
                                continue

                            title = vuln.get("Title", {}).get("Value", cve_id)
                            notes_text = " ".join(
                                n.get("Value", "") for n in vuln.get("Notes", [])
                            )

                            drivers = list(set(DRIVER_RE.findall(notes_text)))
                            msrc_url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"

                            items.append(IntelItem(
                                url=msrc_url,
                                title=title,
                                summary=notes_text[:500],
                                source="msrc",
                                cve_ids=[cve_id],
                                drivers=drivers,
                            ))

                    except Exception:
                        logger.exception("Error processing MSRC update %s", update_id)

        except Exception:
            logger.exception("MSRC collection failed")

        logger.info("MSRC: collected %d items", len(items))
        return items
