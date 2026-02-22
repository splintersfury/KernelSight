"""NVD CVE data enrichment source."""

import logging
import time

import httpx

from . import IntelItem

logger = logging.getLogger(__name__)


class NVDSource:
    """Enriches CVE data from the NVD API."""

    def __init__(self, config: dict):
        self.api_url = config.get("api_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.api_key = config.get("api_key", "")
        rate = config.get("rate_limit", {})
        self.rate_limit = rate.get("requests_per_minute", 5)
        self._delay = 60.0 / self.rate_limit

    def enrich_cve(self, cve_id: str) -> dict | None:
        """Fetch CVE details from NVD API.

        Returns dict with cvss_score, cwe_ids, affected_products, or None on failure.
        """
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            with httpx.Client(timeout=30) as client:
                resp = client.get(
                    self.api_url,
                    params={"cveId": cve_id},
                    headers=headers,
                )

                if resp.status_code != 200:
                    logger.warning("NVD API returned %d for %s", resp.status_code, cve_id)
                    return None

                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return None

                cve_data = vulns[0].get("cve", {})

                # Extract CVSS score
                metrics = cve_data.get("metrics", {})
                cvss_score = None
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        cvss_data = metrics[version]
                        if cvss_data:
                            cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore")
                            break

                # Extract CWE IDs
                cwe_ids = []
                for weakness in cve_data.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        val = desc.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_ids.append(val)

                # Extract affected products (CPE)
                affected = []
                for config in cve_data.get("configurations", []):
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe = match.get("criteria", "")
                            if "microsoft" in cpe.lower() and match.get("vulnerable"):
                                affected.append(cpe)

                return {
                    "cvss_score": cvss_score,
                    "cwe_ids": cwe_ids,
                    "affected_products": affected[:10],
                }

        except Exception:
            logger.exception("NVD enrichment failed for %s", cve_id)
            return None
        finally:
            time.sleep(self._delay)

    def collect(self) -> list[IntelItem]:
        """NVD is used for enrichment, not direct collection. Returns empty list."""
        return []
