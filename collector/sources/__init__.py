"""KernelSight collector source scrapers."""

from dataclasses import dataclass, field


@dataclass
class IntelItem:
    """A single intelligence item from a source."""

    url: str
    title: str
    summary: str
    source: str
    cve_ids: list[str] = field(default_factory=list)
    drivers: list[str] = field(default_factory=list)
    technique_tags: list[str] = field(default_factory=list)
    raw_content: str = ""

    @property
    def dedup_key(self) -> str:
        """Key for deduplication — URL normalized."""
        return self.url.rstrip("/").lower()
