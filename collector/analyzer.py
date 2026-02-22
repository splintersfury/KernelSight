"""Content analyzer — classifies IntelItems into KernelSight technique categories."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from sources import IntelItem

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DRIVER_RE = re.compile(r"\b([\w]+\.sys)\b", re.IGNORECASE)

# Well-known Windows kernel API names (sinks) that indicate technique areas
SINK_KEYWORDS = {
    "ioctl-handlers": [
        "DeviceIoControl", "IRP_MJ_DEVICE_CONTROL", "METHOD_NEITHER",
        "METHOD_BUFFERED", "IOCTL",
    ],
    "buffer-overflow": [
        "RtlCopyMemory", "memcpy", "memmove", "heap overflow",
        "buffer overflow", "stack overflow", "OOB write",
    ],
    "integer-overflow": [
        "integer overflow", "integer underflow", "truncation",
        "RtlULongAdd", "safe math",
    ],
    "type-confusion": [
        "type confusion", "ObReferenceObjectByHandle", "object type",
        "WOW64", "vtable",
    ],
    "use-after-free": [
        "use-after-free", "UAF", "dangling pointer", "double free",
        "reference count", "refcount",
    ],
    "race-conditions": [
        "race condition", "TOCTOU", "double fetch", "spinlock",
        "mutex", "concurrency",
    ],
    "mdl-mapping": [
        "MmProbeAndLockPages", "MmMapLockedPages", "MDL",
        "MmGetSystemAddressForMdl",
    ],
    "pool-overflow": [
        "pool overflow", "pool corruption", "heap spray",
        "pool feng shui", "adjacent allocation",
    ],
    "write-what-where": [
        "write-what-where", "arbitrary write", "ProbeForWrite",
        "arbitrary read",
    ],
    "token-swapping": [
        "token swap", "token manipulation", "SYSTEM token",
        "privilege escalation", "EPROCESS",
    ],
    "previous-mode-manipulation": [
        "PreviousMode", "ExGetPreviousMode", "KernelMode bypass",
    ],
    "kaslr": [
        "KASLR", "info leak", "information disclosure",
        "kernel pointer", "NtQuerySystemInformation",
    ],
    "vbs-hvci": [
        "VBS", "HVCI", "hypervisor", "secure kernel", "VTL",
    ],
    "pool-spray-feng-shui": [
        "pool spray", "feng shui", "heap grooming", "LFH",
        "segment heap",
    ],
    "io-ring": [
        "I/O Ring", "IoRing", "NtSubmitIoRing",
    ],
}


@dataclass
class ProposedChange:
    """A proposed change to the KernelSight knowledge base."""

    change_type: str  # "new_case_study", "update_references", "new_technique_xref"
    target_file: str
    additions: dict = field(default_factory=dict)
    source_url: str = ""
    confidence: float = 0.0
    description: str = ""


class Analyzer:
    """Classifies IntelItems into KernelSight techniques and proposes changes."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.techniques = self._load_techniques()
        self.existing_cves = self._load_existing_cves()

    def _load_techniques(self) -> dict:
        """Load technique tags from index/techniques.yaml."""
        path = self.repo_root / "index" / "techniques.yaml"
        if not path.exists():
            logger.warning("techniques.yaml not found at %s", path)
            return {}

        with open(path) as f:
            data = yaml.safe_load(f)

        techniques = {}
        for t in data.get("techniques", []):
            slug = t["slug"]
            techniques[slug] = {
                "tags": [tag.lower() for tag in t.get("tags", [])],
                "cves": t.get("cves", []),
                "path": t.get("path", ""),
            }
        return techniques

    def _load_existing_cves(self) -> set[str]:
        """Load already-indexed CVE IDs."""
        path = self.repo_root / "index" / "cve_index.yaml"
        if not path.exists():
            return set()

        with open(path) as f:
            data = yaml.safe_load(f)

        return {c["cve_id"] for c in data.get("cves", [])}

    def _classify_techniques(self, item: IntelItem) -> list[tuple[str, float]]:
        """Classify an IntelItem into technique slugs with confidence scores."""
        text = f"{item.title} {item.summary} {item.raw_content}".lower()
        matches = []

        # Check SINK_KEYWORDS first (higher confidence)
        for slug, keywords in SINK_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw.lower() in text)
            if score > 0:
                confidence = min(0.4 + (score * 0.15), 0.95)
                matches.append((slug, confidence))

        # Check technique tags from YAML
        for slug, info in self.techniques.items():
            tag_score = sum(1 for tag in info["tags"] if tag in text)
            if tag_score > 0:
                confidence = min(0.3 + (tag_score * 0.1), 0.85)
                # Don't duplicate if already matched via SINK_KEYWORDS
                if not any(m[0] == slug for m in matches):
                    matches.append((slug, confidence))

        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:5]

    def analyze(self, item: IntelItem) -> list[ProposedChange]:
        """Analyze an IntelItem and return proposed changes."""
        changes = []
        techniques = self._classify_techniques(item)

        for cve_id in item.cve_ids:
            if cve_id not in self.existing_cves:
                # New CVE — propose a new case study
                target = f"docs/case-studies/{cve_id}.md"
                driver_str = ", ".join(item.drivers) if item.drivers else "unknown"
                technique_str = techniques[0][0] if techniques else "unknown"
                confidence = techniques[0][1] if techniques else 0.3

                changes.append(ProposedChange(
                    change_type="new_case_study",
                    target_file=target,
                    additions={
                        "cve_id": cve_id,
                        "drivers": item.drivers,
                        "techniques": [t[0] for t in techniques],
                        "source_url": item.url,
                        "summary": item.summary[:300],
                    },
                    source_url=item.url,
                    confidence=confidence,
                    description=f"New CVE {cve_id} ({driver_str}) — {technique_str}",
                ))
            else:
                # Existing CVE — propose reference update
                target = f"docs/case-studies/{cve_id}.md"
                changes.append(ProposedChange(
                    change_type="update_references",
                    target_file=target,
                    additions={
                        "url": item.url,
                        "title": item.title,
                        "source": item.source,
                    },
                    source_url=item.url,
                    confidence=0.7,
                    description=f"New reference for {cve_id}: {item.title[:80]}",
                ))

        # Technique cross-references (even without CVE)
        if not item.cve_ids and techniques:
            top_slug, top_conf = techniques[0]
            if top_conf >= 0.5:
                info = self.techniques.get(top_slug, {})
                target = info.get("path", f"docs/vuln-classes/{top_slug}.md")
                changes.append(ProposedChange(
                    change_type="new_technique_xref",
                    target_file=target,
                    additions={
                        "url": item.url,
                        "title": item.title,
                        "technique": top_slug,
                    },
                    source_url=item.url,
                    confidence=top_conf,
                    description=f"New reference for {top_slug}: {item.title[:80]}",
                ))

        return changes
