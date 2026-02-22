"""Tests for the KernelSight collector analyzer."""

import sys
from pathlib import Path

import pytest

# Add collector directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sources import IntelItem
from analyzer import Analyzer, ProposedChange, SINK_KEYWORDS


@pytest.fixture
def repo_root(tmp_path):
    """Create a minimal repo structure for testing."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()

    # Minimal techniques.yaml
    (index_dir / "techniques.yaml").write_text("""
version: 1
techniques:
  - slug: buffer-overflow
    title: Buffer Overflow
    section: vuln-classes
    path: docs/vuln-classes/buffer-overflow.md
    tags: [overflow, heap, memcpy, RtlCopyMemory]
    cves: [CVE-2024-30085]
  - slug: use-after-free
    title: Use-After-Free
    section: vuln-classes
    path: docs/vuln-classes/use-after-free.md
    tags: [uaf, use_after_free, dangling, refcount]
    cves: [CVE-2024-38193]
""")

    # Minimal cve_index.yaml
    (index_dir / "cve_index.yaml").write_text("""
version: 1
cves:
  - cve_id: "CVE-2024-30085"
  - cve_id: "CVE-2024-38193"
""")

    return tmp_path


@pytest.fixture
def analyzer(repo_root):
    return Analyzer(repo_root)


class TestAnalyzer:
    def test_loads_techniques(self, analyzer):
        assert "buffer-overflow" in analyzer.techniques
        assert "use-after-free" in analyzer.techniques

    def test_loads_existing_cves(self, analyzer):
        assert "CVE-2024-30085" in analyzer.existing_cves
        assert "CVE-2024-38193" in analyzer.existing_cves

    def test_new_cve_proposes_case_study(self, analyzer):
        item = IntelItem(
            url="https://example.com/cve-2099-12345",
            title="CVE-2099-12345: heap overflow in test.sys",
            summary="A heap overflow in test.sys allows EoP via memcpy overflow",
            source="msrc",
            cve_ids=["CVE-2099-12345"],
            drivers=["test.sys"],
        )

        changes = analyzer.analyze(item)
        assert len(changes) >= 1
        new_studies = [c for c in changes if c.change_type == "new_case_study"]
        assert len(new_studies) == 1
        assert new_studies[0].additions["cve_id"] == "CVE-2099-12345"

    def test_existing_cve_proposes_reference_update(self, analyzer):
        item = IntelItem(
            url="https://example.com/new-writeup",
            title="New analysis of CVE-2024-30085",
            summary="Deep dive into cldflt.sys heap overflow",
            source="blog:test",
            cve_ids=["CVE-2024-30085"],
            drivers=["cldflt.sys"],
        )

        changes = analyzer.analyze(item)
        ref_updates = [c for c in changes if c.change_type == "update_references"]
        assert len(ref_updates) == 1
        assert ref_updates[0].additions["url"] == "https://example.com/new-writeup"

    def test_technique_classification_buffer_overflow(self, analyzer):
        item = IntelItem(
            url="https://example.com/research",
            title="Exploiting heap overflow via RtlCopyMemory in driver",
            summary="This post covers buffer overflow exploitation with memcpy and heap spray",
            source="blog:test",
        )

        techniques = analyzer._classify_techniques(item)
        slugs = [t[0] for t in techniques]
        assert "buffer-overflow" in slugs

    def test_dedup_key(self):
        item = IntelItem(
            url="https://Example.Com/Path/",
            title="Test",
            summary="Test",
            source="test",
        )
        assert item.dedup_key == "https://example.com/path"


class TestSinkKeywords:
    def test_all_slugs_are_valid_strings(self):
        for slug, keywords in SINK_KEYWORDS.items():
            assert isinstance(slug, str)
            assert len(slug) > 0
            assert isinstance(keywords, list)
            assert all(isinstance(kw, str) for kw in keywords)
