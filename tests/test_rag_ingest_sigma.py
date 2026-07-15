"""Tests for `rag.ingest_sigma` — the SigmaHQ rule → RagRecord
projection. Runs entirely against synthetic rule files under
tmp_path; no network, no real Sigma checkout.

Covers the projection helpers (tag normalization, kill-chain
extraction, condition/logsource/author rendering) and the
`build_records` walk: filtering, primary-technique selection,
deterministic sort, citation URLs at the pinned tag.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from rag.ingest_sigma import (
    SIGMA_LICENSE,
    SIGMA_SOURCE,
    SIGMA_TAG,
    _author_text,
    _condition_text,
    _kill_chain_phases,
    _logsource_text,
    _normalized_attack_tags,
    build_records,
)


class TestNormalizedAttackTags:
    def test_technique_and_subtechnique_forms(self):
        tags = ["attack.t1055", "attack.t1055.001", "attack.execution"]
        assert _normalized_attack_tags(tags) == ["T1055", "T1055.001"]

    def test_sorted_deduplicated(self):
        tags = ["attack.t1547", "attack.t1055", "attack.t1055"]
        assert _normalized_attack_tags(tags) == ["T1055", "T1547"]

    def test_non_technique_tags_dropped(self):
        tags = ["attack.g0016", "attack.s0002", "cve.2021.44228", "attack.persistence"]
        assert _normalized_attack_tags(tags) == []

    def test_none_and_non_string_tolerated(self):
        assert _normalized_attack_tags(None) == []
        assert _normalized_attack_tags([42, "attack.t1003"]) == ["T1003"]


class TestKillChainPhases:
    def test_phase_tags_extracted_sorted(self):
        tags = ["attack.persistence", "attack.execution", "attack.t1055"]
        assert _kill_chain_phases(tags) == ["execution", "persistence"]

    def test_group_software_and_foreign_tags_dropped(self):
        tags = ["attack.g0016", "attack.s0002", "detection.threat_hunting"]
        assert _kill_chain_phases(tags) == []


class TestRenderingHelpers:
    def test_condition_string_and_list_forms(self):
        assert _condition_text({"condition": "selection and not filter"}) == (
            "selection and not filter"
        )
        assert _condition_text({"condition": ["sel1", "sel2"]}) == "sel1 | sel2"
        assert _condition_text(None) == "n/a"
        assert _condition_text({}) == "n/a"

    def test_logsource_rendered_as_pairs(self):
        assert _logsource_text({"product": "windows", "service": "sysmon"}) == (
            "product=windows, service=sysmon"
        )
        assert _logsource_text(None) == "n/a"

    def test_author_string_list_and_missing(self):
        assert _author_text("Florian Roth") == "Florian Roth"
        assert _author_text(["A", "B"]) == "A, B"
        assert _author_text(None) == "Sigma rule authors"


def _write_rule(root: Path, rel: str, body: str) -> None:
    path = root / "rules" / "windows" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body), encoding="utf-8")


@pytest.fixture
def sigma_root(tmp_path: Path) -> Path:
    root = tmp_path / "sigma"
    _write_rule(
        root,
        "process_creation/proc_creation_win_injection.yml",
        """\
        title: Suspicious Remote Thread
        status: stable
        description: Detects remote thread creation.
        author: Test Author
        level: high
        logsource:
            product: windows
            category: process_creation
        detection:
            selection:
                Image: '*\\rundll32.exe'
            condition: selection
        tags:
            - attack.t1055.001
            - attack.t1055
            - attack.defense_evasion
        """,
    )
    _write_rule(
        root,
        "registry/registry_persistence.yml",
        """\
        title: Registry Run Key
        status: test
        description: Detects run-key persistence.
        logsource:
            product: windows
        detection:
            selection:
                TargetObject: '*\\Run\\*'
            condition: selection
        tags:
            - attack.t1547.001
            - attack.persistence
        """,
    )
    _write_rule(
        root,
        "deprecated/old_rule.yml",
        """\
        title: Old Rule
        status: deprecated
        detection:
            condition: selection
        tags:
            - attack.t1003
        """,
    )
    _write_rule(
        root,
        "untagged/no_attack_tag.yml",
        """\
        title: No Technique Anchor
        status: stable
        detection:
            condition: selection
        tags:
            - detection.threat_hunting
        """,
    )
    _write_rule(root, "broken/bad_yaml.yml", "title: [unclosed\n")
    return root


class TestBuildRecords:
    def test_projection_filtering_and_sort(self, sigma_root: Path, capsys):
        records = build_records(sigma_root)

        # deprecated, tagless, and unparseable rules are dropped.
        assert len(records) == 2
        # Sorted by (technique_id, citation_url); the first normalized
        # tag (ascending) is the primary technique anchor.
        assert [r.technique_id for r in records] == ["T1055", "T1547.001"]

        injection = records[0]
        assert injection.name == "Suspicious Remote Thread"
        assert injection.source == SIGMA_SOURCE
        assert injection.license == SIGMA_LICENSE
        assert injection.platforms == ["Windows"]
        assert injection.kill_chain_phases == ["defense_evasion"]
        # Description composes rule text + detection shape + tags.
        assert "Detects remote thread creation." in injection.description
        assert "product=windows" in injection.description
        assert "T1055 T1055.001" in injection.description
        assert "Authored by: Test Author." in injection.description

        # Citation pins the tag and uses the repo-relative posix path.
        assert f"/blob/{SIGMA_TAG}/rules/windows/process_creation/" in injection.citation_url

        # Skip counters surface on stderr rather than silently dropping.
        err = capsys.readouterr().err
        assert "1 status" in err
        assert "1 no-attack-tag" in err
        assert "1 parse-error" in err

    def test_missing_rules_dir_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            build_records(tmp_path / "nope")

    def test_output_is_deterministic(self, sigma_root: Path):
        first = [r.model_dump() for r in build_records(sigma_root)]
        second = [r.model_dump() for r in build_records(sigma_root)]
        assert first == second
