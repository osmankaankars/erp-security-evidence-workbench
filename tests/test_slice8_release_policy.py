"""Release-candidate metadata and documentation policy checks."""

from __future__ import annotations

import tomllib
from pathlib import Path

from erp_security_evidence_workbench import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict[str, object]:
    return tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_rc_version_has_one_package_source_of_truth() -> None:
    configuration = _pyproject()
    project = configuration["project"]
    setuptools = configuration["tool"]["setuptools"]

    assert __version__ == "0.1.0rc1"
    assert "version" not in project
    assert project["dynamic"] == ["version"]
    assert setuptools["dynamic"]["version"] == {
        "attr": "erp_security_evidence_workbench.__version__"
    }


def test_release_candidate_tool_versions_are_exact() -> None:
    configuration = _pyproject()

    assert configuration["build-system"]["requires"] == ["setuptools==84.0.0"]
    assert set(configuration["project"]["optional-dependencies"]["dev"]) == {
        "build==1.6.0",
        "jsonschema==4.26.0",
        "mypy==1.20.2",
        "pytest==8.4.2",
        "ruff==0.16.5",
        "setuptools==84.0.0",
        "wheel==0.48.0",
    }
    assert configuration["project"]["dependencies"] == []


def test_release_candidate_declares_mit_license_and_canonical_urls() -> None:
    project = _pyproject()["project"]

    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert project["urls"] == {
        "Changelog": (
            "https://github.com/osmankaankars/erp-security-evidence-workbench/"
            "blob/main/CHANGELOG.md"
        ),
        "Issues": "https://github.com/osmankaankars/erp-security-evidence-workbench/issues",
        "Repository": "https://github.com/osmankaankars/erp-security-evidence-workbench",
    }

    license_text = (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in license_text
    assert "Copyright (c) 2026 Osman Kaan Kars" in license_text
    assert "Permission is hereby granted, free of charge" in license_text


def test_required_release_candidate_documents_exist() -> None:
    required_paths = (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/pull_request_template.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "SECURITY.md",
        "THIRD_PARTY_NOTICES.md",
        "docs/ARCHITECTURE.md",
        "docs/CLAIM_EVIDENCE.md",
        "docs/OBSERVED_PERFORMANCE.md",
        "docs/RELEASE_CANDIDATE.md",
        "docs/REPRODUCIBILITY.md",
        "docs/RULE_AUTHORING.md",
    )

    missing = [path for path in required_paths if not (PROJECT_ROOT / path).is_file()]

    assert missing == []
