"""Static policy checks for the inert, pinned CI definition."""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
CODEQL_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "codeql.yml"


def test_ci_uses_only_full_length_pinned_official_actions() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")
    action_refs = re.findall(r"^\s*uses: ([^@\s]+)@([^\s#]+)", content, re.MULTILINE)

    assert action_refs == [
        ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1"),
        ("actions/setup-python", "5fda3b95a4ea91299a34e894583c3862153e4b97"),
    ]
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in action_refs)


def test_ci_has_read_only_permissions_and_no_privileged_trigger() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    assert "permissions:\n  contents: read\n" in content
    assert "persist-credentials: false" in content
    assert "pull_request_target:" not in content
    assert "workflow_run:" not in content
    assert "contents: write" not in content
    assert "id-token: write" not in content
    assert "push:\n    branches: [main]\n" in content
    assert "cancel-in-progress: true" in content


def test_ci_uses_posix_python_matrix_and_local_gate() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    assert "runs-on: ${{ matrix.os }}" in content
    assert "os: [ubuntu-24.04, macos-15]" in content
    assert 'python-version: ["3.11", "3.12", "3.13", "3.14"]' in content
    assert 'python-version: "${{ matrix.python-version }}"' in content
    assert "run: make bootstrap BOOTSTRAP_PYTHON=python" in content
    assert "run: make ci" in content
    assert 'python-version: "3.11.16"' not in content
    assert "actions/cache" not in content
    assert "actions/upload-artifact" not in content


def test_codeql_uses_only_pinned_official_actions_and_minimal_permissions() -> None:
    content = CODEQL_WORKFLOW.read_text(encoding="utf-8")
    action_refs = re.findall(r"^\s*uses: ([^@\s]+)@([^\s#]+)", content, re.MULTILINE)

    assert action_refs == [
        ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1"),
        ("github/codeql-action/init", "cdf488f595d80d6e07e03d4674febd5ab45fa938"),
        ("github/codeql-action/analyze", "cdf488f595d80d6e07e03d4674febd5ab45fa938"),
    ]
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in action_refs)
    assert "permissions:\n  contents: read\n  security-events: write\n" in content
    assert "persist-credentials: false" in content
    assert "pull_request_target:" not in content
    assert "workflow_run:" not in content
    assert "contents: write" not in content
    assert "id-token: write" not in content
    assert "push:\n    branches: [main]\n" in content
    assert "schedule:" in content
    assert "workflow_dispatch:" in content
