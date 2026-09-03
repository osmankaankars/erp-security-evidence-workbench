"""Acceptance contracts for deterministic synthetic multi-source replay."""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from erp_security_evidence_workbench.cli import main

AS_OF = "2026-09-01T12:45:00Z"


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def _write_source(path: Path, value: object, *, jsonl: bool = False) -> str:
    if jsonl:
        assert isinstance(value, list)
        content = b"".join(_canonical_bytes(item) for item in value)
    else:
        content = _canonical_bytes(value)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _scenario(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    honeypot = tmp_path / "honeypot-events.jsonl"
    indicators = tmp_path / "threat-indicators.json"
    changes = tmp_path / "change-events.jsonl"
    honeypot_digest = _write_source(
        honeypot,
        [
            {
                "action": "SIGN_IN",
                "dataset_classification": "synthetic",
                "event_id": f"event-{index}",
                "occurred_at": occurred_at,
                "outcome": outcome,
                "principal_id": "analyst-7",
                "schema_version": "erpsec.synthetic-honeypot-event/v1",
                "sensor_id": "sensor-lab-a",
                "source_address": "198.51.100.42",
            }
            for index, (occurred_at, outcome) in enumerate(
                (
                    ("2026-09-01T12:00:00Z", "failure"),
                    ("2026-09-01T12:04:00Z", "failure"),
                    ("2026-09-01T12:08:00Z", "failure"),
                    ("2026-09-01T12:10:00Z", "success"),
                ),
                start=1,
            )
        ],
        jsonl=True,
    )
    indicator_digest = _write_source(
        indicators,
        [
            {
                "confidence": "high",
                "dataset_classification": "synthetic",
                "indicator_id": "indicator-doc-address",
                "indicator_type": "ip",
                "schema_version": "erpsec.synthetic-threat-indicator/v1",
                "valid_from": "2026-09-01T00:00:00Z",
                "valid_until": "2026-09-02T00:00:00Z",
                "value": "198.51.100.42",
            }
        ],
    )
    change_digest = _write_source(
        changes,
        [
            {
                "action": "GRANT_PRIVILEGE",
                "dataset_classification": "synthetic",
                "object_id": "role-lab-operator",
                "occurred_at": "2026-09-01T12:20:00Z",
                "outcome": "success",
                "principal_id": "analyst-7",
                "record_id": "change-1",
                "record_type": "change_event",
                "schema_version": "erpsec.synthetic-evidence/v1",
            }
        ],
        jsonl=True,
    )
    manifest = tmp_path / "replay-manifest.json"
    _write_source(
        manifest,
        [
            {
                "dataset_classification": "synthetic",
                "replay_id": "scenario-detection-correlation",
                "schema_version": "erpsec.synthetic-replay-manifest/v1",
                "sources": [
                    {
                        "adapter": "erpsec.synthetic-honeypot/v1",
                        "path": honeypot.name,
                        "sha256": honeypot_digest,
                        "source_id": "source-honeypot",
                    },
                    {
                        "adapter": "erpsec.synthetic-threat-intel/v1",
                        "path": indicators.name,
                        "sha256": indicator_digest,
                        "source_id": "source-threat-intel",
                    },
                    {
                        "adapter": "erpsec.synthetic-evidence/v1",
                        "path": changes.name,
                        "sha256": change_digest,
                        "source_id": "source-change-audit",
                    },
                ],
            }
        ],
    )
    return manifest


def _manifest_document(path: Path) -> list[dict[str, object]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, list)
    return value


def _rewrite_source_and_digest(
    manifest: Path,
    *,
    source_id: str,
    records: list[dict[str, object]],
) -> Path:
    document = _manifest_document(manifest)
    root = document[0]
    sources = root["sources"]
    assert isinstance(sources, list)
    descriptor = next(item for item in sources if item["source_id"] == source_id)
    source_path = manifest.parent / str(descriptor["path"])
    descriptor["sha256"] = _write_source(
        source_path,
        records,
        jsonl=source_path.suffix == ".jsonl",
    )
    _write_source(manifest, document)
    return source_path


def _run_replay(
    manifest: Path,
    output: Path,
    *,
    report_format: str = "json",
    rule: str = "all",
) -> int:
    return main(
        [
            "replay",
            str(manifest),
            "--as-of",
            AS_OF,
            "--format",
            report_format,
            "--output",
            str(output),
            "--rule",
            rule,
        ]
    )


def test_installed_replay_contract_emits_v2_correlations_and_is_deterministic(
    tmp_path: Path,
) -> None:
    manifest = _scenario(tmp_path)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    arguments = [
        "replay",
        str(manifest),
        "--as-of",
        AS_OF,
        "--format",
        "json",
        "--output",
    ]

    assert main([*arguments, str(first), "--rule", "all"]) == 1
    assert main([*arguments, str(second), "--rule", "all"]) == 1
    assert first.read_bytes() == second.read_bytes()

    report = json.loads(first.read_text(encoding="utf-8"))
    assert report["schema_version"] == "erpsec.report/v2"
    assert report["replay"]["replay_id"] == "scenario-detection-correlation"
    assert [item["rule_id"] for item in report["evaluations"]] == [
        "ERP007",
        "ERP008",
        "ERP009",
    ]
    assert {item["rule_id"] for item in report["findings"]} == {
        "ERP007",
        "ERP008",
        "ERP009",
    }
    correlations = report["correlations"]
    assert len(correlations) == 3
    assert len({item["correlation_id"] for item in correlations}) == 3
    assert all(len(item["correlation_id"]) == 64 for item in correlations)
    assert all(item["window"]["semantics"] == "closed_interval_inclusive" for item in correlations)
    assert all(len(item["steps"]) >= 2 for item in correlations)
    assert all("correlation_id" in item for item in report["findings"])

    evidence_fields_by_rule = {
        finding["rule_id"]: {
            source_ref.get("field", source_ref.get("json_pointer", "")).rsplit("/", 1)[-1]
            for evidence in finding["evidence_refs"]
            for source_ref in (evidence["source_ref"],)
        }
        for finding in report["findings"]
    }
    assert {"action", "occurred_at", "outcome", "principal_id", "source_address"} <= (
        evidence_fields_by_rule["ERP007"]
    )
    assert {"action", "occurred_at", "outcome", "source_address"} <= evidence_fields_by_rule[
        "ERP008"
    ]
    assert {"action", "object_id", "occurred_at", "outcome", "principal_id"} <= (
        evidence_fields_by_rule["ERP009"]
    )


def test_replay_html_and_sarif_expose_the_same_correlation_ids(tmp_path: Path) -> None:
    manifest = _scenario(tmp_path)
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    sarif_path = tmp_path / "report.sarif"

    assert _run_replay(manifest, json_path) == 1
    assert _run_replay(manifest, html_path, report_format="html") == 1
    assert _run_replay(manifest, sarif_path, report_format="sarif") == 1

    report = json.loads(json_path.read_text(encoding="utf-8"))
    correlation_ids = {item["correlation_id"] for item in report["correlations"]}
    html = html_path.read_text(encoding="utf-8")
    assert '<section id="correlations">' in html
    assert all(f'data-correlation-id="{value}"' in html for value in correlation_ids)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    assert {
        item["correlation_id"] for item in run["properties"]["erpsec.correlations"]
    } == correlation_ids
    assert {
        item["properties"]["erpsec.correlationId"] for item in run["results"]
    } == correlation_ids


def test_replay_rejects_digest_mismatch_without_publishing(tmp_path: Path) -> None:
    manifest = _scenario(tmp_path)
    output = tmp_path / "report.json"
    document = _manifest_document(manifest)
    sources = document[0]["sources"]
    assert isinstance(sources, list)
    sources[0]["sha256"] = "0" * 64
    _write_source(manifest, document)

    assert _run_replay(manifest, output) == 2
    assert not output.exists()


@pytest.mark.parametrize("invalid_path", ["../events.jsonl", "nested/events.jsonl", ".."])
def test_replay_rejects_source_path_escape(
    tmp_path: Path,
    invalid_path: str,
) -> None:
    manifest = _scenario(tmp_path)
    output = tmp_path / "report.json"
    document = _manifest_document(manifest)
    sources = document[0]["sources"]
    assert isinstance(sources, list)
    sources[0]["path"] = invalid_path
    _write_source(manifest, document)

    assert _run_replay(manifest, output) == 2
    assert not output.exists()


def test_honeypot_adapter_rejects_real_world_ip_space(tmp_path: Path) -> None:
    manifest = _scenario(tmp_path)
    output = tmp_path / "report.json"
    records = [
        json.loads(line)
        for line in (tmp_path / "honeypot-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    records[0]["source_address"] = "8.8.8.8"
    _rewrite_source_and_digest(
        manifest,
        source_id="source-honeypot",
        records=records,
    )

    assert _run_replay(manifest, output) == 2
    assert not output.exists()


def test_replay_deduplicates_repeated_successes_for_one_semantic_episode(
    tmp_path: Path,
) -> None:
    manifest = _scenario(tmp_path)
    output = tmp_path / "report.json"
    records = [
        json.loads(line)
        for line in (tmp_path / "honeypot-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    duplicate_success = dict(records[-1])
    duplicate_success["event_id"] = "event-5"
    duplicate_success["occurred_at"] = "2026-09-01T12:10:30Z"
    _rewrite_source_and_digest(
        manifest,
        source_id="source-honeypot",
        records=[*records, duplicate_success],
    )

    assert _run_replay(manifest, output, rule="ERP007") == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert len(report["findings"]) == len(report["correlations"]) == 1


def test_replay_window_boundaries_are_inclusive_and_one_second_over_is_clean(
    tmp_path: Path,
) -> None:
    exact_manifest = _scenario(tmp_path / "exact")
    exact_output = exact_manifest.parent / "report.json"
    assert _run_replay(exact_manifest, exact_output, rule="ERP007") == 1

    over_dir = tmp_path / "over"
    over_manifest = _scenario(over_dir)
    over_output = over_dir / "report.json"
    records = [
        json.loads(line)
        for line in (over_dir / "honeypot-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    records[0]["occurred_at"] = "2026-09-01T11:59:59Z"
    _rewrite_source_and_digest(
        over_manifest,
        source_id="source-honeypot",
        records=records,
    )

    assert _run_replay(over_manifest, over_output, rule="ERP007") == 0
    report = json.loads(over_output.read_text(encoding="utf-8"))
    assert report["correlations"] == []
    assert report["findings"] == []


@pytest.mark.parametrize("success_id", ["a-success", "z-success"])
@pytest.mark.parametrize(
    ("report_format", "suffix"),
    [("json", "json"), ("html", "html"), ("sarif", "sarif")],
)
def test_erp007_same_second_events_never_infer_order_from_record_id(
    tmp_path: Path,
    success_id: str,
    report_format: str,
    suffix: str,
) -> None:
    root = tmp_path / report_format / success_id
    manifest = _scenario(root)
    output = root / f"report.{suffix}"
    records = [
        json.loads(line)
        for line in (root / "honeypot-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    for record in records:
        record["occurred_at"] = "2026-09-01T12:10:00Z"
    records[-1]["event_id"] = success_id
    _rewrite_source_and_digest(
        manifest,
        source_id="source-honeypot",
        records=records,
    )

    assert _run_replay(manifest, output, report_format=report_format, rule="ERP007") == 0
    if report_format == "json":
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["correlations"] == []
        assert report["findings"] == []
    elif report_format == "sarif":
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["runs"][0]["results"] == []
        assert report["runs"][0]["properties"]["erpsec.correlations"] == []
    else:
        html = output.read_text(encoding="utf-8")
        assert "No finding records were emitted." in html
        assert "No correlation episodes were emitted." in html


def test_replay_never_opens_a_network_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _scenario(tmp_path)
    output = tmp_path / "report.json"

    def _forbidden_socket(*args: object, **kwargs: object) -> socket.socket:
        del args, kwargs
        raise AssertionError("network access is forbidden during replay")

    monkeypatch.setattr(socket, "socket", _forbidden_socket)

    assert _run_replay(manifest, output) == 1


def test_replay_refuses_to_overwrite_a_declared_source(tmp_path: Path) -> None:
    manifest = _scenario(tmp_path)
    source = tmp_path / "honeypot-events.jsonl"
    original = source.read_bytes()

    assert _run_replay(manifest, source) == 2
    assert source.read_bytes() == original


def test_replay_manifest_rejects_unknown_adapter_and_non_synthetic_classification(
    tmp_path: Path,
) -> None:
    for case, mutation in (
        ("adapter", ("sources", 0, "adapter", "erpsec.remote-feed/v1")),
        ("classification", ("dataset_classification", "internal")),
    ):
        root = tmp_path / case
        manifest = _scenario(root)
        output = root / "report.json"
        document = _manifest_document(manifest)
        if mutation[0] == "sources":
            sources = document[0]["sources"]
            assert isinstance(sources, list)
            sources[mutation[1]][mutation[2]] = mutation[3]
        else:
            document[0][mutation[0]] = mutation[1]
        _write_source(manifest, document)

        assert _run_replay(manifest, output) == 2
        assert not output.exists()


def test_replay_rejects_non_synthetic_source_record_without_publishing(tmp_path: Path) -> None:
    manifest = _scenario(tmp_path)
    output = tmp_path / "report.json"
    records = [
        json.loads(line)
        for line in (tmp_path / "honeypot-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    records[0]["dataset_classification"] = "internal"
    _rewrite_source_and_digest(
        manifest,
        source_id="source-honeypot",
        records=records,
    )

    assert _run_replay(manifest, output) == 2
    assert not output.exists()


def test_replay_excludes_events_after_as_of_but_includes_exact_boundary(tmp_path: Path) -> None:
    for case, occurred_at, expected_exit in (
        ("exact", AS_OF, 1),
        ("after", "2026-09-01T12:45:01Z", 0),
    ):
        root = tmp_path / case
        manifest = _scenario(root)
        output = root / "report.json"
        records = [
            json.loads(line)
            for line in (root / "honeypot-events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        for record, failure_time in zip(
            records[:-1],
            ("2026-09-01T12:35:00Z", "2026-09-01T12:39:00Z", "2026-09-01T12:43:00Z"),
            strict=True,
        ):
            record["occurred_at"] = failure_time
        records[-1]["occurred_at"] = occurred_at
        _rewrite_source_and_digest(
            manifest,
            source_id="source-honeypot",
            records=records,
        )

        assert _run_replay(manifest, output, rule="ERP007") == expected_exit
        report = json.loads(output.read_text(encoding="utf-8"))
        assert bool(report["correlations"]) is bool(expected_exit)


def test_indicator_validity_end_is_inclusive_and_one_second_over_is_clean(
    tmp_path: Path,
) -> None:
    for case, valid_until, expected_exit in (
        ("exact", "2026-09-01T12:10:00Z", 1),
        ("over", "2026-09-01T12:09:59Z", 0),
    ):
        root = tmp_path / case
        manifest = _scenario(root)
        output = root / "report.json"
        indicators = json.loads((root / "threat-indicators.json").read_text(encoding="utf-8"))
        indicators[0]["valid_until"] = valid_until
        _rewrite_source_and_digest(
            manifest,
            source_id="source-threat-intel",
            records=indicators,
        )

        assert _run_replay(manifest, output, rule="ERP008") == expected_exit
        report = json.loads(output.read_text(encoding="utf-8"))
        assert bool(report["correlations"]) is bool(expected_exit)


def test_sensitive_change_window_end_is_inclusive_and_one_second_over_is_clean(
    tmp_path: Path,
) -> None:
    for case, occurred_at, expected_exit in (
        ("exact", "2026-09-01T12:40:00Z", 1),
        ("over", "2026-09-01T12:40:01Z", 0),
    ):
        root = tmp_path / case
        manifest = _scenario(root)
        output = root / "report.json"
        changes = [
            json.loads(line)
            for line in (root / "change-events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        changes[0]["occurred_at"] = occurred_at
        _rewrite_source_and_digest(
            manifest,
            source_id="source-change-audit",
            records=changes,
        )

        assert _run_replay(manifest, output, rule="ERP009") == expected_exit
        report = json.loads(output.read_text(encoding="utf-8"))
        assert bool(report["correlations"]) is bool(expected_exit)


@pytest.mark.parametrize(
    ("report_format", "suffix"),
    [("json", "json"), ("html", "html"), ("sarif", "sarif")],
)
def test_erp009_same_second_events_do_not_establish_causal_order(
    tmp_path: Path,
    report_format: str,
    suffix: str,
) -> None:
    root = tmp_path / report_format
    manifest = _scenario(root)
    output = root / f"report.{suffix}"
    changes = [
        json.loads(line)
        for line in (root / "change-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    changes[0]["occurred_at"] = "2026-09-01T12:10:00Z"
    _rewrite_source_and_digest(
        manifest,
        source_id="source-change-audit",
        records=changes,
    )

    assert _run_replay(manifest, output, report_format=report_format, rule="ERP009") == 0
    if report_format == "json":
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["correlations"] == []
        assert report["findings"] == []
    elif report_format == "sarif":
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["runs"][0]["results"] == []
        assert report["runs"][0]["properties"]["erpsec.correlations"] == []
    else:
        html = output.read_text(encoding="utf-8")
        assert "No finding records were emitted." in html
        assert "No correlation episodes were emitted." in html


def test_correlation_ids_ignore_manifest_order_and_source_filename(tmp_path: Path) -> None:
    first_manifest = _scenario(tmp_path / "first")
    second_manifest = _scenario(tmp_path / "second")
    first_output = first_manifest.parent / "report.json"
    second_output = second_manifest.parent / "report.json"
    document = _manifest_document(second_manifest)
    sources = document[0]["sources"]
    assert isinstance(sources, list)
    honeypot = next(item for item in sources if item["source_id"] == "source-honeypot")
    old_path = second_manifest.parent / str(honeypot["path"])
    new_path = second_manifest.parent / "renamed-events.jsonl"
    old_path.rename(new_path)
    honeypot["path"] = new_path.name
    sources.reverse()
    _write_source(second_manifest, document)

    assert _run_replay(first_manifest, first_output) == 1
    assert _run_replay(second_manifest, second_output) == 1
    first = json.loads(first_output.read_text(encoding="utf-8"))
    second = json.loads(second_output.read_text(encoding="utf-8"))
    assert {item["rule_id"]: item["correlation_id"] for item in first["correlations"]} == {
        item["rule_id"]: item["correlation_id"] for item in second["correlations"]
    }
