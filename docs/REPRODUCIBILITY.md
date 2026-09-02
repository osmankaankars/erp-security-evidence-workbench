# Reproducibility

## Scope

Reproducibility here means byte-identical generated project artifacts when the documented source
tree, interpreter and tool versions, command arguments, locale, timezone, and
`SOURCE_DATE_EPOCH` are held fixed. It does not prove source authenticity, equivalent behavior on
every platform, or identical archives from a different build stack.

## Package build

Create a development environment with the exact pins in `pyproject.toml`, then build into a new or
empty destination:

```bash
python3.11 scripts/build_release.py build \
  --output /absolute/new/release-artifacts \
  --source-date-epoch 1788307200
```

The builder copies a bounded source allowlist into two independent temporary staging trees,
normalizes staged modification times, and invokes `python -B -s -m build --no-isolation` twice in
the same sanitized environment used to record build-tool versions. It rejects any differing wheel
or source-distribution bytes.

Only the compared archives and deterministic `build-manifest.json` are published into the selected
directory. The output directory must be new or empty and must not be a symbolic link. The builder
intentionally records version-control identity as unavailable because it operates on bounded staged
inputs without VCS metadata. The separate source snapshot requires a resolvable committed `HEAD`
and hashes the exact regular-file blobs named by that tree. It has no filesystem or non-Git
fallback.

The source manifest lists each bounded input's canonical relative path, byte length, and SHA-256.
Its staged-tree digest commits to the canonical serialization of those entries. It is not a signed
attestation.

## Source snapshot and release metadata

After the release revision is committed, create a deterministic source snapshot manifest:

```bash
PYTHONDONTWRITEBYTECODE=1 python3.11 scripts/release_artifacts.py source-snapshot \
  --source-root . \
  --output /absolute/new/release-artifacts/source-snapshot.json
```

The command requires a real Git repository with a resolvable committed `HEAD`. Staged or unstaged
tracked changes, non-ordinary index flags, unsupported tree entries, malformed Git output, and Git
object failures are rejected before an output is written. File names and bytes come only from the
resolved `HEAD` tree and blobs; ignored and untracked files are neither inputs nor cleanliness
blockers. The starting revision and tracked state are checked again after object inspection.

Generate the SPDX inventory and write `SHA256SUMS` only after every other release asset is final.
The complete workflow is documented in [../release/README.md](../release/README.md).

## Synthetic corpus and example reports

Check committed generated inputs without rewriting them:

```bash
PYTHONPATH=src python3.11 scripts/synthetic_corpus.py check \
  --corpus examples/scenarios
```

Generate a preview into a new or empty destination:

```bash
PYTHONPATH=src python3.11 scripts/example_reports.py generate \
  --output /absolute/new/example-report-preview
```

Reconstruct the expected bytes and compare them with the committed report set:

```bash
PYTHONPATH=src python3.11 scripts/example_reports.py check \
  --reports examples/reports
```

Managed manifests and checksum entries use deterministic ordering and serialization.

## Environment record

Record at least:

- operating system and architecture;
- Python implementation and full version;
- exact `build`, `setuptools`, and `wheel` versions;
- fixed source-date epoch;
- staged source-tree digest, plus the separate resolved-`HEAD` tree/blob-bound snapshot revision
  and digest;
- artifact filenames, sizes, and SHA-256 digests.

Build metadata must not contain usernames, home directories, temporary paths, hostnames, arbitrary
environment variables, or wall-clock execution timestamps.

## Known limits

- Archive equivalence is qualified by the recorded build environment.
- Development dependencies are exact direct pins but not a hash-locked, platform-specific
  transitive lock.
- SHA-256 detects byte differences; it does not establish authorship, confidentiality, legal
  clearance, or vulnerability status.
- Local and hosted CI results support only the exact revisions and environments they exercised.
