# Release artifact workflow

The policies in this directory and `scripts/release_artifacts.py` provide deterministic,
fail-closed inspection for the `0.1.0rc1` prerelease. They do not upload, sign, or publish a
release.

## Build reproducible archives

```bash
python3.11 scripts/build_release.py build \
  --output /absolute/new/release-artifacts \
  --source-date-epoch 1788307200
```

The output directory must be new or empty. The command builds twice from independent staged copies,
requires byte-identical wheel and source-distribution files, checks their exact member policies,
and writes `build-manifest.json`.

## Inspect archives

```bash
PYTHONDONTWRITEBYTECODE=1 python3.11 scripts/release_artifacts.py inspect \
  --kind wheel \
  --archive /absolute/new/release-artifacts/erp_security_evidence_workbench-0.1.0rc1-py3-none-any.whl \
  --policy release/wheel-members.txt

PYTHONDONTWRITEBYTECODE=1 python3.11 scripts/release_artifacts.py inspect \
  --kind sdist \
  --archive /absolute/new/release-artifacts/erp_security_evidence_workbench-0.1.0rc1.tar.gz \
  --policy release/sdist-members.txt
```

## Generate metadata

Create SPDX metadata from the inspected wheel with the same canonical epoch:

```bash
PYTHONDONTWRITEBYTECODE=1 python3.11 scripts/release_artifacts.py sbom \
  --wheel /absolute/new/release-artifacts/erp_security_evidence_workbench-0.1.0rc1-py3-none-any.whl \
  --policy release/wheel-members.txt \
  --source-date-epoch 1788307200 \
  --output /absolute/new/release-artifacts/erp-security-evidence-workbench-0.1.0rc1.spdx.json
```

Record the selected committed source tree:

```bash
PYTHONDONTWRITEBYTECODE=1 python3.11 scripts/release_artifacts.py source-snapshot \
  --source-root . \
  --output /absolute/new/release-artifacts/source-snapshot.json
```

This command requires a real Git repository with a resolvable committed `HEAD`. Staged or unstaged
tracked changes and non-ordinary index flags fail closed. Names and content are read exclusively
from regular-file entries in the resolved `HEAD` tree and its blobs; the index and working-tree
filesystem are not content sources, and there is no non-Git or unborn-`HEAD` fallback. Ignored and
untracked files are neither snapshot inputs nor cleanliness blockers.

Write checksums last so every other regular release asset is included:

```bash
PYTHONDONTWRITEBYTECODE=1 python3.11 scripts/release_artifacts.py checksums \
  --artifact-dir /absolute/new/release-artifacts
```

`sbom`, `source-snapshot`, and `checksums` atomically replace an existing regular output file.
Symbolic links and other non-regular output targets are refused. The checksum command processes
regular files in filename order, excludes `SHA256SUMS` itself, and rejects subdirectories or
non-regular entries.

## Inspection boundary

The archive inspector rejects links, absolute or traversing names, unsafe permission modes, members
outside the exact policy, known cache/internal-document paths, selected local-path markers, and
fixed secret-like canaries. ZIP and tar member counts, metadata sizes, and decompressed aggregate
bytes are bounded before or during inspection.

The SPDX document records exact unresolved `Requires-Dist` declarations from the wheel. It does
not assert that dependencies were resolved, installed, licensed, or checked for vulnerabilities.
These checks are not a general secret scanner, malware scanner, legal review, license-compliance
decision, vulnerability-clearance result, or cryptographic provenance attestation.
