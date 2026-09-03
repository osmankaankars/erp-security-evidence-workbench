# Threat model

## Overview

This document covers the `0.2.0rc1` implementation of ERP Security Evidence Workbench. The product
boundary is a Python 3.11+ command-line process that accepts explicitly
named local synthetic CSV, JSON, or JSONL files, normalizes a fixed schema, evaluates a fixed
registry of deterministic rules, renders JSON/HTML/SARIF bytes, and publishes one new local report.
It has no connector, service, account, credential, remediation, telemetry, or runtime network
path (`cli._parser`, `cli.main`, `ingest.load_evidence`, and `replay.load_replay_manifest`).

The actual data flow is:

```text
operator paths and options
        |
        v
CLI validation -> descriptor-anchored adapters -> canonical evidence bundle
        -> optional digest-pinned replay adapters -> coverage + deterministic rules
        -> bounded evidence references and correlation episodes
        -> JSON / static HTML / SARIF renderer -> no-overwrite local publisher
```

The report is built in memory before any publication path is created. Input normalization does not
retain an arbitrary raw record object; it constructs a fixed canonical record type and a
minimized source reference (`normalization.normalize_payload`, the replay normalizers, and
`src/erp_security_evidence_workbench/models.py`).

Replay adds a local manifest trust boundary: every basename-local source must be a distinct regular
file, match a declared SHA-256 digest, use an allowlisted adapter, declare synthetic classification,
and limit IP data to documentation ranges. The digest detects mismatch but is not a signature or
source-authenticity proof. A manifest cannot declare a URL or executable command.

## Assets and security objectives

- Preserve input file bytes, permission bits, and modification time; never open input for writing.
- Do not follow a final-component input symlink or accept a non-regular input.
- Do not return a successful analysis from a source that changes during the checked read window.
- Never replace an existing output path or publish a partial report as a valid final report.
- Keep report bytes coherent with the engine result and preserve deterministic bytes for identical
  evidence and options.
- Keep runtime offline and subprocess-free.
- Keep diagnostics generic; do not echo records, paths, identifiers, exception text, or
  credential-like values.
- Bound source parsing and pathological fixed-rule evidence fan-out before rendering.

Reports are not confidentiality-free artifacts. JSON always includes minimized source and evidence
manifests, so even a clean JSON report contains basenames, SHA-256 digests, format/adapter IDs,
bounded counts, record IDs, and exact locators. SARIF always includes the minimized source inventory
and adds record IDs/locators only for finding results. HTML limits source provenance to the
basename, format, record ID, and locator attached to each rendered finding; a clean HTML report has
no source inventory. Every format must be handled as potentially sensitive even though only
synthetic evidence is authorized.

## Trust boundaries and assumptions

1. **Operator to CLI.** Arguments and requested paths are untrusted strings. Argument failures use
   a fixed diagnostic instead of reflecting the supplied value
   (`cli._SafeArgumentParser`).
2. **Filesystem namespace to opened descriptors.** Source and output parent directories are opened
   once; final-component operations use a basename plus `dir_fd`. Before an input descriptor can be
   acquired, the adapter blocks `SIGINT` for the complete descriptor-owning scope, checks a pending
   signal at bounded safe points under Python's default `SIGINT`-to-`KeyboardInterrupt` handler,
   makes bounded close attempts for both owned descriptors, and only then restores the prior
   thread mask. Its binary wrapper is non-owning. Inputs use `O_NOFOLLOW`, regular-file checks,
   identity/state comparisons before and after parsing, and a parent-binding check
   (`adapters.parse_source` and its descriptor helpers).
3. **Untrusted bytes to canonical model.** Bounded adapters parse the complete source and strict
   normalization rejects unknown fields, unsupported types, non-synthetic classification, invalid
   identifiers, and duplicate record IDs (`adapters._parse_open_source`,
   `normalization.normalize_payload`, `ingest.load_evidence`, and the replay normalizers).
4. **Canonical model to finding engine.** Coverage is checked before evaluation. The run is rejected
   if retained finding evidence would exceed 30,000 references
   (`rules._preflight_coverage` and `rules.evaluate_rules`).
5. **In-memory report to filesystem.** The publisher requests a random exclusive temporary no
   broader than mode `0600` in the opened parent, forces exact mode `0600` before writing, writes and
   file-syncs the complete bytes, links a
   new final name exclusively, verifies inode/mode/size and the parent binding, then performs
   bounded best-effort name cleanup. Before any publisher descriptor can be acquired, the publisher
   blocks `SIGINT` for the complete descriptor/name-owning scope, checks for a pending signal after
   acquisition, writing, and at pre-link and immediately-pre-commit safe points, performs identity-aware cleanup and
   closes descriptors, and only then restores the prior thread mask. The acquisition helpers also
   record returned descriptors in caller-created owners before returning. If unlink itself repeatedly
   fails during a pre-link descriptor write,
   sync, or verification failure, a mode-`0600` temporary name can remain. An interruption before
   `fchmod` can leave only an empty file no broader than `0600`; later partial/complete residuals are
   exactly `0600`. If the complete final link was created but its verification failed, one or both of the
   mode-`0600` final and temporary names can remain while the operation reports failure
   (`reporting.write_new_report` and its descriptor-relative publication helpers).
6. **Development supply chain.** Runtime dependencies are empty. Development dependencies and two
   GitHub Actions workflows are a separate trust boundary; actions are pinned by full commit SHA
   and checkout credentials are not persisted. The CI token is limited to `contents: read`.
   CodeQL additionally receives only `security-events: write`, which is required to upload its
   analysis result. Each workflow still writes its ephemeral runner filesystem, resolves or uses
   development tooling, and executes checked-out code with the runner's process and network
   authority (`pyproject.toml:5-36`, `Makefile:8-33`, `.github/workflows/ci.yml`, and
   `.github/workflows/codeql.yml`).
   Source-snapshot generation additionally trusts the local Git executable and object database. It
   requires one resolvable committed `HEAD`, rejects dirty tracked/index state and non-ordinary
   index flags, reads only regular-file blobs from that exact tree, and rechecks state and `HEAD`
   before output. Non-Git and unborn repositories have no filesystem fallback
   (`scripts/release_artifacts.py`).
7. **Embedding caller to lower-level modules.** The CLI composes alias checks, ingestion, evaluation,
   rendering, and publication. Direct Python callers receive report bytes without filesystem
   protections unless they separately call `write_new_report`; that publisher accepts arbitrary
   bytes and does not establish rule semantics. The `SIGINT` ownership guarantee is for this
   project's single-threaded CLI process using Python's default `SIGINT` handler; an embedding host
   with another `SIGINT`-unblocked thread or a custom handler is outside it. Process-directed
   delivery can cross a peer-thread boundary before Python records a returned descriptor. The
   embedding process owns correct sequencing, signal/thread
   policy, matching rule parameters, retention, and any transport
   (`cli.main`, the `reporting.build_*_report` functions, and `reporting.write_new_report`).

Supported filesystem hardening assumes a local POSIX host with the Python `dir_fd`, `O_NOFOLLOW`,
`O_DIRECTORY`, `fchmod`, `fsync`, and hard-link behavior exercised on macOS/Linux. The operator is
trusted to supply only independently generated, non-secret synthetic data and to protect the
resulting report. Directory mode-bit checks do not enumerate ACLs or extended access-control rules;
effective directory access remains an operator/host assumption.

## Threat actors

- An author of a malformed or adversarial local input file.
- A concurrent local process able to alter an input name/file or the requested output directory.
- An untrusted pull-request author whose checked-out code may execute on a workflow runner. The CI
  token is repository-read-only; the CodeQL token additionally has narrowly scoped
  `security-events: write` authority. Runner filesystem, process, and network authority are
  separate.

The following are outside the guaranteed boundary: a compromised operator account, a malicious
process with unrestricted access under the same user ID, a compromised Python interpreter or
kernel, arbitrary monkeypatching/interposition of standard-library filesystem calls, physical
access, a multithreaded embedding host with another `SIGINT`-unblocked thread, a custom signal
handler, and malicious development dependencies already executing during bootstrap. In particular,
no ownership claim is possible if a replaced `os.open` creates a descriptor and raises before
returning it. These exclusions are limitations, not assertions that the scenarios are harmless.

## Prioritized attack surface

Each row is an architecture-derived attacker-story hypothesis. A row becomes a confirmed finding
only when the behavior is reproduced; resolved reproductions are recorded separately below.

| Priority | Surface | Control and evidence | Residual risk |
| --- | --- | --- | --- |
| High | Input path substitution, symlink, FIFO/device swap, or in-read mutation | Descriptor-relative `O_NOFOLLOW` open, nonblocking open before regular-file check, pre/open/post identity and state comparisons, parent-binding verification, and dedicated filesystem-hardening tests | A same-UID process can continue racing after the last verification point; this is detection at defined checkpoints, not an immutable filesystem snapshot |
| High | Forged, partial, or overwritten final report | Exclusive random temporary requested no broader than `0600`, exact `fchmod(0600)` before writing, complete direct descriptor writes plus `fsync`, exclusive hard link, inode/mode/size verification, no-overwrite collision handling, parent-binding verification, and interrupt cleanup (`reporting.write_new_report` and its publication helpers) | Portable Python cannot link directly from an unnamed file descriptor on both macOS and Linux; trusted-directory/same-UID assumptions remain |
| Medium | Resource exhaustion | Per-source, aggregate, line/row, scalar, object, depth, and record ceilings plus a 30,000 finding-evidence-reference ceiling (`adapters.IngestLimits`, `rules.MAX_FINDING_EVIDENCE_REFS`) | A valid maximum input/report can still use material CPU, memory, and disk; there is no performance or service-level claim |
| Medium | Evidence or credential disclosure | Fixed diagnostics, no arbitrary raw payload retention, minimized provenance, output escaping, and privacy canaries across all report formats | Basenames and record IDs are intentionally reportable and are not secret-scanned or silently redacted |
| Medium | HTML/SARIF injection or network-capable output | HTML context escaping, fixed CSP and no active/external resources; SARIF uses structured JSON and relative percent-encoded basename URIs (`html_report.render_html_report`, `sarif_report.render_sarif_report`) | A downstream viewer has its own parser and security boundary; this project does not certify viewers |
| Low | Runtime network/process escape | Runtime imports are standard-library/project code; tests monkeypatch common socket/process seams and installed-wheel probes reject `socket.*`, `subprocess.Popen`, `os.system`, `os.posix_spawn`, and `os.posix_spawnp` audit events (`tests/test_cli.py`, `tests/test_replay_v2.py`, and `scripts/package_smoke.py`) | The audit hook does not block every possible process primitive (for example, `os.fork`) and is verification-only; development bootstrap and CI use package/network/process infrastructure |
| Low | CI action or dependency compromise | Official actions pinned to full SHAs; CI token limited to `contents: read`; CodeQL token limited to `contents: read` plus `security-events: write`; checkout credentials disabled; runtime dependency set empty | Pull-request code and development dependencies execute with ephemeral runner process/filesystem and available network authority; requirements are not hash-locked and no vulnerability-database conclusion is claimed |
| Low | Misleading revision-bound source snapshot through working-tree substitution or unresolved Git state | Snapshot paths and bytes come from one resolved `HEAD` tree and regular-file blobs; staged/unstaged changes, hidden index flags, unsupported entries, Git failures, and a changed `HEAD` fail closed; regression tests cover linked worktrees and ignored internal files | A compromised Git executable or object database is outside this tool's independent verification boundary; the manifest is not signed |

## Severity calibration

- **Critical:** remote code execution, credential theft, real-data exfiltration, or destructive
  writeback introduced into the runtime boundary. None is known in the current implementation.
- **High:** a complete local run can silently replace input, publish attacker-selected/partial bytes
  as a verified report, overwrite an existing path, or perform network/process activity.
- **Medium:** a constrained local attacker can cause bounded denial of service, metadata disclosure,
  misleading state, or temporary-artifact retention without crossing into live systems.
- **Low:** defense-in-depth, development-only supply-chain, portability, or documentation gaps that
  do not invalidate the documented runtime contract.

## Confirmed findings, hypotheses, and residuals

Regression tests reproduce and guard against concrete failures previously identified during
hardening, including final-component input replacement, undetected post-read mutation,
output-parent pathname re-resolution, an
unverified final link surviving interruption, descriptor ownership-transfer gaps at input parent,
input source, publisher parent, temporary, helper-return, descriptor-wrapper, and CPython
`try`-boundary opcode transitions, a
restrictive-umask cleanup gap, restoration-error collision misclassification, and control
characters in ancestor path components. The current tests reproduce those paths with real process
`SIGINT` delivery and verify descriptor/name cleanup plus thread-mask restoration. The current
ownership wrappers block `SIGINT` before acquisition and through cleanup. A signal observable at an
explicit safe point prevents publication or rolls back the uncommitted final. A signal that first
becomes pending after the last safe-point check is treated as post-commit and may propagate after the
cleanup while the verified complete final remains.

This is checkpoint-based cooperative interruption, not asynchronous syscall cancellation. A signal
is deferred while resolve/parse/write/`fsync`/verify/cleanup work runs, repeated standard signals may
coalesce, and the mechanism cannot make a hung kernel or filesystem operation return. If `SIGINT`
was already blocked on entry, the prior mask and pending-signal policy are preserved rather than
synthesizing `KeyboardInterrupt`.

Residual hypotheses are deliberately not promoted to findings without proof: a sufficiently timed
same-UID temporary-name substitution, mutation after the final input checkpoint, or namespace
replacement after the final parent check may still change what a textual path resolves to. The
publisher rejects group- or world-writable non-sticky output directories, but it does not claim
protection from a fully compromised account. `SIGKILL`, kernel panic, power loss, directory-entry
durability, and hostile network filesystems are outside the process-level atomicity claim; see
`docs/LIMITATIONS.md`.
