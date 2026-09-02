# Report formats

This document defines the `0.1.0rc1` report contract. All formats are deterministic projections of
the same validated, synthetic-only rule-engine result; none represents a live-system or compliance
conclusion.

The `analyze` command requires an explicit `--format json`, `--format html`, or
`--format sarif`. The output suffix is not inferred, and the output path must be new and distinct
from every input path.

All three serializers receive the same engine-validated findings and evaluations. A finding keeps
the same rule ID, rule version, native severity, stable fingerprint, and field-level evidence
references in every format. Renderer or publication failures exit `2` and never deliberately
promote a partial artifact. The bounded-cleanup exception for complete mode-`0600` names is
documented below.

## JSON

JSON is the canonical `erpsec.report/v1` contract. It contains the complete minimized evidence and
source manifests, selected-rule evaluations, findings, run metadata, and tool version.

## HTML

HTML is a UTF-8, self-contained investigation view with a summary, evaluations, findings,
field-level evidence locations, rule details, limitations, and run metadata. It contains one
hash-authorized inline stylesheet and no JavaScript, external CSS, fonts, images, forms, trackers,
or network-capable resources. Dynamic text and attributes are context escaped; source basenames
are displayed as text and never linked.

The clean-state wording is deliberately qualified. “No findings in supplied evidence” means only
that the selected rules did not match the fully processed supplied files. It does not prove
source-system completeness, security, compliance, or absence of risk.

## SARIF

SARIF output targets version 2.1.0. Selected rules appear once in the driver catalog; each result
references that catalog entry and preserves the canonical fingerprint and native severity.
`high` maps to SARIF `error`, and `medium` maps to `warning`; an unmapped future severity fails
rendering rather than being silently downgraded.

Only relative, percent-encoded source basenames are emitted as artifact URIs. CSV rows and JSONL
lines map to SARIF `region.startLine`. JSON evidence keeps its exact RFC 6901 pointer in location
properties and does not invent a line or column. Basename URIs identify supplied artifacts; they
are not guaranteed to be report-relative files.

Development tests validate generated SARIF offline against a hash-pinned, unchanged copy of the
[official OASIS SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json).
The runtime does not load that schema and performs no network access.

## State and exit semantics

- Complete run with no findings: report is published; exit `0`.
- Complete run with findings: report is published; exit `1`.
- Incomplete evidence: diagnostic only, no report; exit `2`.
- Validation or rendering failure: diagnostic only, no report; exit `2`.
- Publication failure: diagnostic only; exit `2`. Normally no final report remains, but repeated
  cleanup failure can leave a mode-`0600` residual name as described below.

Incomplete and fatal runs are intentionally not rendered as valid-looking partial reports. The
current evaluation contract therefore remains `matched` or `not_matched`; it does not invent a
third partial-success status. Process-level interruptions such as `KeyboardInterrupt` are not
ordinary CLI exit-code outcomes and may propagate to the caller.

The no-overwrite publisher resolves the existing parent once, anchors operations to its opened
directory descriptor, and rejects a group/world-writable non-sticky parent. It creates a mode-`0600`
temporary file with an exclusive name, forces mode `0600`, completes direct descriptor writes, and
file-synchronizes that inode. It then creates the requested name through an exclusive descriptor-
relative hard link and verifies that the final name, temporary descriptor, and original parent still
identify the expected objects. Existing final names are always refused.

The verified final hard link is the publication commit point. Cleanup before and after that point is
identity-aware, bounded, and best effort. Interruption immediately after creation plus repeated
unlink failure can leave an empty temporary no broader than mode `0600`; after the publisher forces
exact `0600`, repeated cleanup failure following descriptor write, file-sync, or temporary verification
can leave a partial or complete temporary report. If a fully written final link was created but verification failed, independent
cleanup attempts can leave one or both of the complete mode-`0600` final and temporary names while the
operation reports failure.
Repeated temporary-name cleanup failure after commit can leave a hidden mode-`0600` hard link beside
the authoritative final report. If an interruption occurs after the final link has actually
committed, the interruption may propagate while that complete final remains; the publisher does not
roll back the committed name.

On the normal, single-threaded POSIX CLI path using Python's default
`SIGINT`-to-`KeyboardInterrupt` handler, `SIGINT` is blocked before either descriptor-anchored input
or publication flow can acquire a descriptor and remains blocked through its complete
descriptor/name-owning scope. Bounded safe-point checks inspect for a pending signal during input
and immediately before report linking and commit. Outer cleanup makes bounded close attempts for
recorded descriptors and
identity-aware, bounded name-removal attempts before the prior thread mask is restored and
`KeyboardInterrupt` propagates. The input reader's binary wrapper is non-owning, and acquisition
helpers additionally record a returned descriptor before they return. This does not cover a
compromised/interposed `os.open` that creates a kernel descriptor and raises before returning it,
or an interposed cleanup primitive that raises a non-OS exception; modifying the trusted runtime
beneath the process is outside this contract.
A signal that first becomes pending after the publisher's last pre-commit safe-point check is
treated as post-commit and may propagate after cleanup while the verified complete final remains.
A multithreaded embedding host with another `SIGINT`-unblocked thread or a custom signal handler is
outside this guarantee; that host must establish its own process-wide signal policy before calling
the lower-level modules. If `SIGINT` was already blocked on entry, the prior mask and pending-signal
policy are preserved and no `KeyboardInterrupt` is synthesized. Delivery is checkpoint-based while
resolve/parse/write/`fsync`/verify/cleanup work runs; repeated standard signals may coalesce, and the
mechanism cannot cancel a hung syscall.

The filesystem contract assumes POSIX-style descriptor-relative, inode, hard-link, no-follow, and
sticky-bit semantics on a local filesystem. Mode `0600` does not isolate root or another process
under the same UID. The report inode is file-synchronized, but the directory entry is not directory-
synchronized; crash, `SIGKILL`, power-loss, unusual filesystem, secure-erasure, and cryptographic-
attestation guarantees are not claimed.

## Installed-wheel smoke contract

The clean-install package smoke builds and installs the wheel with package-index access and runtime
dependency resolution disabled. Under a verification hook that rejects `socket.*`,
`subprocess.Popen`, `os.system`, `os.posix_spawn`, and `os.posix_spawnp` audit events, it invokes the
installed CLI for one finding and one clean input in JSON, HTML, and SARIF. The hook does not cover
every possible process primitive and is injected only by the harness; the normal CLI is not an
operating-system sandbox.

Standard-library checks use the JSON reports as the canonical semantic oracle. They require HTML
and SARIF parity for run state, selected-rule evaluations, finding fingerprints, rule IDs and
versions, native severities, and field-level evidence locations. The HTML check also enforces the
self-contained resource and content-policy boundary; the SARIF check enforces the 2.1.0 envelope,
unique selected-rule descriptors, severity levels, relative artifact URIs, and format-appropriate
location semantics. The installed-wheel smoke is one layer of the release-candidate verification;
the full gate also runs static checks, the complete test suite, deterministic examples, privacy
checks, and artifact inspection.

## Examples

```bash
PYTHONPATH=src python3.11 -m erp_security_evidence_workbench analyze \
  examples/audit-logging-disabled.json \
  --as-of 2026-09-01T00:00:00Z \
  --format html \
  --output /tmp/erpsec-report.html

PYTHONPATH=src python3.11 -m erp_security_evidence_workbench analyze \
  examples/audit-logging-disabled.json \
  --as-of 2026-09-01T00:00:00Z \
  --format sarif \
  --output /tmp/erpsec-report.sarif.json
```
