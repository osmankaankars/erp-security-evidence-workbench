# Privacy model

## Scope

ERP Security Evidence Workbench is authorized only for independently generated synthetic evidence.
The `dataset_classification: synthetic` field is enforced, but it is a contract marker rather than
a content classifier. The tool cannot determine whether a user mislabeled real, personal,
employer, customer, credential, or secret material
(`normalize_payload` and the replay adapter normalizers).

There is no telemetry, analytics, account, cookie, session, connector, remote schema retrieval, or
runtime network call. Runtime dependencies are empty (`pyproject.toml:5-11`).

## Data lifecycle

| Stage | Data handled | Retention/disclosure behavior |
| --- | --- | --- |
| Input | Explicit local CSV, JSON, or JSONL bytes; for replay, one manifest plus its digest-pinned basename-local sources | Opened read-only and consumed under fixed limits; the tool does not rewrite the source. Raw bytes exist transiently in ordinary Python process memory, which is not securely zeroed. Files remain owned and retained by the operator. |
| Normalization | Fixed evidence, observed-event, and threat-indicator records | Only allowed typed fields and minimized `SourceRef` values enter the canonical bundle; unknown/raw payload fields are rejected, not retained. |
| Evaluation | Canonical records, selected rules, explicit analysis time | Deterministic in-memory findings reference exact supporting records and fields. Replay episodes additionally retain source IDs, ordered record IDs, timestamps, opaque hashes, and fixed explanations. Cumulative finding evidence is capped at 30,000 references. |
| Report | JSON, HTML, or SARIF bytes | JSON always includes minimized source and evidence manifests. Replay v2 also includes the manifest basename/digest, source IDs, correlation window timestamps, record IDs, and field locators. It does not serialize the source address or indicator value itself. SARIF retains the canonical replay and correlation objects in namespaced properties; HTML renders the bounded correlation chain but omits the replay manifest object and clean source inventory. Every format must still be treated as potentially sensitive. |
| Diagnostic | A fixed user-facing error category | Does not include the supplied path, raw record, identifier, exception string, or secret-like canary. |
| Publication | New local report plus a private temporary hard link during commit | Temporary creation requests mode `0600`, so an acquisition-time empty residual is no broader than `0600`; the publisher forces exact `0600` before writing, and the final hard link shares that inode. Every unlink is bounded best effort. Repeated unlink failure may leave an empty acquisition-time name, or a later partial/complete exact-`0600` temporary. After the final link, only fully written bytes are involved, but failed link verification can leave one or both complete private names even when the operation reports failure. Retention and deletion of every residual/final report name are the operator's responsibility. |

Canonical serialization, evidence references, source manifests, and correlation episodes are
defined in `src/erp_security_evidence_workbench/models.py`. Report construction consumes that
bounded model rather than the original records (`reporting._prepare_report`).

## Intentional provenance versus secrets

Basenames and explicit record IDs are evidence-linkage values. The project does **not** silently
hash, redact, or replace them, because doing so would break deterministic fingerprints and reviewer
traceability. It also does not claim heuristic secret detection: a token-looking string can be a
false positive, and an actual secret can avoid known prefixes.

Therefore:

- input filenames and explicit record IDs must be fictional and non-secret;
- report files must be handled as potentially sensitive even when the authorized input is
  synthetic;
- generated semantic IDs are SHA-256 integrity identities, not an anonymization guarantee;
- replay dedupe keys and correlation IDs are deterministic identities, not encryption or
  anonymity guarantees;
- source SHA-256 digests in JSON and SARIF are integrity metadata, not encryption;
- clean SARIF retains the minimized artifact inventory so a reviewer can see which sources were
  evaluated; it does not contain semantic record fields or raw rows.

Tests use fictional credential-shaped canaries to prove that semantic values such as a
`principal_id` are not copied into JSON, HTML, or SARIF findings. A separate contract test proves
that an accepted explicit record ID remains traceable even when it happens to resemble a token;
this is intentional provenance, not secret detection. Fatal diagnostic tests prove that even
reportable provenance is not reflected on an error path
(`tests/test_slice7_privacy_resources.py`).

## Output minimization by format

- **JSON** is the canonical complete minimized report and always includes evidence/source manifests,
  including on clean runs.
- **HTML** renders investigation-relevant report fields as escaped text, with no external resource,
  script, image, font, form, or tracker.
- **SARIF** always represents each supplied source as a relative percent-encoded basename plus digest
  and bounded metadata. Finding locations add the record ID and exact locator needed for review.

No format contains the complete input row/object, principal attributes, role IDs, object IDs,
timestamps, or capability values merely because they appeared in a source. A field contributes only
through the fixed rule and report contracts.

## Operator responsibilities

- Use only first-principles synthetic, non-secret evidence.
- Choose input and output directories controlled by the operator. The publisher rejects a
  group- or world-writable non-sticky output directory.
- Restrict access to the final report and any backups, copies, viewer caches, terminal history, or
  CI artifacts created outside this program.
- Do not treat mode `0600` as protection from root or another process running under the same user
  ID; the program does not create an operating-system sandbox or a separate security principal.
- Delete reports according to the operator's own retention needs; the project has no retention
  service or secure-erasure feature.
- Do not upload reports to third-party SARIF/HTML viewers without separately reviewing that
  viewer's data handling.

No statement in this model authorizes real data. See `docs/SYNTHETIC_DATA_POLICY.md` and
`docs/LIMITATIONS.md`.
