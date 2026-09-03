# Synthetic replay scenarios

These fixtures are fictional, vendor-neutral, and restricted to IANA documentation address
ranges. `detection-correlation` produces one finding for each replay rule; `clean-baseline`
provides complete evidence for the same rules without a match. No fixture contains customer,
employer, product, credential, or live-system data.

Replay either manifest through the installed CLI:

```console
erpsec replay examples/replay/detection-correlation/replay-manifest.json \
  --as-of 2026-09-01T12:45:00Z --rule all --format json --output report.json
```

The committed reports are deterministic examples, not compliance evidence.
