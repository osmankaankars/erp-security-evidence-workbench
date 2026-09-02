## Summary

Describe the problem, the bounded change, and its observable outcome.

## Verification

List the checks you ran and their results.

```text
make check
```

## Boundary impact

Describe any change to schemas, rules, reports, privacy, dependencies, determinism, resource
ceilings, or filesystem behavior. Write “None” when the boundary is unchanged.

## Checklist

- [ ] The change is focused and includes an appropriate regression test.
- [ ] `make check` passes, or any unavailable check is clearly explained.
- [ ] Fixtures and examples contain only independently authored synthetic data.
- [ ] No secrets, real ERP evidence, employer/customer material, or sensitive paths are included.
- [ ] The offline, input-read-only, non-remediating runtime boundary is preserved.
- [ ] User-facing behavior and affected technical contracts are documented.
- [ ] I have read and will follow the Code of Conduct.
