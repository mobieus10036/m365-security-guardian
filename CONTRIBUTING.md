# Contributing

Thanks for helping improve M365 Security Guardian.

## Before You Open a PR

1. Fork and create a feature branch.
2. Keep changes focused and scoped.
3. Run tests locally:

```powershell
./Invoke-Tests.ps1
```

4. Ensure generated artifacts are not committed (`reports/`, `test-reports/`, `baselines/`).

## Pull Request Checklist

- [ ] Tests pass locally
- [ ] New or changed logic has tests
- [ ] Docs updated when behavior changes
- [ ] No credentials, tenant IDs, or report data are included

## Coding Expectations

- Follow existing PowerShell naming and comment-based help conventions.
- Keep each assessment module read-only.
- Return the standard assessment object shape from `Test-*` functions.

## Security

Security issues must be reported privately. See [SECURITY.md](SECURITY.md).
