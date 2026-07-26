# Test Suite

[Repository home](../README.md)

Pytest modules in this directory exercise CLI behavior, policies,
transformations, archives, signing, cleanup, packaging, and security
invariants. Test files follow `test_<area>.py`; individual tests use
`test_<behavior>`.

Run every test with:

```bash
uv run --extra dev pytest -q
```

For a focused run that does not evaluate whole-package coverage, use
`uv run --extra dev pytest -q tests/test_core.py --no-cov`. Always run the
complete suite before review.

The documentation tests ensure command examples, policy claims, local links,
and this README hierarchy remain valid. Pytest enforces 100% aggregate
statement coverage for the application package.
