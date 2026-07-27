# GitHub Workflows

[Repository home](../../README.md)

- [`ci.yml`](./ci.yml) runs the locked quality gate for pushes to `dev` and
  `main`, and for pull requests targeting `main`. Push and pull-request
  concurrency groups remain separate so both branch-tip and prospective-merge
  validation can complete. The minimum-runtime job is pinned to Python 3.12.13;
  the second job tracks the supported Python 3.14 feature line.
- [`release.yml`](./release.yml) accepts only version tags whose commits belong
  to `origin/main`, runs the locked quality gate, validates release artifacts,
  and publishes through PyPI Trusted Publishing.

Third-party actions are pinned to full commit SHAs with version comments.
[`dependabot.yml`](../dependabot.yml) proposes weekly GitHub Actions updates.
Keep workflow commands aligned with [`scripts/run.sh`](../../scripts/run.sh)
and install dependencies from `uv.lock` with `uv sync --frozen --extra dev`.
