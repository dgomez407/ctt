# Controlled Text Transfer Package

[Source index](../README.md) | [Repository home](../../README.md)

- [`cli.py`](./cli.py) defines command parsing and user-facing output.
- [`core.py`](./core.py) implements policies, preflight, preparation,
  verification, restoration, archives, and diffs.
- [`signing.py`](./signing.py) defines detached-signature interfaces.
- [`cleanup.py`](./cleanup.py) implements safe repository cleanup.
- [`__main__.py`](./__main__.py) supports `python -m controlled_text_transfer`.

Public usage is documented in the [CLI and Python API guide](../../docs/api.md).
