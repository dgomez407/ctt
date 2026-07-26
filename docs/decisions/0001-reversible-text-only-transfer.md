# ADR-001: Use reversible text-only transfer transformation

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-25

## Context

The transfer boundary accepts text files with a `.txt` suffix, while the
source repository contains Python, Markdown, configuration, and other source
files with their original extensions. The workflow must preserve source bytes
and filenames without modifying the source directory.

## Decision

Append `.txt` to each selected transfer filename, preserve the relative path,
and keep the content as UTF-8 text. Add a UTF-8 BOM only to transfer copies
when policy enables it. Record the original BOM state and remove only the
transport-added BOM during restoration.

The tool will not Base64-encode ordinary text files.

## Alternatives considered

### Replace the original extension

Rejected because `module.py -> module.txt` loses information and makes manual
recovery dependent on the manifest.

### Base64-encode all content

Rejected because it increases size, reduces inspectability, complicates CDS
content inspection, and provides no benefit for text-only files.

### Modify files in place

Rejected because preparation must be non-destructive and source repositories
may be under version control or subject to independent integrity controls.

## Consequences

- Transfer files remain inspectable as text.
- Restoration can be byte-for-byte accurate, including BOM state.
- File permissions are recorded separately because filename translation cannot
  preserve filesystem metadata.
- Binary files and invalid UTF-8 files are skipped rather than transformed.

## Related implementation

- `src/controlled_text_transfer/core.py`: BOM handling and reversible filename mapping.
- `README.md`: transfer workflow and operational notes.
- `SECURITY.md`: trust-boundary limitations.
