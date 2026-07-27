import re
from pathlib import Path

from controlled_text_transfer import bootstrap, core, signing
from controlled_text_transfer.core import Policy

ROOT = Path(__file__).resolve().parents[1]


def test_documented_security_ceilings_match_runtime_constants():
    contract = (ROOT / "docs" / "security-hardening.md").read_text(encoding="utf-8")
    expected = {
        "Manifest": (core.MAX_MANIFEST_BYTES, "2 MiB"),
        "Detached signature": (signing.MAX_SIGNATURE_BYTES, "256 KiB"),
        "Archive input": (core.MAX_ARCHIVE_INPUT_BYTES, "128 MiB"),
        "Expanded archive": (core.MAX_ARCHIVE_BYTES, "256 MiB"),
        "Archive members": (core.MAX_ARCHIVE_MEMBERS, "2,000"),
        "Manifest file records": (core.MAX_ARCHIVE_MEMBERS, "2,000"),
        "Individual member or payload file": (core.MAX_ARCHIVE_MEMBER_BYTES, "10 MiB"),
        "Compression ratio": (core.MAX_COMPRESSION_RATIO, "100:1"),
        "Relative path depth": (core.MAX_SECURITY_PATH_DEPTH, "16 components"),
        "Relative path length": (core.MAX_SECURITY_PATH_LENGTH, "180 characters"),
        "Streaming buffer": (core.STREAM_BUFFER_BYTES, "64 KiB"),
    }

    for label, (_runtime, documented) in expected.items():
        assert f"| {label} | {documented} |" in contract

    assert core.MAX_MANIFEST_BYTES == 2 * 1024 * 1024
    assert bootstrap.MAX_MANIFEST_BYTES == core.MAX_MANIFEST_BYTES
    assert bootstrap.MAX_ZIP_INPUT_BYTES == core.MAX_ARCHIVE_INPUT_BYTES
    assert bootstrap.MAX_ZIP_EXPANDED_BYTES == core.MAX_ARCHIVE_BYTES
    assert bootstrap.MAX_ZIP_MEMBERS == core.MAX_ARCHIVE_MEMBERS
    assert bootstrap.MAX_ZIP_MEMBER_BYTES == core.MAX_ARCHIVE_MEMBER_BYTES
    assert bootstrap.MAX_COMPRESSION_RATIO == core.MAX_COMPRESSION_RATIO
    assert bootstrap.MAX_PATH_DEPTH == core.MAX_SECURITY_PATH_DEPTH
    assert bootstrap.MAX_PATH_LENGTH == core.MAX_SECURITY_PATH_LENGTH
    assert bootstrap.STREAM_BUFFER_BYTES == core.STREAM_BUFFER_BYTES

    assert signing.MAX_SIGNATURE_BYTES == 256 * 1024
    assert core.MAX_ARCHIVE_INPUT_BYTES == 128 * 1024 * 1024
    assert core.MAX_ARCHIVE_BYTES == 256 * 1024 * 1024
    assert core.MAX_ARCHIVE_MEMBERS == 2_000
    assert core.MAX_ARCHIVE_MEMBER_BYTES == 10 * 1024 * 1024
    assert core.STREAM_BUFFER_BYTES == 64 * 1024


def test_documented_policy_yaml_is_parseable(tmp_path: Path, monkeypatch):
    policy_doc = (ROOT / "docs" / "policy.md").read_text(encoding="utf-8")
    yaml_blocks = re.findall(r"```yaml\n(.*?)```", policy_doc, flags=re.DOTALL)
    assert yaml_blocks

    for index, block in enumerate(yaml_blocks):
        if "hash_algorithm: blake3" in block:
            monkeypatch.setitem(
                __import__("sys").modules,
                "blake3",
                type(
                    "Blake3Module",
                    (),
                    {
                        "blake3": staticmethod(
                            lambda _data: type("Hash", (), {"hexdigest": lambda self: "0" * 64})()
                        )
                    },
                ),
            )
        path = tmp_path / f"policy-{index}.yaml"
        path.write_text(block, encoding="utf-8")
        Policy.from_file(path)


def test_security_documentation_covers_required_residual_risks():
    documents = re.sub(
        r"\s+",
        " ",
        "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "SECURITY.md",
                "docs/security-hardening.md",
                "docs/TODO.md",
            )
        ).lower(),
    )
    for claim in (
        "not a cross domain solution",
        "key_label",
        "--allow-unverified-signature",
        "cannot raise",
        "1,024 bytes",
        "malware",
    ):
        assert claim.lower() in documents


def test_markdown_relative_links_use_explicit_relative_paths_and_exist():
    ignore_dirs = {".venv", ".pytest_cache", ".git", "build", "dist"}
    md_files = [
        path for path in ROOT.rglob("*.md")
        if not any(part in ignore_dirs for part in path.parts)
    ]
    link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

    for md_file in md_files:
        content = md_file.read_text(encoding="utf-8")
        for match in link_pattern.finditer(content):
            _text, target = match.groups()
            target = target.strip()
            if target.startswith(("http://", "https://", "mailto:", "#", "file://")):
                continue
            target_path = target.split("#")[0]
            if not target_path:
                continue

            assert target_path.startswith(("./", "../")), (
                f"Relative link '{target}' in {md_file.relative_to(ROOT)} "
                "must start with './' or '../'"
            )

            resolved = (md_file.parent / target_path).resolve()
            assert resolved.exists(), (
                f"Link target '{target}' in {md_file.relative_to(ROOT)} "
                f"does not exist (resolved to {resolved})"
            )

