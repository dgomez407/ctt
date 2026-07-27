import re
from pathlib import Path

from controlled_text_transfer import core, signing
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
        "Individual member or payload file": (core.MAX_ARCHIVE_MEMBER_BYTES, "10 MiB"),
        "Compression ratio": (core.MAX_COMPRESSION_RATIO, "100:1"),
        "Relative path depth": (core.MAX_SECURITY_PATH_DEPTH, "16 components"),
        "Relative path length": (core.MAX_SECURITY_PATH_LENGTH, "180 characters"),
        "Streaming buffer": (core.STREAM_BUFFER_BYTES, "64 KiB"),
    }

    for label, (_runtime, documented) in expected.items():
        assert f"| {label} | {documented} |" in contract

    assert core.MAX_MANIFEST_BYTES == 2 * 1024 * 1024
    assert signing.MAX_SIGNATURE_BYTES == 256 * 1024
    assert core.MAX_ARCHIVE_INPUT_BYTES == 128 * 1024 * 1024
    assert core.MAX_ARCHIVE_BYTES == 256 * 1024 * 1024
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
