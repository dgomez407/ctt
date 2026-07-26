"""Command-line interface for Controlled Text Transfer workflows."""

from __future__ import annotations

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

from .core import Policy, TransferError, diff, preflight, prepare, restore, self_package, verify
from .signing import ManifestSigner


def _add_policy_option(parser: argparse.ArgumentParser) -> None:
    """Add source-policy selection to a policy-aware command."""
    parser.add_argument(
        "--policy", type=Path, help="load compatibility and content rules from YAML"
    )


def _add_log_option(parser: argparse.ArgumentParser) -> None:
    """Add structured audit logging to a command that emits audit events."""
    parser.add_argument(
        "--log-json", action="store_true", help="write one JSON audit event to stderr"
    )


class JsonFormatter(logging.Formatter):
    """Format supported audit fields as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        """Return one JSON object for a log record."""
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname,
                "event": record.getMessage(),
                **{
                    k: v for k, v in record.__dict__.items() if k in {"files", "skipped", "dry_run"}
                },
            }
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctt", description="Prepare, verify, and restore text-only transfer packages."
    )
    parser.set_defaults(policy=None, log_json=False)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare_parser = commands.add_parser(
        "prepare", help="create and self-verify a transfer package"
    )
    _add_policy_option(prepare_parser)
    _add_log_option(prepare_parser)
    prepare_parser.add_argument("source", type=Path, help="directory containing source text files")
    prepare_parser.add_argument("transfer", type=Path, help="new package path")
    prepare_parser.add_argument(
        "--dry-run", action="store_true", help="validate without writing a package"
    )
    prepare_parser.add_argument(
        "--strict", action="store_true", help="fail if any file is rejected"
    )
    prepare_parser.add_argument(
        "--json-report", type=Path, help="write the preflight report to a file"
    )
    prepare_parser.add_argument(
        "--sign", action="store_true", help="sign with a trusted injected signer"
    )
    prepare_parser.add_argument(
        "--key-label",
        default="external-managed-key",
        help="record a non-secret signer label in the manifest",
    )

    self_package_parser = commands.add_parser(
        "self-package", help="package CTT codebase into a .txt-only self-bootstrapping bundle"
    )
    _add_policy_option(self_package_parser)
    _add_log_option(self_package_parser)
    self_package_parser.add_argument(
        "destination", type=Path, help="new self-bootstrap package path"
    )
    self_package_parser.add_argument(
        "--source", type=Path, help="source directory to package (default: current directory)"
    )
    self_package_parser.add_argument(
        "--format",
        default="zip",
        choices=["directory", "zip", "tar", "tar.gz"],
        help="package output format (default: zip)",
    )
    self_package_parser.add_argument(
        "--dry-run", action="store_true", help="validate without writing a package"
    )

    preflight_parser = commands.add_parser(
        "preflight", help="evaluate source files without packaging"
    )
    _add_policy_option(preflight_parser)
    preflight_parser.add_argument("source", type=Path, help="directory to evaluate")
    preflight_parser.add_argument(
        "--json", action="store_true", help="write the full report as JSON"
    )

    verify_parser = commands.add_parser("verify", help="check package integrity and authenticity")
    _add_log_option(verify_parser)
    verify_parser.add_argument("transfer", type=Path, help="package directory or archive")
    verify_parser.add_argument(
        "--require-signature", action="store_true", help="reject packages without a signature"
    )
    verify_parser.add_argument(
        "--allow-unverified-signature",
        action="store_true",
        help="permit a signed package without an available trusted verifier",
    )

    restore_parser = commands.add_parser("restore", help="verify and reconstruct original files")
    _add_log_option(restore_parser)
    restore_parser.add_argument("transfer", type=Path, help="package directory or archive")
    restore_parser.add_argument("destination", type=Path, help="new directory for restored files")
    restore_parser.add_argument(
        "--dry-run", action="store_true", help="verify without writing restored files"
    )
    restore_parser.add_argument(
        "--require-signature", action="store_true", help="reject packages without a signature"
    )
    restore_parser.add_argument(
        "--allow-unverified-signature",
        action="store_true",
        help="permit a signed package without an available trusted verifier",
    )

    diff_parser = commands.add_parser("diff", help="compare a package with a source directory")
    _add_policy_option(diff_parser)
    diff_parser.add_argument("transfer", type=Path, help="package directory or archive")
    diff_parser.add_argument("source", type=Path, help="current source directory")
    diff_parser.add_argument("--json", action="store_true", help="write comparison results as JSON")
    diff_parser.add_argument(
        "--require-signature", action="store_true", help="reject packages without a signature"
    )
    diff_parser.add_argument(
        "--allow-unverified-signature",
        action="store_true",
        help="permit a signed package without an available trusted verifier",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    signer: Optional[ManifestSigner] = None,
) -> int:
    """Run the CLI and return a process-compatible status code.

    Trusted hosts may inject a signer; transferred data never selects commands.
    """
    args = _parser().parse_args(argv)
    log = logging.getLogger("controlled_text_transfer")
    log.setLevel(logging.INFO)
    h = logging.StreamHandler()
    h.setFormatter(
        JsonFormatter() if args.log_json else logging.Formatter("%(levelname)s: %(message)s")
    )
    log.handlers[:] = [h]
    try:
        policy = Policy.from_file(args.policy)
        if args.command == "preflight":
            report = preflight(args.source, policy)
            output = json.dumps(report.to_dict(), indent=2)
            if args.json:
                print(output)
            else:
                print(
                    f"accepted: {report.accepted_count}\n"
                    f"rejected: {report.rejected_count}\n"
                    f"total bytes: {report.total_bytes}"
                )
            return 0
        if args.command == "self-package":
            m, _ = self_package(
                args.destination,
                source=args.source,
                package_format=args.format,
                policy=policy,
                signer=signer,
                dry_run=args.dry_run,
                logger=log,
            )
        elif args.command == "prepare":
            report = preflight(args.source, policy)
            if args.json_report:
                args.json_report.write_text(
                    json.dumps(report.to_dict(), indent=2) + "\n",
                    encoding="utf-8",
                )
            if args.sign and signer is None:
                raise TransferError("trusted signer is required")
            m = prepare(
                args.source,
                args.transfer,
                policy,
                dry_run=args.dry_run,
                strict=args.strict,
                signer=signer if args.sign else None,
                key_label=args.key_label,
                logger=log,
            )
        elif args.command == "verify":
            m = verify(
                args.transfer,
                signer=signer,
                require_signature=args.require_signature,
                allow_unverified_signature=args.allow_unverified_signature,
                logger=log,
            )
        elif args.command == "diff":
            result = diff(
                args.transfer,
                args.source,
                policy,
                signer=signer,
                require_signature=args.require_signature,
                allow_unverified_signature=args.allow_unverified_signature,
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                for category, paths in result.items():
                    print(f"{category}: {len(paths)}")
                    for path in paths:
                        print(f"  {path}")
            return 0
        else:
            m = restore(
                args.transfer,
                args.destination,
                dry_run=args.dry_run,
                signer=signer,
                require_signature=args.require_signature,
                allow_unverified_signature=args.allow_unverified_signature,
                logger=log,
            )
        print(json.dumps({"files": len(m.files), "skipped": m.skipped}, indent=2))
        return 0
    except (TransferError, OSError, ValueError) as exc:
        log.error(str(exc))
        return 2
