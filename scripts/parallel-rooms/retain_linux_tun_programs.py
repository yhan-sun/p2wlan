"""Copy existing failed-run images by their recorded digests; never rebuild/run."""
import argparse
import json
import os
from pathlib import Path

import linux_tun_image_store as image_store


def retain(args, manifest):
    reports = []
    for report in args.report:
        if report.exists():
            if report.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("original report exceeds capacity")
            value = json.loads(report.read_text())
            if value.get("source_commit") != args.head:
                raise ValueError("original report checkout mismatch")
            reports.append(value)
    store = image_store.prepare(args, manifest)
    sources = [("daemon", args.daemon), ("control", args.control)]
    if getattr(args, "relay", None) is not None:
        sources.append(("relay", args.relay))
    for role, source in sources:
        expected = {r.get("binary_sha256", {}).get(role) for r in reports} - {None}
        row = dict(role=role, available=False)
        manifest["images"].append(row)
        if not expected:
            row["reason"] = "original_measured_image_digest_unavailable"
        elif len(expected) != 1 or not source.is_file() or source.is_symlink():
            row["reason"] = "original_image_missing_or_conflicting"
        else:
            target = (store or args.output) / ("p2wlan-" + role)
            image_store.retain(source, target, expected, row, shared=store is not None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--relay", type=Path, help="optional original measured Relay image")
    parser.add_argument("--image-store", type=Path, help="shared bounded original images for this exact checkout/run")
    parser.add_argument("--head", required=True)
    parser.add_argument("--report", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.head) != 40 or any(c not in "0123456789abcdef" for c in args.head):
        parser.error("head must be the original checkout commit")
    if len(args.report) > 3:
        parser.error("at most the original three reports may be inspected")
    args.output.mkdir(exist_ok=False)
    manifest = dict(schema_version=1, scope="recorded_original_program_bytes_only",
                    actual_checkout=args.head, run_id=os.environ.get("GITHUB_RUN_ID"),
                    run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"), images=[],
                    rebuilt=False, executed=False, no_native_IO_authority_granted=True)
    try:
        retain(args, manifest)
    except (OSError, ValueError, TypeError) as error:
        manifest["retention_failure"] = type(error).__name__
        raise
    finally:
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
