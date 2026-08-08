from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import PurePosixPath, Path
from typing import Any

ALLOWED_STATUSES = {
    "VALIDATED_RELEASE",
    "CANDIDATE",
    "TEMPORARY_DURABLE_PUBLICATION_PENDING",
    "EXPECTED_IDENTITY_ONLY",
    "RETIRED",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

class VerificationError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repo_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError("durable_repository_path must be a non-empty string")
    if "\\" in value or "\x00" in value:
        raise VerificationError("unsafe repository path")
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
        raise VerificationError("unsafe repository path")
    return value


def _sha(value: str, field: str = "sha256") -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise VerificationError(f"{field} must be lowercase 64-hex SHA-256")
    return value


def verify_index(index: dict[str, Any], durable_inventory: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if index.get("schema") not in {1, 2}:
        raise VerificationError("unsupported artifact-index schema")
    if index.get("project") != "MUSKEGON Shield Communication":
        raise VerificationError("unexpected project identity")

    baseline = index.get("current_expected_baseline")
    if not isinstance(baseline, dict):
        raise VerificationError("missing current_expected_baseline")
    expected = _sha(baseline.get("expected_sha256"), "expected baseline SHA-256")
    baseline_status = baseline.get("status")
    if baseline_status not in ALLOWED_STATUSES:
        raise VerificationError("invalid baseline status")

    bytes_present = baseline.get("bytes_durably_present")
    if not isinstance(bytes_present, bool):
        raise VerificationError("bytes_durably_present must be boolean")
    if baseline_status == "EXPECTED_IDENTITY_ONLY" and bytes_present:
        raise VerificationError("expected-only baseline cannot claim durable bytes")
    if baseline_status == "VALIDATED_RELEASE" and not bytes_present:
        raise VerificationError("validated release must have durable bytes")

    records = index.get("artifacts", [])
    if records is None:
        records = []
    if not isinstance(records, list):
        raise VerificationError("artifacts must be a list")

    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    verified = []
    for rec in records:
        if not isinstance(rec, dict):
            raise VerificationError("artifact record must be an object")
        name = rec.get("logical_name")
        if not isinstance(name, str) or not name.strip():
            raise VerificationError("artifact logical_name is required")
        if name in seen_names:
            raise VerificationError(f"duplicate logical_name: {name}")
        seen_names.add(name)

        status = rec.get("status")
        if status not in ALLOWED_STATUSES:
            raise VerificationError(f"invalid status for {name}")
        path = rec.get("durable_repository_path")
        artifact_sha = rec.get("sha256")

        if status == "TEMPORARY_DURABLE_PUBLICATION_PENDING":
            if path is not None:
                raise VerificationError(f"pending artifact {name} must not claim durable path")
            if artifact_sha is not None:
                _sha(artifact_sha)
            verified.append({"logical_name": name, "status": status, "durable": False})
            continue

        if status == "EXPECTED_IDENTITY_ONLY":
            if path is not None:
                raise VerificationError(f"expected-only artifact {name} must not claim durable path")
            _sha(artifact_sha)
            verified.append({"logical_name": name, "status": status, "durable": False})
            continue

        path = _repo_path(path)
        if path in seen_paths:
            raise VerificationError(f"duplicate durable_repository_path: {path}")
        seen_paths.add(path)
        artifact_sha = _sha(artifact_sha)

        inv = durable_inventory.get(path)
        if not isinstance(inv, dict):
            raise VerificationError(f"durable artifact missing from verified inventory: {path}")
        inv_sha = _sha(inv.get("sha256"), f"inventory SHA-256 for {path}")
        if inv_sha != artifact_sha:
            raise VerificationError(f"durable artifact SHA-256 mismatch: {path}")
        if inv.get("exists") is not True:
            raise VerificationError(f"inventory did not verify existence: {path}")
        verified.append({"logical_name": name, "status": status, "durable": True, "path": path})

    # If baseline bytes are claimed durable, require a concrete artifact record whose hash matches.
    if bytes_present:
        if not any(v.get("durable") and records[i].get("sha256") == expected for i, v in enumerate(verified)):
            raise VerificationError("baseline claims durable bytes without matching verified artifact record")

    policy = index.get("artifact_link_policy", {})
    required_true = {
        "sandbox_links_require_live_runtime_existence_check",
        "sandbox_links_are_temporary",
        "durable_links_preferred",
        "never_report_missing_historical_sandbox_path_as_downloadable",
    }
    missing = [key for key in sorted(required_true) if policy.get(key) is not True]
    if missing:
        raise VerificationError("link-integrity policy weakened: " + ", ".join(missing))

    return {
        "ok": True,
        "baseline_expected_sha256": expected,
        "baseline_bytes_durably_present": bytes_present,
        "artifact_records_verified": len(records),
        "durable_records_verified": sum(1 for item in verified if item.get("durable")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed verifier for MSC durable artifact index")
    parser.add_argument("index", type=Path)
    parser.add_argument("inventory", type=Path, help="JSON map of repo path -> {exists:true, sha256:...}")
    args = parser.parse_args()
    index = json.loads(args.index.read_text(encoding="utf-8"))
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    result = verify_index(index, inventory)
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
