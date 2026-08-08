import copy
import pytest
from artifact_index_verifier import VerificationError, verify_index

H = "a" * 64
BASE = {
    "schema": 2,
    "project": "MUSKEGON Shield Communication",
    "current_expected_baseline": {
        "version": "10.19.0",
        "expected_sha256": "1" * 64,
        "bytes_durably_present": False,
        "status": "EXPECTED_IDENTITY_ONLY",
    },
    "artifact_link_policy": {
        "sandbox_links_require_live_runtime_existence_check": True,
        "sandbox_links_are_temporary": True,
        "durable_links_preferred": True,
        "never_report_missing_historical_sandbox_path_as_downloadable": True,
    },
    "artifacts": [],
}

def test_expected_only_baseline_is_valid():
    assert verify_index(copy.deepcopy(BASE), {})["ok"]

def test_expected_only_cannot_claim_bytes():
    x = copy.deepcopy(BASE); x["current_expected_baseline"]["bytes_durably_present"] = True
    with pytest.raises(VerificationError, match="expected-only"):
        verify_index(x, {})

def test_validated_release_requires_bytes():
    x = copy.deepcopy(BASE); x["current_expected_baseline"]["status"] = "VALIDATED_RELEASE"
    with pytest.raises(VerificationError, match="durable bytes"):
        verify_index(x, {})

def test_durable_record_requires_inventory_presence():
    x = copy.deepcopy(BASE); x["artifacts"] = [{
        "logical_name":"tool", "artifact_type":"degraded_mode_tooling", "status":"CANDIDATE",
        "durable_repository_path":"engineering/tool.py", "sha256":H
    }]
    with pytest.raises(VerificationError, match="missing from verified inventory"):
        verify_index(x, {})

def test_durable_record_requires_hash_match():
    x = copy.deepcopy(BASE); x["artifacts"] = [{
        "logical_name":"tool", "artifact_type":"degraded_mode_tooling", "status":"CANDIDATE",
        "durable_repository_path":"engineering/tool.py", "sha256":H
    }]
    with pytest.raises(VerificationError, match="mismatch"):
        verify_index(x, {"engineering/tool.py":{"exists":True,"sha256":"b"*64}})

def test_durable_record_verified():
    x = copy.deepcopy(BASE); x["artifacts"] = [{
        "logical_name":"tool", "artifact_type":"degraded_mode_tooling", "status":"CANDIDATE",
        "durable_repository_path":"engineering/tool.py", "sha256":H
    }]
    r=verify_index(x, {"engineering/tool.py":{"exists":True,"sha256":H}})
    assert r["durable_records_verified"] == 1

def test_pending_must_not_claim_durable_path():
    x=copy.deepcopy(BASE); x["artifacts"]=[{
        "logical_name":"zip","artifact_type":"release_zip","status":"TEMPORARY_DURABLE_PUBLICATION_PENDING",
        "durable_repository_path":"releases/a.zip","sha256":H
    }]
    with pytest.raises(VerificationError, match="must not claim durable path"):
        verify_index(x,{})

def test_expected_identity_must_not_claim_path():
    x=copy.deepcopy(BASE); x["artifacts"]=[{
        "logical_name":"zip","artifact_type":"release_zip","status":"EXPECTED_IDENTITY_ONLY",
        "durable_repository_path":"releases/a.zip","sha256":H
    }]
    with pytest.raises(VerificationError, match="must not claim durable path"):
        verify_index(x,{})

def test_rejects_path_traversal():
    x=copy.deepcopy(BASE); x["artifacts"]=[{
        "logical_name":"tool","artifact_type":"tool","status":"CANDIDATE",
        "durable_repository_path":"engineering/../secret","sha256":H
    }]
    with pytest.raises(VerificationError, match="unsafe repository path"):
        verify_index(x,{})

def test_rejects_backslash_path():
    x=copy.deepcopy(BASE); x["artifacts"]=[{
        "logical_name":"tool","artifact_type":"tool","status":"CANDIDATE",
        "durable_repository_path":"engineering\\tool.py","sha256":H
    }]
    with pytest.raises(VerificationError, match="unsafe repository path"):
        verify_index(x,{})

def test_rejects_duplicate_logical_names():
    x=copy.deepcopy(BASE); rec={"logical_name":"x","artifact_type":"tool","status":"EXPECTED_IDENTITY_ONLY","sha256":H}
    x["artifacts"]=[copy.deepcopy(rec),copy.deepcopy(rec)]
    with pytest.raises(VerificationError, match="duplicate logical_name"):
        verify_index(x,{})

def test_rejects_duplicate_durable_paths():
    x=copy.deepcopy(BASE); x["artifacts"]=[
      {"logical_name":"x","artifact_type":"tool","status":"CANDIDATE","durable_repository_path":"engineering/x","sha256":H},
      {"logical_name":"y","artifact_type":"tool","status":"CANDIDATE","durable_repository_path":"engineering/x","sha256":H},
    ]
    inv={"engineering/x":{"exists":True,"sha256":H}}
    with pytest.raises(VerificationError, match="duplicate durable_repository_path"):
        verify_index(x,inv)

def test_rejects_weakened_link_policy():
    x=copy.deepcopy(BASE); x["artifact_link_policy"]["sandbox_links_require_live_runtime_existence_check"]=False
    with pytest.raises(VerificationError, match="policy weakened"):
        verify_index(x,{})

def test_rejects_uppercase_sha():
    x=copy.deepcopy(BASE); x["current_expected_baseline"]["expected_sha256"]="A"*64
    with pytest.raises(VerificationError, match="lowercase"):
        verify_index(x,{})

def test_baseline_bytes_claim_requires_matching_artifact():
    x=copy.deepcopy(BASE)
    x["current_expected_baseline"]["status"]="VALIDATED_RELEASE"
    x["current_expected_baseline"]["bytes_durably_present"]=True
    x["artifacts"]=[{"logical_name":"other","artifact_type":"release_zip","status":"CANDIDATE","durable_repository_path":"releases/other.zip","sha256":H}]
    with pytest.raises(VerificationError, match="without matching"):
        verify_index(x,{"releases/other.zip":{"exists":True,"sha256":H}})
