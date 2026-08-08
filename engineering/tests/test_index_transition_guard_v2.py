from copy import deepcopy
import pytest
from index_transition_guard_v2 import TransitionError, canonical_sha256, verify_transition

H='a'*64

def base():
    return {
      'project':'MUSKEGON Shield Communication','generation':2,
      'current_expected_baseline':{'version':'10.19.0','expected_sha256':H,'bytes_durably_present':False,'status':'EXPECTED_IDENTITY_ONLY'},
      'artifact_link_policy':{'sandbox_links_are_temporary':True,'durable_links_preferred':True},
      'artifacts':[{'logical_name':'tool','status':'CANDIDATE','sha256':'b'*64,'durable_repository_path':'engineering/tool.py','publication_commit':'c'*40}]
    }

def next_index(old):
    n=deepcopy(old); n['generation']=old['generation']+1; n['previous_index_sha256']=canonical_sha256(old); return n

def test_valid_append():
    o=base(); n=next_index(o); n['artifacts'].append({'logical_name':'test','status':'CANDIDATE','sha256':'d'*64,'durable_repository_path':'engineering/test.py','publication_commit':'e'*40})
    r=verify_transition(o,n); assert r['ok'] and r['new_records']==['test']

def test_generation_skip_rejected():
    o=base(); n=next_index(o); n['generation']=7
    with pytest.raises(TransitionError,match='generation'): verify_transition(o,n)

def test_bad_previous_hash_rejected():
    o=base(); n=next_index(o); n['previous_index_sha256']='0'*64
    with pytest.raises(TransitionError,match='prior index'): verify_transition(o,n)

def test_baseline_version_rollback_rejected():
    o=base(); n=next_index(o); n['current_expected_baseline']['version']='10.18.9'
    with pytest.raises(TransitionError,match='rollback'): verify_transition(o,n)

def test_same_version_hash_mutation_rejected():
    o=base(); n=next_index(o); n['current_expected_baseline']['expected_sha256']='f'*64
    with pytest.raises(TransitionError,match='hash mutation'): verify_transition(o,n)

def test_durable_baseline_cannot_disappear():
    o=base(); o['current_expected_baseline']['bytes_durably_present']=True; o['current_expected_baseline']['status']='VALIDATED_RELEASE'; n=next_index(o); n['current_expected_baseline']['bytes_durably_present']=False
    with pytest.raises(TransitionError,match='disappearance'): verify_transition(o,n)

def test_record_deletion_rejected():
    o=base(); n=next_index(o); n['artifacts']=[]
    with pytest.raises(TransitionError,match='artifact deletion'): verify_transition(o,n)

def test_hash_rewrite_rejected():
    o=base(); n=next_index(o); n['artifacts'][0]['sha256']='f'*64
    with pytest.raises(TransitionError,match='immutable'): verify_transition(o,n)

def test_path_rewrite_rejected():
    o=base(); n=next_index(o); n['artifacts'][0]['durable_repository_path']='other.py'
    with pytest.raises(TransitionError,match='immutable'): verify_transition(o,n)

def test_status_downgrade_rejected():
    o=base(); n=next_index(o); n['artifacts'][0]['status']='EXPECTED_IDENTITY_ONLY'
    with pytest.raises(TransitionError,match='downgrade'): verify_transition(o,n)

def test_retirement_is_allowed_and_sticky():
    o=base(); n=next_index(o); n['artifacts'][0]['status']='RETIRED'; assert verify_transition(o,n)['ok']
    o2=n; n2=next_index(o2); n2['artifacts'][0]['status']='CANDIDATE'
    with pytest.raises(TransitionError,match='resurrection'): verify_transition(o2,n2)

def test_link_policy_true_cannot_weaken():
    o=base(); n=next_index(o); n['artifact_link_policy']['sandbox_links_are_temporary']=False
    with pytest.raises(TransitionError,match='policy rollback'): verify_transition(o,n)
