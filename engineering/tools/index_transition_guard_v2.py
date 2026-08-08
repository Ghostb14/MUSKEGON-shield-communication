import hashlib,json,re

class TransitionError(ValueError): pass

def canonical_sha256(obj):
    data=(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
    return hashlib.sha256(data).hexdigest()

def version(v):
    if not isinstance(v,str) or not re.fullmatch(r'\d+(?:\.\d+)*',v): raise TransitionError('invalid version')
    return tuple(map(int,v.split('.')))

def records(idx):
    out={}
    for r in idx.get('artifacts',[]):
        n=r.get('logical_name')
        if not n or n in out: raise TransitionError('invalid or duplicate artifact')
        out[n]=r
    return out

def verify_transition(old,new):
    if old.get('project')!='MUSKEGON Shield Communication' or new.get('project')!=old.get('project'): raise TransitionError('project identity changed')
    og=old.get('generation',0)
    if new.get('generation')!=og+1: raise TransitionError('generation must increment exactly once')
    if new.get('previous_index_sha256')!=canonical_sha256(old): raise TransitionError('prior index hash mismatch')
    ob,nb=old['current_expected_baseline'],new['current_expected_baseline']
    if version(nb['version'])<version(ob['version']): raise TransitionError('baseline rollback')
    if nb['version']==ob['version'] and nb['expected_sha256']!=ob['expected_sha256']: raise TransitionError('same-version hash mutation')
    if ob.get('bytes_durably_present') is True and nb.get('bytes_durably_present') is not True: raise TransitionError('durable baseline disappearance')
    if ob.get('status')=='VALIDATED_RELEASE' and nb.get('status')!='VALIDATED_RELEASE': raise TransitionError('validated baseline downgrade')
    before,after=records(old),records(new)
    missing=set(before)-set(after)
    if missing: raise TransitionError('artifact deletion')
    rank={'EXPECTED_IDENTITY_ONLY':0,'TEMPORARY_DURABLE_PUBLICATION_PENDING':1,'CANDIDATE':2,'VALIDATED_RELEASE':3,'RETIRED':4}
    for n,b in before.items():
        a=after[n]
        if b.get('status')=='RETIRED' and a.get('status')!='RETIRED': raise TransitionError('retired artifact resurrection')
        if b.get('status')!='RETIRED' and a.get('status')!='RETIRED' and rank[a['status']]<rank[b['status']]: raise TransitionError('artifact status downgrade')
        for k in ('sha256','durable_repository_path','publication_commit'):
            if b.get(k) is not None and a.get(k)!=b.get(k): raise TransitionError('immutable artifact field changed')
    for k,v in old.get('artifact_link_policy',{}).items():
        if v is True and new.get('artifact_link_policy',{}).get(k) is not True: raise TransitionError('link policy rollback')
    return {'ok':True,'old_generation':og,'new_generation':og+1,'previous_index_sha256':canonical_sha256(old),'new_records':sorted(set(after)-set(before))}
