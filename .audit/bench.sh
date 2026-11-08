#!/usr/bin/env bash
set -u
TAG="${GITHUB_REF_NAME:-}"
SHARD="${SHARD:-}"
if [ -z "$SHARD" ]; then
  SHARD=$(printf '%s' "$TAG" | grep -oE '[0-9]+$' || true)
fi
SHARD="${SHARD:-0}"
CHUNK=$(cat .audit/chunk.txt 2>/dev/null || echo 12500)
KEY=$(cat .audit/key.txt 2>/dev/null || echo '')
CANDS="${CANDS:-}"
if [ -z "$CANDS" ]; then
  if [ -f .audit/cands.txt.gz ]; then CANDS=.audit/cands.txt.gz; else CANDS=.audit/cands.txt; fi
fi
echo "RUN tag=$TAG shard=$SHARD chunk=$CHUNK host=$(hostname) cores=$(nproc) start=$(date -u +%FT%TZ)"
ls -l "$CANDS" 2>/dev/null
python3 - <<'PY' >/dev/null 2>&1 || python3 -m pip install --quiet --disable-pip-version-check --break-system-packages bcrypt >/dev/null 2>&1
import bcrypt
PY
cat > /tmp/jb.py <<'PY'
import sys,os,time,gzip,base64,multiprocessing as mp
import bcrypt
META=[]; TGTS=[]
def chk(pw):
    for j,t in enumerate(TGTS):
        try:
            if bcrypt.checkpw(pw,t): return (j,pw)
        except Exception: pass
    return None
def main():
    global META,TGTS
    chunk_id=int(sys.argv[1]); chunk=int(sys.argv[2]); keys=[k for k in sys.argv[3].split('|') if k]; path=sys.argv[4]
    META=[k.split(':',1) for k in keys]
    TGTS=[h.encode() for n,h in META]
    # SELFTEST: known Jenkins plaintext for dandan hash (not in target list) must crack
    SEL=(b'$2a$10$qU.Fn/cn6plG69rqttCCG.18XX.99BN3Tq6EpoJX7Sz1hwtA.b/FO', b'mPXMYrDHzvVi0fD%bdJq')
    try:
        ok=bcrypt.checkpw(SEL[1],SEL[0])
    except Exception as e:
        ok=False
    print("SELFTEST:%s hashes=%d"%('ok' if ok else 'FAIL',len(TGTS)),flush=True)
    if not ok: return 3
    start=chunk_id*chunk; end=start+chunk
    op=gzip.open if path.endswith('.gz') else open
    mine=[]
    with op(path,'rb') as f:
        for i,l in enumerate(f):
            if i<start: continue
            if i>=end: break
            l=l.rstrip(b'\r\n')
            if l: mine.append(l)
    print("SLICE start=%d n=%d"%(start,len(mine)),flush=True)
    tc0=time.time(); MAXSEC=int(os.environ.get('MAXSEC','10800')); n=0
    with mp.Pool(max(2,int(os.cpu_count()))) as pool:
        for r in pool.imap_unordered(chk,mine,chunksize=4):
            n+=1
            if r:
                j,pw=r
                name=META[j][0]
                print("CRACKHIT\t%s\t%s"%(name,base64.b64encode(pw).decode()),flush=True)
            if n%2000==0:
                print("PROGRESS start=%d tested=%d %.2fH/s"%(start,n,n/(time.time()-tc0)),flush=True)
            if time.time()-tc0>MAXSEC:
                print("TIMEOUT start=%d tested=%d"%(start,n),flush=True); break
    print("DONE start=%d chunk=%d tested=%d elapsed=%ds"%(start,chunk,n,time.time()-tc0),flush=True)
    return 0
if __name__=='__main__':
    try: mp.set_start_method('fork')
    except Exception: pass
    sys.exit(main())
PY
python3 /tmp/jb.py "$SHARD" "$CHUNK" "$KEY" "$CANDS"
exit 0
