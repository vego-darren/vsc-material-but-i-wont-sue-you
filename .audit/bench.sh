#!/usr/bin/env bash
set -u
TAG="${GITHUB_REF_NAME:-}"
SHARD=$(printf '%s' "$TAG" | grep -oE '[0-9]+$' || true)
SHARD="${SHARD:-0}"
NSHARDS=$(cat .audit/nshards.txt 2>/dev/null || echo 1)
KEY=$(cat .audit/key.txt 2>/dev/null || echo '')
CANDS=""
for c in .audit/cands.txt.gz .audit/cands.txt; do [ -f "$c" ] && CANDS="$c" && break; done
REG=".audit/regions.txt"
echo "RUN tag=$TAG shard=$SHARD nshards=$NSHARDS chunk=REGION host=$(hostname) cores=$(nproc) start=$(date -u +%FT%TZ)"
ls -l "$CANDS" "$REG" 2>/dev/null
python3 - <<'PY' >/dev/null 2>&1 || python3 -m pip install --quiet --disable-pip-version-check --break-system-packages bcrypt >/dev/null 2>&1
import bcrypt
PY
cat > /tmp/rb.py <<'PY'
import sys,os,hmac,hashlib,base64,time,gzip,math,multiprocessing as mp
import bcrypt
TGTS=[]
def prep(pw): return base64.b64encode(hmac.new(b'wp-sha384',pw,hashlib.sha384).digest())
def chk(pw):
    p=prep(pw)
    try:
        for j,t in enumerate(TGTS):
            if bcrypt.checkpw(p,t): return (pw,j)
    except Exception: return None
def main():
    global TGTS
    shard=int(sys.argv[1]); nsh=int(sys.argv[2]); keys=[k for k in sys.argv[3].split('|') if k]
    path=sys.argv[4]; regpath=sys.argv[5]
    TGTS=[k.replace('$wp','').replace('$2y$','$2b$').encode() for k in keys]
    if not TGTS: print('NOKEY'); return 1
    regs=[]
    for line in open(regpath):
        line=line.strip()
        if not line or line.startswith('#'): continue
        a,b=line.split()[:2]; regs.append((int(a),int(b)))
    # each shard gets a contiguous sub-slice of every region
    mine=[]
    for a,b in regs:
        L=b-a
        if L<=0: continue
        per=max(1,int(math.ceil(L/float(nsh))))
        sa=a+shard*per; sb=min(b,sa+per)
        if sa<sb and sa<b: mine.append((sa,sb))
    mine.sort()
    cands=[]
    op=gzip.open if path.endswith('.gz') else open
    ri=0
    with op(path,'rb') as f:
        for i,l in enumerate(f):
            while ri<len(mine) and i>=mine[ri][1]: ri+=1
            if ri>=len(mine): break
            a,b=mine[ri]
            if i<a: continue
            l=l.rstrip(b'\r\n')
            if l: cands.append(l)
    tc0=time.time(); n=0
    MAXSEC=int(os.environ.get('MAXSEC','19800'))
    print('SLICE shard=%d regions=%d cand=%d'%(shard,len(mine),len(cands)),flush=True)
    with mp.Pool(max(2,int(os.cpu_count()))) as pool:
        for r in pool.imap_unordered(chk,cands,chunksize=4):
            n+=1
            if r:
                pw,idx=r
                print("CRACKHIT:%s:%s"%(idx,pw.decode('utf-8','replace')),flush=True)
            if n%1000==0:
                print("PROGRESS shard=%d tested=%d %.2fH/s"%(shard,n,n/(time.time()-tc0)),flush=True)
            if time.time()-tc0>MAXSEC:
                print("TIMEOUT shard=%d tested=%d"%(shard,n),flush=True); break
    print("DONE shard=%d regions=%d cand=%d tested=%d elapsed=%ds"%(shard,len(mine),len(cands),n,time.time()-tc0),flush=True)
    return 0
if __name__=='__main__':
    try: mp.set_start_method('fork')
    except Exception: pass
    sys.exit(main())
PY
python3 /tmp/rb.py "$SHARD" "$NSHARDS" "$KEY" "$CANDS" "$REG"
exit 1
