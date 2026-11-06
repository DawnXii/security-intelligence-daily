#!/usr/bin/env python3
"""SID deep-source enrichment v2.

The feed story is the SIGNAL; the article's body must carry PRIMARY content:
  A) CROSS-POOL — same event reported by our other sources (44 feeds) = free depth;
  B) PRIMARY PAGES — fetch the event's own-domain statement/advisory URL found in any
     pool title/summary/link (official vendor path wins: security advisories, incident
     statements); plus deterministic official APIs for CVE cards (NVD record via the
     existing nvd-delta endpoint, GHSA via existing GHSA API);
  C) DDG search (html/lite) only when A+B find < 2 sources — best effort, may be blocked.

Writes data/deep/<date>/<item-hash>.json {sources:[{url,title,kind,excerpt}]}.
validate.py check_brief + fact-trace pools include these excerpts (see validate patch).
Risk-control: honest UA, per-card <=6 page fetches, 0.8s spacing, per-day cache, no retries.
"""
import hashlib, json, os, re, sys, time, urllib.parse, urllib.request
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
CST = timezone(timedelta(hours=8))
UA = "SID-Daily/1.0 (security-intelligence-daily; read-only consumer)"
EXCERPT_CAP = 6000
DOM_CAP = 160000  # bytes read per page

OFFICIAL_DOMAINS = re.compile(
    r"(?:^|\.)(binance\.com|polymarket\.com|gitlab\.com|cisco\.com|apache\.org|microsoft\.com|"
    r"google\.org|google\.com|ubuntu\.com|debian\.org|kernel\.org|oracle\.com|aws\.amazon\.com|"
    r"amazon\.com|cloudflare\.com|fastly\.com|okta\.com|crowdstrike\.com|microsoft\.us|us-cert\.cisa\.gov|"
    r"cisa\.gov|nist\.gov|slowmist\.com|chainalysis\.com|trmlabs\.com|elliptic\.co|nethermind\.io|"
    r"certik\.co|github\.github\.io|osv\.dev)$", re.I)
AUTH_MEDIA = re.compile(r"(?:^|\.)(cyberkendra\.com|cointelegraph\.com|theblock\.co|coindesk\.com|"
    r"decrypt\.com|reuters\.com|bloomberg\.com|wsj\.com|ft\.com|thenextweb\.com|bleepingcomputer\.com)$", re.I)
STATE_HINT = re.compile(r"(statement|announcement|advisory|security note|incident|post-?mortem|"
    r"root cause|update|resolution|disclosure|compromis|hack|exploit|vulnerab|cease|frozen|recover)", re.I)

def fetch(url, timeout=18):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        ct = r.headers.get("content-type", "")
        return r.read(DOM_CAP), ct

def strip_html(raw):
    t = raw.decode("utf-8", "ignore")
    t = re.sub(r"(?is)<(script|style|noscript|svg|head|nav|footer|form)[^>]*>.*?</\1>", " ", t)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = re.sub(r"&nbsp;|&#160;", " ", t)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n\s*\n+", "\n", t)
    return t.strip()

def norm_url(u):
    u = urllib.parse.urldefrag(u)[0]
    if u.endswith("/"): u = u[:-1]
    return u

def host_of(u):
    return urllib.parse.urlparse(u).netloc.lower().lstrip("www.")

def is_dup(url, seen):
    n = norm_url(url).lower()
    if n in seen: return True
    seen.add(n); return False

def load_pool(run_date):
    p = os.path.join(DATA, "candidates", run_date, "raw.json")
    if not os.path.exists(p): return []
    try:
        return json.load(open(p))["items"]
    except Exception:
        return []

def entities(item):
    ents = []
    for f in ("cve", "affected", "actor"):
        v = item.get(f) or ""
        for x in re.findall(r"CVE-\d{4}-\d{4,7}|[A-Za-z][A-Za-z0-9._-]{2,}", str(v))[:2]:
            ents.append(x)
    t = str(item.get("title_zh", "")) + " " + str(item.get("summary_zh", ""))
    # extract english entity tokens from our own zh prose too
    for x in re.findall(r"[A-Za-z][A-Za-z0-9.+_/-]{2,}", t):
        if x.lower() not in [e.lower() for e in ents]:
            ents.append(x)
    return ents[:8]

STOPWORDS = re.compile(r"^(and|the|for|with|http|https|says|after|new|s|re|ve|ll|hack|hacked|security|update|live|report|says|amid|over|from|will|says)$", re.I)

def strong_entities(item):
    """proper-noun-grade entities only: CVEs and named products/orgs (len>=5, word-bounded later)."""
    ents = []
    for f in ("cve", "affected", "actor"):
        v = str(item.get(f) or "")
        for x in re.findall(r"CVE-\d{4}-\d{4,7}|[A-Z][A-Za-z0-9.+-]{4,}", v):
            if x not in ents: ents.append(x)
    t = str(item.get("summary_zh", "")) + " " + str(item.get("title_zh", ""))
    t = re.sub(r"</?k>", " ", t)
    for x in re.findall(r"CVE-\d{4}-\d{4,7}|[A-Z][A-Za-z0-9.+-]{4,}", t):
        if x not in ents and not STOPWORDS.match(x.lower()):
            ents.append(x)
    return ents[:8]

def cross_pool(item, pool):
    """other feed items about the same event, by shared strong entity (word boundary)."""
    ents = strong_entities(item)
    pats = [(e, re.compile(r"\b" + re.escape(e) + r"\b", re.I)) for e in ents if len(e) >= 5 or e.startswith("CVE")]
    scored = []
    mine = norm_url(item.get("link", ""))
    for cand in pool:
        if norm_url(cand.get("link", "")) == mine: continue
        blob = cand.get("title", "") + " " + cand.get("summary", "")
        n = sum(1 for _, pt in pats if pt.search(blob))
        if n >= 1 and (n >= 2 or any(pt.search(cand.get("title", "")) for _, pt in pats)):
            scored.append((n, cand))
    scored.sort(key=lambda t: (-t[0], -len(t[1].get("summary", ""))))
    return [c for _, c in scored[:5]]

def primary_urls(item, pool_hits):
    """official statement/advisory URLs mentioned anywhere + same-domain article."""
    urls = []
    blob = " ".join([str(item.get("summary_zh", "")), str(item.get("action", "")), str(item.get("impact", ""))])
    urls += re.findall(r"https?://[^\s\u4e00-\u9fff\"']+", blob)
    src_link = item.get("link", "")
    h = host_of(src_link)
    for ph in pool_hits:
        hl = ph.get("link", "")
        if host_of(hl) == h:
            continue
        urls.append(hl)
    return [u for u in urls if u.startswith("http")]

def score_url(u):
    hh = host_of(u) or ""
    s = 0
    if OFFICIAL_DOMAINS.search(hh): s += 10
    if AUTH_MEDIA.search(hh): s += 5
    if re.search(r"(security|advisory|announcement|support|news|blog|statement|incident|press)", u, re.I): s += 3
    if ".gov" in hh: s += 8
    return s

def nvd_official(item):
    """deterministic official record for CVE cards via the existing NVD endpoint."""
    cve = (item.get("cve") or "")
    m = re.search(r"CVE-\d{4}-\d{4,7}", str(cve)) or re.search(r"CVE-\d{4}-\d{4,7}", str(item.get("title_zh", "")) + str(item.get("summary_zh", "")))
    if not m: return None
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + m.group(0)
    try:
        raw, _ = fetch(url, timeout=25)
        d = json.loads(raw)
        v = (d.get("vulnerabilities") or [{}])[0].get("cve", {})
        desc = (v.get("descriptions") or [{}])[0].get("value", "")
        cvss = ""
        for m2 in v.get("metrics", {}).values():
            if m2: cvss = m2[0].get("cvssData", {}).get("baseScore", "") ; break
        refs = [r.get("url") for r in v.get("references", []) if r.get("url")][:4]
        if not desc: return None
        return {"url": url, "title": f"NVD official record {m.group(0)}", "kind": "official-api",
                "excerpt": (desc + f"\nCVSS: {cvss}\nRefs: " + " ".join(refs))[:EXCERPT_CAP]}
    except Exception:
        return None

def ddq(q):
    for ep in ("https://html.duckduckgo.com/html/?q=", "https://lite.duckduckgo.com/lite/?q="):
        try:
            raw, _ = fetch(ep + urllib.parse.quote(q))
            html = raw.decode("utf-8", "ignore")
            links = re.findall(r'class="result__a" href="([^"]+)"', html)
            out = []
            for href in links[:8]:
                m = re.search(r"uddg=([^&]+)", href)
                out.append(urllib.parse.unquote(m.group(1)) if m else urllib.parse.unquote(href))
            if out: return out
        except Exception:
            continue
    return []

def build_doc(item, pool, run_date):
    seen = set()
    out = []
    # B: official API for CVE cards first (free & deterministic)
    nrec = nvd_official(item)
    if nrec:
        out.append(nrec); is_dup(nrec["url"], seen)
    # A: cross-pool
    xp = cross_pool(item, pool)
    # C: primary URLs (official statements + pool articles), fetch top ones
    cand_urls = primary_urls(item, xp)
    cand_urls = [u for u in cand_urls if not is_dup(u, set())]
    cand_urls.sort(key=lambda u: -score_url(u))
    fetch_budget = 3 - min(len(out), 2) if out else 3
    for u in cand_urls:
        if len(out) >= 3 or fetch_budget <= 0: break
        if is_dup(u, seen): continue
        fetch_budget -= 1
        try:
            raw, ct = fetch(u)
            if "json" in ct:
                text = json.dumps(json.loads(raw), ensure_ascii=False)[:EXCERPT_CAP]
            else:
                text = strip_html(raw)[:EXCERPT_CAP]
        except Exception:
            continue
        if len(text) < 250: continue
        hh = host_of(u)
        kind = "official" if OFFICIAL_DOMAINS.search(hh) or ".gov" in hh else ("authority" if AUTH_MEDIA.search(hh) else "reporting")
        title = re.search(r"<title[^>]*>(.*?)</title>", raw.decode("utf-8", "ignore"), re.S)
        out.append({"url": u, "title": (title.group(1).strip()[:90] if title else hh),
                    "kind": kind, "excerpt": text})
        time.sleep(0.8)
    # pool items as depth: try FULLTEXT of top 2 (feed summaries are truncated leads), else lead
    ft_budget = 2
    for ph in xp[:4]:
        u = ph.get("link", "")
        if not u or u in seen or u == norm_url(item.get("link", "")): continue
        seen.add(u)
        excerpt = (ph.get("title", "") + "\n" + ph.get("summary", ""))[:EXCERPT_CAP]
        if ft_budget > 0 and "ransomware.live" not in u:
            ft_budget -= 1
            try:
                raw, _ = fetch(u)
                t = strip_html(raw)[:EXCERPT_CAP]
                if len(t) >= 350:
                    excerpt = t
            except Exception:
                pass
        out.append({"url": u, "title": ph.get("title", "")[:90], "kind": "pool-cross", "excerpt": excerpt})
        time.sleep(0.6)
    if len(out) < 2:
        ents = entities(item)
        q = " ".join(ents[:3]) + " official statement"
        for u in ddq(q):
            if len(out) >= 2: break
            if is_dup(u, seen): continue
            try:
                raw, _ = fetch(u)
                text = strip_html(raw)[:EXCERPT_CAP]
            except Exception:
                continue
            if len(text) < 250: continue
            out.append({"url": u, "title": host_of(u), "kind": "search", "excerpt": text})
    return out

def main():
    run_date = sys.argv[1] if len(sys.argv) > 1 else datetime.now(CST).strftime("%Y-%m-%d")
    ana_path = os.path.join(DATA, "analysis", f"{run_date}.validated.json")
    if not os.path.exists(ana_path):
        ana_path = os.path.join(DATA, "analysis", f"{run_date}.json")
    ana = json.load(open(ana_path))
    todo = [x for x in ana if x.get("include") and int(x.get("score", 0)) >= 75]
    ddir = os.path.join(DATA, "deep", run_date)
    os.makedirs(ddir, exist_ok=True)
    pool = load_pool(run_date)
    res = {"targets": len(todo), "pool": len(pool), "done": []}
    for it in todo:
        outp = os.path.join(ddir, it["hash"] + ".json")
        if os.path.exists(outp):
            res["done"].append((it["hash"][:8], "cached")); continue
        try:
            srcs = build_doc(it, pool, run_date)
        except Exception as e:
            srcs = []; res["done"].append((it["hash"][:8], f"ERR {str(e)[:60]}"))
        doc = {"hash": it["hash"], "title": it.get("title_zh", ""), "date": run_date,
               "fetched_at": datetime.now(CST).isoformat(), "sources": srcs}
        tmp = outp + ".tmp"; json.dump(doc, open(tmp, "w"), ensure_ascii=False, indent=1); os.replace(tmp, outp)
        res["done"].append((it["hash"][:8], [f"{s['kind']}:{host_of(s['url'])}" for s in srcs]))
    print(json.dumps(res, ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
