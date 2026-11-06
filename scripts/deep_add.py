#!/usr/bin/env python3
"""deep_add.py — the AI's own hands for deep sourcing (v1.10 companion to deep.py).

deep.py covers deterministic channels (cross-pool fulltext, NVD official, primary domains).
THIS script is for the ANALYST LAYER: the agent decides what more to chase (official
follow-ups, technical writeups, prior-case comparisons, attacker-flow analysis), searches
through several engines with its own query, inspects candidates, then fetches chosen pages
into the SAME per-card deep pool — so anything the AI digs passes the same provenance gate.

usage:
  deep_add.py <date> <hash> --search "your query"          → print candidate list (JSON)
  deep_add.py <date> <hash> --fetch URL [--kind K]         → fetch + append to deep pool
  deep_add.py <date> <hash> --list                          → current deep sources (titles/urls)

kinds: official | authority | investigation | prior-case | followup | reporting | search
"""
import json, os, re, sys, time, urllib.parse, urllib.request
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
CST = timezone(timedelta(hours=8))
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 SID-Daily/1.0 (read-only researcher)"
EXCERPT_CAP = 8000

def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(160000), r.headers.get("content-type", "")

def strip_html(raw):
    t = raw.decode("utf-8", "ignore")
    t = re.sub(r"(?is)<(script|style|noscript|svg|head|nav|footer|form)[^>]*>.*?</\1>", " ", t)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = re.sub(r"&nbsp;|&#160;", " ", t)
    t = re.sub(r"&amp;", "&", t)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n\s*\n+", "\n", t)
    return t.strip()

def search(query, limit=10):
    """multi-engine scrape, best-effort; returns [{url,title,snippet,engine}]"""
    out = []
    q = urllib.parse.quote_plus(query)
    try:  # bing
        raw, _ = fetch(f"https://www.bing.com/search?q={q}&count=15")
        h = raw.decode("utf-8", "ignore")
        for m in re.finditer(r'<li class="b_algo".*?<h2><a href="([^"]+)"[^>]*>(.*?)</a>.*?(?:<p[^>]*>(.*?)</p>)?</li>', h, re.S):
            url = m.group(1)
            title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            snip = re.sub(r"<[^>]+>", "", m.group(3) or "").strip()
            if url.startswith("http"): out.append({"url": url, "title": title[:120], "snippet": snip[:200], "engine": "bing"})
    except Exception:
        pass
    for ep, pat in (("https://html.duckduckgo.com/html/?q=", r'class="result__a" href="([^"]+)"[^>]*>(.*?)</a>'),
                    ("https://lite.duckduckgo.com/lite/?q=", r'<a rel="nofollow" href="([^"]+)"[^>]*>(.*?)</a>')):
        try:
            raw, _ = fetch(ep + q)
            h = raw.decode("utf-8", "ignore")
            for url, title in re.findall(pat, h)[:limit]:
                if "uddg=" in url:
                    url = urllib.parse.unquote(re.search(r"uddg=([^&]+)", url).group(1))
                if url.startswith("http"):
                    out.append({"url": url, "title": re.sub(r"<[^>]+>", "", title).strip()[:120],
                                "snippet": "", "engine": "ddg"})
            if out: break
        except Exception:
            continue
    seen = set(); ded = []
    for r in out:
        n = urllib.parse.urldefrag(r["url"])[0]
        if n not in seen:
            seen.add(n); ded.append(r)
    return ded[:limit]

def deep_path(run_date, h):
    return os.path.join(DATA, "deep", run_date, h + ".json")

def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(2)
    run_date, h = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    doc = {"hash": h, "date": run_date, "sources": []}
    p = deep_path(run_date, h)
    if os.path.exists(p):
        doc = json.load(open(p))
    if args[0] == "--search":
        res = search(" ".join(args[1:]))
        print(json.dumps({"query": " ".join(args[1:]), "results": res}, ensure_ascii=False, indent=1))
    elif args[0] == "--fetch":
        url = args[1]
        kind = "search"
        if "--kind" in args:
            kind = args[args.index("--kind") + 1]
        try:
            raw, ct = fetch(url)
            if "json" in ct:
                text = json.dumps(json.loads(raw), ensure_ascii=False)[:EXCERPT_CAP]
            else:
                text = strip_html(raw)[:EXCERPT_CAP]
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e)[:200], "url": url})); sys.exit(1)
        m = re.search(r"<title[^>]*>(.*?)</title>", raw.decode("utf-8", "ignore"), re.S)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else urllib.parse.urlparse(url).netloc
        doc["sources"] = [s for s in doc.get("sources", []) if s.get("url") != url]
        doc["sources"].append({"url": url, "title": title, "kind": kind, "excerpt": text,
                               "added_by": "ai", "added_at": datetime.now(CST).isoformat()})
        doc["fetched_at"] = datetime.now(CST).isoformat()
        tmp = p + ".tmp"; json.dump(doc, open(tmp, "w"), ensure_ascii=False, indent=1); os.replace(tmp, p)
        print(json.dumps({"ok": True, "url": url, "title": title, "bytes": len(text),
                          "total_sources": len(doc["sources"])}, ensure_ascii=False))
    elif args[0] == "--list":
        print(json.dumps({"hash": h, "sources": [{"url": s["url"], "title": s.get("title", "")[:80],
                                                  "kind": s.get("kind"), "bytes": len(s.get("excerpt", ""))}
                                                 for s in doc.get("sources", [])]}, ensure_ascii=False, indent=1))
    else:
        print(__doc__); sys.exit(2)

if __name__ == "__main__":
    main()
