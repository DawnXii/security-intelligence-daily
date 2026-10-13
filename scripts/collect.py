#!/usr/bin/env python3
"""SID collect — 采集 RSS 来源，规范化、去重、持久化。幂等：按 run_date + item hash 去重。
退出码：0=成功(含部分来源失败) 2=无任何来源成功(硬失败)。stdout 最后一行输出 JSON 摘要。"""
import hashlib, json, os, re, sys, time, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
CST = timezone(timedelta(hours=8))

FEEDS = [
    {"id": "thn", "name": "The Hacker News", "url": "https://thehackernews.com/feeds/posts/default", "tags": ["general"]},
    {"id": "bleo", "name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "tags": ["general", "ransomware"]},
    {"id": "netsec", "name": "NetSec Learn", "url": "https://feeds.feedburner.com/netsec", "tags": ["research"]},
    {"id": "cisa", "name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "tags": ["vuln", "gov"]},
    {"id": "cloudflare", "name": "Cloudflare Blog", "url": "https://blog.cloudflare.com/rss/", "tags": ["infra"]},
    {"id": "aws", "name": "AWS Security", "url": "https://aws.amazon.com/blogs/security/feed/", "tags": ["cloud", "infra"]},
    {"id": "ghsec", "name": "GitHub Security", "url": "https://github.blog/security/feed/", "tags": ["cicd", "supplychain"]},
    {"id": "isc", "name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "tags": ["general"]},
    {"id": "krebs", "name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/", "tags": ["crime", "phishing"]},
    {"id": "google", "name": "Google Safety", "url": "https://blog.google/technology/safety-security/rss/", "tags": ["general"]},
    {"id": "trailofbits", "name": "Trail of Bits", "url": "https://blog.trailofbits.com/index.xml", "tags": ["research", "supplychain"]},
    {"id": "chainalysis", "name": "Chainalysis Blog", "url": "https://www.chainalysis.com/blog/feed/", "tags": ["crypto", "web3"]},
]

UA = "Mozilla/5.0 (compatible; SID-collector/1.0)"

def fetch(url, timeout=20, retries=2):
    """带退避+抖动的抓取。代理由环境 HTTP(S)_PROXY 自动继承。"""
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            last = e
            if attempt < retries:
                time.sleep(min(8, 1.5 * (2 ** attempt)) + (os.getuid() % 3) * 0.1)
    raise last

def strip_html(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()

def parse_items(raw):
    """支持 RSS2.0 与 Atom。"""
    items = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        cleaned = re.sub(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]", b"", raw)
        root = ET.fromstring(cleaned)
    ns = {"a": "http://www.w3.org/2005/Atom"}
    if root.tag.endswith("}feed") or root.tag == "feed":
        for e in root.findall("a:entry", ns):
            t = e.find("a:title", ns)
            l = e.find("a:link", ns)
            u = e.find("a:updated", ns)
            if u is None:
                u = e.find("a:published", ns)
            s = e.find("a:summary", ns)
            if s is None:
                s = e.find("a:content", ns)
            items.append({
                "title": strip_html(t.text if t is not None else ""),
                "link": (l.get("href") if l is not None else ""),
                "date": (u.text or "") if u is not None else "",
                "summary": strip_html(s.text if s is not None else "")[:800],
            })
    else:
        for it in root.iter("item"):
            g = lambda tag: (it.findtext(tag) or "").strip()
            items.append({
                "title": strip_html(g("title")),
                "link": g("link"),
                "date": g("pubDate") or g("dc:date"),
                "summary": strip_html(g("description"))[:800],
            })
    return [i for i in items if i["title"] and i["link"]]

def norm_date(s):
    try:
        return parsedate_to_datetime(s).astimezone(CST).isoformat()
    except Exception:
        return s

def main():
    run_date = sys.argv[1] if len(sys.argv) > 1 else datetime.now(CST).strftime("%Y-%m-%d")
    run_id = f"{run_date}-{int(time.time())}"
    os.makedirs(os.path.join(DATA, "candidates", run_date), exist_ok=True)
    cand_file = os.path.join(DATA, "candidates", run_date, "raw.json")
    status_file = os.path.join(DATA, "status", f"{run_date}.json")
    cooldown_file = os.path.join(DATA, "status", "source_cooldown.json")

    seen = {}
    existing = []
    if os.path.exists(cand_file):
        try:
            existing = json.load(open(cand_file))["items"]
            for it in existing:
                seen[it["hash"]] = True
        except Exception:
            existing = []

    cooldown = {}
    if os.path.exists(cooldown_file):
        try:
            cooldown = json.load(open(cooldown_file))
        except Exception:
            cooldown = {}

    results, new_items = [], []
    for f in FEEDS:
        if cooldown.get(f["id"], {}).get("until", 0) > time.time():
            results.append({"source": f["id"], "status": "cooldown", "count": 0})
            continue
        try:
            raw = fetch(f["url"])
            items = parse_items(raw)
            cnt = 0
            for it in items:
                h = hashlib.sha256((it["link"].strip().lower() + "|" + it["title"].strip().lower()).encode()).hexdigest()[:16]
                if h in seen:
                    continue
                seen[h] = True
                cnt += 1
                new_items.append({**it, "hash": h, "source": f["id"], "source_name": f["name"],
                                  "tags": f["tags"], "date": norm_date(it["date"]), "collected_at": datetime.now(CST).isoformat()})
            results.append({"source": f["id"], "status": "ok", "count": cnt, "total_feed": len(items)})
            cooldown.pop(f["id"], None)
        except Exception as e:
            results.append({"source": f["id"], "status": "fail", "error": str(e)[:200]})
            cooldown[f["id"]] = {"until": time.time() + 3600, "error": str(e)[:200]}

    all_items = existing + new_items
    tmp = cand_file + ".tmp"
    json.dump({"run_id": run_id, "run_date": run_date, "count": len(all_items), "items": all_items},
              open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, cand_file)
    json.dump(cooldown, open(cooldown_file, "w"), indent=1)

    ok = sum(1 for r in results if r["status"] == "ok")
    hard_fail = ok == 0
    status = {"run_id": run_id, "run_date": run_date, "stage": "collect",
              "sources_total": len(FEEDS), "sources_ok": ok,
              "sources_fail": [r for r in results if r["status"] not in ("ok",)],
              "new_items": len(new_items), "total_items": len(all_items),
              "finished_at": datetime.now(CST).isoformat()}
    json.dump(status, open(status_file + ".tmp", "w"), ensure_ascii=False, indent=1)
    os.replace(status_file + ".tmp", status_file)

    print(json.dumps(status, ensure_ascii=False))
    sys.exit(2 if hard_fail else 0)

if __name__ == "__main__":
    main()
