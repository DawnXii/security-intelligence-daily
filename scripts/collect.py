#!/usr/bin/env python3
"""SID collect — 采集 RSS 来源，规范化、去重、持久化。幂等：按 run_date + item hash 去重。
退出码：0=成功(含部分来源失败) 2=无任何来源成功(硬失败)。stdout 最后一行输出 JSON 摘要。"""
import hashlib, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
CST = timezone(timedelta(hours=8))

FEEDS = [
    {"id": "thn", "name": "The Hacker News", "url": "https://thehackernews.com/feeds/posts/default", "tags": ["general"]},
    {"id": "secaff", "name": "Security Affairs", "url": "https://securityaffairs.com/feed", "tags": ["general", "vuln"]},
    {"id": "porsw", "name": "PortSwigger Research", "url": "https://portswigger.net/research/rss", "tags": ["research", "vuln"]},
    {"id": "register", "name": "The Register Security", "url": "https://www.theregister.com/security/headlines.atom", "tags": ["general", "infra"]},
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
    {"id": "rwlive", "name": "Ransomware.live", "url": "https://api.ransomware.live/rss", "tags": ["ransomware", "incident"]},
    {"id": "derp", "name": "Derp.ca Research", "url": "https://www.derp.ca/feed", "tags": ["malware", "research"]},
    {"id": "phpnet", "name": "PHP.net News", "url": "https://www.php.net/feed.atom", "tags": ["vuln", "vendor"]},
    {"id": "wpsec", "name": "WordPress News", "url": "https://wordpress.org/news/feed/", "tags": ["vuln", "vendor"]},
]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_WINDOW_DAYS = 7    # 生成候选项的回溯窗口
KEV_REF_DAYS = 60      # 写入参考索引（供 build 判定 KEV 在野）的回溯窗口

GHSA_URL = "https://api.github.com/advisories?per_page=100&sort=published&type=reviewed&severity={sev}"
GHSA_SEVS = ("critical", "high")

# RansomLook（CERT-AG）勒索团伙跟踪 API：近 N 天新增受害者帖 → 按团伙聚合为结构化候选
RL_POSTS_URL = "https://www.ransomlook.io/api/posts?days={days}"
RL_GROUP_URL = "https://www.ransomlook.io/group/{name}"
RL_WINDOW_DAYS = 7
RL_MIN_VICTIMS = 3     # 聚合后团伙 7 天受害者数达到该阈值才生成候选（避免单条噪音淹没版面）
GHSA_WINDOW_DAYS = 7   # 只收近期发布的 advisory
GHSA_ECO = {"npm", "pip", "go", "maven", "rubygems", "rust", "composer", "nuget", "swift",
            "pub", "hex", "erlang", "actions", "terraform"}  # API 小写生态名

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

    # CISA KEV 结构化补充：近 N 天新增的已确认在野利用漏洞，生成合成候选项 + 参考索引
    kev_status = "skip"
    try:
        kev = json.loads(fetch(KEV_URL, timeout=30).decode("utf-8", "replace"))
        cutoff = (datetime.now(CST) - timedelta(days=KEV_WINDOW_DAYS)).strftime("%Y-%m-%d")
        cutoff_ref = (datetime.now(CST) - timedelta(days=KEV_REF_DAYS)).strftime("%Y-%m-%d")
        ref = {}
        added = 0
        for v in kev.get("vulnerabilities", []):
            da = v.get("dateAdded", "")
            if da < cutoff_ref:
                continue
            ref[v["cveID"]] = {"dateAdded": da, "product": v.get("product", ""),
                               "vendor": v.get("vendorProject", ""), "requiredAction": v.get("requiredAction", "")}
            if da < cutoff:
                continue
            cve = v["cveID"]
            title = f"CISA KEV: {v.get('vendorProject','')} {v.get('product','')} — {cve} 已确认在野利用"
            link = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?selected_cve=" + cve
            h = hashlib.sha256((link.lower() + "|" + title.lower()).encode()).hexdigest()[:16]
            if h in seen:
                continue
            seen[h] = True
            added += 1
            summary = (f"{cve} 已被 CISA 列入已知被利用漏洞目录（KEV），dateAdded {da}。"
                       f"厂商/产品：{v.get('vendorProject','')} {v.get('product','')}。"
                       f"要求的处置：{v.get('requiredAction','')}。"
                       f"备注：{v.get('notes','') or ''}".strip())[:800]
            new_items.append({"title": title, "link": link, "date": da,
                              "summary": strip_html(summary), "hash": h, "source": "kev",
                              "source_name": "CISA KEV", "tags": ["vuln", "kev"],
                              "collected_at": datetime.now(CST).isoformat()})
        kev_status = "ok"
        ref_file = os.path.join(DATA, "status", f"{run_date}-kev-index.json")
        json.dump({"asof": datetime.now(CST).isoformat(), "cutoff": cutoff_ref, "entries": ref},
                  open(ref_file + ".tmp", "w"), ensure_ascii=False, indent=1)
        os.replace(ref_file + ".tmp", ref_file)
        results.append({"source": "kev", "status": "ok", "count": added, "total_feed": len(kev.get("vulnerabilities", []))})
        cooldown.pop("kev", None)
    except Exception as e:
        kev_status = "fail"
        results.append({"source": "kev", "status": "fail", "error": str(e)[:200]})

    # GitHub Advisory DB (GHSA)：critical/high + 近期发布 + 生态组件类（wolfSSL/Next.js 这类）
    ghsa_status = "skip"
    try:
        advs_all, added_g = {}, 0
        for sev_q in GHSA_SEVS:
            for page in (1, 2):
                try:
                    advs = json.loads(fetch(GHSA_URL.format(sev=sev_q) + f"&page={page}", timeout=30).decode("utf-8", "replace"))
                except Exception:
                    break
                if not isinstance(advs, list) or not advs:
                    break
                for a in advs:
                    key = a.get("ghsa_id") or a.get("cve_id")
                    if key:
                        advs_all.setdefault(key, a)
        cutoff_g = (datetime.now(CST) - timedelta(days=GHSA_WINDOW_DAYS)).strftime("%Y-%m-%d")
        for a in advs_all.values():
            pub = (a.get("published_at") or "")
            if pub and pub < cutoff_g:
                continue
            summary0 = strip_html(a.get("summary") or "")
            if summary0.startswith("Microsoft Security Advisory"):
                continue  # MSRC 月度补丁镜像，量大噪音高
            pkgs = {((v.get("package") or {}).get("name") or "") for v in a.get("vulnerabilities", [])}
            pkgs.discard("")
            ecos = {((v.get("package") or {}).get("ecosystem") or "") for v in a.get("vulnerabilities", [])}
            if not (ecos & GHSA_ECO):
                continue  # 只要生态组件类（npm/PyPI/Go/Maven/Actions/…）
            cve = a.get("cve_id") or a.get("ghsa_id")
            link = a.get("html_url") or f"https://github.com/advisories/{a.get('ghsa_id')}"
            # 同一 CVE 的多 RID/多包变体只保留一条
            h = hashlib.sha256(f"ghsa|{cve}".lower().encode()).hexdigest()[:16]
            if h in seen:
                continue
            seen[h] = True
            added_g += 1
            sev = a.get("severity", "")
            cvss = (a.get("cvss") or {}).get("score") or 0
            detail = strip_html(a.get("description") or "")[:400]
            fixed = sorted({str(v.get("first_patched_version")) for v in a.get("vulnerabilities", [])
                            if v.get("first_patched_version")})[:3]
            pkg_clean = sorted({p.split(".Runtime")[0].split(".App.Runtime")[0] for p in pkgs})
            title = f"GHSA/{cve}: {'/'.join(pkg_clean[:2]) or 'component'} {summary0[:70]}"
            body = (f"严重程度 {sev}（CVSS {cvss}）。受影响组件：{', '.join(pkg_clean[:4]) or '见公告'}"
                    f"（生态 {', '.join(sorted(e for e in ecos if e)[:3])}）。"
                    + (f"修复版本：{', '.join(fixed)}。" if fixed else "")
                    + f"摘要：{summary0[:300]} 详情：{detail}")[:800]
            new_items.append({"title": title, "link": link, "date": pub,
                              "summary": strip_html(body), "hash": h, "source": "ghsa",
                              "source_name": "GitHub Advisory", "tags": ["vuln", "supplychain"],
                              "collected_at": datetime.now(CST).isoformat()})
        ghsa_status = "ok"
        results.append({"source": "ghsa", "status": "ok", "count": added_g, "total_feed": len(advs_all)})
        cooldown.pop("ghsa", None)
    except Exception as e:
        ghsa_status = "fail"
        results.append({"source": "ghsa", "status": "fail", "error": str(e)[:200]})

    # RansomLook 结构化补充：近 7 天受害者帖按团伙聚合 → 活跃团伙情报候选 + 当日参考索引
    rl_status = "skip"
    try:
        rl_posts = json.loads(fetch(RL_POSTS_URL.format(days=RL_WINDOW_DAYS), timeout=30).decode("utf-8", "replace")).get("posts", [])
        by_group = {}
        for p in rl_posts:
            g = (p.get("group_name") or "").strip().lower()
            if not g:
                continue
            by_group.setdefault(g, []).append(p)
        added_rl = 0
        rl_index = {}
        for g, posts in sorted(by_group.items(), key=lambda kv: -len(kv[1])):
            victims = sorted({(p.get("post_title") or "").strip() for p in posts if p.get("post_title")})
            latest = max((p.get("discovered") or "" for p in posts), default="")
            rl_index[g] = {"posts_7d": len(posts), "victims": len(victims),
                           "sample": victims[:5], "latest": latest}
            if len(victims) < RL_MIN_VICTIMS:
                continue
            link = RL_GROUP_URL.format(name=urllib.parse.quote(g))
            h = hashlib.sha256(f"ransomlook|{g}|{run_date}".encode()).hexdigest()[:16]
            if h in seen:
                continue
            seen[h] = True
            added_rl += 1
            title = f"RansomLook: 团伙 {g} 7 天内新增 {len(victims)} 名受害者"
            summary = (f"RansomLook 跟踪数据显示，勒索团伙 {g} 近 {RL_WINDOW_DAYS} 天在泄密站发布 {len(posts)} 条帖子，"
                       f"涉及受害者 {len(victims)} 家，最新发现时间 {latest}。"
                       f"受害者样例：{', '.join(victims[:8])}").strip()[:800]
            new_items.append({"title": title, "link": link, "date": latest or run_date,
                              "summary": strip_html(summary), "hash": h, "source": "ransomlook",
                              "source_name": "RansomLook", "tags": ["ransomware"],
                              "collected_at": datetime.now(CST).isoformat()})
        rl_status = "ok"
        ref_file = os.path.join(DATA, "status", f"{run_date}-ransomlook-index.json")
        json.dump({"asof": datetime.now(CST).isoformat(), "window_days": RL_WINDOW_DAYS,
                   "total_posts": len(rl_posts), "groups": rl_index},
                  open(ref_file + ".tmp", "w"), ensure_ascii=False, indent=1)
        os.replace(ref_file + ".tmp", ref_file)
        results.append({"source": "ransomlook", "status": "ok", "count": added_rl, "total_feed": len(rl_posts)})
        cooldown.pop("ransomlook", None)
    except Exception as e:
        rl_status = "fail"
        results.append({"source": "ransomlook", "status": "fail", "error": str(e)[:200]})

    all_items = existing + new_items

    # ---- derp.ca 恶意软件基础设施遥测（Top families 周活聚合，源自 derp.ca/malware 沙箱统计）----
    dtm_status = "fail"
    try:
        dtm_html = fetch("https://www.derp.ca/malware", timeout=25).decode("utf-8", "replace")
        seg = dtm_html[dtm_html.find('data-week-top'):]
        arts = re.findall(r"<article.*?</article>", seg, re.S)[:10]
        fams = []
        for ar in arts:
            fam = re.search(r'href="/([^/"]+)/"[^>]*>([^<]+)</a>', ar)
            pct = re.search(r'([\d.]+)% of week', ar)
            cnt = re.search(r'font-bold tabular-nums[^>]*>([\d,]+)<', ar)
            if fam and cnt:
                fams.append((fam.group(2).strip(), cnt.group(1), pct.group(1) if pct else "?"))
        if fams:
            top = "、".join(f"{n} {c} 样本（{p}%）" for n, c, p in fams[:6])
            h = hashlib.sha256(f"derptelem|{run_date}".encode()).hexdigest()[:16]
            if h not in seen:
                seen[h] = True
                summary = (f"derp.ca 恶意软件基础设施跟踪器（Hatching Triage 沙箱遥测）近 7 天活跃家族 Top{len(fams)}："
                           + top + "。完整榜单见来源页。")
                new_items.append({"title": f"恶意软件家族周活跃遥测：{fams[0][0]} 占比 {fams[0][2]}%",
                                  "link": "https://www.derp.ca/malware", "date": datetime.now(CST).isoformat(),
                                  "summary": summary, "hash": h, "source": "derptelem",
                                  "source_name": "Derp Malware Telemetry", "tags": ["malware", "telemetry"],
                                  "collected_at": datetime.now(CST).isoformat()})
                all_items = existing + new_items
            dtm_status = "ok"
            results.append({"source": "derptelem", "status": "ok", "count": 1, "families": len(fams)})
            cooldown.pop("derptelem", None)
        else:
            results.append({"source": "derptelem", "status": "fail", "error": "no families parsed"})
    except Exception as e:
        results.append({"source": "derptelem", "status": "fail", "error": str(e)[:200]})

    # ---- NVD 近 48h 新发布 CVE 增量网（一手 CVE 数据，兜厂商发布早于媒体报道的窗口）----
    nvd_status = "fail"
    try:
        import datetime as _dt
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        now_u = _dt.datetime.now(_dt.timezone.utc)
        ps, pe = (now_u - _dt.timedelta(hours=48)).strftime(fmt), now_u.strftime(fmt)
        rows, start, total = [], 0, None
        while total is None or (start < total and start < 4000):
            q = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
                 f"?pubStartDate={ps}&pubEndDate={pe}&resultsPerPage=2000&startIndex={start}")
            d = None
            for _try in range(3):
                try:
                    with urllib.request.urlopen(urllib.request.Request(q, headers={"User-Agent": "SID-Daily/1.0"}), timeout=90) as r:
                        d = json.loads(r.read())
                    break
                except Exception:
                    if _try == 2:
                        raise
                    time.sleep(8)
            total = d.get("totalResults", 0); batch = d.get("vulnerabilities", [])
            rows += batch; start += len(batch)
            if not batch or start >= total or start >= 4000:
                break
            time.sleep(15)  # keyless NVD rate limit: 5 req/30s
        SENS = re.compile(r"php|wordpress|wp-|cisco|fortinet|palo alto|ivanti|sonicwall|juniper|vmware|windows|microsoft|exchange|sharepoint|defender|drupal|joomla|magento|opensearch|elastic|nginx|apache|gitlab|jenkins|docker|kubernetes|confluence|atlassian|next\.?js|react|vpn|firewall|router|switch|nas\b|lenovo|d-link|tp-link|hyku|smart tv|smartcam|nuclei|roundcube|zabbix|zoho|sage|commvault|veeam|veeam", re.I)
        picked = []
        for v in rows:
            c = v.get("cve", {})
            m = (c.get("metrics") or {}).get("cvssMetricV31") or (c.get("metrics") or {}).get("cvssMetricV40") or []
            score = max((x.get("cvssData", {}).get("baseScore", 0) or 0) for x in m) if m else 0
            desc = next((x["value"] for x in (c.get("descriptions") or []) if x.get("lang") == "en"), "")
            if not desc:
                continue
            if score >= 7.5 or (score == 0 and SENS.search(c.get("id", "") + " " + desc)):
                picked.append((score, c.get("id", ""), c.get("published", "")[:10], desc))
        picked.sort(key=lambda x: -x[0])
        added_nvd = 0
        for score, cid, pub, desc in picked[:25]:
            h = hashlib.sha256(f"nvd|{cid}".encode()).hexdigest()[:16]
            if h in seen:
                continue
            seen[h] = True; added_nvd += 1
            new_items.append({"title": f"CVE 新收录 {cid}：评分 {score}" if score else f"CVE 新收录 {cid}（评分待定）",
                              "link": f"https://nvd.nist.gov/vuln/detail/{cid}", "date": pub or run_date,
                              "summary": f"NVD 新发布（published {pub}）：{desc[:400]}。评分：{score or '暂无'}。受影响范围以描述文本与厂商通告为准。",
                              "hash": h, "source": "nvd", "source_name": "NVD (NIST)",
                              "tags": ["vuln", "cve"], "collected_at": datetime.now(CST).isoformat()})
        all_items = existing + new_items
        nvd_status = "ok"
        results.append({"source": "nvd", "status": "ok", "count": added_nvd, "window_total": total})
        cooldown.pop("nvd", None)
    except Exception as e:
        results.append({"source": "nvd", "status": "fail", "error": str(e)[:150]})

    # ---- X/Twitter 高信号研究账号增量（每日 1 次 search；凭据缺失则 fail 显示，透明披露）----
    x_status = "fail"
    try:
        import datetime as _dt
        import subprocess as _sp
        X_ACCTS = ["googleprojectzero", "CISAgov", "vxunderground", "malwrhunterteam",
                   "GossiTheDog", "unit42", "splunkresearch", "elasticsecurit",
                   "badrabbit", "GroupIB_", "avast_ars", "treddun", "GeloSchnyder",
                   "craiu", "s4xbyr", "n1zzo", "d1ruba"]
        since = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        q = "(" + " ".join(f"from:{a}" for a in X_ACCTS) + \
            ' (CVE OR PoC OR zero-day OR "in the wild" OR exploited OR KEV OR breach OR ransomware)' + \
            f" -is:retweet lang:en since:{since})"
        r = _sp.run(["xurl", "search", q, "-n", "100"], capture_output=True, text=True, timeout=90)
        out = (r.stdout or "").strip()
        if r.returncode != 0 or not out.startswith("{"):
            raise RuntimeError((r.stderr or out)[:150])
        posts = json.loads(out).get("data") or []
        SIGNAL = re.compile(r"(CVE-\d{4}-\d+|\bPoC\b|zero-?day|exploited|in the wild|KEV|breach)", re.I)
        added_x = 0
        for p in posts:
            txt = (p.get("text") or "").strip()
            if len(txt) < 40 or not SIGNAL.search(txt):
                continue
            tid = str(p.get("id", ""))
            h = hashlib.sha256(f"x|{tid}".encode()).hexdigest()[:16]
            if h in seen:
                continue
            seen[h] = True; added_x += 1
            author = p.get("author_id") or ""
            new_items.append({"title": f"X 快讯 {txt[:60]}",
                              "link": f"https://x.com/i/status/{tid}", "date": datetime.now(CST).isoformat(),
                              "summary": ("X 帖（未交叉证实，以官方来源为准）：" + txt[:400]),
                              "hash": h, "source": "x", "source_name": "X curated researchers",
                              "tags": ["social"], "collected_at": datetime.now(CST).isoformat()})
        all_items = existing + new_items
        x_status = "ok"
        results.append({"source": "x", "status": "ok", "count": added_x, "fetched": len(posts)})
        cooldown.pop("x", None)
    except Exception as e:
        results.append({"source": "x", "status": "fail", "error": str(e)[:150]})

    # ---- abuse.ch 指标遥测（风控纪律：每端点每日仅 1 次查询、无重试、key 不落任何输出）----
    def _abusech_key():
        v = os.environ.get("ABUSECH_KEY", "").strip()
        if v:
            return v
        p = os.path.join(BASE, ".secrets", "abusech.key")
        return open(p).read().strip() if os.path.exists(p) else ""

    def _abusech_post(url, payload, key):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Auth-Key": key, "Content-Type": "application/json",
                                              "User-Agent": "SID-Daily/1.0 (security-intelligence-daily; read-only consumer)"})
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.loads(r.read())

    ak = _abusech_key()

    # ThreatFox：近 24h 新增 IOC 聚合
    tf_status = "fail"
    if ak:
        try:
            d = _abusech_post("https://threatfox-api.abuse.ch/api/v1/", {"query": "get_iocs", "days": 1}, ak)
            rows = d.get("data") or []
            if d.get("query_status") == "ok" and rows:
                import collections as _C
                tt = _C.Counter(r["threat_type"] for r in rows)
                mw = _C.Counter((r.get("malware_printable") or r["malware"]).lower() for r in rows)
                comp = sum(1 for r in rows if str(r.get("is_compromised")) == "true")
                h = hashlib.sha256(f"threatfox|{run_date}".encode()).hexdigest()[:16]
                if h not in seen:
                    seen[h] = True
                    mtop = "、".join(f"{n} {c}" for n, c in mw.most_common(5))
                    ttop = "、".join(f"{n} {c}" for n, c in tt.most_common(3))
                    summary = (f"abuse.ch ThreatFox 近 24 小时新增 IOC {len(rows)} 条（按类型：{ttop}）；"
                               f"活跃家族 Top5：{mtop}；其中 {comp} 条指向被入侵的合法主机（compromised）。"
                               "完整指标以 abuse.ch 数据为准，本文仅汇总分布。")
                    new_items.append({"title": f"ThreatFox 日新增 IOC {len(rows)} 条：{mw.most_common(1)[0][0]} 居首",
                                      "link": "https://threatfox.abuse.ch/browse/", "date": datetime.now(CST).isoformat(),
                                      "summary": summary, "hash": h, "source": "threatfox",
                                      "source_name": "abuse.ch ThreatFox", "tags": ["malware", "botnet", "telemetry"],
                                      "collected_at": datetime.now(CST).isoformat()})
                    all_items = existing + new_items
                tf_status = "ok"
                results.append({"source": "threatfox", "status": "ok", "count": len(rows)})
            else:
                results.append({"source": "threatfox", "status": "fail", "error": str(d.get("query_status", "no data"))})
        except Exception as e:
            results.append({"source": "threatfox", "status": "fail", "error": str(e)[:120]})
    else:
        results.append({"source": "threatfox", "status": "fail", "error": "no auth key"})

    # URLhaus：近 24h 新增恶意 URL（v2 CSV 导出，端点按邮箱确认状态放行）
    uh_status = "fail"
    if ak:
        try:
            req = urllib.request.Request(f"https://urlhaus-api.abuse.ch/v2/files/exports/{ak}/recent.csv",
                                         headers={"User-Agent": "SID-Daily/1.0 (security-intelligence-daily; read-only consumer)"})
            with urllib.request.urlopen(req, timeout=40) as r:
                csv_text = r.read().decode("utf-8", "replace")
            import csv as _csv, io as _io
            rows = list(_csv.DictReader(_io.StringIO(csv_text)))
            if rows:
                import collections as _C
                mal = _C.Counter((x.get("malware") or "unknown").lower() for x in rows)
                act = sum(1 for x in rows if (x.get("url_status") or "").lower() == "online")
                h = hashlib.sha256(f"urlhaus|{run_date}".encode()).hexdigest()[:16]
                if h not in seen:
                    seen[h] = True
                    mtop = "、".join(f"{n} {c}" for n, c in mal.most_common(5))
                    summary = (f"abuse.ch URLhaus 近 24 小时新增恶意 URL {len(rows)} 条（当前仍在线 {act} 条），"
                               f"关联恶意软件 Top5：{mtop}。该类条目多为挂马站/载荷投递/C2 面板，明细以 abuse.ch 数据为准。")
                    new_items.append({"title": f"URLhaus 日增恶意 URL {len(rows)} 条",
                                      "link": "https://urlhaus.abuse.ch/browse/", "date": datetime.now(CST).isoformat(),
                                      "summary": summary, "hash": h, "source": "urlhaus",
                                      "source_name": "abuse.ch URLhaus", "tags": ["malware", "web", "telemetry"],
                                      "collected_at": datetime.now(CST).isoformat()})
                    all_items = existing + new_items
                uh_status = "ok"
                results.append({"source": "urlhaus", "status": "ok", "count": len(rows)})
            else:
                results.append({"source": "urlhaus", "status": "fail", "error": "empty export"})
        except urllib.error.HTTPError as e:
            note = "email not confirmed" if e.code == 403 else f"http {e.code}"
            results.append({"source": "urlhaus", "status": "fail", "error": note})
        except Exception as e:
            results.append({"source": "urlhaus", "status": "fail", "error": str(e)[:120]})
    else:
        results.append({"source": "urlhaus", "status": "fail", "error": "no auth key"})

    tmp = cand_file + ".tmp"
    json.dump({"run_id": run_id, "run_date": run_date, "count": len(all_items), "items": all_items},
              open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, cand_file)
    json.dump(cooldown, open(cooldown_file, "w"), indent=1)

    ok = sum(1 for r in results if r["status"] == "ok")
    ok_feed = sum(1 for r in results if r["status"] == "ok" and r["source"] not in ("kev", "ghsa", "ransomlook", "derptelem", "threatfox", "urlhaus", "nvd", "x"))
    hard_fail = ok == 0
    status = {"run_id": run_id, "run_date": run_date, "stage": "collect",
              "sources_total": len(FEEDS) + 8, "sources_ok": ok_feed + (1 if kev_status == "ok" else 0) + (1 if ghsa_status == "ok" else 0) + (1 if rl_status == "ok" else 0) + (1 if dtm_status == "ok" else 0) + (1 if tf_status == "ok" else 0) + (1 if uh_status == "ok" else 0) + (1 if nvd_status == "ok" else 0) + (1 if x_status == "ok" else 0),
              "sources_fail": [r for r in results if r["status"] not in ("ok",)],
              "new_items": len(new_items), "total_items": len(all_items),
              "finished_at": datetime.now(CST).isoformat()}
    json.dump(status, open(status_file + ".tmp", "w"), ensure_ascii=False, indent=1)
    os.replace(status_file + ".tmp", status_file)

    print(json.dumps(status, ensure_ascii=False))
    sys.exit(2 if hard_fail else 0)

if __name__ == "__main__":
    main()
