#!/usr/bin/env python3
"""SID history — 跨天去重记忆（确定性层）。

data/history/pushed.json: 每条已发布（pages_deployed）条目的指纹：
  {date, link_norm, cves:[...], digest, source}
规则：
- annotate（prepare 调用）：候选与 **早于 run_date** 的历史比对。
  * 同 link 且 summary digest 相同 = 上游原文无变化 → 直接剔除（suppressed）。
  * link 或 CVE 命中但内容有变/新文章 → 保留并附 previously_reported:[{date,title}]，交分析 AI 判断是否有实质进展。
- record（publish 成功后调用）：把当日 include 条目写入历史；同日期重写 = 幂等。
匹配键：norm(link) 与 CVE 集合（标题/正文提取，大写归一）。
"""
import hashlib, json, os, re, sys
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
HIST = os.path.join(DATA, "history", "pushed.json")
CST = timezone(timedelta(hours=8))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

def norm_link(u: str) -> str:
    u = (u or "").strip().lower()
    # KEV 目录页：条目身份在 ?selected_cve= 参数里，必须保留，否则所有 KEV 项共享一个 link
    m = re.search(r"[?&]selected_cve=(cve-\d{4}-\d{4,7})", u, re.I)
    u = re.sub(r"[?#].*$", "", u)
    u = re.sub(r"^https?://", "", u)
    u = u.rstrip("/")
    u = re.sub(r"^www\.", "", u)
    if m and "known-exploited-vulnerabilities-catalog" in u:
        u = u + "?cve=" + m.group(1).upper()
    return u

def digest(text: str) -> str:
    t = re.sub(r"\s+", " ", (text or "")).strip()
    return hashlib.sha1(t.encode("utf-8", "replace")).hexdigest()[:16]

def load():
    if os.path.exists(HIST):
        return json.load(open(HIST))
    return {"updated_at": None, "entries": []}

def save(h):
    h["updated_at"] = datetime.now(CST).isoformat()
    os.makedirs(os.path.dirname(HIST), exist_ok=True)
    tmp = HIST + ".tmp"
    json.dump(h, open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, HIST)

def _cves_of(item):
    return sorted({c.upper() for c in CVE_RE.findall(
        (item.get("title") or "") + " " + (item.get("summary") or ""))})

def annotate(run_date, items):
    """就地过滤/标注 items（prepare 调用）。返回 (kept, suppressed_count)。
    items 元素需含 link/summary/title；命中变化时写入 it['previously_reported']。"""
    h = load()
    prior = [e for e in h["entries"] if e["date"] < run_date]
    by_link = {}
    by_cve = {}
    for e in prior:
        by_link.setdefault(e["link_norm"], []).append(e)
        for c in e.get("cves", []):
            by_cve.setdefault(c, []).append(e)
    kept, dropped = [], 0
    for it in items:
        ln = norm_link(it.get("link", ""))
        cves = set(_cves_of(it))
        hits = list(by_link.get(ln, []))
        for c in cves:
            hits += by_cve.get(c, [])
        if not hits:
            kept.append(it); continue
        # 同链接且摘要未变 = 上游无新内容，确定性剔除
        dg = digest(it.get("summary", ""))
        same_content = [e for e in hits if e["link_norm"] == ln and e.get("digest") == dg]
        if same_content and len(same_content) == len(hits):
            dropped += 1
            continue
        uniq = {}
        for e in hits:
            uniq[(e["date"], e["title"])] = None
        it["previously_reported"] = sorted(
            [{"date": d, "title": t} for (d, t) in uniq], key=lambda x: x["date"])
        kept.append(it)
    return kept, dropped

def record(run_date):
    """把 run_date 当日 include 条目写入历史（同日重写，幂等）。"""
    va = os.path.join(DATA, "analysis", f"{run_date}.validated.json")
    ai = os.path.join(DATA, "candidates", run_date, "analysis-input.json")
    if not (os.path.exists(va) and os.path.exists(ai)):
        print(json.dumps({"history": "skip", "reason": "missing inputs"})); return
    src = {it["hash"]: it for it in json.load(open(ai))["items"]}
    ana = json.load(open(va))
    items = ana if isinstance(ana, list) else ana.get("items", ana.get("analysis", []))
    h = load()
    h["entries"] = [e for e in h["entries"] if e["date"] != run_date]
    added = 0
    for it in items:
        if not it.get("include"):
            continue
        base = src.get(it.get("hash"))
        if base is None:
            continue
        h["entries"].append({
            "date": run_date, "link_norm": norm_link(base.get("link", "")),
            "cves": _cves_of(base), "digest": digest(base.get("summary", "")),
            "source": base.get("source", ""), "title": base.get("title", "")[:160]})
        added += 1
    save(h)
    print(json.dumps({"history": "recorded", "date": run_date, "added": added,
                      "total": len(h["entries"])}, ensure_ascii=False))

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: history.py record <date> | stats")
    cmd = sys.argv[1]
    if cmd == "record":
        record(sys.argv[2] if len(sys.argv) > 2 else datetime.now(CST).strftime("%Y-%m-%d"))
    elif cmd == "stats":
        h = load()
        dates = {}
        for e in h["entries"]:
            dates[e["date"]] = dates.get(e["date"], 0) + 1
        print(json.dumps({"entries": len(h["entries"]), "by_date": dict(sorted(dates.items()))},
                         ensure_ascii=False))
    else:
        sys.exit(f"unknown cmd {cmd}")

if __name__ == "__main__":
    main()
