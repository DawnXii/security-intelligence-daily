#!/usr/bin/env python3
"""SID triage — 从 prepare 批次中启发式排序，选出当日分析集（≤40 条），摘要截断。
单一输入文件，供分析 agent 在**一个会话内顺序完成**（本机 delegate/并发不可用，架构按此设计）。"""
import glob, json, os, re, sys
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
CST = timezone(timedelta(hours=8))
MAX_ITEMS = 40

SRC_W = {"cisa": 8, "ghsec": 6, "trailofbits": 5, "cloudflare": 4, "aws": 4, "google": 4,
         "bleo": 3, "thn": 3, "secaff": 3, "register": 3, "krebs": 3, "isc": 2, "chainalysis": 2, "netsec": 2,
         "kev": 9, "ghsa": 5, "rwlive": 4, "ransomlook": 6, "derp": 6, "derptelem": 8}
PAT = [
    (r"cve-\d{4}-\d+|exploit(ed|ing)?|in the wild|active(ly)? exploit|zero.?day", 10, "vuln"),
    (r"remote code execution|\brce\b|unauthenticated|privilege escalation|code execution|memory corruption|use-after-free|sandbox escape|vm escape", 9, "vuln"),
    (r"cvss (?:v[234]? )?(?:10|9\.\d|8\.\d)|maximum.severity|critical vulnerability|cvss 10", 8, "vuln"),
    (r"patches|advisory|vulnerab|flaw|security update", 4, "vuln"),
    (r"supply.?chain|typosquat|malicious (?:package|dependency|extension|npm|pypi)|backdoor|trojan(ed)? (?:npm|package|library)", 10, "supplychain"),
    (r"ransomware|ransom[- ]?(?:ware|look|attack)|lockbit|blackcat|akira|qilin|alpharoot|cl0p|play group|wicked|empress|sidewinder|leak.s?ite|data leak|double extortion|extortion", 10, "ransomware"),
    (r"malware|botnet|trojan|rootkit|stealer|loader|infostealer|cryptomin|worm|rat\b|malicious (?:app|extension|browser)|c2 server|command.and.control", 8, "malware"),
    (r"ttp|tactics|techniques|att\.ck|mitre att&ck|post[- ]?exploitation|lateral movement|persistence|living off the land|detection (?:evasion|rules)|ioc\b|yara|threat hunt", 7, "ttp"),
    (r"breach|hack(ed|ers|ing)?|attack(er|s|ing)?|compromis|data theft|stolen", 6, "incident"),
    (r"phish|credential|social engineer|mfa bypass|session hijack|oauth", 6, "phishing"),
    (r"blockchain|wallet|validator|rpc|cryptograph|private key|exchange", 6, "crypto-infra"),
    (r"cloud|azure|aws|gcp|kubernetes|docker|container|iam|identity", 4, "infra"),
    (r"cisa|advisory|kevc|fbi|interpol|eu ?police|sanction", 4, "gov"),
]
W = 600  # summary 截断长度，兼顾事实密度与上下文预算

def main():
    run_date = sys.argv[1] if len(sys.argv) > 1 else datetime.now(CST).strftime("%Y-%m-%d")
    files = sorted(glob.glob(os.path.join(DATA, "candidates", run_date, "batch-*.json")))
    if not files:
        print(json.dumps({"error": "no batches"})); sys.exit(2)
    items = []
    for f in files:
        items += json.load(open(f))["items"]

    now = datetime.now(CST)
    scored = []
    for it in items:
        text = it["title"] + " " + it["summary"]
        s = SRC_W.get(it["source"], 1)
        cats = set()
        for pat, w, cat in PAT:
            if re.search(pat, text, re.I):
                s += w; cats.add(cat)
        try:
            d = datetime.fromisoformat(it["date"])
            if (now - d).total_seconds() < 86400 * 3:
                s += 5
        except Exception:
            pass
        scored.append((s, cats, it))
    scored.sort(key=lambda x: -x[0])
    # 来源配额：防止单一来源（如 CISA ICS 批量通告）挤占版面
    CAPS = {"cisa": 8, "kev": 5, "ghsa": 8, "ransomlook": 4, "rwlive": 4}
    MINQ = {"ransomlook": 2}  # 关键新类保底：勒索聚合情报至少进分析集 2 条，保证类别覆盖
    sel, per_src, chosen = [], {}, set()
    def add(s, cats, it):
        chosen.add(it["hash"])
        per_src[it["source"]] = per_src.get(it["source"], 0) + 1
        sel_item = {"hash": it["hash"], "source": it["source"], "source_name": it["source_name"],
                    "title": it["title"], "link": it["link"], "date": it["date"],
                    "summary": it["summary"][:W], "heuristic_score": s,
                    "heuristic_cats": sorted(cats)}
        if it.get("previously_reported"):
            sel_item["previously_reported"] = it["previously_reported"]
        sel.append(sel_item)
    # 先为保底来源预留高分槽位
    for src, need in MINQ.items():
        taken = 0
        for s, cats, it in scored:
            if taken >= need:
                break
            if it["source"] == src and it["hash"] not in chosen:
                add(s, cats, it); taken += 1
    # 其余槽位按分数与配额填充
    for s, cats, it in scored:
        src = it["source"]
        if it["hash"] in chosen:
            continue
        if per_src.get(src, 0) >= CAPS.get(src, MAX_ITEMS):
            continue
        if len(sel) >= MAX_ITEMS:
            break
        add(s, cats, it)
    out = os.path.join(DATA, "candidates", run_date, "analysis-input.json")
    tmp = out + ".tmp"
    json.dump({"run_date": run_date, "triage_from": len(items), "count": len(sel),
               "items": sel, "triaged_at": now.isoformat()}, open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, out)
    print(json.dumps({"out": out, "from": len(items), "selected": len(sel),
                      "min_heuristic": sel[-1]["heuristic_score"] if sel else 0}, ensure_ascii=False))

if __name__ == "__main__":
    main()
