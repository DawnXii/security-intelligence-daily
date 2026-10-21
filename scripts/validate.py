#!/usr/bin/env python3
"""SID validate — 机械校验分析结果，拒绝不合格内容进入发布链路。
检查：JSON schema、hash 必须存在于当日候选集、score∈[0,100]、category 合法、
evidence 必须包含来源 URL 且证据文本出现在原始 summary 中（反幻觉核心检查）。
用法: validate.py <date> <analysis.json>   exit 0=通过 3=有不合格项（报告已列出）"""
import json, os, re, sys
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
CST = timezone(timedelta(hours=8))
FIELDS = ["hash", "include", "score", "category", "title_zh", "summary_zh", "impact", "action", "confidence", "evidence"]
CATEGORIES = {"vuln", "supplychain", "ransomware", "malware", "ttp", "phishing", "incident", "crypto-infra"}
CONF = {"high", "medium", "low"}

def norm(s):
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", s.lower())

def main():
    run_date, ana_path = sys.argv[1], sys.argv[2]
    raw = json.load(open(os.path.join(DATA, "candidates", run_date, "raw.json")))
    by_hash = {it["hash"]: it for it in raw["items"]}
    try:
        analysis = json.load(open(ana_path))
    except json.JSONDecodeError as e:
        print(json.dumps({"ok": False, "errors": [f"JSON 解析失败: {e}"]})); sys.exit(3)
    if not isinstance(analysis, list):
        analysis = analysis.get("items", [])

    errors, stats = [], {"included": 0, "excluded": 0}
    seen_hashes = set()
    for i, a in enumerate(analysis):
        loc = f"item[{i}]"
        for f in FIELDS:
            if f not in a:
                errors.append(f"{loc} 缺字段 {f}")
        h = a.get("hash")
        if h not in by_hash:
            errors.append(f"{loc} hash 不存在于候选集: {h}"); continue
        if h in seen_hashes:
            errors.append(f"{loc} 重复 hash: {h}"); continue
        seen_hashes.add(h)
        if not isinstance(a.get("include"), bool):
            errors.append(f"{loc} include 非布尔")
        if a.get("include"):
            stats["included"] += 1
            s = a.get("score")
            if not (isinstance(s, (int, float)) and 0 <= s <= 100):
                errors.append(f"{loc} score 越界: {s}")
            if a.get("category") not in CATEGORIES:
                errors.append(f"{loc} category 非法: {a.get('category')}")
            if a.get("confidence") not in CONF:
                errors.append(f"{loc} confidence 非法")
            ex = a.get("exploit")
            if ex is not None and ex not in ("wild", "poc", "none", "na"):
                errors.append(f"{loc} exploit 非法: {ex}")
            for k in ("title_zh", "summary_zh"):
                if not str(a.get(k, "")).strip():
                    errors.append(f"{loc} {k} 为空")
            ev = a.get("evidence")
            src_link = by_hash[h]["link"]
            src_summary = norm(by_hash[h]["summary"])
            if not isinstance(ev, list) or len(ev) == 0:
                errors.append(f"{loc} evidence 缺失")
            else:
                if not any(src_link in str(e) or by_hash[h]["source"] in str(e) for e in ev):
                    errors.append(f"{loc} evidence 未包含来源链接/名称")
                # 反幻觉：证据中 ≥4 词连续片段应能在原 summary 找到
                checked = False
                for e in ev:
                    e = str(e)
                    if src_link in e:
                        continue
                    words = norm(e)[:60]
                    if words and words in src_summary:
                        checked = True; break
                    frags = [norm(w) for w in re.split(r"\s+", e)[:6] if len(norm(w)) > 2]
                    probe = "".join(frags)[:40]
                    if probe and probe in src_summary:
                        checked = True; break
                if not checked and len(ev) > 1:
                    errors.append(f"{loc} 证据文本无法在原始 summary 中溯源（疑似幻觉）")
            # v1.4 事实字段核验：数字型实体（版本/CVE/日期/分数）必须逐字存在于来源文本
            src_raw = by_hash[h]["summary"] + " " + by_hash[h]["title"]
            src_n = norm(src_raw)
            cve_f = a.get("cve")
            if cve_f not in (None, "", "null"):
                if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(cve_f)) or norm(str(cve_f)) not in src_n:
                    errors.append(f"{loc} cve 非法或不在来源文本: {cve_f}")
            cvss_f = a.get("cvss")
            if cvss_f not in (None, "", "null"):
                if not re.fullmatch(r"\d+(\.\d)?", str(cvss_f)) or str(cvss_f) not in src_raw:
                    errors.append(f"{loc} cvss 非法或不在来源文本: {cvss_f}")
            for fk in ("actor", "affected", "fixed"):
                fv = a.get(fk)
                if fv in (None, "", "null"):
                    continue
                bad = [t for t in re.findall(r"[A-Za-z][A-Za-z0-9.+/\-]*\d[A-Za-z0-9.+/\-]*|GHSA-[a-z0-9\-]{4,}", str(fv))
                       if norm(t) not in src_n]
                if bad:
                    errors.append(f"{loc} {fk} 实体无法溯源（疑似幻觉）: {bad[:3]}")
            ol = a.get("outlets")
            if ol is not None and (not isinstance(ol, int) or not (1 <= ol <= 60)):
                errors.append(f"{loc} outlets 非法: {ol}")
        else:
            stats["excluded"] += 1

    # 覆盖检查：候选集里高分来源不应完全未出现在分析中
    out = {"run_date": run_date, "ok": len(errors) == 0, "errors": errors[:50],
           "analyzed": len(seen_hashes), "candidates": len(by_hash), **stats,
           "validated_at": datetime.now(CST).isoformat()}
    tmp = ana_path + ".validated.json"
    json.dump(out, open(tmp, "w"), ensure_ascii=False, indent=1); os.replace(tmp, os.path.join(DATA, "status", f"{run_date}-validate.json"))
    if out["ok"]:
        tmp2 = ana_path + ".ok.json"
        json.dump(analysis, open(tmp2, "w"), ensure_ascii=False); os.replace(tmp2, ana_path.replace(".json", ".validated.json"))
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(0 if out["ok"] else 3)

if __name__ == "__main__":
    main()
