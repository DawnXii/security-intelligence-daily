#!/usr/bin/env python3
"""SID build — 从校验通过的分析结果生成站点 Markdown 与运行记录。
输入: data/analysis/<date>.json (已通过 validate) + data/status/<date>.json
输出: site/_posts/<date>.md, data/runs/<date>/run.json
状态分级：analysis_done / saved_local / git_committed / site_built / site_deployed 分开记录。"""
import json, os, sys
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA, SITE = os.path.join(BASE, "data"), os.path.join(BASE, "site")
CST = timezone(timedelta(hours=8))
CATS = {"vuln": "漏洞与在野利用", "supplychain": "供应链/CI-CD", "ttp": "攻击战术与恶意软件",
        "phishing": "钓鱼与社工", "incident": "重大事件", "crypto-infra": "区块链基础设施"}

def main():
    run_date = sys.argv[1] if len(sys.argv) > 1 else datetime.now(CST).strftime("%Y-%m-%d")
    ana_path = os.path.join(DATA, "analysis", f"{run_date}.json")
    val_path = os.path.join(DATA, "status", f"{run_date}-validate.json")
    col_path = os.path.join(DATA, "status", f"{run_date}.json")
    if not os.path.exists(ana_path):
        print(json.dumps({"error": f"missing {ana_path}"})); sys.exit(2)
    if not os.path.exists(val_path) or not json.load(open(val_path)).get("ok"):
        # 纪律：未通过校验的分析不得发布
        print(json.dumps({"error": "validation not passed; refuse to build"})); sys.exit(3)

    analysis = json.load(open(ana_path))
    items = [a for a in analysis if a.get("include")]
    items.sort(key=lambda a: -a.get("score", 0))
    col = json.load(open(col_path)) if os.path.exists(col_path) else {}

    lines = [f"# 安全情报日报 · {run_date}", ""]
    if items:
        top = max(items, key=lambda a: a.get("score", 0))
        lines += [f"**今日焦点**：{top['title_zh']}", ""]
    for cat in ("vuln", "supplychain", "crypto-infra", "ttp", "phishing", "incident"):
        sel = [a for a in items if a.get("category") == cat]
        if not sel:
            continue
        lines += [f"## {CATS[cat]}", ""]
        for a in sel:
            ev = [e for e in a.get("evidence", []) if str(e).startswith("http")]
            link = ev[0] if ev else ""
            lines += [
                f"### {a['title_zh']}",
                f"评分 {a.get('score','?')} · 置信度 {a.get('confidence','?')}",
                "",
                a.get("summary_zh", ""), "",
                f"**影响**：{a.get('impact','')}", "",
                f"**建议**：{a.get('action','')}", "",
            ]
            if link:
                lines += [f"来源：{link}", ""]
    if not items:
        lines += ["今日无达到发布标准的条目（宁缺毋滥）。", ""]

    fails = col.get("sources_fail", [])
    if fails:
        lines += ["> ⚠️ 覆盖不足披露：部分来源本次采集失败，内容可能不完整。", ""]

    fm = f"""---
layout: post
title: "安全情报日报 {run_date}"
date: {run_date}
---

"""
    os.makedirs(os.path.join(SITE, "_posts"), exist_ok=True)
    post = os.path.join(SITE, "_posts", f"{run_date}-report.md")
    tmp = post + ".tmp"
    open(tmp, "w").write(fm + "\n".join(lines))
    os.replace(tmp, post)

    run_log = {"run_id": f"{run_date}-{int(datetime.now(CST).timestamp())}",
               "machine": "tencentbj-1", "role": "primary",
               "run_date": run_date,
               "prompt_version": "analyze-v1.0",
               "sources_total": col.get("sources_total"), "sources_ok": col.get("sources_ok"),
               "sources_fail_n": len(fails),
               "collected": col.get("total_items"), "published_items": len(items),
               "analysis_done": True, "saved_local": True,
               "git_committed": False, "site_built": False, "site_deployed": False,
               "needs_human": bool(fails) or len(items) == 0,
               "finished_at": datetime.now(CST).isoformat()}
    rdir = os.path.join(DATA, "runs", run_date); os.makedirs(rdir, exist_ok=True)
    json.dump(run_log, open(os.path.join(rdir, "run.json"), "w"), ensure_ascii=False, indent=1)
    print(json.dumps(run_log, ensure_ascii=False))

if __name__ == "__main__":
    main()
