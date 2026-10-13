#!/usr/bin/env python3
"""SID prepare — 对 raw.json 规则预筛并分批，供分析 agent 使用。
关键词预筛只做减法（去明显无关），最终取舍由分析阶段决定。
输出: data/candidates/<date>/batch-N.json（每批 ≤40 条，含全量未过筛项的 excluded 计数）。"""
import json, os, re, sys
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
CST = timezone(timedelta(hours=8))
BATCH_SIZE = 40

# 命中任一关键词即保留（宽口径；agent 再做语义精选）
KEEP = re.compile(
    r"vulner|exploit|breach|ransom|supply.?chain|malware|botnet|phish|credential|zero.?day|"
    r"cve-\d|backdoor|cryptomin|worm|trojan|rootkit|typosquat|npm|pypi|docker|image|"
    r"kubernetes|k8s|cloud|azure|aws|gcp|ci/cd|github action|gitlab|jenkins|devops|"
    r"blockchain|crypto exchange|wallet|validator|rpc|node operat|private key|"
    r"identity|active directory|okta|vpn|firewall|router|switch|firmware|ics|ot security|"
    r"attribution|apt|cisa|nsa|fbi|interpol|sanctions.*cyber",
    re.I,
)
# 明显无关（营销/招聘/活动通告）直接排除
DROP = re.compile(r"webinar|job (listing|opening)|hiring|sponsor|conference recap|award|giveaway", re.I)

def main():
    run_date = sys.argv[1] if len(sys.argv) > 1 else datetime.now(CST).strftime("%Y-%m-%d")
    raw_file = os.path.join(DATA, "candidates", run_date, "raw.json")
    if not os.path.exists(raw_file):
        print(json.dumps({"error": f"missing {raw_file}"})); sys.exit(2)
    items = json.load(open(raw_file))["items"]

    kept, dropped = [], 0
    for it in items:
        text = it["title"] + " " + it["summary"]
        if DROP.search(text) and not KEEP.search(it["title"]):
            dropped += 1
            continue
        if KEEP.search(text) or it["source"] in ("cisa", "netsec", "trailofbits", "ghsec"):
            kept.append(it)
        else:
            dropped += 1

    outdir = os.path.join(DATA, "candidates", run_date)
    batches = [kept[i:i+BATCH_SIZE] for i in range(0, len(kept), BATCH_SIZE)] or [[]]
    # 幂等：重写全部批次文件，并清理旧批次
    for f in os.listdir(outdir):
        if re.match(r"batch-\d+\.json", f):
            os.remove(os.path.join(outdir, f))
    meta = {"run_date": run_date, "total_raw": len(items), "kept": len(kept),
            "dropped": dropped, "batches": len(batches),
            "prepared_at": datetime.now(CST).isoformat()}
    for n, b in enumerate(batches, 1):
        json.dump({**meta, "batch": n, "items": b},
                  open(os.path.join(outdir, f"batch-{n}.json"), "w"), ensure_ascii=False, indent=1)
    print(json.dumps(meta, ensure_ascii=False))

if __name__ == "__main__":
    main()
