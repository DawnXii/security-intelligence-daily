#!/usr/bin/env bash
# daily.sh <run_date> — SID 确定性环节：采集→预筛→triage；并补推历史 pending 日期。
set -uo pipefail
cd ~/security-intelligence
D="${1:-$(TZ=Asia/Shanghai date +%F)}"

python3 scripts/collect.py || { echo "COLLECT_FAIL"; exit 2; }
python3 scripts/prepare.py "$D" || exit 2
python3 scripts/triage.py "$D" || exit 2

# 补发队列：之前推送失败的日期（已 validated 的）
for f in data/status/*.json; do
  d=$(basename "$f" .json)
  if python3 -c "import json,sys;sys.exit(0 if json.load(open('$f')).get('pending_publish') else 1)" 2>/dev/null; then
    echo "retrying pending publish: $d"
    python3 scripts/publish.py "$d" || true
  fi
done
echo "STAGE_OK $D"
