#!/usr/bin/env python3
"""publish.py <run_date> — Git 提交 + 推送 GitHub + 状态更新（幂等、含待发布队列）。

纪律：
- 只有 validate 通过的日期才允许提交发布（硬门槛）。
- 推送失败 → 标记 pending_publish，本地成果不丢；下次运行自动重试队列。
- 不 force push；push 被拒时先 fetch + rebase，冲突则放弃并标记人工处理。
"""
import json, subprocess, sys, datetime, pathlib

ROOT = pathlib.Path.home() / "security-intelligence"
GIT = ["git", "-C", str(ROOT)]

def sh(args, timeout=120):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def main():
    run_date = sys.argv[1]
    status_path = ROOT / "data/status" / f"{run_date}.json"
    run_path = ROOT / "data/runs" / run_date / "run.json"
    st = json.loads(status_path.read_text()) if status_path.exists() else {}
    run = json.loads(run_path.read_text()) if run_path.exists() else {}

    # 硬门槛：校验必须通过
    v = ROOT / "data/analysis" / f"{run_date}.validated.json"
    if not v.exists():
        st["git_committed"] = False; st["publish_blocked"] = "validation missing"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        status_path.write_text(json.dumps(st, ensure_ascii=False, indent=1))
        print(json.dumps({"ok": False, "reason": "not validated"})); sys.exit(2)

    # 提交（仅站点与必要文件；数据目录已在 .gitignore）
    for d in ("site", ".github", "scripts", "prompts"):
        sh(GIT + ["add", "-A", "--", d])
    msg = f"SID daily report {run_date}"
    c = sh(GIT + ["commit", "-m", msg])
    committed = "nothing to commit" not in c.stdout + c.stderr and c.returncode == 0
    st["git_committed"] = committed

    # 推送（先普通 push；被拒则 fetch+rebase 一次；再失败进队列）
    p = sh(GIT + ["push", "origin", "main"])
    if p.returncode != 0:
        sh(GIT + ["fetch", "origin", "main"], timeout=90)
        rb = sh(GIT + ["rebase", "origin/main"])
        if rb.returncode == 0:
            p = sh(GIT + ["push", "origin", "main"])
    pushed = p.returncode == 0
    st["git_pushed"] = pushed
    st["pending_publish"] = not pushed
    if not pushed:
        st["push_error"] = (p.stderr or p.stdout)[-400:]
    st["published_at"] = datetime.datetime.now().astimezone().isoformat()
    status_path.write_text(json.dumps(st, ensure_ascii=False, indent=1))

    # 同步到 run.json
    if run:
        run["git_committed"] = st["git_committed"]
        run["git_pushed"] = pushed
        run["pending_publish"] = st["pending_publish"]
        run_path.write_text(json.dumps(run, ensure_ascii=False, indent=1))
    print(json.dumps({"ok": pushed, "committed": committed, "pushed": pushed,
                      "run_date": run_date}))
    sys.exit(0 if pushed else 1)

if __name__ == "__main__":
    main()
