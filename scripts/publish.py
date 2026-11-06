#!/usr/bin/env python3
"""publish.py <run_date> — Git 提交 + 推送 main，由 GitHub Actions 部署 Pages（幂等）。

纪律：
- 只有 validate 通过的日期才允许提交发布（硬门槛）。
- 推送失败 → pending_publish，本地成果不丢；daily.sh 自动重试队列。
- 不 force push；被拒先 fetch+rebase，仍失败则标记人工处理。
- Pages 新版部署：push main 触发 "Deploy GitHub Pages" workflow
  （actions/jekyll-build-pages 构建 site/ + actions/deploy-pages 部署），
  本脚本轮询该 commit 的 run 结果作为发布确认。
"""
import json, os, subprocess, sys, datetime, pathlib, time

ROOT = pathlib.Path.home() / "security-intelligence"
REPO = "DawnXii/security-intelligence-daily"
GIT = ["git", "-C", str(ROOT)]
WF = "Deploy GitHub Pages"

def sh(args, timeout=180):
    env = dict(os.environ, https_proxy="http://127.0.0.1:2080",
               http_proxy="http://127.0.0.1:2080")
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)

def gh_api(args, timeout=60):
    return sh(["gh", "api"] + args, timeout=timeout)

def wait_deploy(sha, max_wait=420):
    """轮询 sha 对应的 workflow run，返回 (conclusion, run_id)。"""
    deadline = time.time() + max_wait
    run_id = None
    while time.time() < deadline:
        r = gh_api([f"repos/{REPO}/actions/workflows",
                    "--jq", ".workflows[] | select(.name==\"%s\") | .id" % WF])
        wid = r.stdout.strip().splitlines()[0] if r.returncode == 0 and r.stdout.strip() else None
        if wid:
            r = gh_api([f"repos/{REPO}/actions/workflows/{wid}/runs",
                        "--jq", "([.workflow_runs[] | select(.head_sha==\"%s\")][0]) | \"\\(.id) \\(.status) \\(.conclusion)\"" % sha])
            if r.returncode == 0 and r.stdout.strip() and r.stdout.strip() != "null null null":
                run_id, status, conclusion = r.stdout.strip().split(" ", 2)
                if status == "completed":
                    return conclusion, run_id
        time.sleep(15)
    return "timeout", run_id

def main():
    run_date = sys.argv[1]
    status_path = ROOT / "data/status" / f"{run_date}.json"
    run_path = ROOT / "data/runs" / run_date / "run.json"
    st = json.loads(status_path.read_text()) if status_path.exists() else {}
    run = json.loads(run_path.read_text()) if run_path.exists() else {}

    # 硬门槛：校验必须通过
    v = ROOT / "data/analysis" / f"{run_date}.validated.json"
    if not v.exists():
        st["git_committed"] = False
        st["publish_blocked"] = "validation missing"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        status_path.write_text(json.dumps(st, ensure_ascii=False, indent=1))
        print(json.dumps({"ok": False, "reason": "not validated"})); sys.exit(2)

    # 提交到 main（site/、prompts/、scripts/；数据目录在 .gitignore）
    for d in ("site", "scripts", "prompts"):
        sh(GIT + ["add", "-A", "--", d])
    c = sh(GIT + ["commit", "-m", f"SID daily report {run_date}"])
    committed = c.returncode == 0 and "nothing to commit" not in (c.stdout + c.stderr)
    st["git_committed"] = committed

    # 推送 main（失败先 rebase 一次，不 force）
    p = sh(GIT + ["push", "origin", "main"])
    if p.returncode != 0:
        sh(GIT + ["fetch", "origin", "main"])
        if sh(GIT + ["rebase", "origin/main"]).returncode == 0:
            p = sh(GIT + ["push", "origin", "main"])
    pushed = p.returncode == 0
    st["git_pushed"] = pushed
    st["pending_publish"] = not pushed
    if not pushed:
        st["push_error"] = (p.stderr or p.stdout)[-400:]

    # 等待 Actions 部署结果（新版 Pages）
    deployed = False
    if pushed:
        head = sh(GIT + ["rev-parse", "HEAD"]).stdout.strip()
        has_new = committed
        if not has_new:
            # 无新提交也确认 HEAD 的最近一次部署结论
            r = gh_api([f"repos/{REPO}/actions/runs?head_sha={head}", "--jq",
                        "[.workflow_runs[] | select(.name==\"%s\")][0] | \"\\(.status) \\(.conclusion)\"" % WF])
            has_new = "completed success" not in (r.stdout or "")
        if has_new:
            conclusion, run_id = wait_deploy(head)
            deployed = conclusion == "success"
            st["deploy_run_id"] = run_id
            st["deploy_conclusion"] = conclusion
        else:
            deployed = True
    st["pages_deployed"] = deployed
    if deployed:
        # 发布成功才落跨天历史（record 幂等：同日重写）
        try:
            sys.path.insert(0, os.path.join(ROOT, "scripts"))
            import history
            history.record(run_date)
        except Exception as exc:  # noqa: BLE001
            print(f"publish: history record FAILED ({exc})", file=sys.stderr)
    st["published_at"] = datetime.datetime.now().astimezone().isoformat()
    status_path.write_text(json.dumps(st, ensure_ascii=False, indent=1))

    if run:
        run["git_committed"] = committed
        run["git_pushed"] = pushed
        run["pages_deployed"] = deployed
        run["pending_publish"] = st["pending_publish"]
        run_path.write_text(json.dumps(run, ensure_ascii=False, indent=1))
    ok = pushed and deployed
    print(json.dumps({"ok": ok, "committed": committed, "pushed": pushed,
                      "pages_deployed": deployed, "run_date": run_date}))
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
