#!/usr/bin/env python3
"""publish.py <run_date> — Git 提交 + 推送 main + 同步 gh-pages 站点（幂等、含待发布队列）。

纪律：
- 只有 validate 通过的日期才允许提交发布（硬门槛）。
- 推送失败 → pending_publish，本地成果不丢；daily.sh 自动重试队列。
- 不 force push；被拒先 fetch+rebase，仍失败则标记人工处理。
- Pages 采用传统 gh-pages 构建（无需 workflow scope）；push 后用 gh api 触发构建。
"""
import json, os, subprocess, sys, datetime, pathlib, shutil

ROOT = pathlib.Path.home() / "security-intelligence"
REPO = "DawnXii/security-intelligence-daily"
GIT = ["git", "-C", str(ROOT)]

def sh(args, timeout=180):
    env = dict(os.environ, https_proxy="http://127.0.0.1:2080",
               http_proxy="http://127.0.0.1:2080")
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)

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

    # 同步站点内容到 gh-pages 并触发传统 Pages 构建（主题+首页+posts 全量）
    pages_pushed = False
    PAGES = ROOT / "pages"
    if pushed and PAGES.exists():
        for sub in ("_posts", "_layouts"):
            shutil.copytree(ROOT / "site" / sub, PAGES / sub, dirs_exist_ok=True)
        for f in ("index.md", "_config.yml"):
            src = ROOT / "site" / f
            if src.exists():
                shutil.copy2(src, PAGES / f)
        sh(["git", "-C", str(PAGES), "add", "-A"])
        pc = sh(["git", "-C", str(PAGES), "commit", "-m", f"site update {run_date}"])
        nothing = "nothing to commit" in (pc.stdout + pc.stderr)
        pp = sh(["git", "-C", str(PAGES), "push",
                 f"https://github.com/{REPO}.git", "gh-pages:gh-pages"])
        pages_pushed = nothing or pp.returncode == 0
        if pages_pushed and not nothing:
            subprocess.run(["gh", "api", "-X", "POST",
                            f"repos/{REPO}/pages/builds", "--jq", ".status"],
                           capture_output=True, text=True, timeout=60,
                           env=dict(os.environ,
                                    https_proxy="http://127.0.0.1:2080",
                                    http_proxy="http://127.0.0.1:2080"))
    st["pages_pushed"] = pages_pushed
    st["published_at"] = datetime.datetime.now().astimezone().isoformat()
    status_path.write_text(json.dumps(st, ensure_ascii=False, indent=1))

    if run:
        run["git_committed"] = committed
        run["git_pushed"] = pushed
        run["pages_pushed"] = pages_pushed
        run["pending_publish"] = st["pending_publish"]
        run_path.write_text(json.dumps(run, ensure_ascii=False, indent=1))
    print(json.dumps({"ok": pushed and pages_pushed, "committed": committed,
                      "pushed": pushed, "pages_pushed": pages_pushed,
                      "run_date": run_date}))
    sys.exit(0 if (pushed and pages_pushed) else 1)

if __name__ == "__main__":
    main()
