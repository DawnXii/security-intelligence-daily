#!/usr/bin/env python3
"""SID build — 从校验通过的分析结果生成站点 Markdown 与运行记录。
输入: data/analysis/<date>.json (已通过 validate) + data/status/<date>.json
输出: site/_posts/<date>.md, data/runs/<date>/run.json
状态分级：analysis_done / saved_local / git_committed / site_built / site_deployed 分开记录。"""
import collections, json, os, sys, zlib, re
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA, SITE = os.path.join(BASE, "data"), os.path.join(BASE, "site")
CST = timezone(timedelta(hours=8))
CATS = {"vuln": "漏洞与在野利用", "supplychain": "供应链 / CI-CD", "ransomware": "勒索软件与数据泄露",
        "malware": "恶意软件与僵尸网络", "ttp": "攻击战术与技术", "phishing": "钓鱼与社工",
        "incident": "重大安全事件", "crypto-infra": "区块链基础设施"}


def build_iocs_page(run_date):
    """Standalone Indicators page: last 7 days of collected IOCs, filter/copy/download."""
    import glob as _g
    from html import escape as esc
    from datetime import timedelta
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from collect import _ioc_tags
    days = [(datetime.strptime(run_date, "%Y-%m-%d") - timedelta(n)).strftime("%Y-%m-%d") for n in range(7)]
    merged, seen_i = [], set()
    per_day_cap = {"threatfox": 300, "urlhaus": 300, "openphish": 300}
    for d in days:
        day_rows = []
        for f in sorted(_g.glob(os.path.join(DATA, "iocs", f"{d}-*.json"))):
            src = f.split("-")[-1].replace(".json", "")
            try:
                rs = json.load(open(f))
            except Exception:
                continue
            rs.sort(key=lambda r: -(r.get('c') or 0))
            day_rows += rs[: per_day_cap.get(src, 300)]
        for r in day_rows:
            i = (r.get("i") or "").strip()
            if i and i not in seen_i:
                seen_i.add(i)
                z = r.get("z") or ""
                f_ = (r.get("f") or "").lower()
                tt_ = (r.get("tt") or "").lower()
                arch_ = r.get("arch") or []
                os_ = (r.get("os") or "").lower()
                if "tt" not in r:  # 旧落盘格式兼容
                    k_ = (r.get("k") or "")
                    if z == "threatfox":
                        tt_ = k_.lower()
                    elif z == "urlhaus":
                        tt_ = f_
                        ff, arch_, oo = _ioc_tags(k_)
                        f_ = ff.lower()
                        os_ = oo.lower()
                    elif z == "openphish":
                        tt_ = "phishing"
                        f_ = ""
                merged.append({"d": d[5:], "i": i, "t": r.get("t") or "", "f": f_,
                               "tt": tt_, "arch": arch_, "os": os_,
                               "c": r.get("c") or "", "z": z})
    if not merged:
        return 0
    fams = collections.Counter(r['f'].lower() for r in merged if r['f'])
    types = sorted({r['t'] for r in merged if r['t']})
    srcs = sorted({r['z'] for r in merged if r['z']})
    dlist = sorted({r['d'] for r in merged}, reverse=True)
    def chip(group, v, lab, on=False):
        return f'<button class="ichip{" on" if on else ""}" data-k="{group}" data-v="{esc(str(v))}">{esc(str(lab))}</button>'
    tp_chips = chip("tp", "all", "全部类型", True) + "".join(chip("tp", t, {"ip:port": "IP", "sha256_hash": "SHA256", "url": "URL", "domain": "DOMAIN"}.get(t, t)) for t in types)
    fm_chips = chip("fm", "all", "全部", True) + "".join(chip("fm", f, f) for f, _ in fams.most_common(12))
    tts = collections.Counter(r['tt'] for r in merged if r['tt'])
    ars = collections.Counter(a for r in merged for a in (r['arch'] or []))
    oss = collections.Counter(r['os'] for r in merged if r['os'])
    tt_chips = chip("tt", "all", "全部", True) + "".join(chip("tt", x, x) for x, _ in tts.most_common(8))
    ar_chips = chip("ar", "all", "全部", True) + "".join(chip("ar", x, x) for x, _ in ars.most_common(8))
    os_chips = chip("os", "all", "全部", True) + "".join(chip("os", x, x) for x, _ in oss.most_common(6))
    z_chips = chip("z", "all", "全部", True) + "".join(chip("z", z, z) for z in srcs)
    d_chips = chip("d", "all", "近7天", True) + "".join(chip("d", x, x) for x in dlist)
    data_json = json.dumps(merged, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\u002f")
    page = "---\nlayout: default\n---\n" + open(os.path.join(BASE, "templates", "iocpage.html"), encoding="utf-8").read()
    page = (page.replace("__N__", str(len(merged))).replace("__TP__", tp_chips)
            .replace("__D__", d_chips).replace("__FM__", fm_chips).replace("__Z__", z_chips)
            .replace("__TT__", tt_chips).replace("__AR__", ar_chips).replace("__OS__", os_chips)
            .replace("__DATA__", data_json))
    od = os.path.join(SITE, "iocs")
    os.makedirs(od, exist_ok=True)
    open(os.path.join(od, "index.html"), "w", encoding="utf-8").write(page)
    return len(merged)


WEEK_CN = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]

def mech_brief(items, run_date):
    """Mechanical situation brief from the day's selected items (no new facts)."""
    n = len(items)
    if not n:
        return None
    wild = sum(1 for a in items if a.get("exploit") == "wild")
    poc = sum(1 for a in items if a.get("exploit") == "poc")
    cats = collections.Counter(a.get("category", "") for a in items)
    top = items[0]
    dist = "、".join(f"{CATS.get(c, c)}×{k}" for c, k in cats.most_common(3))
    parts = [f"入选 {n} 条"]
    if wild:
        parts.append(f"{wild} 条确认在野利用")
    if poc:
        parts.append(f"{poc} 条公开 PoC")
    dek = "今日" + " · ".join(parts) + f"，类别分布：{dist}。"
    chips = [f"{n} 事件", f"在野 {wild}", f"PoC {poc}", f"{len(cats)} 类别", f"顶分 {top.get('score', '—')}"]
    return {"headline": top.get("title_zh", ""), "dek": dek, "chips": chips, "wild": wild, "n": n}


def yaml_q(t):
    return str(t).replace('"', '\\"').replace("\n", " ").replace("\r", " ")


def refresh_home_slot(run_date, brief, ai_brief=None):
    idx = os.path.join(SITE, "index.html")
    src = open(idx, encoding="utf-8").read()
    if "<!--TODAY_START-->" not in src:
        return False
    if brief:
        wd = WEEK_CN[datetime.strptime(run_date, "%Y-%m-%d").weekday()]
        hl = ai_brief["headline"] if ai_brief else brief["headline"]
        body = ai_brief["pulse"] if ai_brief else brief["dek"]
        stats = [(str(brief["n"]), "今日事件"), (str(brief["wild"]), "在野利用"),
                 (str(brief["chips"][3].split()[0]), "类别数"),
                 (str(brief["chips"][4].split()[-1]), "顶分")]
        inner = ('<p class="td-date">' + run_date + f"（{wd}）</p>\n"
                 f'<h1 class="td-h">{hl}</h1>\n'
                 f'<p class="td-pulse">{body}</p>\n'
                 '<div class="td-stats">' + "".join(f'<div class="stat"><b>{v}</b><span>{lab}</span></div>' for v, lab in stats) + '</div>\n'
                 f'<a class="td-cta" href="{{{{ \'/{run_date}/report.html\' | relative_url }}}}">阅读今日完整简报 →</a>')
    else:
        inner = ('<p class="td-date">' + run_date + '</p>\n'
                 '<h1 class="td-h">今日简报生成中</h1>\n'
                 '<p class="td-pulse">每日 04:00 自动聚合分析后更新。</p>')
    out = re.sub(r"<!--TODAY_START-->.*?<!--TODAY_END-->",
                 "<!--TODAY_START-->\n" + inner + "\n<!--TODAY_END-->", src, flags=re.S)
    open(idx, "w", encoding="utf-8").write(out)
    return True

def load_brief(run_date):
    """AI situation brief (optional): {headline, pulse}. Preferred over mech fallback."""
    p = os.path.join(DATA, "analysis", f"{run_date}-brief.json")
    try:
        b = json.load(open(p, encoding="utf-8"))
        if b.get("headline") and b.get("pulse"):
            return b
    except Exception:
        pass
    return None


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

    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    lines = []
    top_score = max((a.get("score", 0) for a in items), default=0)
    cats_present = [c for c in ("vuln", "supplychain", "ransomware", "malware", "ttp", "phishing", "incident", "crypto-infra")
                    if any(a.get("category") == c for a in items)]

    IN_WILD = re.compile(r"已在野|在野利用|主动利用|遭[^，。]{0,10}利用|被[^，。]{0,10}利用|正在利用|利用尝试|零日|列入 KEV|加入 KEV|KEV 目录|exploited", re.I)
    POC = re.compile(r"\bPoC\b|概念验证|proof[- ]of[- ]concept|利用代码已公开", re.I)
    CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
    kev_index = {}
    kev_path = os.path.join(DATA, "status", f"{run_date}-kev-index.json")
    if os.path.exists(kev_path):
        kev_index = json.load(open(kev_path)).get("entries", {})

    EXPLOIT_LABEL = {"wild": ("在野利用", "xw"), "poc": ("PoC 公开", "xp"),
                     "none": ("未公开利用", "xn"), "na": ("", "")}

    def exploit_tag(a):
        ex = a.get("exploit")
        if ex in EXPLOIT_LABEL and EXPLOIT_LABEL[ex][0]:
            lab, cls = EXPLOIT_LABEL[ex]
            # 有 KEV 索引佐证时升级标签
            if ex == "wild":
                for cve in CVE_RE.findall(str(a.get("title_zh", "")) + " " + str(a.get("summary_zh", ""))):
                    if cve in kev_index:
                        return ("在野利用·KEV", "xw")
            return (lab, cls)
        # 旧数据无字段 → 仅漏洞类做机械判定兜底，其他类别不打标签
        if a.get("category") != "vuln":
            return ("", "")
        text = " ".join([a.get("title_zh", ""), a.get("summary_zh", "") or "", a.get("impact", "") or ""])
        for cve in CVE_RE.findall(text):
            if cve in kev_index:
                return ("在野利用·KEV", "xw")
        if IN_WILD.search(text):
            return ("在野利用", "xw")
        if POC.search(text):
            return ("PoC 公开", "xp")
        return ("未公开利用", "xn")

    def risk_tier(a):
        s = a.get("score", 0)
        return "P0" if s >= 85 else ("P1" if s >= 75 else "P2")

    def exploit_chip(a, cat):
        """漏洞类完整利用标签；勒索类只在活跃攻击时打标签。"""
        if cat == "vuln":
            return exploit_tag(a)
        if cat == "ransomware":
            return ("活跃攻击", "xw") if a.get("exploit") == "wild" else ("", "")
        return ("", "")

    # 目录（TOC）：侧边栏导航，按分节分组 + 图例
    if items:
        toc = ['<nav class="toc" id="toc" aria-label="目录">', '<h2>目录 <span>Contents</span></h2>',
               '<p class="legend">利用状态：<b class="xw">在野</b> 已确认/KEV · '
               '<b class="xp">PoC</b> 公开利用代码 · <b class="xn">未公开</b> 暂无情报<br>'
               '优先级：<b class="rp0">P0</b> ≥85 · <b class="rp1">P1</b> 75–84 · <b class="rp2">P2</b> ≤74</p>',
               '<div class="toc-scroll">']
        for cat in cats_present:
            sel = [a for a in items if a.get("category") == cat]
            toc.append(f'<div class="grp"><p class="tg-h"><a href="#sec-{cat}">'
                       f'{CATS[cat]}</a><span class="tg-c">{len(sel)}</span></p><ol>')
            for a in sel:
                aid = f"{cat}-{zlib.crc32(a['title_zh'].encode()) % 100000:05d}"
                a["__aid"] = aid
                focus = "★" if a.get("score", 0) == top_score else ""
                xlab, xcls = exploit_chip(a, cat)
                rt = risk_tier(a)
                toc.append(f'<li><a class="toc-link" href="#{aid}"><span class="tc">{focus or "·"}</span>'
                           f'<span class="tt">{esc(a["title_zh"])}</span>'
                           f'<span class="meta"><i class="rp {rt.lower()}">{rt}</i>'
                           + (f'<i class="xs {xcls}">{xlab}</i>' if xlab else "")
                           + '</span></a></li>')
            toc.append('</ol></div>')
        toc.append('</div></nav>')
        toc.append("")
        lines += toc

    if items:
        lines.append('<div class="feed-col">')  # open feed-col
        fails = col.get("sources_fail", [])
        if fails:
            lines += ['<div class="alert">⚠ 覆盖不足披露：部分来源本次采集失败，内容可能不完整。</div>', ""]
    else:
        fails = col.get("sources_fail", [])

    for ci, cat in enumerate(cats_present, 1):
        sel = [a for a in items if a.get("category") == cat]
        lines += [f'<p class="section-label" id="sec-{cat}"><span class="n">{ci:02d}</span>{CATS[cat]}</p>', ""]
        for a in sel:
            ev = [e for e in a.get("evidence", []) if str(e).startswith("http")]
            link = ev[0] if ev else ""
            is_focus = a.get("score", 0) == top_score and items
            cls = "intel focus" if is_focus else "intel"
            tag = "今日焦点" if is_focus else ""
            aid = a.get("__aid", f"{cat}-x")
            rt = risk_tier(a)
            xchip = ""
            xlab, xcls = exploit_chip(a, cat)
            if xlab:
                xchip = f'<i class="xs {xcls}">{xlab}</i>'
            # v1.4 事实条：cve/cvss/actor/版本/多源计数（字段缺省则整条不渲染）
            facts = ""
            chips, vers = [], []
            if a.get("cve"):
                chips.append(f'<b class="fct fcve">{esc(str(a["cve"]))}</b>')
            if a.get("cvss") not in (None, "", "null"):
                chips.append(f'<b class="fct fcvss">CVSS {esc(str(a["cvss"]))}</b>')
            if a.get("actor") not in (None, "", "null"):
                chips.append(f'<b class="fct factor">{esc(str(a["actor"]))}</b>')
            if isinstance(a.get("outlets"), int) and a["outlets"] > 1:
                chips.append(f'<b class="fct fout">{a["outlets"]} 源报道</b>')
            if a.get("affected") not in (None, "", "null"):
                vers.append(f'<span class="fv"><b>受影响</b> {esc(str(a["affected"]))}</span>')
            if a.get("fixed") not in (None, "", "null"):
                vers.append(f'<span class="fv"><b>修复</b> {esc(str(a["fixed"]))}</span>')
            if chips or vers:
                facts = '<div class="intel-facts">' + ("".join(chips) if chips else "") + \
                        (('<div class="fvers">' + "".join(vers) + '</div>') if vers else "") + '</div>'
            lines += [
                f'<div class="{cls} reveal" id="{aid}">',
                f'<div class="intel-head"><span class="chip">{tag or CATS[cat]}</span>{xchip}'
                f'<span class="score">处置 <i class="rp {rt.lower()}">{rt}</i> · CONF {esc(a.get("confidence","?"))}<i>{esc(a.get("score","?"))}</i></span></div>',
                '<div class="intel-body">',
                f'<h3>{esc(a["title_zh"])}</h3>',
                f'<p class="sum">{esc(a.get("summary_zh",""))}</p>',
                facts,
                '<div class="intel-grid">',
                f'<div class="cell"><b>Impact</b><p>{esc(a.get("impact",""))}</p></div>',
                f'<div class="cell"><b>Action</b><p>{esc(a.get("action",""))}</p></div>',
                '</div>',
                '</div>',
                f'<div class="intel-foot"><span>{esc(run_date)} · SID ANALYSIS</span>'
                + (f'<a href="{link}" target="_blank" rel="noopener">SOURCE ↗</a>' if link else "<span>SOURCE N/A</span>")
                + '</div>',
                '</div>',
                "",
            ]
    if not items:
        lines += ['<div class="empty">今日无达到发布标准的条目，请查阅往期。</div>', ""]

    if items:
        lines.append('</div>')  # /feed-col

    brief = mech_brief(items, run_date)
    ai_brief = load_brief(run_date)
    fm = f"""---
layout: post
title: "安全情报日报 {run_date}"
date: {run_date}
events: {len(items)}
"""
    if brief:
        hl = ai_brief["headline"] if ai_brief else brief["headline"]
        dk = ai_brief["pulse"] if ai_brief else brief["dek"]
        fm += f'headline: "{yaml_q(hl)}"\ndek: "{yaml_q(dk)}"\n'
        fm += "brief_stats: [" + ", ".join(f'"{yaml_q(c)}"' for c in brief["chips"]) + "]\n"
    fm += "---\n\n"""
    os.makedirs(os.path.join(SITE, "_posts"), exist_ok=True)
    # 输出 .html：Jekyll 不跑 markdown 处理器，卡片 HTML 原样渲染（URL 不变 /YYYY/MM/DD/report.html）
    post = os.path.join(SITE, "_posts", f"{run_date}-report.html")
    old_md = os.path.join(SITE, "_posts", f"{run_date}-report.md")
    if os.path.exists(old_md):
        os.remove(old_md)
    tmp = post + ".tmp"
    open(tmp, "w").write(fm + "\n".join(lines))
    os.replace(tmp, post)

    run_log = {"run_id": f"{run_date}-{int(datetime.now(CST).timestamp())}",
               "machine": "tencentbj-1", "role": "primary",
               "run_date": run_date,
               "prompt_version": "analyze-v1.4",
               "sources_total": col.get("sources_total"), "sources_ok": col.get("sources_ok"),
               "sources_fail_n": len(fails),
               "collected": col.get("total_items"), "published_items": len(items),
               "analysis_done": True, "saved_local": True,
               "git_committed": False, "site_built": False, "site_deployed": False,
               "needs_human": bool(fails) or len(items) == 0,
               "finished_at": datetime.now(CST).isoformat()}
    rdir = os.path.join(DATA, "runs", run_date); os.makedirs(rdir, exist_ok=True)
    json.dump(run_log, open(os.path.join(rdir, "run.json"), "w"), ensure_ascii=False, indent=1)
    run_log["ioc_page_rows"] = build_iocs_page(run_date)
    run_log["home_slot"] = refresh_home_slot(run_date, brief, ai_brief)
    print(json.dumps(run_log, ensure_ascii=False))

if __name__ == "__main__":
    main()
