# Prompt CHANGELOG

## analyze v1.3 — 2026-10-19（stable）
- 变更：新增「跨天查重」规则节。候选条目由 scripts/history.py 标注 previously_reported（同链接或同 CVE 命中已发布历史）；带标注条目默认 include=false，仅实质进展（利用状态变化/首次入 KEV/补丁发布/勒索聚合受害者数 +≥15 或距上次 ≥7 天/执法打击）可跟进，且 summary_zh 第一句须写明跟进日期与增量。上游原文未变的重复报道在 prepare 阶段已被确定性剔除（history_dropped），不进分析集。
- 动因：10-14~19 实测同事件连推（n0n 三连推、Cisco 邮件网关三连推、包管理器研究两连推），用户要求"无新进展不重复推送"。
- 回归（2026-10-19 全量 40 条实跑）：入选 10→6；validate 0 违规；被剔 8 条均为 REPEAT 无进展（n0n +3、CISA 中方通告第三次、PAN-OS/Atlassian/TanStack/KEDA 等）；保留跟进类 1 条（BeyondTrust 首入 KEV）；新事件 4 条正常入选。verify_sid 全绿。
- 风险：进展判断仍在分析 AI 语义层，标注只给事实不给结论；history 匹配基于 link/CVE，跨源转载（新 URL 且无 CVE）依赖当日语义去重兜底。

## analyze v1.2 — 2026-10-14（stable）
- 变更：
  1. category 枚举从 6 类细化为 8 类：vuln | supplychain | ransomware | malware | ttp | phishing | incident | crypto-infra。拆分原 ttp"攻击战术与恶意软件"混合类，勒索软件独立成类（配合新增 ransomware.live / RansomLook 信源）。
  2. 新增 title_zh 简化规则：≤22 个汉字、无标点堆砌、只留核心事实主体，细节放 summary_zh。动因：侧边目录导航栏需要短标题才不溢出。
  3. 分类判定细则补充：勒索团伙攻击/受害者公布→ransomware；恶意样本/僵尸网络/C2→malware；技术剖析与检测→ttp；纯受害报道/诉讼/趋势→incident。
- 回归（2026-10-14 全量 40 条实跑）：入选 10 条，validate 0 违规；分类分布 vuln 6 / supplychain 1 / ransomware 1 / malware 1 / ttp 1；exploit 5 wild / 3 na / 2 none。标题全部 ≤22 汉字。勒索类经 triage MINQ 保底进入分析集。基线 v1.1 = 10 选中、exploit 8 wild/1 none/1 na（条目集合随新信源变化属预期）。
- 风险：历史日期分析 JSON 仍是 6 类旧枚举，build.py CATS 保留旧键显示（缺失类不会渲染分区，无崩溃路径）。

## analyze v1.0 — 2026-10-13（stable）
- 创建原因：初始稳定版，覆盖关注优先级、评分规则、JSON 输出契约与反虚构纪律。
- 基线：无历史版本。
- 验收：首次每日运行人工复核入选条目质量；不满足标准时先出 v1.1 candidate，不直接改 stable。

## analyze v1.1 — 2026-10-14（stable）
- 变更：输出契约新增 exploit 字段（wild|poc|none|na，全类别必填），判定只依据条目原文。
- 动因：站点需要按利用状态（在野/PoC/未公开）分级展示，机械关键词判定不可靠。
- 回归：2026-10-13 测试集（40 条）对比 v1.0 基线——入选集合/评分/排序完全一致，仅新增 exploit 字段；validate 0 违规。记录于 prompts/tests/。
- 风险：分析会话输出多一个字段，token 略增；旧日期数据无该字段时 build 用机械判定兜底（仅漏洞类打标签）。
