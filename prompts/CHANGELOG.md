# Prompt CHANGELOG

## analyze v1.4 — 2026-10-20（stable）
- 变更：参考 derp.ca 简报形态做内容富化，风格不变。① 叙事三层强化：summary_zh=The story（披露主体/关键数字/时间线/利用与修复状态），impact=Why it matters（暴露人群/已确认后果），action=处置清单（版本号/工具名取自来源）。② 新增结构化事实字段（全部可选，缺省不渲染）：cve、cvss、actor（归因标签）、affected/fixed（受影响/修复版本）、outlets（当日清单内同 CVE/同主体条目数）。③ validate 扩展反幻觉核验：cve 格式+逐字溯源；cvss 数字须在原文；actor/affected/fixed 内所有含数字英文实体 token 必须逐字来自来源文本；outlets int 1–60。④ build 卡片新增 intel-facts 事实条（CVE 黑底琥珀 chip/CVSS 琥珀/归因红/N 源报道虚线；版本行小字）。负向测试：伪造 CVE-2026-99999 被 rc=3 拦截。
- 顺修：TOC 图例 `&lt;` 在 Pages 构建被二次转义显示为字面 "&lt;75" → 改纯文本 ≤74（build.py，历史 bug）。
- 回归（2026-10-19 重建实跑）：6/6 卡片带事实条，validate 0 违规，live 渲染结构正确、无转义泄漏；旧字段缺省时卡片与 v1.3 渲染完全一致（向后兼容）。

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
## v1.5 (2026-10-22) — 每日态势简报字段
- 动因：用户反馈首页固定文案与"拿单一事件当头条"的现代性不足；简报应为编辑部式当日综合态势。
- 变更：items 契约不变；新增独立文件 data/analysis/<D>-brief.json {headline,pulse}，由分析 AI 当日撰写。
- 校验：validate.check_brief 机器回算 入选数/在野数、CVE 与数字逐字溯源，越界即拦截。
- 渲染：build 优先 brief，缺省机械聚合 fallback（历史日期与未配置日自动可用）。
- 风险：pulse 为综合叙述，纪律靠 check_brief+提示词双层约束；未过校验不发布。
## v1.6 (2026-10-22) — AI <k> 风险主体标记
- 动因：机器正则追不上开放词表实体；用户要求统一高亮视觉并扩到首页 TODAY 卡。
- 变更：字段内 <k>实体</k> 标记契约；build rich() 统一渲染（AI 标记 + 机器兜底 CVE/分数字/状态词，单一 .hl 样式）；validate.check_ktags 校验配对/长度/数量/禁入字段。
- 风险：标签滥用破坏排版——数量与长度上限+禁入字段双层闸。

## analyze-v1.7 (stable, 启用 2026-10-28)
- 新增标题自包含可读规则：禁二字压缩动词造成的施受歧义（用户点名"低权限可升 Proxy Admin"理解性差）；英文角色名要带中文锚点。
- 当日实例已人工修正：LiteLLM CVE-2026-114612 标题改为"LiteLLM 低权限用户可伪造凭据提权至 Proxy Admin"。
- 同时 build.py 修复：卡片标题字段改走 rich()（此前裸 esc 渲染致 `<k>` 以 &lt;k&gt; 形式在浏览器显示为字面标签——10-28 报告页泄漏根因）。

## analyze-v1.6 (stable, 启用 2026-10-26)
- 本版含两个增量：<k> 风险主体标记规则（先前已入 stable/v1.6）+ qu-ai-wei 中文简报去 AI 味复检（本次合并追加）。
- 动因：用户要求优化 AI 日报文风；英文 humanizer 已在库但对中文无效，收编 qu-ai-wei (MIT, upstream SHA 1d32e80) 为 magpie skill，v1.6 增补节将其在 brief 环节接入流水线。
- 约束：事实 token 冻结、check_brief 机械闸优先、禁假人味。
- 首跑（手动）：2026-10-26 日报 pulse/headline 重写，validate 通过（含 sabotage 反证：改计数即 FAIL），已发布线上。
- 教训：candidates/v1.6 与 stable/v1.6 命名撞车（前者基于旧 candidates/v1.5，缺 stable 已有的 <k> 节）——合并修复；未来增量必须先 diff stable 现状。
# analyze v1.8 (2026-10-30): headline 点名纪律+HL_BAN 机械闸（修「边界设备与代码托管平台同时挨打」抽象口水标题事故）；10-30 日报 headline 已重写重发布验证
# analyze v1.9 (2026-10-30): headline 纯事实句——删编辑归纳尾巴（用户否决「成在野共性」）；HL_BAN 扩展 共性/缩影/趋势/信号/收敛 等。同日补源 coindesk+theblock（42→44，币安 5.8B 被盗漏报根治），triage crypto 事件权重 8→12+金额信号 10，币安卡 score92 手工补分析并重发布上线。verify_sid MINQ 字符串断言修复（2} → 2,）。
# sources wave2 (2026-10-30): +cymkend/csecguru/decrypt/cointel (44→48)，Polymarket 前端投毒补卡上线；triage 加平台名/金额/供应链状态三档权重
