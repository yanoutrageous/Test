# M3 图形、标签检索与模板闭环阶段报告

## 结论

M3 于 2026-07-25 达到 `ACCEPTED`，正式基线为
`STATE-M3-YANYAN-REV-002`，可以进入 M4 的独立备份、恢复和活动状态切换门。
M3 只发布派生状态，未迁移、覆盖或切换活动 SQLite；这仍不是 M5 客户交付验收。

REV-001 首次跑通真实流程后，可视检查发现几何 SVG 的一个 `y2` 坐标被写成字面格式
占位符。该候选明确标记为 `SUPERSEDED_NOT_ACCEPTED`。REV-002 修复渲染器，并把几何
线段坐标、函数采样数和统计柱高纳入数据级同源门禁，重新执行真实流程、可视检查和两层
门禁后才接受。

## 已实现

- 几何、函数、统计三类 FigureIR 均通过现有 v1 合同；每类保留原图回退，同时从同一
  FigureIR 生成 SVG 和受控 TikZ；
- SVG 边界拒绝脚本、外链、事件属性、实体、DOCTYPE、活动 CSS、非本地 URL、重复属性
  和超限树；登记的损坏 SVG 被拒绝且没有改变 preferred revision；
- 图形候选具备批准、拒绝、preferred 切换和已批准 revision 回滚；几何辅助线图和建系图
  也通过登记 Copy 进入本地原貌轨道；
- 冻结知识点/方法标签版本、别名、废弃词迁移；24 个真实证据绑定候选中，23 个保持
  approved，1 个解答变化探针变为 stale；无证据方法标签被拒绝；
- 解答变化会同时令绑定标签与旧索引行失效；显式重建只从 approved、非 stale 事实输入
  生成 19 条新鲜索引行；
- 混合检索组合结构化筛选、FTS5 题干列、批准标签和本地确定性向量，返回每条命中的
  分数、片段和原因；支持自然语言筛选、相似题和从结果加入组卷篮；
- 索引不读取解析正文，只使用题干和批准标签，PII 命中数为 0；不下载模型、不保存权重、
  不联网；
- B5 模板只接受固定 token 集、枚举和数值范围，拒绝任意 TeX/标记注入；字体从已有源
  PDF 的内嵌缓冲读取，不绑定本机字体路径；
- 模板 visual regression 检查页型、锚点（最大 1 mm）、溢出、字体内嵌和静默替代。
  合格 REV-002 可激活，4 mm 左移候选被阻止并拒绝；缺字体失败关闭；
- 模板基线更新路由固定返回 403，要求独立 D2 审计，不能借编辑或激活操作偷换基线；
- UJ-020—025 与 UJ-040—045 全部通过本地 Flask 公开路由执行。

## 正式派生状态

- 路径：`data/derived/M3/STATE-M3-YANYAN-REV-002`
- 文件：39 个，其中 manifest 管理制品 38 个
- 总大小：1,294,484 bytes
- tree SHA-256：
  `aa863de6937b625c6fd232ae89e7dc0a499b7f7944a834b9c43651cc2be76958`
- manifest SHA-256：
  `57613118c509335496eee1088ef1ac98f18844f307526a73f0c57e089bcc13d9`
- taxonomy：`TAXONOMY-M3-MATH-V1`
- semantic index：`INDEX-M3-YANYAN-REV-002`
- active template：`TEMPLATE-M3-B5-REV-002`

六个登记 SVG Copy 的有效载荷合计 18,383 bytes。所有正式 JSON 只含项目相对路径或
逻辑 revision ID；源物理路径留在 Git 忽略的本机映射与路径脱敏 Copy provenance 中。

## 检索与模板验收

- 搜索金标 6 例，Hit@3 = 1.0，MRR = 0.833333；
- 索引 19/19 approved 题目，维度 256，权重文件 0 bytes，网络需求为 false；
- approved 标签 23，rejected 1，stale 1；正式过滤从不使用 candidate/rejected/stale；
- `--rebuild-index` 从发布的事实输入重建后 payload SHA-256 仍为
  `bf4c88cef4857273e343cef752e86d300e11db298f6dda179f81c70747e07cbb`；
- 模板页数、B5 页尺寸、主要锚点、边界、字体内嵌和替代均通过；静默字体替代 0；
- 几何、函数、统计 SVG 及通过候选模板共 4 张正式预览已目视确认，无裁切、乱码、错误
  连线或柱高漂移。

这里的“语义向量”是确定性的中文字符/二元组/批准标签哈希特征，不是神经网络 embedding。
该取舍满足本地、离线、可重建和低存储目标，也避免把约 771 MiB 标签参考集复制进仓库。

## 自动验证

- 真实流程 `RUN-20260725-M3-REAL-PIPELINE-R2-175`：PASS；
- 核心门 `RUN-20260725-M3-CORE-R2-176`：79/79；
- 完整阶段门 `RUN-20260725-M3-GATE-R2-178`：504/504；
- inventory `RUN-20260725-M3-INVENTORY-R2-177`：63 个生产源、444 个受控入口、
  18 个分片，unknown/unmigrated/invalid 均为 0；
- 完整门的活动数据库、6,580 项保护树、runtime watcher、句柄围栏、run tree、不可变
  证据、来源见证和进程树全部通过；
- 活动数据库前后均为
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`；
- failure probe 在仅写出 26 个文件、860,422 bytes 时故意中断，缺少 manifest 的 staging
  被发布门拒绝，failure formal target 不存在。

## 空间、耗时与可迁移性

M3 正式状态约 1.23 MiB，六个新 Copy 连 provenance 也只有数十 KiB；没有模型权重、
标签证据集副本或字体副本进入正式状态。真实流程结束时 E 盘可用 97,390,379,008 bytes，
完整门结束后约 99.10 GB（PowerShell 十进制显示）。

日常启动和检索不运行门禁，也不会重新复制来源或重建索引。只有代码/合同变化、显式
`--rebuild-index`、新 Figure/Template revision 或阶段验收才运行对应构建；因此后续正常
使用不会重复本轮约两分钟的完整安全门，也不会反复占用大量 E 盘空间。

阶段收尾把 13 个已被替代的 M2/M3 门禁、inventory preview、故障/组件暂存、R1 证据和
M3 REV-001 候选可恢复地迁到
`${LOCALAPPDATA}/Codex/workspace-relief/yanoutrageous-Test/m3-cleanup-20260725/`：
共 527 个文件、38,336,312 bytes。迁后 13 个源目录均不存在、13 个 relief 目标均存在，
文件数和总字节数匹配；relief 中逐文件 SHA-256 清单的汇总 digest 为
`24f84d7c6b6cb686cd2168fae2e03b5dbf05d12be2c887cbdc792343b81b3bd2`。
最终 M3 176/178、inventory 177、R2 真实流程/索引重建证据和 REV-002 继续留在 E 盘热目录。
整理后 E 盘可用 100,280,741,888 bytes。relief 是可恢复本机缓存，不是异盘灾备。

根路径仍由 `app/project_root.py` 与路径无关 marker 确定；manifest 不含 E 盘、用户名或
父目录。换电脑时重建 `.venv`，复制正式 `data/derived/M3/...REV-002`、M1 数据库版本和
必要 Copy，再按 manifest 复算哈希即可。外部原始 SVG 若需重新构建，必须在新机重新绑定
忽略的逻辑源映射。

## 已知限制与下一步

- 当前验收覆盖真实 19 题和 6 个冻结搜索查询，不等于多年度大题库效果基线；
- 本地哈希向量不是神经模型，不宣称深层语义泛化；
- 当前正式模板闭环只覆盖 B5 代表页，更多页面族须使用新 revision；
- M3 未授权活动库迁移或切换。

下一步 M4 必须在不覆盖当前活动库的前提下，建立客户可理解的备份、恢复、校验、显式
激活与回滚旅程；只有独立恢复演练通过后才能变更 active-state 指针。
