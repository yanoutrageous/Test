# 初始风险登记册

## 1. 使用规则

- 风险必须绑定事实、触发条件、负责人阶段、缓解措施和验证证据；
- 每个 Slice 开始和结束更新风险；
- 新风险不因“不在计划中”而忽略；
- 风险关闭必须有证据，不能只写“已注意”；
- P0/P1 缺陷与高影响安全风险不能条件关闭；
- 风险变化需同步`RUN_STATE.json`和阶段报告。

等级：可能性 L/M/H；影响 L/M/H/Critical。

## 2. 初始风险

| ID | 风险 | 可能性 | 影响 | 触发/证据 | 缓解与门禁 | 责任阶段 | 当前状态 |
|---|---|---:|---:|---|---|---|---|
| R-001 | 越界写删或灾难性递归删除 | M | Critical | 任意写路径未统一 Guard；历史上用户曾遭遇整机内容误删 | WorkspaceGuard、禁止命令、单写者、manifest、隔离删除、Test 外写入证明 | M0 | Open |
| R-002 | 任意`db_path/output_path/project_root`逃逸 | H | Critical | 现有代码多个入口接受调用者路径 | 封闭入口、统一 Guard、攻击矩阵 | M0 | Open |
| R-003 | Junction/符号链接/ADS/TOCTOU 绕过 | M | Critical | Windows 路径复杂且现有保护不统一 | 逐层 Reparse Point、ADS、父目录二次检查、故障测试 | M0 | Open |
| R-004 | 当前数据库为空，旧报告不可复现 | H | H | 核心业务表为 0 行 | 建立事实基线和可重建种子批次，旧报告只作历史资料 | M0/M1 | Open |
| R-005 | 数据库迁移损坏活动数据 | M | Critical | schema 将大幅版本化 | 一致快照、副本迁移、完整性、staging、回滚 | M0+ | Open |
| R-006 | NEW9 无文本层，无法恢复精确字体/语义 | H | H | 91 页无可提取文本和字体 | 分离视觉/内容真值；整页回归；字体等效声明 | M0/M1 | Open |
| R-007 | 多种页面尺寸被误当成一个模板 | H | H | 176×250、182×257、184×260、A4、A3 共存 | 模板族和版本化 token，分别金标 | M0/M1 | Open |
| R-008 | MathType OLE、WMF、Corel 轮廓兼容失败 | H | H | 多份 DOCX 含大量 OLE/WMF，答题卡无文本层 | 原件保留、规范化派生、代表压力样本、降级轨 | M1 | Open |
| R-009 | 字体缺失、字宽漂移或商业许可不允许分发 | H | H | 方正、汉仪、宋体等混用 | FontManifest、哈希/替代检测、许可门禁、客户自备说明 | M0/M1/M5 | Open |
| R-010 | OCR/裁切/跨页结果看似成功但内容错误 | H | H | 自动识别天然不确定 | 候选状态、原貌对照、人工复核、低置信失败路径 | M1 | Open |
| R-011 | 预计难度与实测 P 含义相反 | M | H | 现有 difficulty 与测量学 P 易混用 | 分字段、明确方向、数据来源和审核 | M0/M1 | Open |
| R-012 | 没有逐题真实用时却伪造时间约束 | H | M | 成绩表主要为整卷用时 | expected_time 人审；observed item time 缺失即留空 | M1/M2 | Open |
| R-013 | 蓝图无解时系统静默放宽硬约束 | M | H | 自动求解常见错误行为 | 硬/软分离、不可行核心、属性测试、UI 缺口报告 | M2 | Open |
| R-014 | 五类文档题号/分值/答案漂移 | M | Critical | 若各输出独立取最新数据会不一致 | 单一 PaperRevision、staging 交叉核对、原子 bundle | M2 | Open |
| R-015 | 学生卷泄漏答案/隐藏元数据 | M | Critical | 文本层、附件、书签、alt text 可泄漏 | 内容投影和多层泄漏扫描、真实 PDF 检查 | M2/M5 | Open |
| R-016 | SVG/TikZ 视觉正确但数学语义错误 | H | H | 现有图形有多次人工修订 | FigureIR、数据/约束检查、人工批准、原图回退 | M3 | Open |
| R-017 | 恶意/非法 SVG 或 TeX 执行主动内容 | M | Critical | 已发现非法 SVG；TeX 可执行外部命令 | 安全解析、禁止外链/脚本/foreignObject/shell escape | M0/M3 | Open |
| R-018 | 自动标签把推测当事实 | H | H | 方法标签依赖解析且语义复杂 | candidate/approved/stale、解析证据、人工审核 | M3 | Open |
| R-019 | 语义搜索质量低或索引过期 | H | M | 模型/语料变更，人工金标尚未建立 | 混合检索、金标 Recall/nDCG、重建索引、stale 管理 | M3 | Open |
| R-020 | 模板编辑器执行任意 TeX/命令 | M | Critical | 若开放源码输入会破坏边界 | 受控 token、静态检查、沙箱编译 | M3 | Open |
| R-021 | 视觉基线被自动更新以掩盖退化 | M | H | 视觉系统常见误用 | 基线更新独立 D2 审计，旧基线不可覆盖 | M3 | Open |
| R-022 | 当前数据库备份只是文件复制，不一致 | H | Critical | WAL 状态下 copy2 不可靠 | SQLite Backup API、完整性、实际恢复 | M4 | Open |
| R-023 | “备份存在”但无法恢复 | H | Critical | 尚无完整恢复产品流程 | staging 恢复、故障注入、恢复后用户旅程 | M4 | Open |
| R-024 | 同盘备份无法抵御整个 D 盘故障 | H | H | 当前唯一写根限制 | 对客户准确披露；异盘灾备需用户另行授权 | M4/M5 | Accepted limitation |
| R-025 | 批量渲染/备份耗尽磁盘并诱发危险清理 | M | Critical | 参考资产约 2.6 GiB，派生可能倍增 | 小样估算、minimum_free、停止而不自动清理 | All | Open |
| R-026 | CDN/遥测接触成绩和题库 | H | Critical | 现有 HTML 引用远程脚本 | 静态依赖本地化、CSP、断网验收、网络审计 | M0/M3/M5 | Open |
| R-027 | PII 进入日志、embedding、Git 或客户包 | H | Critical | XLSX 含姓名、学号、IP、QQ | restricted Copy、匿名化、扫描、禁止列表 | All | Open |
| R-028 | 原卷、解析、字体许可阻止客户分发 | M | H | 本地使用不等于可再分发 | 许可清单、local-use-only、客户自备、发布阻断 | M0/M5 | Open |
| R-029 | 新依赖来源/许可/安装越权 | M | H | 长任务可能不断补工具 | 依赖审计、项目内优先、官方锁版、系统高风险暂停 | All | Open |
| R-030 | 长任务死循环、重复覆盖或状态丢失 | M | H | 多阶段、长渲染和上下文续作 | 幂等键、状态机、两次重试、检查点、RUN_STATE | All | Open |
| R-031 | 多代理同时写导致冲突/数据损坏 | M | H | 共享工作区 | 单写者锁，子代理只读或不重叠，主执行者合并 | All | Open |
| R-032 | 测试很多但用户流程不可用 | H | Critical | 用户此前项目曾只写约 50 个测试但未跑通 | 需求追踪、真实 UI 旅程、fresh-user、客户验收脚本 | All/M5 | Open |
| R-033 | Git 混入 Base、PII、密钥或大文件 | M | Critical | 当前 Base 有未跟踪资产 | 显式暂存、staged 扫描、禁止`add -A`、Draft PR | All | Open |
| R-034 | Git 远端分叉诱发强推/历史改写 | M | H | 长期分支可能漂移 | fetch 审计、普通 push、分叉硬停止、revert 回滚 | All | Open |
| R-035 | GitHub CLI 未认证阻塞首次规划 push | H | M | 历史审计曾失败；2026-07-11 已确认认证、仓库身份和 ADMIN 权限 | 不绕过认证；使用授权 origin；本仓库采用 GitHub noreply 作者身份 | PRE-M0 | Closed |
| R-036 | 客户包只在开发者环境可运行 | M | Critical | 隐式 PATH、字体、缓存和联网依赖 | portable root、依赖锁、fresh-user、断网冷启动 | M5 | Open |
| R-037 | 实机打印未授权却宣称已验证 | M | M | 打印池可能写系统目录 | PDF/打印预览门禁；实机打印需另行授权和记录 | M5 | Open |
| R-038 | 把静态扫描/测试实验室误称为 hostile-code OS sandbox | M | Critical | Python audit hook、watcher 和句柄围栏不能约束任意恶意 native/反射代码 | 受信任源码审查、固定 bootstrap、Job Object、watcher/fence、禁止未审阅 native 测试；准确披露边界 | M0/All | Open |
| R-039 | 把调用者提供的 pair evidence 当成实际字节证明 | M | Critical | S2 `PairEvidence`仍只绑定声明；若未来入口绕过 S3-E live lease 会重新引入风险 | S3-E Test-local writer 已在 exact reservation 内从 live handles 重算、mutation 前再验、target 全树复算并以 operation chain 对账；生产 writer继续断开，S3-H 冻结后再评估关闭 | M0 | Open |
| R-040 | 把内存 audit sink 当成可恢复的持久审计 | M | Critical | S2 sink 仅用于候选失败关闭，进程退出即丢失 | S3 追加式持久 ledger、批次 receipt、启动校验、故障注入和恢复演练 | M0 | Open |

## 3. 风险关闭要求

关闭风险必须记录：

- 修复/接受决定；
- 对应 commit、测试和真实旅程；
- 恢复/回滚证据；
- 剩余风险；
- 关闭人和日期。

`Accepted limitation`必须出现在客户已知限制中；不得用“接受”隐藏实际缺陷。
