# 当前状态

更新时间：2026-07-13 13:22 +08:00

## 长期执行状态

- 计划版本：1.0.1
- 当前阶段：M0 入场审计完成，M0 尚未验收
- 当前切片：已按用户要求从关机暂停点恢复，继续`M0-S3-F synthetic Copy + dual ledgers`设计冻结与实现；恢复前已核验本地、origin 和 Draft PR #2 head 均为`26fdf8794b9fc90c4ea8702bb9e91877fe4e5600`、工作区干净、无活动 writer、活动 SQLite 哈希不变；S3 与 M0 总门仍未通过
- M0—M5 实现：M0 已开始；M1—M5 未开始
- 本任务有效终点：按用户最新明确要求，仅完成 M0；M0 正式验收、提交、普通 push、checkpoint tag 和交接完成后立即停止，M1 延后到新的用户任务。项目整体 M0—M5 路线图保持不变，本条只限制当前任务执行范围
- 当前禁止：活动数据库迁移、题库导入、OCR、正式排版、批量资产、备份切换和业务文件清理

## Git 状态基线

- 仓库：`https://github.com/yanoutrageous/Test.git`
- 长期集成分支：`agent/m0-m5-local-v1`
- 分支基线：规划分支提交`bfd4d35973974a223f465cd08910f303518a8586`
- `Base/高考题原卷/`为用户本地资产，已由根`.gitignore`保护，明确不属于本次提交范围
- 规划发布范围仅为`.gitignore`与`Task`中的可跟踪规范；`Task/local/`本机路径映射被忽略，禁止提交
- 本次及后续提交必须显式暂存文件，禁止`git add -A`

## 当前数据事实

- 活动 SQLite 已有 25 张表；`source_papers`、`questions`、`question_assets`、结构化内容、复核事件和导入批次当前均为 0 条
- 历史质量报告中的题量不能作为当前可复现基线
- 目标 NEW9 PDF 已在 Test 内，但其正文无可提取文字层；视觉回归必须包含整页像素/锚点检查
- 活动 SQLite SHA-256 为`1505bf05...ad1c94`，`integrity_check=ok`、外键违规 0、`user_version=0`，19 个业务表均为 0 行
- 历史“1123 题/阶段 14”报告不是当前可复现事实
- 生产静态 inventory V9 覆盖`app/`和`scripts/`的 49 个源文件、460 个副作用入口和 19 个分片；`UNKNOWN=0`、未授权安全内核构造 0，但 460 项仍全部`UNMIGRATED_BLOCKED`
- Policy V7 digest 为`8df50ded...e4d88`；生产 boundary 固定根且`writer_available=false`，`m0_exit_allowed=false`
- S3-E 最终核心回归`RUN-20260712-M0-S3E-016`为`30 passed`，launcher 门`RUN-20260712-M0-S3E-LAUNCHER-018`为`72 passed`，组合门`RUN-20260712-M0-S3E-COMBINED-019`为`399 passed`；JUnit failure/error/skip 均为 0
- RUN-009 保护树前后均 93,762 条、运行时变更 0、句柄围栏 93,762 个；活动 SQLite 前后 SHA-256 相同；source inputs unchanged
- Scanner V9 使用`UTF8_LF_V1`规范化并加入 operation ledger、pair reservation、最终 revalidation、跨账本 ancestor 和目录 publish/recovery 私有调用 exact canary；inventory payload 为`339a14b1...d3a6fee`，生产 writer 与`m0_exit_allowed`均为 false

## 工具与发布状态

- GitHub CLI 2.96.0 已根据用户本轮一次性授权，以用户范围通过 Windows Package Manager 安装
- 安装位置：`%LOCALAPPDATA%\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe`
- GitHub CLI 已认证为授权仓库管理员账号；`gh repo view`确认远端、默认分支和权限正确
- 本仓库 Git 作者邮箱已改为 GitHub noreply 地址，未修改全局 Git 配置，避免公开提交暴露个人邮箱
- 规划提交范围、隐私、二进制、大文件、忽略规则和远端同名分支已通过独立只读审计
- 规划契约提交`522393d`及状态提交`bfd4d35`已普通 push 到`agent/long-run-execution-spec`
- 规划草稿 PR：`https://github.com/yanoutrageous/Test/pull/1`
- 长期集成分支首个 M0 审计提交为`f3ab652`，已 push
- M0-S1 候选核心、安全测试启动器与证据提交为`2dc2984`，已 push；远端 SHA 与本地一致
- M0-S2 冻结证据为`RUN-20260711-M0-S2-EOL-020-FINAL`；实现和证据已作为`e82eb507414f9dd7b27282d8496e048016bca4ee`显式提交并普通 push，远端分支和 Draft PR #2 head 已核验一致
- M0-S3-B 冻结证据为`RUN-20260711-M0-S3-WRITER-009`与`RUN-20260711-M0-S3-B-FULL-011`；实现、inventory、ADR 与报告已作为`793fb88055b19ea2de53395a07c4be523eeb5f73`显式提交并普通 push，远端分支和 Draft PR #2 head 已核验一致
- M0-S3-C 冻结证据为`RUN-20260711-M0-S3C-WRITER-016-FINAL`与`RUN-20260711-M0-S3C-FULL-017-FINAL`；实现、inventory、ADR 与报告已作为`a999f32718b0ed22d2683585c7d079a0c9bbb749`显式提交并普通 push，origin、远端 refs 与 Draft PR #2 head 已核验一致
- M0-S3-D 冻结证据为`RUN-20260711-M0-S3D-022`与`RUN-20260711-M0-S3D-WRITER-014`；实现、V8 inventory、ADR 与报告已作为`1b5b9bd9cddcdc472f92146748b6f8ab4f53b6f4`显式提交并普通 push，origin、远端 refs 与 Draft PR #2 head 已核验一致
- 长期草稿 PR：`https://github.com/yanoutrageous/Test/pull/2`（base=`main`，head=`agent/m0-m5-local-v1`）
- 除 GitHub CLI 外，本轮未安装 OCR、TeX、模型、字体或其他项目依赖

## 当前长期执行的首批动作

1. M0-S3-D operation context pin、固定 job staging、不可变 contract、多维预算和 live double-pass tree observation 已作为`1b5b9bd`完成显式提交、普通 push 与远端核验；
2. M0-S3-E exact reservation、独立 operation chain、source-root no-replace publish、target rescan 与只追加恢复真值表已通过本地组合门和独立暂存审计，并作为`39586568a405124417d105d8e876d25ec94e06e6`完成普通 push；当前进入 S3-F 合成 Copy 与双 ledger；
3. 完成迁移/SQLite Backup API、领域 IR、金标、M0 真实流程和独立审计，形成 M0 验收、checkpoint tag 与交接后停止本任务；不得在本任务中进入 M1。

## 当前暂停检查点

- 暂停时间：2026-07-12 02:16:57 +08:00；原因：用户准备关闭电脑；
- 暂停记录前已核验 head：`f6a94eb075735bf2c1de5eefff148bb0b068d4b1`；暂停记录写入前工作区干净，本地与 origin 一致；最终暂停提交以恢复时本地/origin/PR 三方一致的当前 head 为准；
- 没有进行中的业务 mutation，没有处理真实业务数据；生产 writer 仍断开，460 个入口仍全部`UNMIGRATED_BLOCKED`；
- 已于 2026-07-13 13:22:55 +08:00 完成恢复核验：本地、origin、Draft PR #2 均为`26fdf8794b9fc90c4ea8702bb9e91877fe4e5600`，工作区干净，旧 writer PID 不存在，活动 SQLite SHA-256 未变化；现从 S3-F 设计冻结继续，不重复 S3-E，不进入 M1。

## 已知限制与未决项

- 精确字体许可尚未审计：不阻塞金标测量，但阻塞“字体完全一比一”的正式声明。
- 当前备份只能位于 Test 内：不具备异盘灾备能力，不能对客户宣称可抵御整个 D 盘故障。
- 固定生产 boundary、Policy V7、Test-only 句柄 writer、audit/operation ledger 和 S3-E pair publish/recovery 已通过本地组合门，但生产 writer 仍断开；460 个入口尚未迁移，在 Copy/quarantine/数据库等后续门禁完成前不得处理真实资料。
- S2 `PairEvidence`仍只是候选声明；S3-E 实际 mutation 只在 exact `_ReservedPairLease`和 live observed lease 内执行，声明或 detached 摘要都不能授权 rename。
- audit key revision 位于 Test 内、Git 忽略的本地明文存储；不能抵御已取得 Test 读取权的恶意本机用户；没有外部 witness 时也不能证明完整账本尾部未被一致回滚。
- Test-only writer 的 spent-ticket 记忆和诊断缓存已固定上限；ReFS/128-bit File ID 高位非零兼容、硬件断电语义和业务 operation recovery 仍未声明通过。
- 安全测试实验室针对受信任、已审阅的仓库测试代码，不是任意 hostile native-code 的 OS sandbox。
- 普通用户态 Windows 目录 handle/oplock 不能冻结 child namespace；S3-E 已使用最后检查、内核 no-replace、target full rescan 与`IN_DOUBT`/seal，但仍不声明 hostile-writer 原子快照。
- 本机普通账户不能创建实际目录 symlink（WinError 1314）；不自动启用开发者模式或提升权限，该门禁保持 IN_PROGRESS。
