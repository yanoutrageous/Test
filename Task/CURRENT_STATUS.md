# 当前状态

更新时间：2026-07-11 23:20 +08:00

## 长期执行状态

- 计划版本：1.0.1
- 当前阶段：M0 入场审计完成，M0 尚未验收
- 当前切片：`M0-S3-D operation lease/job staging/tree evidence`实现、inventory、定向门禁和独立审计已通过，正在形成并发布内部检查点；S3 与 M0 总门仍未通过
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
- 生产静态 inventory V8 覆盖`app/`和`scripts/`的 48 个源文件、459 个副作用入口和 19 个分片；`UNKNOWN=0`、未授权安全内核构造 0，但 459 项仍全部`UNMIGRATED_BLOCKED`
- Policy V7 digest 为`8df50ded...e4d88`；生产 boundary 固定根且`writer_available=false`，`m0_exit_allowed=false`
- S3-D 定向回归`RUN-20260711-M0-S3D-022`为`185 passed`；综合 writer/static 回归`RUN-20260711-M0-S3D-WRITER-014`为`502 passed, 1 deselected`，JUnit failure/error/skip 均为 0；唯一 deselected 仍是 WinError 1314 的实际 symlink 权限门禁
- WRITER-014 保护树前后均 86,351 条、运行时变更 0、句柄围栏 86,351 个；活动 SQLite 前后 SHA-256 相同；source inputs unchanged
- Scanner V8 使用`UTF8_LF_V1`规范化并加入 job runtime 私有构造与 exact canary；inventory payload 为`8834f86a...d1cca4`，生产 writer 与`m0_exit_allowed`均为 false

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
- M0-S3-D 冻结候选证据为`RUN-20260711-M0-S3D-022`与`RUN-20260711-M0-S3D-WRITER-014`；实现、V8 inventory、ADR 与报告已通过独立`NO P0 / NO P1`审计，当前待显式提交、普通 push 和远端核验
- 长期草稿 PR：`https://github.com/yanoutrageous/Test/pull/2`（base=`main`，head=`agent/m0-m5-local-v1`）
- 除 GitHub CLI 外，本轮未安装 OCR、TeX、模型、字体或其他项目依赖

## 当前长期执行的首批动作

1. M0-S3-D operation context pin、固定 job staging、不可变 contract、多维预算和 live double-pass tree observation 已通过门禁，下一动作是显式提交、普通 push 和远端核验；
2. 随后执行 M0-S3-E—H 的 operation ledger、pair reservation 内 publish、Copy、quarantine 和受控外部进程；当前仍保持生产 writer 断开；
3. 完成迁移/SQLite Backup API、领域 IR、金标、M0 真实流程和独立审计，形成 M0 验收、checkpoint tag 与交接后停止本任务；不得在本任务中进入 M1。

## 已知限制与未决项

- 精确字体许可尚未审计：不阻塞金标测量，但阻塞“字体完全一比一”的正式声明。
- 当前备份只能位于 Test 内：不具备异盘灾备能力，不能对客户宣称可抵御整个 D 盘故障。
- 固定生产 boundary、Policy V7、Test-only 句柄 writer、audit ledger 和 S3-D job/tree runtime 已通过，但生产 writer 仍断开；459 个入口尚未迁移，在完整 pair/Copy/数据库门禁完成前不得处理真实资料。
- S2 `PairEvidence`仍是调用者声明；S3-D live tree lease已从实际 handles 重算 manifest、源树、条目数和拓扑，但摘要不是 mutation authority，S3-E 必须在 exact live lease 和持久 operation ledger 内完成 mutation 前后重验。
- audit key revision 位于 Test 内、Git 忽略的本地明文存储；不能抵御已取得 Test 读取权的恶意本机用户；没有外部 witness 时也不能证明完整账本尾部未被一致回滚。
- Test-only writer 的 spent-ticket 记忆和诊断缓存已固定上限；ReFS/128-bit File ID 高位非零兼容、硬件断电语义和业务 operation recovery 仍未声明通过。
- 安全测试实验室针对受信任、已审阅的仓库测试代码，不是任意 hostile native-code 的 OS sandbox。
- 普通用户态 Windows 目录 handle/oplock 不能冻结 child namespace；S3-D 只声明双遍稳定性观察，不声明 hostile-writer 原子快照。S3-E 必须以 pre/post rescan 与`IN_DOUBT`/seal处理剩余窗口。
- 本机普通账户不能创建实际目录 symlink（WinError 1314）；不自动启用开发者模式或提升权限，该门禁保持 IN_PROGRESS。
