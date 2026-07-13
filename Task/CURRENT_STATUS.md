# 当前状态

更新时间：2026-07-13 22:00 +08:00

## 长期执行状态

- 计划版本：1.0.1
- 当前阶段：M0 入场审计完成，M0 尚未验收
- 当前切片：按用户要求在最近安全断点暂停`M0-S3-F synthetic Copy + dual ledgers`；实现候选及失败修复保留在未提交工作区，尚未运行修复后的核心/launcher/组合安全回归；S3 与 M0 总门仍未通过
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
- RUN-009 保护树前后均 93,762 条、运行时变更 0、句柄围栏 93,762 个；活动 SQLite 前后 SHA-256 相同。旧结果字段`source inputs unchanged`只是该次已监测保护集的起止/运行时证据，不声称监控整机或未登记外部源
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

- 暂停时间：2026-07-13 22:00:02 +08:00；原因：用户要求在最近可恢复安全断点暂停；
- 暂停记录前本地与 origin head 均为`01cfbb12012040b03e82745e828cf3ff85dc1bf1`；没有活动 safe launcher 或 Git 进程，没有进行中的业务 mutation，没有处理真实业务数据；
- 活动 SQLite SHA-256 仍为`1505BF05BD8E385EADA30642110596363C561C330DA02A40A497072064AD1C94`，D 盘可用空间为 588,403,019,776 bytes；生产 writer 仍断开，460 个入口仍全部`UNMIGRATED_BLOCKED`；
- 暂停记录前工作区为 36 个 tracked modified 与 7 个 untracked S3-F 文件。不得清理、覆盖或丢弃这些候选；完整恢复入口见`Task/reports/M0/M0-S3-F-pause-20260713.md`；
- `RUN-20260713-M0-S3F-INTEGRATION-020`为修复前证据：167 项中 150 通过、17 失败，但数据库、保护树、运行时 watcher、句柄围栏、合成源 witness、进程树和 immutable evidence 均保持安全。17 项对应修复已经完成编译/导入预检，尚未以 safe launcher 复跑；
- V4 Copy plan/opaque TXN 独立复审为 P0=0/P1=0；异常边界代码复审为 P0=0/P1=0。其威胁模型文档 P1 已修正文案，但因本次暂停，最终文档复审尚未收口；
- 已确认`RUN-20260713-M0-S3F-INTEGRATION-021`、`RUN-20260713-M0-S3F-LAUNCHER-022`、`RUN-20260713-M0-S3F-COMBINED-023`均未创建。恢复后先复核文档边界，再依次使用这些唯一编号运行；不得复用 RUN-020，不得提前进入 S3-G。

## 已知限制与未决项

- 精确字体许可尚未审计：不阻塞金标测量，但阻塞“字体完全一比一”的正式声明。
- 当前备份只能位于 Test 内：不具备异盘灾备能力，不能对客户宣称可抵御整个 D 盘故障。
- 固定生产 boundary、Policy V7、Test-only 句柄 writer、audit/operation ledger 和 S3-E pair publish/recovery 已通过本地组合门，但生产 writer 仍断开；460 个入口尚未迁移，在 Copy/quarantine/数据库等后续门禁完成前不得处理真实资料。
- S2 `PairEvidence`仍只是候选声明；S3-E 实际 mutation 只在 exact `_ReservedPairLease`和 live observed lease 内执行，声明或 detached 摘要都不能授权 rename。
- audit key revision 位于 Test 内、Git 忽略的本地明文存储；不能抵御已取得 Test 读取权的恶意本机用户；没有外部 witness 时也不能证明完整账本尾部未被一致回滚。
- Test-only writer 的 spent-ticket 记忆和诊断缓存已固定上限；ReFS/128-bit File ID 高位非零兼容、硬件断电语义和业务 operation recovery 仍未声明通过。
- 安全测试实验室针对受信任、已审阅的仓库测试代码，不是 hostile native-code 或 hostile same-process Python 反射/monkeypatch 的 OS/语言沙箱；S3-F 异常 vault 只收窄经密封公开 boundary 的正常调用泄漏面，不能隔离能够绕过 boundary 的恶意同进程代码。
- 普通用户态 Windows 目录 handle/oplock 不能冻结 child namespace；S3-E 已使用最后检查、内核 no-replace、target full rescan 与`IN_DOUBT`/seal，但仍不声明 hostile-writer 原子快照。
- 本机普通账户不能创建实际目录 symlink（WinError 1314）；不自动启用开发者模式或提升权限，该门禁保持 IN_PROGRESS。
