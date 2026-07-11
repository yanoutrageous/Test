# 当前状态

更新时间：2026-07-11 18:09 +08:00

## 长期执行状态

- 计划版本：1.0.1
- 当前阶段：M0 入场审计完成，M0 尚未验收
- 当前切片：`M0-S3-B Test-only handle kernel`候选已通过全量回归，待提交/push 检查点；S3 与 M0 门禁均未通过
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
- 生产静态 inventory 覆盖`app/`和`scripts/`的 46 个源文件、442 个副作用入口和 18 个分片；`UNKNOWN=0`，但 442 项仍全部`UNMIGRATED_BLOCKED`
- Policy V6 digest 为`315a036a...0110b4`；生产 boundary 固定根且`writer_available=false`，`m0_exit_allowed=false`
- S3-B 定向回归为`314 passed, 1 deselected`；全量回归 RUN-011 为`402 passed, 1 deselected`，JUnit failure/error/skip 均为 0；唯一 deselected 仍是 WinError 1314 的实际 symlink 权限门禁
- RUN-011 保护树前后均 37,767 条、运行时变更 0、句柄围栏 37,767 个；活动 SQLite 前后 SHA-256 相同
- Scanner V6 使用`UTF8_LF_V1`规范化并扩展 native/dynamic capability provenance；根`.gitattributes`继续固定源码、测试和 Task 证据为 LF

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
- M0-S3-B 冻结候选为`RUN-20260711-M0-S3-WRITER-009`与`RUN-20260711-M0-S3-B-FULL-011`；402 项全量回归期间数据库、保护树、运行时 watcher、不可变证据和进程树均干净，当前待显式提交和普通 push
- 长期草稿 PR：`https://github.com/yanoutrageous/Test/pull/2`（base=`main`，head=`agent/m0-m5-local-v1`）
- 除 GitHub CLI 外，本轮未安装 OCR、TeX、模型、字体或其他项目依赖

## 当前长期执行的首批动作

1. M0-S3-B Test-only 句柄 writer、同句柄写后核验和 V6 inventory 已通过，完成显式提交、普通 push 与远端核验后形成内部检查点；
2. M0-S3-C—H 建立不可变 segment ledger、key revision、实际 tree evidence、原子 publish、Copy、quarantine 和受控外部进程；当前仍保持生产 writer 断开；
3. 完成迁移/SQLite Backup API、领域 IR、金标、M0 真实流程和独立审计，形成 M0 验收、checkpoint tag 与交接后停止本任务；不得在本任务中进入 M1。

## 已知限制与未决项

- 精确字体许可尚未审计：不阻塞金标测量，但阻塞“字体完全一比一”的正式声明。
- 当前备份只能位于 Test 内：不具备异盘灾备能力，不能对客户宣称可抵御整个 D 盘故障。
- 固定生产 boundary、命名空间策略和 Test-only 句柄 writer 已通过，但生产 writer 仍断开；442 个入口尚未迁移，在持久审计、原子 publish 和逐入口门禁完成前不得处理真实资料。
- S2 `PairEvidence`仍是调用者声明；S3-B 只完成单文件同句柄核验，S3-D/E 仍须重算实际 manifest、源树、条目数和拓扑。
- 当前 audit sink 仍是进程内候选证据，不是持久 ledger；S3-C 完成并通过重启/损坏恢复门禁前不得宣称可恢复审计。
- S3-B writer 的 spent-ticket 有界生命周期、多票据 seal 次要故障证据及 ReFS/128-bit File ID 兼容仍待后续切片关闭；不影响其 Test-only 检查点，但阻塞生产连接。
- 安全测试实验室针对受信任、已审阅的仓库测试代码，不是任意 hostile native-code 的 OS sandbox。
- 本机普通账户不能创建实际目录 symlink（WinError 1314）；不自动启用开发者模式或提升权限，该门禁保持 IN_PROGRESS。
