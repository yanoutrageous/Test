# 当前状态

更新时间：2026-07-24 12:26 +08:00

## 长期执行状态

- 计划版本：1.1.0
- 当前阶段：M0 入场审计完成，M0 尚未验收
- 当前切片：`M0 portable root + relocation rebaseline`与`M0-S3-F synthetic Copy + dual ledgers`候选均已通过本机验收；新机发布工具链已恢复，73 个 allowlisted 文件已显式暂存并通过 staged 审计，等待 checkpoint commit/push。门禁禁止在 checkpoint 前进入 S3-G，S3 与 M0 总门仍未通过
- M0—M5 实现：M0 已开始；M1—M5 未开始
- 本任务有效终点：按用户后续明确要求，连续完成修订后的 M0—M5，直到真实用户流程、恢复演练和客户交付包全部通过；不得把 M0 或代码完成误报为终局
- 当前禁止：活动数据库迁移、题库导入、OCR、正式排版、批量资产、备份切换和业务文件清理

## 2026-07-24 新电脑恢复与可迁移根基线

- 当前物理位置观察为`E:\AAA命题\Test`，主机为`炎炎`，卷为健康 NTFS；项目根及祖先没有 Reparse Point。该绝对路径只属于本次运行证据，不再进入生产权限合同。
- 生产根改为`PORTABLE_LOCAL_NTFS_V1`：受信任`app/project_root.py`位置与根`.exam-bank-root.json`精确内容共同授权；marker 不含盘符/用户名/绝对路径，cwd、环境变量、配置和调用者参数不能扩大根。
- Python 3.12.13、Flask 3.1.3、PyMuPDF 1.28.0、pytest 9.1.1、SQLite 3.50.4 均已导入；现有`.venv`可继续验证，但`pyvenv.cfg`保留旧机创建命令，因此不作为未来迁移产物，后续电脑默认按`requirements.txt`重建。
- 活动数据库 SHA-256 仍为`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`，`integrity_check=ok`、外键违规 0，核心业务表仍为空；迁移重定根当前没有业务数据改写风险。
- Git 分支`agent/m0-m5-local-v1`、本地 HEAD、origin 分支和远端 refs 经 04:00 后重新 fetch 仍均为`6e225c8e4ba06332a197a1acdcbd1f86edce4d99`；恢复前 S3-F 脏工作区为 42 项（35 tracked、7 untracked），聚合 SHA-256 为`85f9541403491f3aebc6aa5dc1d381b53e8f1594edfc3568a12b8a3455eb0469`，已原样保留并增量修改。当前 portable-root、S3-F 与证据合计 73 项（60 tracked、13 untracked）尚未提交。
- 旧主机 writer lock（`DESKTOP-GU0STBA`/PID 283856）已确认失效；本机以`RUN-20260724-M0-PORTABLE-ROOT-024`取得 Git 忽略的单写者锁，没有业务 mutation。
- `RUN-20260724-M0-PORTABLE-FULL-037`最终退出码 0：JUnit 961 passed，failure/error/skip 均为 0；保护树前后均 126,030 项且 digest 相同，活动数据库、运行树、immutable evidence、watcher、句柄围栏、进程树和 80 个登记合成来源均通过。RUN-025/031/034/036 作为失败收敛证据保留，不再代表当前功能状态。
- 现有`tmp`约 7.65 GiB，E 卷剩余空间约 29.91 GiB，全量保护树门成本较高。未获用户明确授权前不得删除或压缩历史运行；完整保护树门保留为低频验收，后续高频回归策略必须另行受审计且不能降低外部零写入保证。
- 旧 D 路径上的 S1—S3-E 实现、提交和语义测试结果仍是历史证据，但其卷、路径链、保护树和外部零写入结论不能直接授权 E 路径。`RUN-20260713-...-021/022/023`不再作为恢复运行计划使用；新基线只使用 2026-07-24 的新唯一 run ID。
- Git 忽略的`Task/local/REFERENCE_PATHS.local.md`已按本机 E 路径重绑定；外部资料仍只读，任何处理仍需先进入当前`PROJECT_ROOT\Copy`并核对哈希。
- 本机映射中的 16 个逻辑参考集、共 25 个明确文件或目录均已只读确认存在；该存在性只对当前电脑成立，下一次迁移必须重新核对，不进入 Git 合同。

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
- 生产静态 inventory V16 覆盖`app/`和`scripts/`的 53 个源文件、464 个副作用入口和 19 个分片；`UNKNOWN=0`、未授权安全内核构造 0，但 464 项仍全部`UNMIGRATED_BLOCKED`
- Policy V7 digest 为`8df50ded...e4d88`；生产 boundary 固定根且`writer_available=false`，`m0_exit_allowed=false`
- S3-E 最终核心回归`RUN-20260712-M0-S3E-016`为`30 passed`，launcher 门`RUN-20260712-M0-S3E-LAUNCHER-018`为`72 passed`，组合门`RUN-20260712-M0-S3E-COMBINED-019`为`399 passed`；JUnit failure/error/skip 均为 0
- RUN-009 保护树前后均 93,762 条、运行时变更 0、句柄围栏 93,762 个；活动 SQLite 前后 SHA-256 相同。旧结果字段`source inputs unchanged`只是该次已监测保护集的起止/运行时证据，不声称监控整机或未登记外部源
- Scanner V16 使用`UTF8_LF_V1`规范化并加入 portable-root authority、external-source、Copy 双账本、operation ledger、pair reservation、最终 revalidation、跨账本 ancestor 和目录 publish/recovery 私有调用 exact canary；inventory payload 为`e31de8130346d87eb1b92109f88580cbb5ea33502d0b316a48a27fe7c172659c`，生产 writer 与`m0_exit_allowed`均为 false

## 工具与发布状态

- 用户已明确授权无交互继续完成交付；新电脑已通过 WinGet 用户范围安装 GitHub CLI 2.96.0。
- 本机 Git 自身可访问远端；Git Credential Manager 中的 GitHub OAuth 凭据经临时`GH_TOKEN`环境桥接后，`gh api user`和`gh auth status`验证账号为`yanoutrageous`。令牌未写入命令、报告或仓库，也未降级保存为明文文件。
- GitHub App 已确认仓库公开且未归档、当前账号具有 admin/push 权限、默认分支为`main`，Draft PR #2 仍 open/mergeable，head 为`6e225c8e4ba06332a197a1acdcbd1f86edce4d99`
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
2. M0-S3-E exact reservation、独立 operation chain、source-root no-replace publish、target rescan 与只追加恢复真值表已通过本地组合门和独立暂存审计，并作为`39586568a405124417d105d8e876d25ec94e06e6`完成普通 push；
3. portable root 与 S3-F 合成 Copy/双 ledger 已由`RUN-20260724-M0-PORTABLE-FULL-037`验收；下一动作是精确暂存审计、checkpoint commit 和普通 push，随后进入 S3-G；
4. 按长期终点继续完成 M0—M5；只有 M5 客户交付包、真实用户流程和恢复演练全部通过后才可结束，不得把 M0 checkpoint 当作终局。

## 历史暂停检查点（已于 2026-07-24恢复）

- 暂停时间：2026-07-13 22:00:02 +08:00；原因：用户要求在最近可恢复安全断点暂停；
- 暂停记录前本地与 origin head 均为`01cfbb12012040b03e82745e828cf3ff85dc1bf1`；没有活动 safe launcher 或 Git 进程，没有进行中的业务 mutation，没有处理真实业务数据；
- 活动 SQLite SHA-256 当时为`1505BF05BD8E385EADA30642110596363C561C330DA02A40A497072064AD1C94`，旧 D 盘当时可用空间为 588,403,019,776 bytes；生产 writer 仍断开，460 个入口仍全部`UNMIGRATED_BLOCKED`；
- 暂停记录前工作区为 36 个 tracked modified 与 7 个 untracked S3-F 文件。不得清理、覆盖或丢弃这些候选；完整恢复入口见`Task/reports/M0/M0-S3-F-pause-20260713.md`；
- `RUN-20260713-M0-S3F-INTEGRATION-020`为修复前历史证据：167 项中 150 通过、17 失败，但安全门保持清洁；对应修复现已由新根`RUN-20260724-M0-PORTABLE-FULL-037`的 961 项全绿回归取代；
- V4 Copy plan/opaque TXN 与异常边界复审的 P0/P1 均已收口；S3-F 当前只缺显式 Git checkpoint；
- `RUN-20260713-M0-S3F-INTEGRATION-021`、`RUN-20260713-M0-S3F-LAUNCHER-022`、`RUN-20260713-M0-S3F-COMBINED-023`均为 superseded/unused，永不复用；完成当前 checkpoint 后可进入 S3-G。

## 已知限制与未决项

- 精确字体许可尚未审计：不阻塞金标测量，但阻塞“字体完全一比一”的正式声明。
- 当前备份只能位于`PROJECT_ROOT`内：不具备异卷灾备能力，不能对客户宣称可抵御整个产品根所在卷故障。
- 固定权限但物理路径可迁移的生产 boundary、Policy V7、Test-only 句柄 writer、audit/operation/Copy 双账本和 S3-E/S3-F publish/recovery 已通过当前新机组合门，但生产 writer 仍断开；464 个入口尚未迁移，在 quarantine/数据库等后续门禁完成前不得处理真实资料。
- S2 `PairEvidence`仍只是候选声明；S3-E 实际 mutation 只在 exact `_ReservedPairLease`和 live observed lease 内执行，声明或 detached 摘要都不能授权 rename。
- audit key revision 位于 Test 内、Git 忽略的本地明文存储；不能抵御已取得 Test 读取权的恶意本机用户；没有外部 witness 时也不能证明完整账本尾部未被一致回滚。
- Test-only writer 的 spent-ticket 记忆和诊断缓存已固定上限；ReFS/128-bit File ID 高位非零兼容、硬件断电语义和业务 operation recovery 仍未声明通过。
- 安全测试实验室针对受信任、已审阅的仓库测试代码，不是 hostile native-code 或 hostile same-process Python 反射/monkeypatch 的 OS/语言沙箱；S3-F 异常 vault 只收窄经密封公开 boundary 的正常调用泄漏面，不能隔离能够绕过 boundary 的恶意同进程代码。
- 普通用户态 Windows 目录 handle/oplock 不能冻结 child namespace；S3-E 已使用最后检查、内核 no-replace、target full rescan 与`IN_DOUBT`/seal，但仍不声明 hostile-writer 原子快照。
- 本机普通账户不能创建实际目录 symlink；独立安全运行`RUN-20260724-M0-SYMLINK-CAPABILITY-038`仅因 WinError 1314 失败，其余保护证据清洁。不自动启用开发者模式或提升权限，该能力门保持 IN_PROGRESS，但不阻塞不依赖 symlink 创建权限的 S3-G 工作。
