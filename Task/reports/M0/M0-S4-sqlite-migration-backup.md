# M0-S4 SQLite 迁移、备份与恢复门禁

## 结论

M0-S4 已在本机通过功能与安全验收，功能检查点为
`29602bc1af5001e486e9df8b5568af1b51984d08`。本切片完成了只读数据库网关、
只追加 schema 迁移目录、SQLite Backup API、一致快照、暂存恢复、数据库副本迁移、
中断恢复和导入批次备份接线。

这不是 M0 总验收，也没有切换或迁移活动数据库。下一切片是 M0-S5
领域模型、IR 与金标基线。

## 严格边界

- 全部写测试只操作 `tmp/test_lab/<run_id>` 内的合成数据库和资产。
- 活动数据库
  `data/db/question_bank.sqlite3` 的 SHA-256 在所有门禁前后均为
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。
- 活动数据库仍为 `user_version=0`，没有 `schema_migrations` 表；25 张现有表和真实业务状态
  未被迁移。`source_papers`、`questions`、`question_assets`、`import_batches` 均为 0 行。
- production writer 仍断开；最终 inventory 的 462 个入口全部为
  `UNMIGRATED_BLOCKED`，`m0_exit_allowed=false`。
- 本切片不声称完成整产品资产备份、客户 UI 恢复旅程、异卷灾备或活动状态切换。

## 实现结果

### 只读网关与零写入 GET

- `connect_database_read_only()` 使用 SQLite URI `mode=ro` 和
  `PRAGMA query_only=ON`，要求数据库已存在、路径绝对、普通文件、单硬链接且无 Reparse。
- 纯读 repository、筛选、结构化内容、来源归属、质量摘要和建议列表不再隐式初始化数据库。
- Web 的题目列表、详情、结构化复核、组卷篮、预览和导出 GET 路径不再执行 lazy
  rebuild/ensure。
- 测试对 8 条 GET 路由逐次复核数据库目录的文件内容、SHA-256、mtime 和 sidecar；
  `-wal`、`-shm`、`-journal` 均未出现。
- 初始化、派生模型重建和质量刷新只保留在显式命令或写操作路径。

### 只追加迁移目录

- 当前目录版本为 1，初始迁移 ID 为 `0001_INITIAL_LEGACY_BASELINE`。
- 规范化 schema SHA-256 为
  `ee853feec02eda2b1c221f98b916c699469bb999fce96792caf4b1769028ac96`。
- 新库、精确 legacy schema、已迁移库和重复执行均有确定状态；未来版本、分叉 schema、
  迁移历史篡改和目录篡改全部 fail closed。
- schema DDL、迁移记录和 `user_version` 在同一 `BEGIN IMMEDIATE` 事务内提交。
- 固定枚举故障点覆盖事务开始前、schema 后、历史记录后、版本写入后和 commit 后；
  事务内中断回滚，commit 后中断由重新检查状态幂等收敛。
- 真实子进程使用 `os._exit` 验证断电窗口；不接受调用者注入的任意回调。

### SQLite Backup API 与暂存恢复

- `DatabaseBackupService` 固定在受信任项目根，活动数据库位置固定为
  `data/db/question_bank.sqlite3`。
- 备份通过 SQLite Backup API 从 WAL 源取得一致快照，不再使用 `copy2` 复制活动库。
- 候选先写入
  `tmp/jobs/INTERNAL/<job_id>/backup/<backup_id>`，通过完整性、外键、业务路径、FTS 和
  canonical manifest 校验后，以 no-replace 方式发布到 `backups/<backup_id>`。
- 发布备份归一化为 DELETE journal 的单 SQLite 文件，并拒绝缺失、额外、篡改、遍历、
  Reparse、硬链接和空间不足。
- 恢复只进入 `data/db/versions/<state_id>` 暂存状态；不会覆盖活动数据库。
- 副本迁移先创建 rescue backup，再恢复/复制到暂存区，只迁移副本，并验证新 schema、
  完整性、外键和 manifest。中断后可重试，失败不会改动活动库。
- 导入批次备份已接入该服务；备份、恢复和迁移 ID 使用足够精度避免碰撞。

### Mock 默认库安全顺序

最终全仓门发现 Mock 结构化纠错在拒绝默认数据库之前先调用初始化。实现已改为先执行
“必须显式指定非默认数据库”的检查，再进行任何数据库操作，并将
`tests/test_structured_ai.py` 纳入 `s4_core` 与 `s4` 固定选择。

## 验收证据

| 证据 | 结果 |
|---|---|
| `RUN-20260725-M0-S4-CORE-FIX-100` | 69/69；修复最小回归通过 |
| `RUN-20260725-M0-S4-INVENTORY-101` | 55 sources、462 entries、19 chunks、`UNKNOWN=0`、462 blocked |
| `RUN-20260725-M0-S4-GATE-102` | 462/462；活动库、保护树、watcher、句柄围栏、run tree、不可变证据、源码见证、进程树全部通过 |
| `RUN-20260725-M0-FULL-GATE-103` | 1038/1038，另 1 个真实目录 symlink 能力用例按既定本机权限边界单独排除 |

`RUN-103` 的关键安全事实：

- 最终退出码 0，JUnit failure/error/skip 均为 0。
- 保护树前后均为 4,817 项且 digest 相同。
- 80 个登记合成来源全部在结束态匹配。
- 活动数据库前后 SHA-256 相同。
- runtime watcher、句柄围栏、run tree、不可变证据和进程树全部通过。
- pytest 用时 1,025.57 秒；这是阶段冻结成本，不是日常门禁成本。

被替代轮次：

- `RUN-096` 只有静态库存测试的旧计数断言失败，安全门干净。
- `RUN-098` 因人为设置 420 秒预算而安全超时，未形成 JUnit，安全门干净。
- `RUN-099` 为 1037 通过、1 失败，定位到 Mock 默认库检查顺序；全部安全门干净，
  已由 CORE-100、S4-102 和 FULL-103 替代。

## 门禁与 E 盘整理

- 日常迭代默认运行受影响的 `*_core`；CORE-100 用时约 40 秒。
- `s4` 只在切片候选稳定时运行；`full` 只在阶段冻结、发布检查点或保护边界变化时运行。
- `tmp/test_lab_archives` 是固定冷目录，不参与每轮保护树重复枚举；只在归档生成和阶段冻结时
  完整复核。
- 本次冻结重算 14 个归档的 SHA-256，重新列出 196,442 个成员和 183 个运行根；
  覆盖差异、哈希差异、成员差异和危险路径均为 0。
- 冷归档合计 680,550,360 bytes（约 649.03 MiB），是一次性历史证据，不随每轮门禁复制。
- E 盘热目录只保留 FULL-103（约 126.41 MiB）和 INVENTORY-101（约 0.49 MiB）。
- 整理后 E 盘可用空间为 64,775,925,760 bytes（约 60.33 GiB）。
- 原始旧运行均在归档校验后可恢复地移动到 C 盘本机恢复区，没有危险递归删除。

## 剩余风险

- 当前备份与暂存恢复仍在同一产品卷；不能抵御整卷故障。
- M4 仍需覆盖数据库之外的 assets、配置、版本指针和客户可执行恢复旅程。
- 活动数据库的迁移/切换尚未授权也未执行；后续只能在具备冻结、回滚和用户流程证据时进行。
- 当前恢复保证针对合作式应用写入者；不声称冻结 hostile external writer。
- 普通账户缺少真实目录 symlink 创建权限（WinError 1314）；不提升权限，不阻塞独立切片。

## 复核命令

```powershell
.\.venv\Scripts\python.exe scripts\run_safe_pytest.py --run-id <unique> --mode s4_core --timeout-seconds 180
.\.venv\Scripts\python.exe scripts\run_safe_pytest.py --run-id <unique> --mode s4 --timeout-seconds 240
.\.venv\Scripts\python.exe scripts\run_safe_pytest.py --run-id <unique> --mode full --exclude-symlink --timeout-seconds 1800
Get-FileHash data/db/question_bank.sqlite3 -Algorithm SHA256
Get-FileHash tmp/test_lab_archives/*.tar.gz -Algorithm SHA256
```
