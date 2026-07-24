# ADR-2026-003：固定生产边界、显式命名空间能力与候选态门禁

- 状态：Accepted
- 日期：2026-07-11
- 决策级别：D2
- 影响里程碑：M0—M5
- Requirement IDs：`M0-SAFE-001`、`M0-SAFE-002`、`M0-SAFE-003`、`M0-SAFE-004`、`M0-SAFE-006`、`M0-SAFE-007`
- 补充 ADR：`ADR-2026-001-central-workspace-guard.md`、`ADR-2026-002-workspace-guard-capability-boundaries.md`、`ADR-2026-005-portable-project-root-and-relocation.md`（只替换物理路径绑定，不允许调用者注入根）

## 背景与已确认事实

M0-S1 只能证明候选路径在检查时位于授权根内，不能证明调用者有权操作该命名空间，也不能把检查、打开句柄、写入和发布绑定成一个不可伪造的事务。现有生产代码还包含数据库、文件、SQL、进程和网络入口；只搜索少数 API 或依赖文件名白名单会漏掉别名、包装器、动态 SQL 和间接调用。

M0-S2 的目标因此不是提前开放写入，而是建立固定生产根、精确上下文、默认拒绝的命名空间策略、不可伪造的候选能力、成对发布/隔离拓扑和可复算的全量入口清单。真正 writer 在完成句柄级竞态控制、写后核验和持久审计前必须保持断开。

## 决定

1. 生产入口只允许通过`get_production_boundary()`取得固定单例。根固定为合同`PROJECT_ROOT`，不接受调用者注入 Guard、根、策略、审计 sink 或配置覆盖。
2. `OperationContext`使用精确枚举、规范化 ASCII ID、作用域、用途、调用方和`INTERNAL/RESTRICTED`分类。生产边界只接受由同一 authority 签发的上下文；S2 不公开生产上下文签发器。
3. `NamespacePolicy` V6 使用固定 rule/grant 全集和稳定 digest。采用最长组件前缀、默认拒绝、精确 caller/purpose/scope/classification 交集；永久保护区、活动数据库、追加文件、Copy、job、发布、备份与 quarantine 均有独立语义。
4. 单路径候选、发布 pair 和 quarantine pair 使用不透明令牌、HMAC 绑定、有限 registry、生命周期和 tombstone。令牌不能 pickle，公开描述和受限审计不泄漏绝对路径或敏感 ID。
5. 生产边界保持`writer_available=false`；`require_writer()`必须失败。S2 的 allow 只表示`CANDIDATE_ONLY`，不能被解释为已经完成写入授权。
6. `PairEvidence`在 S2 只是调用者声明。S3 writer 必须从实际受控句柄重新计算 manifest 哈希、源树哈希、条目数和拓扑，再与候选记录绑定；不允许信任传入值后直接移动。
7. S2 的`CollectingAuditSink`只用于失败关闭和测试证据，不是持久审计账本。S3 必须实现 Test 内追加式、可校验、批次原子的持久 ledger，审计失败时禁止业务写入。
8. 静态扫描器 V5 对`app/`和`scripts/`的 UTF-8 Python/SQL 源先做`CRLF/CR → LF`规范化，再执行确定性 AST/SQL 数据流扫描；新动态能力必须进入`UNKNOWN_DYNAMIC_CAPABILITY`并阻断。根`.gitattributes`把生产源、测试和 Task 证据固定为 LF，避免`core.autocrlf`使 fresh checkout 破坏哈希。扫描器属于受信任仓库 lint，不是任意恶意同进程代码的 OS sandbox。
9. 安全 pytest 启动器使用唯一 Test-local run、Windows Job Object、递归 watcher、现存对象 deny-write/delete 句柄围栏、硬链接/bootstrap 审计和前后快照。它只对已审阅测试源码提供失败关闭证据，不宣称能隔离任意恶意 native/ctypes/reflection 代码。
10. SQLite 活动库和 WAL/SHM 的一致备份只能使用 SQLite Backup API 及完整性/恢复验证，不允许把原始文件复制包装成安全备份。

## 被拒绝方案

### 仅保留路径 Guard 并逐个接入 writer

拒绝。它不能表达调用者、用途、分类、scope、追加、发布 pair 或 quarantine 拓扑，也不能防止未来配置扩大根。

### 先接通 writer，再以测试补齐策略

拒绝。当前 427 个生产入口仍为`UNMIGRATED_BLOCKED`，任何提前接通都会把候选能力误当成原子写能力，并可能触碰活动数据库或真实资料。

### 把测试启动器称为 hostile-code sandbox

拒绝。未授权 restricted token、AppContainer、ACL 或容器改造；夸大保证会掩盖 native 代码边界。当前采用受信任源码审查、静态扫描、Job Object、句柄围栏、watcher 和最终快照的组合。

## 安全、数据和客户体验影响

- 生产写入继续失败关闭，M0-S2 不处理真实题库、原卷、OCR、导出或活动库迁移。
- `RESTRICTED`路径和上下文只记录 HMAC/深度等受限信息；普通异常不携带内部 traceback 或绝对路径。
- Copy work、job 和 quarantine 路径显式加入 classification 分区，避免受限资料降级到 INTERNAL。
- 客户当前不会获得新增业务功能；本切片只降低后续功能接入时的越权和不可追溯风险。

## 迁移、兼容与回滚

本切片只增加候选安全层、测试和清单，没有迁移数据库、移动业务资产或改变活动指针。若回滚，只能通过普通 Git revert 回退代码提交；保留 Test-local实验室和审计证据，不清理现场。既有应用写入口在 S3 迁移完成前继续被 inventory 标记为阻断。

## 验证和真实流程

- 冻结 inventory：45 个生产源、427 个入口、18 个分片，`UNKNOWN=0`，所有入口均`UNMIGRATED_BLOCKED`。
- 冻结测试：`RUN-20260711-M0-S2-EOL-020-FINAL`，354 passed、1 个实际 symlink 权限用例明确 deselected，失败/错误/跳过均为 0。
- Test-local 保护树前后 31,225 条、digest 相同；活动 SQLite 前后 SHA-256 相同。
- 公共生产入口流程`M0-S2-UJ-001`确认固定单例、writer 不可用、未签名上下文得到结构化`INVALID_CONTEXT`和脱敏 DENY 审计，数据库不变。
- 两名独立只读审计者复算 inventory、policy、JUnit、保护树、进程树、数据库和证据哈希，P0=0、P1=0。

## 未决项

- M0-S3：句柄级 writer、实际字节/树 evidence 重算、原子发布、持久审计、Copy ledger、quarantine 和受控外部进程。
- 真实目录 symlink 仍因 WinError 1314 未验证；不得自动提权或启用开发者模式。
- 427 个旧入口尚未迁移，`m0_exit_allowed=false`；本 ADR 不代表 M0 总门通过。

## 审批/审计

D2 候选由主写者实现；最终冻结前完成 production policy/inventory 与 launcher/bootstrap 两路独立只读审计。结论仅批准 M0-S2 候选进入 Git 检查点，不批准接通生产 writer 或进入 M1。
