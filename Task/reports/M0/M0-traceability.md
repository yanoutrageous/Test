# M0 需求—测试—证据追踪矩阵

| Requirement ID | 用户/系统结果 | 主要风险 | 验收条件 | 自动测试/旅程 | 证据 | 状态 |
|---|---|---|---|---|---|---|
| `M0-BASE-001` | 当前代码、环境、数据库和金标事实可复现 | R-004/R-006 | manifest 含哈希、版本、空库事实和限制 | `M0-BASE-T01` | `M0-entry-baseline.json` | PASS |
| `M0-GIT-001` | 规划有安全远端恢复点 | R-033/R-034/R-035 | 显式范围、普通 push、Draft PR | PRE-M0 publish audit | PR #1 | PASS |
| `M0-SAFE-001` | 所有写目标严格在授权 workspace | R-001/R-002 | 合法中文路径通过；全部越界路径零副作用拒绝 | `M0-GUARD-*`、`M0-POLICY-*`、`M0-HANDLE-*`、UJ-067 | S1/S2/S3-B—E 报告；RUN-S3E-COMBINED-019 | IN_PROGRESS（Test-only pair publish/recovery 已通过；生产 writer、Copy/quarantine 和 460 入口迁移待完成） |
| `M0-SAFE-002` | 链接、ADS、设备路径和竞态不能逃逸 | R-003 | Reparse/Junction/ADS/TOCTOU 攻击矩阵通过 | `M0-GUARD-ATTACK-*`、`M0-TICKET-*`、`M0-HANDLE-ATTACK-*`、S3-D/E tree race | S1/S2/S3-B—E 报告；RUN-S3E-008/009 | IN_PROGRESS（pair 内 no-replace、target rescan、PREPARED crash abort/commit recovery 已通过；实际 symlink 权限门与后续 Copy/quarantine 竞态待完成） |
| `M0-SAFE-003` | 测试故障不会碰真实根外目录 | R-001/R-031/R-038 | 全部写测试在 Test test_lab，保护树和活动库不变 | `M0-LAB-*`、`M0-BOOTSTRAP-*` | RUN-S3E-COMBINED-019 manifest/result/JUnit；S3-E 报告 | IN_PROGRESS（399 项组合门期间 watcher、99,504 句柄围栏、保护树和活动库均干净；后续 M0 工具仍须持续纳入同一入口） |
| `M0-SAFE-004` | 外部来源加工前有可信 Copy 台账 | R-010/R-027 | source/copy SHA-256 相同，work 不改 source | UJ-010/M0 Copy flow | S2 Copy namespace policy；ledger 待实现 | IN_PROGRESS（分类/作用域策略通过，尚无 writer/台账真实流程） |
| `M0-SAFE-005` | 关键文件原子写、失败不部分发布 | R-005/R-014/R-023 | staging 验证后原子发布，旧版可用 | `M0-ATOMIC-*` | S3-C file publish；S3-D staging；S3-E pair/operation report；RUN-S3E-008/009 | IN_PROGRESS（目录 pair 的 PREPARED/MUTATED/POST/COMMITTED 与重启对账通过；Copy/quarantine/数据库原子流程仍待 S3-F/G/S4） |
| `M0-SAFE-006` | 业务删除只进入 quarantine | R-001/R-025/R-039 | 精确 manifest、可恢复、无永久清理 | `M0-QUARANTINE-*` | S2 quarantine pair policy；writer 待实现 | IN_PROGRESS（候选拓扑通过，实际 evidence 重算/移动/恢复未开始） |
| `M0-SAFE-007` | 外部工具 cwd/TEMP/网络/参数受控 | R-017/R-026/R-029/R-038 | 允许列表、无 shell、超时和额外输出检查 | `M0-PROCESS-*`、launcher bootstrap canaries | RUN-020；生产 wrapper 待实现 | IN_PROGRESS（测试进程隔离通过；生产外部进程 wrapper 未接入） |
| `M0-DB-001` | 读取不隐式写库或建目录 | R-002/R-005 | query-only 路径哈希不变，GET 零写入 | `M0-DB-READ-*` | 待实现 | NOT_STARTED |
| `M0-DB-002` | schema 有只追加版本和可回滚迁移 | R-005/R-030 | 旧库副本正迁移、重复、中断、回滚通过 | `M0-MIG-*` | 待实现 | NOT_STARTED |
| `M0-DB-003` | SQLite 检查点一致且可恢复 | R-022/R-023 | Backup API、integrity/FK、staging 恢复 | `M0-DB-BACKUP-*` | 待实现 | NOT_STARTED |
| `M0-DOMAIN-001` | 核心对象和 IR 可版本化往返 | R-010/R-014/R-016/R-018 | schema 验证、往返无语义丢失、未知字段策略 | `M0-IR-*` | 待实现 | NOT_STARTED |
| `M0-GOLD-001` | 视觉/内容/评分/图形金标角色清晰 | R-006/R-007/R-009/R-021 | logical ID、哈希、角色、许可、预期结果齐全 | M0 gold registry review | 待实现 | NOT_STARTED |
| `M0-GOLD-002` | 模板族和视觉阈值可量化 | R-006/R-007/R-009 | 页面、锚点、分页、字体替代基线冻结 | M0 visual calibration | 待实现 | NOT_STARTED |
| `M0-FLOW-001` | fresh-state 初始化、合法写、越界拒绝、迁移往返全流程可用 | R-001/R-005/R-032 | UI/公开入口和安全证据全部通过 | M0 entry user flows | 待实现 | NOT_STARTED |

M0-S3-E inventory 当前有 460 个`UNMIGRATED_BLOCKED`入口，`production_writer_connected=false`、`m0_exit_allowed=false`。状态只按当前证据更新；30 个 S3-E 核心流程与 399 个组合回归不能替代 Copy/quarantine、迁移、IR/金标或 M0 真实用户流程。mutation 只接受 exact live leases；恢复范围固定为`COOPERATIVE_APPLICATION_WRITERS_ONLY`，普通目录 handle 仍不能冻结 hostile external child namespace，恢复只追加事实且不清理现场。
