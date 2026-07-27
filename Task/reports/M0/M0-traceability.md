# M0 需求—测试—证据追踪矩阵

| Requirement ID | 用户/系统结果 | 主要风险 | 验收条件 | 自动测试/旅程 | 证据 | 状态 |
|---|---|---|---|---|---|---|
| `M0-BASE-001` | 当前代码、环境、数据库和金标事实可复现 | R-004/R-006 | manifest 含哈希、版本、空库事实和限制 | `M0-BASE-T01` | `M0-entry-baseline.json` | PASS |
| `M0-GIT-001` | 规划有安全远端恢复点 | R-033/R-034/R-035 | 显式范围、普通 push、Draft PR | PRE-M0 publish audit | PR #1 | PASS |
| `M0-SAFE-001` | 所有写目标严格在授权 workspace | R-001/R-002 | 合法中文路径通过；全部越界路径零副作用拒绝 | `M0-GUARD-*`、`M0-POLICY-*`、`M0-HANDLE-*`、UJ-067 | S1/S2/S3-B—H报告；RUN-S6-FLOWS-145/GATE-147/EXIT-149 | PASS（production handle writer已接通；60个源、420个入口全部精确绑定，合法中文写通过，7类越界写副作用0） |
| `M0-SAFE-002` | 链接、ADS、设备路径和竞态不能逃逸 | R-003 | Reparse/Junction/ADS/TOCTOU 攻击矩阵通过 | `M0-GUARD-ATTACK-*`、`M0-TICKET-*`、`M0-HANDLE-ATTACK-*`、S3-D—H tree/crash race | S1/S2/S3-B—H报告；RUN-S6-FLOWS-145/GATE-147 | PASS（实际NTFS Junction、硬链接marker、ADS、设备、UNC及竞态均失败关闭；真实目录symlink创建受普通账户WinError 1314限制且已披露） |
| `M0-SAFE-003` | 测试故障不会碰真实根外目录 | R-001/R-031/R-038 | 全部写测试在 Test test_lab，保护树和活动库不变 | `M0-LAB-*`、`M0-BOOTSTRAP-*` | RUN-S3H-S3-TOTAL-079；RUN-M0-S5-FULL-123；RUN-S6-GATE-147/EXIT-149 | PASS（147的26,870项保护树、82来源、活动库、watcher、句柄围栏和进程树全部干净；149冻结门再次通过） |
| `M0-SAFE-004` | 外部来源加工前有可信 Copy 台账 | R-010/R-027 | source/copy SHA-256相同，work不改source | UJ-010/M0 Copy flow | S3-F/S3-H报告；RUN-S6-FLOWS-145 | PASS（真实Test外109,735-byte PDF通过只读句柄进入不可变Copy；source/Copy/gold哈希相同且provenance路径脱敏） |
| `M0-SAFE-005` | 关键文件原子写、失败不部分发布 | R-005/R-014/R-023 | staging验证后原子发布，旧版可用 | `M0-ATOMIC-*` | S3-C—H reports；M0-S4/S6报告；RUN-S6-GATE-147 | PASS（M0范围内file/Copy/quarantine/restore/SQLite候选均no-replace且可恢复；产品bundle原子发布仍由M2验收） |
| `M0-SAFE-006` | 业务删除只进入 quarantine | R-001/R-025/R-039 | 精确manifest、可恢复、无永久清理 | `M0-QUARANTINE-*` | S3-G/S3-H报告；RUN-S6-GATE-147 | PASS（production入口已绑定；日期分区、脱敏恢复、retained restore和无永久清理合同通过） |
| `M0-SAFE-007` | 外部工具 cwd/TEMP/网络/参数受控 | R-017/R-026/R-029/R-038 | 允许列表、无shell、超时和额外输出检查 | `M0-PROCESS-*`、launcher bootstrap canaries | RUN-S3H-LAUNCHER-076；RUN-S6-GATE-147 | PASS（7个生产external-process入口全部绑定；测试进程隔离、超时、意外子进程回收和危险shell扫描通过） |
| `M0-DB-001` | 读取不隐式写库或建目录 | R-002/R-005 | query-only 路径哈希不变，GET 零写入 | `M0-DB-READ-*` | M0-S4 报告；RUN-S4-GATE-102；RUN-M0-FULL-GATE-103 | PASS |
| `M0-DB-002` | schema 有只追加版本和可回滚迁移 | R-005/R-030 | 旧库副本正迁移、重复、中断、回滚通过 | `M0-MIG-*` | M0-S4 报告；`tests/test_database_migrations.py`；RUN-S4-GATE-102 | PASS |
| `M0-DB-003` | SQLite 检查点一致且可恢复 | R-022/R-023 | Backup API、integrity/FK、staging 恢复 | `M0-DB-BACKUP-*` | M0-S4 报告；`tests/test_database_backup.py`；RUN-S4-GATE-102 | PASS |
| `M0-DOMAIN-001` | 核心对象和 IR 可版本化往返 | R-010/R-014/R-016/R-018 | schema 验证、往返无语义丢失、未知字段策略 | `tests/test_domain_models.py`、`tests/test_ir_contracts.py` | ADR-006；M0-S5报告；RUN-M0-S5-122/FULL-123 | PASS（19类不可变revision、Question/Figure/Paper IR v1、坐标/变换、五类角色、v0.9迁移/回滚和未知字段失败关闭均已冻结） |
| `M0-GOLD-001` | 视觉/内容/评分/图形金标角色清晰 | R-006/R-007/R-009/R-021 | logical ID、哈希、角色、许可、预期结果齐全 | `tests/test_gold_registry.py`、gold preview builder | 18条目/63成员registry；ADR-006；M0-S5报告 | PASS（8个真值角色完整，tracked registry无物理路径或源文件名；许可/PII继续作为发布阻断事实） |
| `M0-GOLD-002` | 模板族和视觉阈值可量化 | R-006/R-007/R-009 | 页面、锚点、分页、字体替代基线冻结 | `tests/test_gold_registry.py`、visual threshold validator | 12个模板族；`visual-thresholds-v1.json`；RUN-M0-S5-122 | PASS（exact页面、0.01 mm表示容差、0.5/1.0 mm锚点、零裁切/溢出/静默替代；真实渲染验收仍属M1） |
| `M0-FLOW-001` | fresh-state初始化、合法写、越界拒绝、迁移往返全流程可用 | R-001/R-005/R-032 | 公开入口和安全证据全部通过 | M0 entry user flows | RUN-S6-FLOWS-145；`M0-S6-real-flow-exit-report.json` | PASS（六条真实流程一次通过，活动库大小/mtime/哈希不变） |

M0-S6 inventory最终为60个生产源、420个入口、17个分片，`UNKNOWN=0`、未迁移入口0、
无效绑定0，`production_writer_connected=true`、`m0_exit_allowed=true`、
`global_status=M0_EXIT_ACCEPTED`。活动数据库仍保持`user_version=0`且未被迁移；
迁移/回滚只在Backup API副本上完成。M0已验收，下一阶段为M1真实试卷生产线。
