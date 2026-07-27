# M0-S3-D Operation lease、固定 job staging 与树证据检查点报告

- 日期：2026-07-11
- 分支：`agent/m0-m5-local-v1`
- 基线：`a999f32718b0ed22d2683585c7d079a0c9bbb749`
- 结论：**S3-D 候选通过，可形成内部检查点；S3-E—H、S4—S6 与 M0 总门仍为 IN_PROGRESS**

## 1. 本切片交付与边界

本切片只在安全启动器创建的 Test-local 合成 workspace 内建立作业生命周期，不连接生产 writer，不处理任何真实原卷、题库、数据库业务数据或导出资产：

- `OperationContext`在 begin 时以 context、manifest、预算和 policy digest 形成原子 pin；活跃 operation 期间外部 revoke 被拒，失败 begin 原子回滚 pin，同一 context 可在 mutex 释放后重试；close 在同一 authority 内原子消费 pin 并撤销 context；
- Windows Local named mutex 覆盖 operation 全生命周期；ledger 在已有 mutex lease 下只读全链重扫，不嵌套取锁、不追加 segment；
- 固定路径仅为`tmp/jobs/<INTERNAL|RESTRICTED>/<JOB_ID>/publish/<MANIFEST_ID>`，所有目录由相对 parent handle 的`NtCreateFile(FILE_CREATE)`创建，不接受已存在对象、不重用 job root、不清理失败残留；
- `job-contract.json`绑定 context、manifest、预算、policy 和 ledger head；创建后保留 share=0 的同一文件 handle，operation 每次使用前复算身份、ADS、大小与 SHA-256；最终验证失败、句柄关闭失败或 native success 无有效 receipt 时 seal writer 并 best-effort 关闭全部已知句柄；
- manifest 逐项冻结路径、类型、大小和 SHA-256；预算覆盖 entries、files、directories、depth、单文件、总字节、UTF-8 路径、open handles、manifest 字节、elapsed time 和 free-space reserve；耗时创建、hash、scan 和 ledger 重验后再次检查；
- 树扫描保留 root/child handles，拒绝 reparse、ADS、硬链接、未知类型、大小写冲突、未声明/缺失项和预算越界；内容 hash、Merkle-like tree、topology、live identity 与 ledger head 形成不可 pickle 的 live evidence lease；
- 复验执行目录 PRE 枚举、节点身份/内容 hash、目录 POST 枚举、最终节点身份/ADS/硬链接检查。任何 owner-side 漂移、writer seal、ledger drift 或资源超限均永久 invalidate evidence，不能通过撤销异常项恢复；
- RESTRICTED 正向路径只允许`IMPORT_SERVICE + COPY_SOURCE`，contract 的`public_ids=null`，异常、repr 与 evidence 不出现 run/job/operation/manifest/checkpoint、绝对路径或 payload；
- production facade 继续`writer_available=false`，没有`begin_operation`、staging、tree evidence 或写接口；459 个生产入口仍全部`UNMIGRATED_BLOCKED`。

## 2. 重要语义限制

普通用户态 Windows 目录 handle、R/RH directory oplock 与变更通知都不能冻结 child namespace。微软合同明确目录内容变化的 oplock break 是 advisory-only，不要求 acknowledgment；因此本切片不声称 hostile-writer 原子 snapshot。

`ObservedTreeEvidence`的准确语义是：在受信任 Test-local 源码、同一 named mutex 与 live handles 下，最近一次前后双遍扫描期间保持稳定的可重验观察。`evidence`属性本身会重新完整验证；摘要不能单独成为 S3-E mutation authority。S3-E 必须接受 exact live lease，在 syscall 前重验、变更后完整重算，并以持久 PREPARED/MUTATED/COMMITTED/IN_DOUBT 账本处理无法消除的外部竞态。

## 3. 安全、失败与恢复矩阵

S3-D 定向测试覆盖：

- INTERNAL 与 RESTRICTED 完整 staging、Unicode 路径、空文件/空目录、manifest/tree/topology/identity/ledger 绑定；
- payload 不符、缺项、额外项、大小写冲突、ADS、directory ADS、硬链接、same-size rewrite、root/nested 竞态、writer seal 与永久 evidence invalidation；
- authorization 后竞争者插入 final、native create success 但 receipt 丢失、invalid disposition/handle、最终 contract revalidate 失败、close-then-seal 与全部已知 handle 可重开验证；
- context 缺 scope、actor/classification 错配、活跃 revoke、closed/replay/cross-thread/pickle 与同 job root 重用拒绝；
- declared budget 8 个维度 exact/+1、open-handle不变量、elapsed/disk reserve、observed extra over-budget、launcher file-depth final/runtime 监控；
- 真实子进程在 contract 后`os._exit`：job residue 保留，abandoned mutex 被 fresh durable open 观察，同 job 不被接管；
- 独立子进程持 operation mutex：parent begin 得`MUTEX_BUSY`且 pin 回滚；释放后同一 parent context 成功重试；
- under-existing-mutex ledger rescan 前后零 append；既有 segment 篡改后 seal，不修补、不新增 segment；
- 生产私有 job/contract lease constructor、alias、反射和敏感赋值继续由 exact static canary 拒绝。

失败运行全部保留并明确不计通过：`S3D-014`因并发`.git/index.lock`被 protected gate 判 effective 97；`S3D-016`暴露硬链接注入已被更早 share fence 阻止；`S3D-018`暴露五项测试预期/状态机缺口；更早 001—012 分别暴露 parent fence、sharing、ADS、directory-stream 与 runtime atomic-file race。没有失败运行改变活动数据库或受保护树。

## 4. 冻结 inventory

冻结预览：`RUN-20260711-M0-S3D-INVENTORY-005`。

| 项目 | 结果 |
|---|---:|
| 生产源文件 | 48 |
| 写/副作用入口 | 459 |
| 分片 | 19 |
| `UNKNOWN_DYNAMIC_CAPABILITY` | 0 |
| `UNMIGRATED_BLOCKED` | 459 |
| unauthorized guard findings | 0 |
| `production_writer_connected` | false |
| `m0_exit_allowed` | false |

| 锚点 | SHA-256 |
|---|---|
| inventory 文件 | `9cf2df8525b28447775d04dcca47c4bace05a224cb8edc637e6ff244854abf43` |
| inventory payload | `8834f86a9f31010bd173b7698422ddff5799111a762ba7659a53ec6d54d1cca4` |
| generator | `43e49d710ed86409961df1de8b149477098907e600d5d5b46f8a66f022d4fce8` |

## 5. 冻结运行证据

定向 S3-D：`RUN-20260711-M0-S3D-022`，结果`185 passed`，pytest/effective=`0/0`。

综合 writer/static：`RUN-20260711-M0-S3D-WRITER-014`，结果`502 passed, 1 deselected`，pytest/effective=`0/0`。唯一 deselected 仍是本机普通账户因`WinError 1314`无法创建实际 directory symlink 的已知能力门；没有提权、启用 Developer Mode 或改变系统策略。

| 门禁 | S3D-022 | WRITER-014 |
|---|---:|---:|
| JUnit tests / failure / error / skip | 185 / 0 / 0 / 0 | 502 / 0 / 0 / 0 |
| timeout | false | false |
| protected runtime changes | 0 | 0 |
| protected tree entry count（前后） | 84,474 / 84,474 | 86,351 / 86,351 |
| activity SQLite SHA 前后 | `1505bf05...ad1c94`相同 | `1505bf05...ad1c94`相同 |
| run tree / ADS / resource gate | safe | safe |
| source inputs | unchanged | unchanged |

| 证据文件 | S3D-022 SHA-256 | WRITER-014 SHA-256 |
|---|---|---|
| run manifest | `3bb6a90db31b850e788a95997ef8eb72bedc9ac476d71e8576f6f5ad39719c74` | `a7d9f26c0258cc4a593c019b7914428040472b0122de4bf33ae1bc48a2d8f759` |
| run result | `abf8e46eeb7deecad67c6a7e32fc7de0a00aa8ad4e65633fe4368596144d8065` | `78689ede3aa1493c89e3858b95ee28ea028a8e903fb6dd6104407157c81d6f4f` |
| JUnit | `338497e616ac495801f7645644189460ce6be3ab27d13e87de1b61112769ff95` | `1bcac390d6cecb812d6fd124ea58aa9060e96240946a2ac38d6be8114c139c4b` |

独立只读安全审计最终结论为`NO P0 / NO P1`，前提是遵守上述 live observation 降级语义；测试覆盖审计也确认本切片可冻结，AFTER_OBSERVE/业务 mutation crash 矩阵留给 S3-E/H。

## 6. 源码锚点

| 文件 | SHA-256 |
|---|---|
| `app/safety/job_operation.py` | `08441ca3da1303a6fc1e6188fb47fe2839aa3487f0309f8a98164207d2efc11a` |
| `app/safety/production_guard.py` | `4eb0bdb703aad00caf9db892df9a9eba4b5db27313d728b1ead6517aefe7e4d3` |
| `app/safety/segment_ledger.py` | `843a95580f6823f03e09c930277e21b9e5dc917f6e6aca002c981fe5d34c8535` |
| `app/safety/static_audit.py` | `96e64a071eb81ab0a577266e7b0b277421e41390cbd8d9a0c02dfa61009b042d` |
| `app/safety/windows_handle_writer.py` | `4204894e029fef637df7e1d4192b120a5dd735bc15fda92d9d3725d25cd953c0` |
| `scripts/run_safe_pytest.py` | `8d27cbbcc0cfd7ae85ded1b009bf951636829d077ebc40000656dc0152c83acb` |
| `tests/test_job_operation.py` | `83fe77c926ae53dba7a7460954de9facb218877fc17e94970fcd44d21bd37601` |
| `tests/test_segment_ledger.py` | `6e73ad0f99df28e9056a79d60ffa799d28fcf6da85dba7d6396bffe51a7934b2` |
| `tests/test_safe_pytest_launcher.py` | `3bd075ccd145c4040457cd2442c99a4ce8e68d8fec73e22508f3f17121e3d084` |
| `tests/test_write_entry_inventory.py` | `f574dfb4e49b56f2fb64c5a7d70aba168d8bc0bd8f3efdbc1dbe9dc17a5dabd1` |

## 7. 下一切片

S3-E 只能在 S3-D live lease 之上新增独立 operation ledger、exact pair reservation、source-root handle no-replace publish、PREPARED/MUTATED/POSTCONDITION/COMMITTED 与重启对账；不得把`PairEvidence`或脱离 lease 的`ObservedTreeEvidence`当 mutation authority。生产 writer、真实业务数据、数据库迁移、OCR、排版、导出和备份仍保持关闭。
