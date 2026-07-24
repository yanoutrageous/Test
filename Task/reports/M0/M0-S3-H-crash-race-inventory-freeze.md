# M0-S3-H 崩溃/竞态矩阵、历史全 DAG 与 S3 冻结

## 结论

M0-S3-H Test-local 候选和 S3 总门已在本机通过，并已形成 S3-H Git 检查点进入 M0-S4。该结论只覆盖受信任仓库源码、协作式应用 writer 和当前声明的 Windows/NTFS 边界，不代表 M0 或 M0—M5 完成：

- production writer 仍为`writer_available=false`；
- 468 个生产副作用入口仍全部`UNMIGRATED_BLOCKED`；
- 活动 SQLite、原始题卷、`Base/`和真实业务资料均未被改写；
- M0-S4 的 SQLite 迁移/Backup API、M0-S5 的领域模型/金标和 M0-S6 的真实用户流程仍未完成；
- 普通账户的真实目录 symlink 创建仍因 WinError 1314 单独受限，没有提权或修改开发者模式。

## 冻结合同

### 历史 operation epoch 解析

1. `logs/operations/segments`在同一 runtime mutex 内执行有界 no-follow 目录清单，最多接受 256 个 canonical operation epoch。
2. epoch 名称、大小写唯一性、对象类型、Reparse/链接属性和目录身份均须精确；未知对象、大小写冲突、替换或清单漂移一律 fail closed。
3. 每个历史 epoch 必须使用 audit ledger 已激活 revision 完整打开并认证。解析完成后再次核对目录身份和清单；验证期间发生替换或增删时封存 writer。
4. 调用方选定的当前 operation ledger 必须是已解析集合中的同一对象、同一 head、同一 policy/revision/audit ancestry，不能用调用者构造的单一 ledger 代替历史集合。

### Audit → Operation → Copy 全 DAG

1. Copy rotation preflight 先认证 audit，再认证全部历史 operation epoch，最后认证每个历史 Copy source/copy 双链。
2. operation segment SHA 和 opaque epoch reference 在历史集合中必须各自只有一个 owner；重复归属或缺失 owner 均为矛盾。
3. 每个 Copy typed terminal 必须解析到唯一 operation epoch、唯一 transaction receipt 和相同 signing revision。
4. operation absence witness 同样必须解析到唯一历史 epoch；引用 epoch 缺失、损坏或使用其他 signing revision 时保持现场并 seal，不自动修复、补链或跳过旧 epoch。
5. 单 epoch helper 只作为多 epoch验证器的窄包装，正式 rotation 使用完整历史集合。

### 崩溃与竞态真值表

| 情形 | 冻结结果 |
|---|---|
| cooperative writer mutex 竞争 | `MUTEX_BUSY_NO_MUTATION` |
| hostile target 在 rename 前抢占 | `ABORTED_NO_OVERWRITE` |
| hostile source namespace 在 native boundary 前漂移 | `REJECTED_NO_MUTATION` |
| native boundary 后 namespace 漂移 | `IN_DOUBT_AND_WRITER_SEALED` |
| 进程在 rename 前`os._exit(71)` | 只追加一次`RECOVERED_ABORT` |
| 进程在 rename 后`os._exit(72)` | 只追加一次`RECOVERED_COMMIT` |
| COMMITTED terminal append 前`os._exit(73)` | 只追加一次`RECOVERED_COMMIT` |
| COMMITTED terminal append 后`os._exit(74)` | replay 原`COMMITTED`且链不增长 |
| hostile external writer freeze | 不作保证；检测到矛盾时 fail closed/seal |

四个真实子进程用例均核对 exact source/target 状态、operation segment 数、terminal state、受保护 sentinel，并在 fresh reopen 后再次 replay，证明恢复只发生一次且不会重复 mutation。

## 主要实现

- `app/safety/operation_ledger.py`
  - 有界 no-follow operation epoch catalog；
  - 同 mutex 历史 resolver、全链认证和结束时身份/清单复核。
- `app/safety/copy_ledger.py`
  - 多 operation epoch terminal/absence-witness 解析；
  - 唯一 segment/epoch-reference owner；
  - Audit → 全部 Operation → Copy 双链的完整 DAG 验证；
  - rotation preflight 对所有历史 Copy epoch执行完整验证。
- `app/safety/production_guard.py`
  - 工厂在同一 mutex 内解析完整历史，验证调用者当前 epoch/head，再创建 Copy ledger；
  - policy、revision、audit ancestry 和完整 DAG 统一 fail closed。
- `app/safety/static_audit.py`
  - resolver、multi-epoch terminal、full-DAG helper 的 exact import/call/private authority scope；
  - 相邻方法或旧单 epoch调用范围不获得授权。
- `scripts/run_safe_pytest.py`
  - 新增`s3h`和`s3h_core`门；
  - 正常 pytest 主进程退出后若 Job Object 仍有意外子进程，显式终止并等待 active process 列表归零后才返回，消除 kill-on-close 异步竞态。

## 测试收敛

| 运行 | 结果 | 结论 |
|---|---:|---|
| `RUN-20260724-M0-S3H-CORE-064` | 11 passed | crash/race 与历史 resolver 核心矩阵通过 |
| `RUN-20260724-M0-S3H-STATIC-065` | 12 passed | exact 静态授权与反向金丝雀通过 |
| `RUN-20260724-M0-S3H-LAUNCHER-066` | 90 passed | S3-H launcher 选择和安全入口通过 |
| `RUN-20260724-M0-S3H-POLICY-067` | 30 passed | 三次 rotation、历史 epoch 和票据兼容通过 |
| `RUN-20260724-M0-S3H-S3-TOTAL-071` | 996 passed, 1 failed | 仅旧 S3-F 静态样例仍把调用放在单 epoch helper；全部安全门干净 |
| `RUN-20260724-M0-S3H-CORE-072` | 34 passed | 样例改为 multi-epoch exact scope 后通过 |
| `RUN-20260724-M0-S3H-INVENTORY-GATE-074` | 34 passed | 首次清单发布后核心门通过 |
| `RUN-20260724-M0-S3H-S3-TOTAL-075` | 996 passed, 1 failed | 暴露 Job Object kill-on-close 后立即检查的异步竞态；全部安全门干净 |
| `RUN-20260724-M0-S3H-LAUNCHER-076` | 90 passed | 显式 terminate + active-list drain 修复通过 |
| `RUN-20260724-M0-S3H-INVENTORY-GATE-078` | 34 passed | 最终清单与 S3-H 核心门通过 |
| `RUN-20260724-M0-S3H-S3-TOTAL-079` | 997 passed，1 deselected | S3 总门最终通过 |

失败轮次 071/075 均保留真实失败，没有降低断言、删除测试或包装成通过。两轮的保护树、活动数据库、runtime watcher、句柄围栏、run tree、不可变证据、源码门和进程树均保持安全；其原因和替代轮次已进入已校验归档。

## 最终 S3 总门

`RUN-20260724-M0-S3H-S3-TOTAL-079`：

- 创建/完成时间：2026-07-24 22:58:34—23:20:31 +08:00；
- effective/pytest exit code：0/0；
- JUnit：997 tests，failure/error/skip 均为 0；另有 1 个真实目录 symlink 用例按独立能力门排除；
- JUnit SHA-256：`b7aa725cbb6d2589930c1a0c10b2af807e17c07e55e1fbeefe02c4b01fb1e39d`；
- 保护树：前后均 4,741 项，digest 均为`f70573b3d06adcd0eb1e10acafff4574f2afdf72890689f62e3809bf2765dcae`；
- 句柄围栏：4,741 项，有效；
- 活动 SQLite 前后 SHA-256 均为`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`；
- 80 个登记源码见证全部匹配，witness SHA-256 为`13808605ceab47d520d2dd09d138ee1ac146fd4e1bc9aa5d6e584c3377ac5873`；
- runtime watcher、run tree、不可变证据、源码状态门和进程树全部通过；
- 运行树 8,795 项、104,187,081 bytes，未超预算。

## 最终静态清单

`RUN-20260724-M0-S3H-INVENTORY-077`与跟踪文件逐字节一致：

- scanner：`M0-S3-STATIC-AUDIT-V16`；
- 53 个生产源、468 个入口、19 个分片；
- `UNKNOWN=0`，468 个入口全部`UNMIGRATED_BLOCKED`；
- `production_writer_connected=false`、`m0_exit_allowed=false`；
- inventory payload SHA-256：`6f9624ecfa941e54cfb1e8f08015952d725785ae15bd1bd9a1a338e27d0d9d9a`；
- manifest file SHA-256：`df0a9bafe99303b0052c9dbff86b0b05bb8b69683ed1bfb5831ee5c564a7bc6f`；
- entries digest：`ddbd195c43989b57de19e03077f090f60ed6887973bb4e55e8397453d1616e91`；
- source-manifest digest：`1943028542323bcd43bba9223947bb38e437e7941332ca7d9b87f998fe473569`。

## 独立只读复核

在 safe launcher 之外使用 PowerShell/.NET 标准 JSON、XML、SHA-256 和严格 UTF-8 解码独立复核：

- `run-result.json`、JUnit testcase 节点和 JUnit 文件哈希一致；
- 14 个最终安全/源码门字段全部为真；
- 19 个 tracked chunk 与 preview、manifest 和 summary 哈希逐个一致，合计 468 条；
- 53 个生产源按`UTF8_LF_V1`重新规范化后，大小和 SHA-256 全部匹配；
- 保护树前后数量一致，复核错误数为 0。

独立复核结论：`PASS`，未发现 P0/P1。

## 门禁存储整理

- 059—067 的 8 个已结束运行归档为`test-lab-increment-RUN-20260724-M0-S3G-POSTCLEAN-059-through-S3H-POLICY-067.tar.gz`，8,005,286 bytes，6,471 个成员，SHA-256 `f226a3b9bcdbd0e84a4088db38b7533d627cee9c2444c3bb119e4dd1d98d3400`。
- 070—078 的 7 个已结束运行归档为`test-lab-RUN-20260724-M0-S3H-070-through-078.tar.gz`，14,103,077 bytes，20,312 个成员，SHA-256 `5bdc4786012e69488f5c40d279333bd464a905ee7e1ea9d80f470c6cbf02d30d`。
- 被替代的 inventory preview 分两包归档，SHA-256 分别为`25c99dcb47eb6c89d0c121dcadc72ea8a651e0f0c318163a9446adb9fb7615bc`和`f99715af4e60b46a58b47964cac94fc0cc2dc9ee069382c8e7b55b40a0bf1e74`。
- 上述原始运行目录已可恢复地迁出 E 盘；没有递归删除或触碰业务资产。
- `tmp/test_lab`只保留最终全绿`079`（约 104.2 MB 逻辑大小），`tmp/inventory_preview`只保留最终`077`（约 0.52 MB）。
- E 盘整理并完成最终门后可用空间约 60.63 GiB。当前 6 个便携归档合计约 617.1 MiB，不进入 Git。

## 后续边界

S3 已冻结，但以下事项继续阻断 M0：

1. M0-S4：只追加 SQLite schema migration、SQLite Backup API、staging restore、完整性和回滚演练；
2. M0-S5：版本化领域对象、Question/Figure/Paper IR、金标 registry 和视觉阈值；
3. M0-S6：真实 Test 外只读样本 Copy、fresh-state 用户流程、独立安全审计和恢复演练；
4. production writer 和 468 个入口只有在对应后续门禁通过后才能逐步接线。

## Git 检查点

- 准入范围恰好 21 个显式路径；未使用`git add -A`或宽范围暂存。
- staged 审计无额外/缺失/禁止路径，无删除、重命名、二进制、超过 1 MiB 文件、异常模式、秘密/PII、新绝对路径或`diff --check`问题。
- S3-H 检查点提交：`b38dd5e5399cc37dae3fa1086b29c7b5e1385477`。
- 已普通 push 到`agent/m0-m5-local-v1`；本地、origin、远端 refs 与 Draft PR #2 head 核验一致。
- Draft PR #2 保持 OPEN/DRAFT/MERGEABLE，没有合并、改为 Ready、force push 或改写历史。
