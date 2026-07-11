# M0-S3-E pair reservation、operation ledger 与目录根发布报告

- 执行日期：2026-07-12（Asia/Shanghai）
- 范围：Test-local、INTERNAL 合成目录发布；生产 writer 继续断开
- 当前结论：S3-E 最终候选、inventory preview、launcher 门、组合门和三路独立复核均通过；S3-F—H、S4—S6 与 M0 总门仍为 IN_PROGRESS

## 1. 本切片完成的边界

本切片只证明同一安全实验室、同一 named mutex、同一 operation/context pin 内的目录根发布与重启对账。没有读取或处理真实题库、原卷、活动数据库、OCR、排版、导出或备份数据；没有删除、覆盖或清理任何失败现场。

生产 facade 仍返回 `writer_available=false`。V9 inventory 的 460 个生产副作用入口仍全部为 `UNMIGRATED_BLOCKED`，`production_writer_connected=false`、`m0_exit_allowed=false`。

## 2. exact pair reservation

S2 的候选 pair 仍不能直接授权 mutation。S3-E 新增线程绑定、不可序列化、单次使用的 `_ReservedPairLease`：

1. `_reserve_pair()`先把 pair/source/target 三条 registry 记录原子替换为 exact `RESERVED` copies，再返回 lease，不再返回旧 `ISSUED`对象；
2. lease 绑定 boundary core、三条 registry 对象、context digest、S3-D `_JobContextPin`、binding SHA-256 和 owner thread；
3. 每次实际使用重新核对 registry 对象身份、Guard、policy、classification flow、pair topology 与 live context pin；
4. `_finish_pair()`只接受 exact live lease 和 `CONSUMED`/`FAILED`终态，typed tombstone 能区分两类结果；
5. 任一 registry、线程、pin、binding 或 cleanup 漂移均失败关闭，不允许重复消费。

旧 `revalidate_pair()`保留“候选重验后消费”的测试语义，不成为 writer API。唯一实际目录发布入口位于 `_OperationLease.execute_publish_pair()`。

## 3. 独立 durable operation ledger

新增 `app/safety/operation_ledger.py`，固定存储为：

```text
logs/operations/segments/<epoch_id>/<sequence>-<segment_sha256>.json
```

该账本与 audit event ledger 分离，采用独立域：

- `OPERATION-SEGMENT-V1`；
- `OPERATION-SEGMENT-AUTH-V1`；
- `OPERATION-TRANSITION-V1`；
- `OPERATION-ROOT-IDENTITY-V1`。

每个 segment 为 canonical ASCII JSON、单硬链接普通文件、previous-hash chain、SHA-256 和 HMAC；先写唯一 PENDING 文件，flush/重开/复算后 source-handle no-replace 发布。启动和每次追加前后都完整扫描全链；未知文件、PENDING、缺号、断链、HMAC/政策/key revision/schema/transition 漂移、同 ID 异文或非法状态跳转均 seal。新事务在写入 `PREPARED` 前一次性预留最坏 `PREPARED/MUTATED/POSTCONDITION_VERIFIED/IN_DOUBT/RECOVERED_*` 五段及对应字节容量。

状态机固定为：

```text
NONE -> PREPARED
PREPARED -> ABORTED | MUTATED | IN_DOUBT
MUTATED -> POSTCONDITION_VERIFIED | IN_DOUBT
POSTCONDITION_VERIFIED -> COMMITTED | IN_DOUBT
未终态 -> RECOVERED_COMMIT | RECOVERED_ABORT（仅限真值表允许）
```

只有 `COMMITTED` segment 已 no-replace 发布、重新全链扫描并返回 exact receipt 后，pair 才进入 `CONSUMED`且调用方才收到成功。`COMMITTED`、`RECOVERED_COMMIT_WITH_NATIVE_MUTATION`和`RECOVERED_COMMIT_OBSERVATION_ONLY`使用分型 receipt；恢复摘要不冒充原生 rename receipt。相同 operation ID 的终态重放只返回既有 durable receipt，不再次 rename 或新增 segment。

operation epoch 的签名 key 固定锚定其 genesis，使旧链和 root identity 在 audit key rotation 后仍可验证；但旧 epoch 立即变为 replay/recovery-only，新事务必须使用当前 active revision 初始化新 epoch。未被 audit chain 实际激活的 key-store revision 不进入 operation authority。factory、普通 begin、terminal replay 和 recovery 均核对所有 transaction/recovery audit heads 仍属于已认证 audit chain。

## 4. 现有 mutex 内 audit append

S3-D operation 从开始到结束一直持有 Windows Local named mutex。pair 的 ISSUE/REVALIDATE audit 因此新增 exact `RuntimeMutexLease` 私有 append 路径，避免嵌套获取同一 mutex：

1. 完整重扫 audit chain；
2. 以当前 active key revision 构造 audit events；
3. immutable segment no-replace 发布；
4. 再次完整重扫并核对 receipt；
5. pair 初始 ISSUE/REVALIDATE 后 operation 明确要求 audit head 恰好增加两个 segment；实际 mutation 前的最终 REVALIDATE 再要求 head 精确增加一个 segment；两次均重新计算 live observed evidence，`PREPARED`绑定最后一个 head。

此路径不向 production facade 暴露，V9 静态门对构造器、私有 imports、反射和所有 mutation/recovery 私有调用点设有 exact allowlist 与 canary。

## 5. handle-bound 目录发布

严格顺序为：

```text
live tree revalidate
-> target parent fences / same-volume / target-absent check
-> PREPARED durable
-> Guard pair reservation + final full-tree revalidate
-> close descendant handles, retain source-root DELETE handle and parent fences
-> final source-bound / target-absent check
-> SetFileInformationByHandle(ReplaceIfExists=false)
-> same source-root handle final-path / file-ID / source-gone / target-bound check
-> MUTATED durable
-> independently reopen target root
-> full target tree rescan and exact source snapshot comparison
-> POSTCONDITION_VERIFIED durable
-> COMMITTED durable
-> pair CONSUMED
```

源根创建 handle 保留 `FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY` access，因此独立目标重开必须 share READ/WRITE/DELETE；原源根 handle 自身仍只 share READ，继续拒绝外部新写者。这一对称共享要求已由真实 NTFS 测试确认。

目录 child namespace 不能由普通用户态 handle/oplock冻结。S3-E 只承诺同应用单写者下的 handle-bound publish；外部竞态由最后检查、内核 no-replace、目标完整复算和 `IN_DOUBT`/seal 检测，不宣称对任意 hostile 本机进程提供原子目录 snapshot。

## 6. 重启对账

对账从 durable operation chain 取得固定 INTERNAL relative locators，不接受调用者重新提供路径。每个存在侧在同一 application mutex 下分别进行两次完整 handle tree scan，并以 operation-key HMAC 复算 root volume/file ID。恢复事实发布后再次执行同样的 source/target 双观察；前后任何漂移都 seal，不返回成功。

唯一自动追加的事实是：

| 上一状态 | source | target | 结果 |
|---|---|---|---|
| PREPARED | exact | absent | RECOVERED_ABORT |
| PREPARED | absent | exact same root/tree | RECOVERED_COMMIT |
| MUTATED/POSTCONDITION_VERIFIED | absent | exact same root/tree | RECOVERED_COMMIT |
| IN_DOUBT，尚无 mutation receipt | exact | absent | RECOVERED_ABORT |
| IN_DOUBT | absent | exact same root/tree | RECOVERED_COMMIT |

双存、双失、任一 mismatch、同内容不同 root ID、audit head/budget 漂移、reparse、扫描竞态或其他组合全部进入 `RECOVERY_CONTRADICTION`并 seal。恢复 reason/state、authority head、scope 和 observation receipt 均由前序 durable facts 重算；`guarantee_scope`固定为`COOPERATIVE_APPLICATION_WRITERS_ONLY`。恢复从不执行 move、replace、delete 或 cleanup，也不宣称抵抗任意 hostile external writer 的原子 snapshot。

## 7. 测试证据

### 通过运行

| Run | 结果 | 关键事实 |
|---|---:|---|
| `RUN-20260712-M0-S3E-007` | 6 passed | 正常 publish、目标竞争不覆盖、未知 PENDING、无账本拒绝、opaque lease/receipt、未决启动阻断 |
| `RUN-20260712-M0-S3E-008` | 7 passed | 增加 PREPARED/source-exact 恢复撤销和 rename 后崩溃恢复提交 |
| `RUN-20260712-M0-S3E-009` | 366 passed | S3-E + S3-D + handle writer + durable ledger + policy/static/inventory 组合门 |
| `RUN-20260712-M0-S3E-016` | 30 passed | 扩展 attack/replay/rotation/capacity/recovery truth matrix 核心门 |
| `RUN-20260712-M0-S3E-LAUNCHER-018` | 72 passed | safe launcher 与 S3-E exact mode selection 门 |
| `RUN-20260712-M0-S3E-COMBINED-019` | 399 passed | 最终 S3-E/S3-D/writer/ledger/policy/static/inventory 组合门 |

`RUN-009`：pytest/effective exit 均为 0；JUnit 366 tests、failure/error/skip 均为 0，SHA-256 为 `9a2bb42c1c09b80358fbf7e3b055accd1836f7c38f555c2f0440fae9d2563239`。保护树前后均 93,762 条、digest 均为 `ab4be5df72f7ef8b45da36d6bca8bbc82c09cb09dd7dfe6e5a02fe306a5e0630`；runtime changes 0；活动 SQLite 前后 SHA-256 均为 `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`；source inputs unchanged。

最终 `RUN-COMBINED-019`：pytest/effective exit 均为 0；JUnit 399 tests、failure/error/skip 均为 0，SHA-256 为 `83252bf90f3a738797470b4b751683ec31260bd8023517e4046ffbd39de0c514`。保护树前后均 99,504 条、digest 均为 `5f54cbc367373f500081e2d3f88e6c8f2f2c8e507a229487159ad9756c6c958c`；runtime changes 0；活动 SQLite 前后 SHA-256 均为 `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`；source inputs unchanged。三名独立只读复核者分别复核最终 pair/audit 绑定、operation/key/capacity、recovery proof/祖先关系，结论均为当前范围 `P0=0、P1=0`。

### 失败但保留的开发运行

- `RUN-20260711-M0-S3E-003`：6 setup errors + 5 static/inventory failures；暴露 operation store 扫描预算与 inventory 漂移；保护树和活动库不变；
- `RUN-20260711-M0-S3E-004`：6 setup errors；确认底层 flat scan 上限为 4096 entries/64 MiB，随后统一预算；
- `RUN-20260711-M0-S3E-005`：3 failures；真实 Windows target reopen 返回 sharing violation 32，确认需要 share WRITE；
- `RUN-20260711-M0-S3E-006`：5 passed、1 failure；剩余失败是 sealed writer 的测试关闭预期，修正为重启后从磁盘链对账。
- `RUN-20260712-M0-S3E-010`：permit 开放状态检查调用了不存在的 helper，安全门以 1 failure/1 teardown error 拒绝；
- `RUN-20260712-M0-S3E-013`：27 passed、1 failure；失败来自 byte-capacity 测试给 flat scanner 注入了无效测试上限，生产实现未越过边界；
- `RUN-20260712-M0-S3E-014`：pytest 未启动；并发只读审计刷新 `.git` 目录元数据，deny-write 建立期正确 `SAFETY_STOP`，源码/数据库/业务文件无变化；
- `RUN-20260712-M0-S3E-015`：29 passed、1 failure；测试仍期待 rotation 后旧 epoch 可继续新事务，修正为旧 epoch 只读并用当前 key 初始化新 epoch。

所有失败运行都由 safe launcher 判为 effective failure，未包装成通过；现场保留在各自 Test-local run 目录。

## 8. V9 inventory

- production sources：49；
- entries：460；
- chunks：19；
- UNKNOWN：0；
- 全部 `UNMIGRATED_BLOCKED`：460；
- inventory serialized file SHA-256：`1e8460c263a32ded3854604e919763e25c175f8fbbec1d7c01a5cf557c39b3ea`；
- inventory payload：`339a14b1e8de24eb8ea97e6f98b791fd24928875be50ce8d9e43f62fbd3a6fee`；
- source manifest：`9911b08fc919eb5afb943e0b0ee48bceda7c115b5b60c5b4133c8c96c886c43f`；
- entries digest：`72d962dd6e1bf59aefd299226504c64021b3640a008516f6f7eed385104dd77c`；
- preview `RUN-20260712-M0-S3E-INVENTORY-017` 与正式 manifest/19 chunks 共 20 个文件逐字节一致。

## 9. 明确保留的限制

- 本切片只开放 INTERNAL 合成目录；RESTRICTED locator/redaction 不在 S3-E 内临时实现，留给 S3-F/G 的 Copy/quarantine 双 ledger；
- 完整尾部与本地事实的一致回滚仍需要外部 witness/备份锚点，M0 当前没有该能力；
- ReFS、硬件断电语义和真实 symlink 权限门仍未验证；
- operation ledger 使用 genesis 时的 active audit key revision 派生独立域 key；rotation 后旧 epoch 只读重放/恢复，新写必须显式初始化当前 active revision 的新 epoch；
- 当前成功不代表 460 个 production 入口已经迁移，也不允许真实业务数据进入 writer。

## 10. 下一步

S3-F 只能在本切片冻结后新增合成 Copy 与 source/copy 双 ledger，SQLite 继续 blocked 到 S4。S3-G 实现 quarantine/保留式 restore；S3-H 扩展真实子进程崩溃点、竞态矩阵、inventory 冻结和独立审计。任何一步都不得接通 production writer 或处理真实业务资料。
