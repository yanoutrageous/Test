# ADR-2026-004：句柄内完成写入/发布，并以不可变 segment 形成持久账本

- 状态：Accepted for Test-local candidate implementation
- 日期：2026-07-11
- 决策级别：D2
- 影响里程碑：M0—M5
- Requirement IDs：`M0-SAFE-001`—`M0-SAFE-007`
- 补充 ADR：`ADR-2026-002-workspace-guard-capability-boundaries.md`、`ADR-2026-003-fixed-production-boundary-and-candidate-only-policy.md`
- 后续修订：`ADR-2026-005`取代固定 D 盘物理路径；本文既有 run 路径继续作为历史证据

## 背景与已确认事实

M0-S2 只签发候选能力。当前`revalidate_pair()`在重验后立即消费 pair 并释放底层 Guard 票据；如果随后再按路径调用`move/replace`，检查与写入之间会重新出现竞态窗口。`PairEvidence`仍是调用者声明，`CollectingAuditSink`只保存在内存，随机 audit HMAC key 也不能跨重启核验受限记录。

现有 namespace 把 Audit/Copy ledger 固定为一个`events.jsonl`。单一可追加文件无法在不截断历史的前提下提供批次整体发布、缺号/断链检查和崩溃后的明确对账。现有 inventory 中唯一`FILESYSTEM_COPY`是 SQLite 文件复制“备份”；它不得迁移为通用 Copy，必须等 S4 SQLite Backup API 与恢复门禁。

微软 Win32 合同确认：

- `CreateFileW`配合`FILE_FLAG_OPEN_REPARSE_POINT`可在打开现存对象时避免正常 Reparse 解析；目录 handle 需要`FILE_FLAG_BACKUP_SEMANTICS`；
- `GetFileInformationByHandleEx`可读取`FileIdInfo`和`FileAttributeTagInfo`，用于把 volume/file ID、属性和 Reparse tag 绑定到已经打开的 handle；
- `SetFileInformationByHandle(FileRenameInfo)`可按 source handle 改名，source handle 必须拥有所需权限，且`ReplaceIfExists=false`时目标冲突必须失败。

Win32 的`FILE_RENAME_INFO.RootDirectory`文档要求设为 NULL，因此实现不得假设它支持目录相对改名。目标使用经过 deny-delete handle 围栏稳定住的同卷绝对路径；source 身份始终由 source handle 决定。

## 决定

### 1. 先建 Test-only handle kernel

S3-B 先实现只在安全 test_lab 使用的最小 Windows handle kernel，生产 facade 保持`writer_available=false`。核心原语仅包括：

- 打开并核对现存对象；
- 持有根、祖先和父目录的 deny-delete handles；
- `CREATE_NEW`独占创建 job/staging 文件；
- 从同一 handle 写入、flush、读回哈希和核对 file ID；
- 打开现存文件并核验后只允许有前置哈希/长度的 append；M0 禁止原地 truncate，替换必须走新 staging 加 no-replace publish，禁止`CREATE_ALWAYS`绕过身份检查。

S3-B 不提供目录创建、rename 或树枚举。Win32 `CreateDirectoryW`不能原子返回新目录 handle，创建后再打开存在 child replacement 窗口；目录 job primitive和受控树枚举延后到 S3-D，source-handle no-replace rename 延后到 S3-E。完成前只使用安全实验室预先建立的合成目录，且不能把 S3-B 描述为 S3 全部完成。

句柄、原始路径和 Win32 handle value 不得泄漏到业务层。所有能力单次使用、不可 pickle；失败后不自动删除残留物，残留 staging 只能由后续 manifest-bound quarantine/recovery 流程处理。

### 2. pair 必须在 reservation 内完成实际操作

实际 publish/quarantine API 必须在`_reserve_pair()`取得 source/target 记录和 live Guard 票据后，在同一内部操作中完成：

```text
reserve
→ 打开并核对 handles
→ 重算 observed evidence
→ 持久 PREPARED
→ handle mutation
→ target 后置重算
→ 持久 COMMITTED/IN_DOUBT
→ finish pair
```

禁止把现有“重验并消费”结果当作随后裸文件操作的授权。S2 的`revalidate_pair()`继续只代表候选测试，不成为 writer API。

### 3. observed evidence 高于 declared evidence

`PairEvidence`继续只用于候选预检。writer 从实际 source handles 重算：规范相对路径、对象类型、每个文件 SHA-256/大小、entry count、total bytes、manifest hash、树 hash、volume/file ID、Reparse/硬链接/额外输出和大小写冲突。声明与实测不一致时零发布失败关闭；发布后必须从 target 完整复算并与 source observed evidence 相同。

### 4. Audit/Copy 改为不可变 segment ledger

Policy V7 将引入两个固定 segment store：

```text
logs/audit/segments/<epoch_id>/<sequence>-<segment_sha256>.json
Copy/ledger/segments/<epoch_id>/<sequence>-<segment_sha256>.json
```

每批一份 canonical UTF-8/LF JSON segment，至少绑定：ledger/epoch/schema、sequence、previous segment hash、batch/transaction/record IDs、policy ID/version/digest、classification/redaction/key ID、canonical records、batch hash、segment hash和 UTC 时间。

segment 先在同目录唯一临时文件写入、flush、重开复算，再以 no-replace 同卷 rename 发布。启动开放任何 Test writer 前，从 genesis 全链验证：文件名、序号、前链、内容哈希、规范 JSON、schema/policy/key、普通单链接文件、无 Reparse、无未知文件。无可修改 head 文件；当前 head 由完整扫描得到。

ledger 写入是最小信任根，不能为了记录 ledger 自身写入而递归调用同一 ledger。其边界由固定工厂、handle kernel、不可变 segment、启动全链验证和故障注入证明。

### 5. operation 状态机失败关闭

业务 mutation 采用：

```text
CANDIDATE → PREPARED → MUTATED → POSTCONDITION_VERIFIED → COMMITTED
```

- PREPARED segment 未持久化：零业务 mutation；
- mutation 前失败：追加 ABORTED；若账本不可用则 seal writer；
- mutation 已发生但终态 segment 失败：不返回成功，标记`IN_DOUBT`并 seal 后续写入；
- 重启只可在实际 evidence 唯一证明“已正确发布”或“未发布且旧状态完整”时追加 RECOVERED_COMMIT/RECOVERED_ABORT；
- source/target 双方同时存在、同时缺失或 evidence 矛盾时保持 sealed 并进入事故响应。

### 6. writer lock 与 key 生命周期

`Task/state/writer.lock`是 Codex 自动化运行层的手工/编排锁，不属于产品运行时写入接口；应用不得借此放宽整个`TASK_CONTROL`。产品运行时单写者使用基于 contract root digest 的 Windows Local named mutex，另以 ledger operation lease 约束业务生命周期。

测试可由私有 factory 注入 Test-only固定 key。生产 HMAC/redaction key 将作为项目内、不可提交 Git、可备份的版本化 key revision 管理；其威胁模型是防止误泄露和检测非预期变化，不宣称能抵御已取得本机项目目录读取权的恶意用户。生产 key store、轮换和恢复在 S3-C 单独实现和审计；完成前生产 writer保持断开。

### 7. Copy、quarantine 和 restore

- S3 Copy 只使用 Test 内合成 external-reference capability 验证流程；不得处理真实 Test 外资料；
- Copy 前后从 source/destination handles 重算身份、大小和 SHA-256，分类不得降级；
- SQLite/WAL/SHM/journal 永不进入通用 Copy，现有复制备份入口保持 blocked 到 S4；
- quarantine 只移动完整目录对象根到边界生成的固定目标，不增加通用 delete；
- restore 保留 quarantine 原对象，只读复制到新 staging，重验后走普通 publish；目标冲突时不覆盖；
- M0 不实现永久 purge。

## S3-C 实现冻结补充（2026-07-11）

S3-C 已在 Test-local candidate 中实现并通过独立复审，以下合同从本切片起冻结：

1. audit key revision 使用 schema 1.0、固定 32 字节 master key 和`HMAC-SHA256-DOMAIN-KDF-V1`；revision 正文 SHA 与文件名互相绑定，旧 revision 不可覆盖；
2. audit segment 使用 schema 1.0、显式 sequence 0 genesis、canonical UTF-8/LF JSON、完整 previous-hash 链、当前 Policy V7 和 key revision SHA；head 只能由启动全链扫描推导；
3. segment hash 使用`LEDGER-SEGMENT-V1`域，segment HMAC 使用`LEDGER-SEGMENT-AUTH-V1`域；key rotation segment 必须由旧 key 认证并绑定新 revision 的完整 SHA；
4. 固定 durable factory 在同一 live Windows Local named-mutex lease 内验证 key/segment store 都为空、发布初始 key 并创建 genesis；open 模式从不创建 key 或 genesis；
5. unknown/PENDING/child directory、缺号、分叉、tamper、schema/policy/key drift 或无法唯一解释的 crash 状态一律保留现场并 seal，不自动删除、截断、改名或补链；
6. audit event v2.1 的完整字段集合、decision/action/error 真值表、pair metadata、visible/HMAC context、SAFE_RELATIVE/HMAC_ONLY path 和 Restricted redaction 在 segment 签入前验证；
7. key store最多 64 个 revision，单 epoch 最多 4096 个 segment、64 MiB 总量、单 segment 2 MiB、单批 256 条；所有容量门在 publish 前判断；
8. production facade 继续`writer_available=false`，公开 namespace 对 audit/Copy ledger 和 key 只读；S3-C 不授权业务层直接构造 Store/Ledger/Sink/Authority 或直接写入其路径。

本冻结具有以下明确边界：

- 项目内 key 文件的威胁模型是防误泄漏与检测变化，不抵御已取得 Test 读取权的本机恶意用户；
- 没有外部 witness 时，项目内链不能证明“完整尾部与外部事实”未被一致回滚；
- 未来 schema、policy 或 audit-event 版本必须经显式 parser registry/新 epoch 迁移，不得让当前 parser 静默接受；
- 固定 factory 的首次初始化是同一 mutex；底层带私有 token 的直接测试 helper 可自行取 mutex，只是 trusted unit-test 例外，不能宣称所有底层构造路径天然同锁；
- 当前不承诺 ReFS 高位 File ID、硬件断电持久性或本机无权限创建的真实 symlink 门禁；
- 安全 launcher 约束受信任仓库测试，不是任意 hostile native code 的 OS sandbox。

S3-C 冻结不改变后续状态机顺序。operation lease、observed tree evidence、pair reservation 内 mutation、Copy 双 ledger、quarantine/restore 仍须在 S3-D—G 分别实现并通过故障恢复门禁。

## 被拒绝方案

### 重验 pair 后调用`shutil.move/os.replace`

拒绝。票据已消费，实际路径操作重新产生竞态，也无法把 observed evidence 与 mutation 原子绑定。

### 单一 JSONL 直接 append 作为全部持久审计

拒绝作为最终设计。崩溃可能留下不可区分的半批次；恢复需要截断历史或猜测。不可变 segment 可明确识别有效/无效批次并保留现场。

### 依赖管理员权限、Developer Mode、ACL 重写或外部沙箱

拒绝。当前授权不允许系统安全策略变化；应用安全边界仍须由自身句柄和数据合同证明。

### 用通用文件复制替代 SQLite Backup API

拒绝。活动 WAL 数据库复制不构成一致快照，也不能通过恢复门禁。

### 在 M0 增加原地 truncate

拒绝。`SetFilePointerEx`只移动文件指针，不能截断；即便增加`SetEndOfFile`，原地截断也会扩大“旧版本已损坏但新版本尚未验证”的事故面。M0 的可变配置和账本采用新 staging、完整读回、no-replace 发布和版本指针，不提供通用 truncate 能力。

## 子切片和验收顺序

1. S3-A：本 ADR、schema 和风险门冻结；
2. S3-B：Test-only handle kernel，生产 writer 仍断开；
3. S3-C：durable segment ledger、key revision、启动全链验证；
4. S3-D：operation lease、job staging、预算与 observed tree evidence；
5. S3-E：pair reservation 内 publish、后置验证和崩溃对账；
6. S3-F：合成 Copy 与双 ledger；SQLite copy 继续 blocked；
7. S3-G：quarantine、保留式 restore、冲突与重启恢复；
8. S3-H：竞态/崩溃矩阵、inventory 重建、独立审计和 S3 冻结。

每个子切片必须通过正常、边界、失败、恢复和安全路径；新入口在完整迁移前保持`UNMIGRATED_BLOCKED`。S3 结束也不等于 M0 验收，不允许进入 M1 或处理真实业务资料。

## S3-D 实现冻结补充（2026-07-11）

S3-D 已在 Test-local candidate 中实现并通过独立复核，冻结以下合同：

1. operation context 必须绑定 manifest、预算和 policy digest 并由 boundary 原子 pin；活跃时 public revoke 拒绝，begin 失败回滚 pin，close 原子消费 pin 和 context；
2. job staging 只允许固定`tmp/jobs/<classification>/<job>/publish/<manifest>`布局；目录使用相对 parent handle 的`NtCreateFile(FILE_CREATE)`，job root 不重用，失败残留不自动删除；
3. `job-contract.json`从创建成功起持有 share=0 的同一 handle，并在 operation 每次使用前复算身份、默认 stream、大小和 SHA-256；任何 post-success 无 receipt、最终复验或 cleanup 不确定性都 seal writer；
4. 预算是不可变 operation 合同，覆盖 entries/files/directories/depth/file/total/path/open-handles/manifest/time/free-space，并在耗时步骤后再次检查；
5. tree evidence 必须来自实际 handles，执行目录 PRE 枚举、节点内容/身份检查、目录 POST 枚举和最终 ADS/hardlink/identity 检查；owner-side 失败永久 invalidate，writer seal 同时撤销所有 live evidence；
6. `ObservedTreeEvidence`不是可脱离 lease 使用的 mutation capability。属性读取会触发完整重验；S3-E 只能接受 exact live lease 并在 mutation 前后自行重验；
7. 普通用户态 Windows 目录 handle 和 directory oplock 不能冻结 child namespace。目录 oplock 对内容变化只提供 advisory break，因此本 ADR 不宣称 hostile-writer 原子 snapshot；无法消除的窗口由 S3-E 的 pre/post scan、持久 operation ledger 与`IN_DOUBT`/seal处理；
8. RESTRICTED job 只允许`IMPORT_SERVICE + COPY_SOURCE`，contract 不保存 public IDs，错误与 repr 不泄露业务标识、绝对路径或 payload；
9. production facade 继续`writer_available=false`；S3-D 不发布业务 pair、不接入真实数据，也不改变全部 inventory 项的`UNMIGRATED_BLOCKED`状态。

本补充拒绝把 directory share mode、oplock 或`ReadDirectoryChangesW`描述为 child namespace 强锁；也拒绝将单次 hash 摘要跨生命周期保存后直接用于发布。

## S3-E 补充：pair reservation 内的目录根发布与独立 operation chain

S3-E 采用以下不可逆约束：

1. pair/source/target registry 必须先原子替换为 exact `RESERVED` copies，再签发 owner-thread、context-pin、binding-bound `_ReservedPairLease`；旧 `ISSUED`对象不能成为 reservation authority；
2. 实际 mutation 只有 `_OperationLease.execute_publish_pair()`一个入口。旧 `revalidate_pair()`继续只做候选重验并消费，不允许随后裸调用 rename；
3. pair ISSUE/REVALIDATE 在 operation 已持有的 exact named-mutex lease 内追加 audit segment，禁止嵌套 mutex；初始授权后 audit head 必须恰好推进两个 segment，mutation 前最终 REVALIDATE 再精确推进一个 segment；两次都重新冻结 live observed evidence，`PREPARED`绑定最终 head；
4. mutation 状态进入独立 `logs/operations/segments/<epoch>` chain，不复用 audit event schema。operation segment 使用独立 domain/HMAC、previous hash、PENDING-to-no-replace publish、启动/追加前后全链扫描和固定资源上限；新事务在`PREPARED`前预留最坏五段生命周期和字节容量；
5. `PREPARED` durable 之前禁止调用 native rename；目录 child handles在最后一次完整 revalidate 后关闭，只保留同一 source-root DELETE handle和父目录围栏；
6. rename 只调用 `SetFileInformationByHandle`且`ReplaceIfExists=false`；native success 后必须核对同一 volume/file ID、source gone、target exact binding，再写`MUTATED`；
7. target 必须独立重开并完整复算 manifest/tree/topology/identity/count/bytes；`POSTCONDITION_VERIFIED`和`COMMITTED`都持久化且重扫确认后才消费 pair并返回成功；
8. native mutation 可能发生后的任何异常先尽力持久化`IN_DOUBT`再 seal；COMMITTED 后 cleanup 失败通过相同 operation ID 只返回既有分型 receipt，不再次 rename；
9. 重启恢复只追加事实，不移动、覆盖、删除或清理：source exact/target absent 可恢复撤销；source absent/target same-root exact 可恢复提交；双存、双失、mismatch、同内容不同 root ID或链/预算/audit head漂移一律`RECOVERY_CONTRADICTION`并 seal。恢复 reason/state/scope/authority head/observation receipt 必须由前序 durable facts重算，scope 固定为`COOPERATIVE_APPLICATION_WRITERS_ONLY`；
10. S3-E 只启用 INTERNAL 合成目录。RESTRICTED locator、Copy 双 ledger和 quarantine/restore 分别留给 S3-F/G，不通过临时明文路径或自创加密绕过。
11. operation epoch 以 genesis 时 active revision 锚定独立签名 key。audit rotation 后旧 epoch 仅允许 replay/recovery，新事务必须用当前 active revision 初始化新 epoch；未实际激活的 key-store revision 不得成为 authority；factory、begin、replay、recovery都核对引用的 audit heads仍在认证链中。

Windows 共享语义的实测补充：source-root handle在创建时取得`FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY`，逻辑 seal 不能撤回既有 access。因此独立 target verification handle 必须 share READ/WRITE/DELETE 才能与原 handle共存；原 handle仍只 share READ，外部新写 handle仍被拒绝。该要求不是 child namespace 强锁。

S3-E 仍不声称 hostile-writer 原子 snapshot。普通用户态目录 handle无法冻结 child namespace，且 rename 前必须关闭 descendant handles。named mutex约束本应用协作写者；最后检查、no-replace、post-rescan和恢复真值表负责检测剩余竞态，检测到不确定性只封存现场。

## S3-F 设计冻结补充：合成外源 Copy 与独立双账本

S3-F 在实现前冻结以下合同；本节若与本 ADR 前文单一`Copy/ledger/segments`示意冲突，以本节为准。该变更只影响 Test-local candidate，生产 writer 继续断开。

### 1. 范围和外源只读能力

1. S3-F 只处理 safe launcher 的`<run>/external/`内合成单文件；模拟项目根为同一 run 下的`<run>/project/`。两者都位于当前经验证的`PROJECT_ROOT\tmp\test_lab\RUN-*`内，但 external 必须在模拟 project 外；不得读取真实原卷、活动数据库或真实 PROJECT_ROOT 外资料。
2. 新建独立`SyntheticReferenceReadPolicy`和私有 factory。该 authority 只有`EXISTING_READ`，不得复用、改根或暴露带 mutation API 的`WorkspaceGuard`/`_WindowsHandleWriter`；固定 root、policy digest、run marker、COPY_ID、classification、owner thread 和单次 lifecycle 全部进入能力绑定。
3. source capability 从根到文件逐级使用 no-follow handle，目录和文件均拒绝 Reparse；源文件只允许普通、单链接、默认 stream 文件。source file handle 在整个 Copy 生命周期保持只读并拒绝 write/delete sharing；开始、读取后和返回前从同一 handle 重算 volume/file ID、大小、SHA-256 和时间/变化证据。
4. S3-F 外源输入上限固定为一个不超过 64 MiB 的文件；目录、多文件输入、ADS、硬链接、named pipe 和不稳定对象不在本切片范围。Copy 对象固定包含外源逐字节副本`payload.bin`和系统生成的 canonical `provenance.json`；后者不是第二个外源输入。S3-F 不声称保留原始文件名。
5. 经固定、密封的公开 boundary 正常调用时，source 的绝对路径、原始名称和 handle 值不得进入业务对象、异常、repr、receipt、audit、operation 或 Copy ledger。external locator 对 INTERNAL 和 RESTRICTED 都只以独立域 HMAC 保存；RESTRICTED 的 run/job/operation/copy/public IDs 同样不得明文落账。

上述异常脱敏边界不是同进程安全沙箱。它不抵御 hostile same-process 代码通过 `__globals__`、`__closure__`、`object.__getattribute__`、`gc`、monkeypatch、`ctypes`、模块或类方法改写等方式绕过公开 boundary、提取或直接调用内部 raw callable；这类能力也不属于 S3-F 的安全声明。能够与本模块同进程执行的仓库源码和测试代码必须视为受信任、已审阅代码，并由静态门和 safe launcher 排除上述绕过。异常 vault 仅用于收窄正常接口上的 traceback/exception 泄漏面，不能作为恶意 Python 代码隔离机制。

### 2. 双账本固定布局和独立认证

原`COPY_LEDGER`父 namespace 改为禁止直接访问；公开 policy 只允许经业务 context 读取以下两个精确、只读 namespace，私有 ledger factory 才拥有写入 store 的能力：

```text
Copy/ledger/source/segments/<run_id>/<sequence>-<segment_sha256>.json
Copy/ledger/copy/segments/<run_id>/<sequence>-<segment_sha256>.json
```

`<run_id>`是 ledger epoch，并绑定`RUN_ID` scope，不再错误绑定`COPY_ID`。两个 store 分别固定：

- `ledger_kind=COPY_SOURCE`，segment hash/auth 域为`COPY-SOURCE-SEGMENT-V1`/`COPY-SOURCE-SEGMENT-AUTH-V1`；
- `ledger_kind=COPY_OPERATION`使用 schema `1.3`，segment hash/auth/key/record 域固定为`COPY-OPERATION-SEGMENT-V4`/`COPY-OPERATION-SEGMENT-AUTH-V4`/`COPY-OPERATION-KEY-ID-V4`/`COPY-TRANSITION-V4`。

两条链从同一已激活 audit key revision 通过不同域派生互不相同的 HMAC key/key ID；segment 不能跨 store、kind、epoch 或 domain 互换。每条链独立拥有 genesis、sequence、previous hash、canonical UTF-8/LF JSON、policy/revision/key binding、PENDING-to-no-replace publish、容量上限、启动全链扫描和 seal 状态。unknown/PENDING、缺号、分叉、非 canonical bytes、错误 schema/policy/key/domain、篡改或引用矛盾一律保留现场并 seal，不自动清理或补链。

### 3. 单向证据 DAG 和状态机

跨链引用只能按以下无环方向形成：

```text
authenticated audit capability head
  -> COPY_SOURCE/SOURCE_OBSERVED record
  -> immutable provenance metadata + publish PREPARED/terminal
  -> COPY_OPERATION terminal
```

1. `SOURCE_OBSERVED`绑定 reference-read policy digest、audit head、classification、locator HMAC、source identity/size/SHA 和 transaction reference；取得真实 source receipt 后，以 source segment SHA、record SHA、完整脱敏 source record 和原 payload manifest 生成 canonical ASCII JSON + LF 的`provenance.json`。S3-E 实际发布树必须是`payload.bin + provenance.json`，因此 operation manifest、目标树和 Copy transition 均逐字节绑定该 metadata；只在 Copy ledger 中保存一个脱离发布树的摘要不满足本合同。
2. Copy operation 在任何目标 mutation 前持久`PREPARED`，绑定 source segment/record、预期 manifest、target locator HMAC、classification、audit ancestor 和资源预算；同时预留 source、Copy 和 publish-operation 三方最坏恢复容量。任一预留不足时目标必须不存在。
3. 实际目录发布仍只走 S3-E 的 exact reserved pair、source-root handle no-replace rename 与独立 target full rescan。S3-F 为 operation ledger 启用严格 typed locator：INTERNAL 为`SAFE_RELATIVE`；RESTRICTED 为域分离`HMAC_ONLY`，二者的字段形状、classification 和恢复输入必须精确匹配，禁止用明文相对路径绕过。该 INTERNAL `SAFE_RELATIVE`仅属于 operation ledger 的冻结语义；Copy ledger 的 persisted plan 对 operation/pair/transaction/source locator/target locator 一律再用 Copy epoch/run-scope key 和独立 role/mode 域投影为 HMAC，不得复制 operation ledger 明文。
4. Copy `PREPARED`必须保存域分离 HMAC 化的 planned operation binding；Copy transition 单独保存 factory 生成的 opaque publish transaction ID 供 typed lookup，persisted plan 只保存其 HMAC 投影。authenticated publish terminal 和 target 独立复算完成后，Copy chain 才依次追加`MUTATED -> POSTCONDITION_VERIFIED -> COMMITTED`；每段绑定 exact publish transaction/terminal segment、source record、目标 root/whole-tree identity、`payload.bin`及`provenance.json`各自 identity/size/SHA 和 manifest/tree/topology。fresh reopen 必须用 transaction ID 取得 typed operation terminal，再由持有 Copy key 的 projector 从真实 terminal 重建完整 HMAC plan 并精确比较，要求它确为同一 operation/context/manifest/target/classification/budget/source ancestry 的`COMMITTED`或`RECOVERED_COMMIT`，不得以“某个 SHA 出现在 operation chain 集合中”替代语义核验。只有 Copy terminal 已持久且所有祖先仍可认证时才能返回 typed success receipt。
5. 合法状态边为`None -> PREPARED -> MUTATED -> POSTCONDITION_VERIFIED -> COMMITTED`、`PREPARED -> ABORTED`、进入 native boundary 后到`IN_DOUBT`，以及从`PREPARED/MUTATED/POSTCONDITION_VERIFIED/IN_DOUBT`到唯一的`RECOVERED_COMMIT/RECOVERED_ABORT`。terminal 后不得追加或再次 mutation；相同事务 replay 只返回原 receipt。

### 4. 分类、SQLite 和不可变原件

1. destination partition 由 source classification 和 context 共同决定：INTERNAL 只能进入`Copy/source/<copy_id>`，RESTRICTED 只能进入`Copy/restricted/<copy_id>`；RESTRICTED 不得降级，字符串伪枚举或 scope/caller/purpose 不精确时零写拒绝。
2. 在 source ledger 或 staging 写入前，按不区分大小写的原始名称和同柄头部检查拒绝`.db/.db3/.sqlite/.sqlite3`、`-wal/-shm/-journal`、`.wal/.shm/.journal`以及`SQLite format 3\0`。活动库、sidecar、journal 或其硬链接永不进入通用 Copy；S4 之前没有例外。
3. target 必须 no-replace；同 copy ID 冲突不得覆盖。成功后的双文件 Copy object 是 immutable object store：公共能力不能 append、existing-write、replace、move或 child-create；可用性由 authenticated Copy receipt、typed publish terminal、canonical provenance 和 live target whole-tree rescan共同决定，不能只因路径存在就自动收养孤儿。

### 5. 崩溃恢复真值表

恢复只追加事实，不复制、rename、覆盖、删除或清理：

- source record 已认证、publish operation 未进入 native boundary且 target 不存在：在追加前执行不消费最终能力的同柄 source checkpoint，追加`RECOVERED_ABORT`后只执行一次 consuming final verification，保留 source record 和 staging；
- publish operation 已认证为 COMMITTED、target 双重 handle scan 与 source/provenance/manifest完全匹配、external source capability 重新验证一致，但 Copy terminal 缺失：只追加一次`RECOVERED_COMMIT`，不得再次发布；
- Copy COMMIT 已持久但调用方未收到：replay 原 typed receipt，segment 数不变；
- source 无法重新验证、target 双存/双失/缺失/错身份/错内容、classification/budget/head漂移、source/copy/operation/audit任一祖先缺失，或任何组合不能唯一解释：`RECOVERY_CONTRADICTION`并 seal，保留现场。

RESTRICTED 恢复不从 HMAC 反推路径，也不得由 Copy 代码根据 context 自行拼接路径。调用者必须在每次`reconcile`前，使用同一 reopened boundary 和此次 recovery operation 的 exact context 对象重新签发单次、owner-thread-bound、purpose-bound recovery locator capability；`reconcile`须在打开 external source、观察 target 或追加账本前消费它，并同时核验 capability 返回的 source/target 与 authenticated publish transition 的两个 locator HMAC。INTERNAL recovery 必须拒绝多余 capability。不得引入可逆路径加密来绕过脱敏合同。

### 6. 验收边界

S3-F 必须通过正常、边界、失败、恢复、安全、属性和故障注入测试，并以 fresh reopen 验证两条链及交叉祖先。safe launcher 只能证明候选没有 Test 外 mutation authority，以及每个已登记合成源的登记快照与`pytest_sessionfinish`终态在 identity/metadata/bytes/default-stream 上等价；该 witness 不证明两个观测点之间从未发生瞬时变化。真正 Copy 生命周期内的不变性由同柄只读、deny-write/delete sharing 和 Copy 前后/恢复重验共同支撑。launcher 不监控整机所有 Test 外路径，不能据此声称全程源不变或全盘动态零写。真实 Test 外 Copy 旅程留在完成 S3-H 安全冻结后的 M0 用户流程，并须对被选 source 及父目录另做定向只读 witness。

本切片不连接 production facade，不迁移任何 production inventory entry，不处理真实业务资料，不实现 quarantine/restore，也不进入 M1。

### 7. S3-H 前不得扩大解释的历史验证边界

1. 新 Copy epoch 的 rotation preflight 只认证**同一逻辑 RUN**映射出的历史 source/copy 双链、HMAC、对称性和 pending 状态；当前没有历史 operation-epoch resolver，因此不声称已经验证所有历史 publish terminal 的完整 operation 祖先。S3-H 必须在生产接线或 M0 exit 前补齐历史 operation resolver、同 mutex 全 DAG 复核，以及旧 operation chain 缺失/损坏的封存测试。
2. 公开 Copy-ledger `EXISTING_READ`票据只证明当前 context 的 RUN_ID 到 opaque epoch 路径映射唯一且由已激活 audit revision 支持；票据不解析 segment，也不证明 JSON、HMAC、previous-hash chain 或业务状态真实。任何正式消费者必须通过`DurableCopyLedgers`完整解析/HMAC 验证或使用 typed receipt，才能把读取字节当作账本事实。
3. 上述限制不降低当前 Test-local Copy 的成功条件：本切片仍须对当前事务 fresh reopen 两条链并验证 source/copy/operation/audit 交叉祖先；限制只禁止把该当前事务证明外推为“所有历史 epoch 的完整 DAG 已验证”。

## S3-G 实现冻结补充（2026-07-24）

S3-G 在 Test-local candidate 中冻结以下合同：

1. quarantine 固定目标为`data/quarantine/<classification>/<UTC-date>/<pair_id>`。日期由 boundary 在 operation 生命周期内钉住；`pair_id`为`YYYYMMDD`加 24 个大写十六进制字符，日期可复核且随机部分为 96 bit。
2. mutation 只接受 exact `_ObservedQuarantineTreeLease`、`_ReservedPairLease`和 live target-partition handle。source 身份由 source-root handle 决定；target partition 从授权到 rename 始终持有 live parent lease。目标已存在、partition 被替换或任一身份漂移时不覆盖并 fail closed。
3. Windows `FILE_RENAME_INFO.RootDirectory`相对形式在当前受支持环境返回 Win32 87，且文档合同不支持把它当作通用相对目录 rename。实现使用同卷固定根内的 absolute target、source-handle rename 与`ReplaceIfExists=false`，并在调用前复核 live target-parent lease。
4. INTERNAL operation locator 使用 canonical safe-relative path；RESTRICTED locator 只持久 HMAC。RESTRICTED 重启恢复须由同 boundary、同 exact context 重新签发 owner-thread、single-use、purpose-bound opaque capability；不得从 HMAC 反推或在业务层保存明文路径。
5. retained restore 只读观察 canonical INTERNAL quarantine object，复制到新 staging，完整复算后走普通 no-replace publish；quarantine 原对象始终保留。目标冲突不覆盖，source 改写或换身份时零发布。
6. rename 前崩溃只可追加唯一`RECOVERED_ABORT`；rename 后只有 exact target evidence 唯一证明 mutation 时可追加`RECOVERED_COMMIT`。terminal replay 不再次 mutation；矛盾状态保持现场并 seal。
7. S3-G 不增加永久 purge、通用 delete 或 production writer。生产 inventory 仍全部`UNMIGRATED_BLOCKED`，活动 SQLite 和真实资料不进入本切片。

冻结证据为`RUN-20260724-M0-S3G-CORE-053`（16/16）、`RUN-20260724-M0-S3G-GATE-058`（543/543）和整理后重复门`RUN-20260724-M0-S3G-POSTCLEAN-059`（543/543）。GATE-058 的保护树前后 140,985 项，POSTCLEAN-059 降至 8,394 项；两轮的活动数据库、runtime watcher、句柄围栏、run tree、不可变证据、源码见证和进程树全部一致或有效。S3-H 的真实子进程 crash matrix、历史 operation resolver、全 DAG 复核和独立 S3 冻结审计仍是后续必需项。

## S3-H 实现冻结补充（2026-07-24）

S3-H 关闭本 ADR 第 7 节保留的历史验证缺口，并冻结以下合同：

1. operation epoch resolver 必须在同一 runtime mutex 内对固定`logs/operations/segments`执行有界 no-follow catalog；最多 256 个 canonical epoch。名称/大小写冲突、非普通目录、Reparse、身份替换、清单漂移或未知对象均 fail closed。
2. resolver 使用 audit ledger 已激活 revision 完整认证每个历史 operation epoch，并在退出前重新核对全部 epoch 身份和目录 catalog；验证过程中发生漂移时 seal。
3. Copy rotation preflight 必须把 audit、所有历史 operation epoch 和所有历史 Copy source/copy 双链作为一个完整 DAG 验证。单 epoch helper 只允许委托给 multi-epoch validator，不能成为 rotation 的历史证明。
4. operation segment SHA 和 opaque epoch reference 必须各自有唯一 owner。typed terminal 或 absence witness 无法解析到唯一历史 epoch、引用损坏/缺失、revision 不同或 transaction receipt 不一致时保持现场并 seal，不自动修复、补链或跳过旧历史。
5. crash/race 真值表固定覆盖 cooperative mutex、hostile target/source drift、native boundary 后`IN_DOUBT`、rename 前后和 terminal append 前后的真实`os._exit`。恢复只追加一个可证明 terminal，fresh reopen replay 不增加 segment、不重复 mutation。
6. hostile external writer 原子 freeze 仍不作保证；支持范围继续是`COOPERATIVE_APPLICATION_WRITERS_ONLY`。无法唯一解释的 namespace 状态必须检测并 seal。
7. safe launcher 在正常主进程退出但 Job Object 仍有意外子进程时，必须显式终止并等待 active process 列表归零后才返回；仅依赖 kill-on-close 的异步效果不足以作为返回后零活动进程证明。
8. S3-H 不连接 production writer、不迁移 468 个入口、不改写活动 SQLite 或真实业务资料。SQLite migration/Backup API 继续留给 S4。

冻结证据为`RUN-20260724-M0-S3H-INVENTORY-GATE-078`（34/34）和 S3 总门`RUN-20260724-M0-S3H-S3-TOTAL-079`（997/997，另有一个独立 symlink 能力用例按既定规则排除）。最终门的保护树前后均 4,741 项，活动 SQLite、runtime watcher、句柄围栏、run tree、不可变证据、80 个源码见证和进程树全部一致或有效。独立只读复核重新计算 JUnit、19 个 inventory chunk 和 53 个`UTF8_LF_V1`源码哈希，差异为 0。

## 回滚

S3-A/B 只增加合同、Test-local候选代码和安全实验室证据，不迁移活动数据库、不移动业务资产、不改变活动指针。失败时以普通 Git revert 形成新提交；保留实验室和审计现场，不清理用户文件。
