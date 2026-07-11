# ADR-2026-004：句柄内完成写入/发布，并以不可变 segment 形成持久账本

- 状态：Accepted for Test-local candidate implementation
- 日期：2026-07-11
- 决策级别：D2
- 影响里程碑：M0—M5
- Requirement IDs：`M0-SAFE-001`—`M0-SAFE-007`
- 补充 ADR：`ADR-2026-002-workspace-guard-capability-boundaries.md`、`ADR-2026-003-fixed-production-boundary-and-candidate-only-policy.md`

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

## 回滚

S3-A/B 只增加合同、Test-local候选代码和安全实验室证据，不迁移活动数据库、不移动业务资产、不改变活动指针。失败时以普通 Git revert 形成新提交；保留实验室和审计现场，不清理用户文件。
