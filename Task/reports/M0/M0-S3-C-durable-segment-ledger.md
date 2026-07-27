# M0-S3-C 不可变审计账本与密钥版本检查点报告

- 日期：2026-07-11
- 分支：`agent/m0-m5-local-v1`
- 基线：`385888d39b30d7d9ff8e219abfe0de64b794cadf`
- 结论：**S3-C 候选通过，可形成内部检查点；S3-D—H、S4—S6 与 M0 总门仍为 IN_PROGRESS**

## 1. 边界与本切片交付

本切片只建立 Test-local 候选的持久审计信任根，不连接生产 writer，也不处理任何真实业务资料：

- `logs/audit/keys/`保存有序、不可覆盖的 32 字节 master-key revision；正文、派生 key ID、revision SHA 和文件名互相绑定；
- `logs/audit/segments/<epoch_id>/`从显式 genesis 开始保存 canonical UTF-8/LF JSON segment；sequence、previous hash、policy、key revision、batch、record、segment SHA、HMAC 与文件名形成完整链；
- 新 key 与 segment 均经句柄 writer 写入唯一`PENDING`文件、flush、重开复算，再以 source-handle、no-replace rename 发布；
- 每次启动从 genesis 全量扫描，不信任可变 head；未知文件/目录、PENDING、缺号、分叉、旧 key 篡改、schema/policy/key 漂移均保留现场并 seal；
- Windows Local named mutex 约束跨进程单写者；固定 durable factory 在同一 live lease 内检查空 key/segment store、发布初始 key 并创建 genesis；
- audit event v2.1 的字段集合、decision/action/error 真值表、single/pair 元数据、context/path redaction、规范相对路径和 path depth 均在签入前验证；
- key rotation 由旧 key 认证并绑定新 revision SHA；历史 audit 与 rotation segment 启动时逐段重放；
- key store、segment 数量、单文件、批次和总账本字节均有写前固定上限；诊断事件缓存有界；
- `DurableAuditSink`提交前异常统一为`INVALID_REQUEST`，提交后 receipt 重算异常统一为`STORAGE_FAILURE`并 seal，异常对象不保留原始 context/cause。

Policy V7 将 audit segment、audit key 与 Copy segment 的公开 namespace 保持只读；项目业务层没有直接 ledger/key mutation grant。实际持久写入只能经过固定 factory、constructor token 和 handle storage。生产 facade 继续明确返回`writer_available=false`。

## 2. 安全与恢复矩阵

73 个 segment-ledger 测试覆盖正常、边界、失败、重启和安全路径，重点包括：

- 真实子进程在 rename 前`os._exit`：PENDING 保留，重启拒绝并 seal；
- 真实子进程在 rename 后`os._exit`：有效 final 被完整重扫接纳，批次幂等重放；
- 独立子进程持 mutex：当前写入得到可重试`MUTEX_BUSY`，释放后同一 ledger 可继续；
- 真实 abandoned mutex：保留 observer handle 后重启准确记录 abandoned，同时不伪造新 segment；
- key/segment 的自洽未知 schema：重新计算 hash、HMAC 与文件名后仍按版本门禁拒绝，证明不是普通 tamper 测试；
- 固定 factory 对 healthy、key-only、key+PENDING 三种 reset 均拒绝，key/segment 名称和字节零变化；
- 同序号两个各自正确签名的 fork、sequence gap、缺 genesis、旧 key 同长度篡改、未知文件和 child directory 均 fail closed；
- staging 验证后创建真实 hardlink：外部 write handle 被 share fence 拒绝，hardlink 可形成，但 rename 后 link-count 后置检查拒绝 receipt 并 seal；合成 alias 仅按精确 cleanup manifest 清理；
- decision/context/path/pair 语义矩阵包含 7 个明确合法行和 23 个单变量非法行；非法行逐项证明账本字节零变化；
- Store/Ledger/Sink/Authority constructor token 运行时拒绝，并以逐路线精确 static-bypass canary 覆盖 alias、partial、`__new__`、subclass、factory、反射和敏感状态赋值。

本切片没有自动修复损坏链、删除 PENDING、覆盖冲突目标、截断历史或猜测恢复结果。

## 3. 生产入口 inventory

冻结预览：`RUN-20260711-M0-S3C-INVENTORY-001`。

| 项目 | 结果 |
|---|---:|
| 生产源文件 | 47 |
| 写/副作用入口 | 451 |
| 分片 | 19 |
| `UNKNOWN_DYNAMIC_CAPABILITY` | 0 |
| `UNMIGRATED_BLOCKED` | 451 |
| `production_writer_connected` | false |
| `m0_exit_allowed` | false |

相对 V6 的 442 项，原入口无删除，新增 9 项：2 个`DURABLE_LEDGER_GATEWAY`、3 个`RUNTIME_SYNCHRONIZATION`、1 个`FILESYSTEM_MOVE_OR_REPLACE`和 3 个`NATIVE_API_BINDING`。后三个 native 项是`ctypes.cast`两处与`memmove`一处固定 ABI/缓冲操作，不是新增 DLL 加载。

冻结锚点：

| 证据 | SHA-256 |
|---|---|
| inventory 文件 | `1d832a3c655a450b81c819a9faf3c9d9674f6cb42957d1f0a95ec2040c1294c4` |
| inventory payload | `47dd8ee60a579e5cbb68949a86d7752c45f961534a172494b3f407855bcdb68a` |
| source manifest | `0b29dc598447cfb2e0dc5e36b452a4a9a8a6190864a8b47130f35129a38240b3` |
| entries | `85260287b28a71b2f55b714c3c0118588633700925aa1c21d2189d703422cec5` |
| generator | `43e49d710ed86409961df1de8b149477098907e600d5d5b46f8a66f022d4fce8` |

Scanner V7 独立重扫结果为 451、`UNKNOWN=0`、production bypass finding=0；Policy V7 digest 为`8df50ded63443c3310603614fd6d317234ce026c351870d0488a84dd1cfe4d88`。

## 4. 冻结测试与证据

定向 writer/ledger 回归：

```text
.venv\Scripts\python.exe -B scripts\run_safe_pytest.py --run-id RUN-20260711-M0-S3C-WRITER-016-FINAL --mode writer --exclude-symlink --timeout-seconds 900
```

结果为`427 passed, 1 deselected in 34.50s`；完整回归：

```text
.venv\Scripts\python.exe -B scripts\run_safe_pytest.py --run-id RUN-20260711-M0-S3C-FULL-017-FINAL --mode full --exclude-symlink --timeout-seconds 900
```

结果为`515 passed, 1 deselected in 65.72s`；JUnit 为 515 tests、0 failure、0 error、0 skip。

| RUN-017 门禁 | 结果 |
|---|---|
| pytest / effective exit | 0 / 0 |
| timeout | false |
| Windows Job Object | 完整进程树已终止 |
| 递归运行时 watcher | valid；0 change |
| deny-write/delete 句柄围栏 | valid；53,260 handles |
| 保护树 | 前后 53,260 条；digest`86f62dd9...092764`相同 |
| 活动 SQLite | 前后`1505bf05...ad1c94`相同 |
| immutable evidence | marker、snapshot、manifest 前后身份与哈希相同 |
| source inputs | unchanged；changed list 为空 |
| run tree | safe；无 reparse/非单链接证据异常 |

冻结证据 SHA-256：

| 证据 | RUN-016 | RUN-017 |
|---|---|---|
| manifest | `649cd151cf7a13b63c8a60018e0d6f4cbbc1780949998104bd01727f9c3dae2a` | `3b8dd1f8388e56bc207421b7ba2a1820b7fd4bb9feb9a2e9df9b0df6ad2e73aa` |
| result | `7382d81022d119d8c120017e4f1234d461559d40388e335a1a6f8a35c702e11c` | `3ad402439614934b6ac05d51afa0706063735a641014c2f79e6d7c32cf8970df` |
| JUnit | `7afe36c0dd7701fa28994cab3d92c5b91a9867686e433a8048b8a36770dd1fe6` | `07a0f680d8bf5f40377f5fc2f2cba190fd32929dd3d8259907e3fcbf7d8d8d88` |

`RUN-20260711-M0-S3C-WRITER-015-FINAL`的 382 个功能测试全部通过，但并发只读审计运行 Git 时短暂产生`.git/index.lock`，launcher 正确将其判为 runtime change 并给出 effective exit 97，因此该运行不作为冻结证据。DEV-012 因外层等待上限误设为 1 秒导致 stdout 关闭；DEV-013 暴露并修复了异常 context 保留；DEV-014 只剩旧 inventory 两项失败。所有失败现场均保留，没有被包装成通过。

实际目录 symlink 门禁仍因本机普通账户`WinError 1314`单独 deselect；没有启用 Developer Mode、提权或改变系统策略。

## 5. 冻结源码锚点

| 文件 | SHA-256 |
|---|---|
| `app/safety/audit_events.py` | `ef06b8d582135813a86f5faa6fea8486a6b9b146b46ef4d4ae5b2438326ce952` |
| `app/safety/namespace_policy.py` | `aca24f9b656b785b5e1298b90b422a9f31a78ed9b8553a11918d9f67437b742d` |
| `app/safety/production_guard.py` | `4c96cb2b2fa211a07f87a74ea9e18e54f1d885040696943adb2003dff8195d6f` |
| `app/safety/segment_ledger.py` | `c908cc70decd04f2853de10748ba70a1019fe0078c04ad7d2f8bee1fb000d1e7` |
| `app/safety/static_audit.py` | `58036f45b50e2583d2b81c11ff9aaf0fb4bfe755deec487f343cda117f686127` |
| `app/safety/windows_handle_writer.py` | `4be70c4cbfd1a3534f4e874b23c0e74ae3cad2f8b1cd274963df0fa6c257c603` |
| `scripts/run_safe_pytest.py` | `ea0224d47d44de82126d6b1ea8522963c1ed86a7c47f0329cbfdd984479310b9` |
| `tests/test_segment_ledger.py` | `a19fd64f7c28230bf72256ddf8e37fb1ef10bb39f6974f5c216f2291fdaccf3d` |
| `tests/test_windows_handle_writer.py` | `a1749e8ae94e84e660a509f512eb04861dd089fd770a7f5edb5a6f626634c016` |
| `tests/test_write_entry_inventory.py` | `917bf1213ad9b1b5c34c90f3490860d680920ecc09d3b8dfb139bbc69cf140cd` |

## 6. 明确限制与下一切片

- 本地 key revision 文件是 Test 内、Git 忽略、可备份的明文 key material；它防误泄漏和检测变化，不抵御已取得项目目录读取权的本机恶意用户；
- 仅靠项目内链无法检测攻击者对“完整尾部 segment 与对应外部事实”进行一致回滚；生产发布需要外部 witness/备份检查点或等价锚点；
- 当前 parser 只接受 schema 1.0、audit event 2.1 与 Policy V7；未来版本必须使用显式 parser registry/新 epoch，不能静默接受；
- 固定 durable factory 的首次初始化在同一 mutex lease 中完成；底层带 constructor token 的直接测试 helper 仍可自行取第二次 mutex，只能描述为 trusted unit-test 例外；
- 当前不宣称 ReFS 高位 File ID 兼容、硬件断电 flush 保证或实际 symlink 权限门禁已通过；
- 当前合法 pair 语义样例固定为`PUBLISH_PAIR + SOURCE`；`QUARANTINE_PAIR + TARGET`及真实 denial/pair 生命周期须在 S3-E/G 接入实际 pair 流程时扩展；
- 当前安全实验室针对受信任、已审阅的仓库测试，不是 hostile native-code OS sandbox；
- S3-C 只完成 audit ledger；业务 operation lease、observed tree evidence、pair publish、Copy ledger、quarantine/restore 和外部进程封装仍分别属于 S3-D—G。

下一切片是 S3-D：operation lease、固定 job staging、预算和 observed tree evidence。生产 writer 继续断开，451 项继续全部`UNMIGRATED_BLOCKED`，不得处理真实业务资料。
