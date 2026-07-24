# M0-S3-G quarantine、保留式 restore 与冲突安全恢复

## 结论

S3-G Test-local 候选已通过核心、组合、静态清单和安全实验室门禁，可以形成 S3-G Git 检查点并进入 S3-H。该结论不代表 S3、M0 或 M0—M5 完成：

- production writer 仍为`writer_available=false`；
- 468 个生产副作用入口仍全部`UNMIGRATED_BLOCKED`；
- 活动 SQLite、原始题卷和真实业务资料未被写入；
- S3-H 的真实子进程崩溃点、竞态矩阵、历史 operation resolver、全 DAG 复核和独立冻结审计仍未完成。

## 冻结合同

### Quarantine

1. 只移动一个已由 live handles 完整观察和重算的目录对象根，不提供通用 delete 或永久 purge。
2. 固定目标为`data/quarantine/<classification>/<UTC-date>/<pair_id>`；日期由边界在 operation 生命周期内钉住。
3. `pair_id`为`YYYYMMDD`加 24 个大写十六进制字符，日期可校验且随机部分为 96 bit。
4. target partition 由受信任 boundary 创建或复用，并从授权到 native mutation 始终持有 live parent lease；partition 被替换、目标抢占或身份变化时 fail closed。
5. source 身份由 source-root handle 决定；目标使用同卷、固定根内的 no-replace handle rename。Windows `FILE_RENAME_INFO.RootDirectory`相对形式在本机返回 Win32 87，最终实现不再依赖该未成立假设。
6. INTERNAL ledger 保存 canonical safe-relative locator；RESTRICTED ledger 只保存 HMAC locator。RESTRICTED 重启恢复必须消费同 boundary、同 context、owner-thread、single-use 的 opaque capability。

### 保留式 restore

1. 当前 S3-G restore 只接受 canonical INTERNAL quarantine object path。
2. quarantine 原对象以只读 live handles 保留；payload 被复制到新的固定 staging，逐项重算后走既有普通 publish。
3. restore 不移动、不修改、不删除 quarantine 原对象。
4. publish 目标已存在时 no-replace 失败，不覆盖；新的独立 operation 可在冲突解除后重新执行。
5. source 在 restore 生命周期内被改写、换身份或结构变化时，live evidence 失效并零发布。

### 恢复

- native rename 前崩溃：目标不存在且 source 完整时追加唯一`RECOVERED_ABORT`。
- native rename 后崩溃：只有 exact target evidence 能唯一证明 mutation 时追加`RECOVERED_COMMIT`。
- terminal replay 幂等，不再次 rename、不增加 segment。
- source/target 双存、双失、错身份、错内容、路径/capability/祖先不匹配时保持现场并 seal，不猜测、不清理。

## 主要实现

- `app/safety/job_operation.py`
  - quarantine source observation、partition lease、pair authorize/execute/replay；
  - retained restore source lease、staging copy、普通 publish 接续；
  - quarantine/restore receipt 与路径 canonicalization。
- `app/safety/windows_handle_writer.py`
  - quarantine/read-only tree open；
  - live target-parent lease 校验；
  - source-handle、absolute target、no-replace directory rename。
- `app/safety/production_guard.py`
  - quarantine pair 的日期编码；
  - RESTRICTED recovery locator capability 与 source/target HMAC 绑定；
  - context/thread/single-use 生命周期和失效回收。
- `app/safety/static_audit.py`
  - 新增 quarantine/restore exact qualified scopes；
  - `target_relative_path.name`只允许在精确的 quarantine pair-id 推导 AST 结构中出现；
  - 相邻或无关作用域继续由反向金丝雀拒绝。
- `scripts/run_safe_pytest.py`
  - pytest stdout/stderr 只写当前排除的 run root；
  - 保护树证据改为确定性`gzip-canonical-json-v1`，结果 schema 1.2。

## 测试与收敛

核心 16 项覆盖：

- INTERNAL quarantine move 与 committed replay；
- RESTRICTED locator 脱敏、分区复用和重启 capability；
- live partition lease 阻止目录替换；
- target race 不覆盖；
- rename 前/后崩溃的 recovered abort/commit；
- retained restore 保留原对象；
- restore conflict 与新 operation 恢复；
- 绝对路径、遍历、RESTRICTED path、坏日期、小写 ID、ADS 和 child path 攻击。

收敛轮次：

| 运行 | 结果 | 说明 |
|---|---:|---|
| `RUN-20260724-M0-S3G-LAUNCHER-046` | 88 passed | launcher 输出捕获与 gzip 证据格式通过 |
| `RUN-20260724-M0-S3G-CORE-051` | 4 passed | 主 quarantine/restore 路径首次通过 |
| `RUN-20260724-M0-S3G-CORE-052` | 15 passed, 1 failed | 唯一缺口为 RESTRICTED 重启 locator |
| `RUN-20260724-M0-S3G-CORE-053` | 16 passed | S3-G 核心矩阵全绿 |
| `RUN-20260724-M0-S3G-COMBINED-056` | 535 passed, 2 failed | 仅静态审计未登记新增 exact scopes；全部安全门干净 |
| `RUN-20260724-M0-S3G-GATE-058` | 543 passed | S3-G 最终组合门全绿 |
| `RUN-20260724-M0-S3G-POSTCLEAN-059` | 543 passed | 历史热目录整理后重复同一门禁，全绿 |

GATE-058 不可变结果：

- effective/pytest exit code：0/0。
- JUnit：543 tests，failure/error/skip 均为 0。
- 保护树：前后均 140,985 项，digest 完全一致。
- 句柄围栏：140,985 项，有效。
- 活动数据库：前后 SHA-256 均为`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。
- runtime watcher、run tree、不可变证据、源码见证和进程树：全部通过。
- 运行树：3,702 项、10,617,771 bytes，保护树快照采用 gzip 格式。

POSTCLEAN-059再次证明整理没有降低门禁：

- 运行时间：20:59:32—21:03:42，共 4 分 10 秒；GATE-058 约 19 分钟。
- JUnit：543 tests，failure/error/skip 均为 0。
- 保护树：前后均 8,394 项且 digest 一致，较 GATE-058 的 140,985 项减少约 94%。
- 活动数据库、runtime watcher、句柄围栏、run tree、不可变证据、源码见证和进程树仍全部通过。
- 运行树：2,074,395 bytes。

## 静态清单

`RUN-20260724-M0-S3G-INVENTORY-057`：

- 53 个生产源文件；
- 468 个副作用入口；
- 19 个分片；
- `UNKNOWN=0`；
- 468 个入口全部`UNMIGRATED_BLOCKED`；
- `production_writer_connected=false`；
- `m0_exit_allowed=false`；
- inventory digest：`89536763bcb33d8624354fccf4539a6489fa6eb1688ba7fd345202d4b5d5d42e`；
- manifest serialized SHA-256：`0875478a76741d69f9cc62ba9587aa56e0c0829307fb57de976f87d84bbd9efe`。

`scan_unauthorized_guard_construction()`为 0 条发现。新增允许范围均限定到 exact qualified method，反向测试证明相邻方法、错误赋值目标和直接 path-name 泄漏仍 fail closed。

## 存储与迁移

历史证据已按`Task/TEST_GATE_RETENTION.md`整理；两个 portable tar.gz 及 SHA-256 见`M0-evidence-storage-20260724.md`。归档不进入 Git，换电脑时如需完整取证历史必须单独携带；源码交付和验收状态不依赖旧物理路径或`.venv`。

## 下一步

S3-H 必须补齐：

1. 使用真实子进程终止点覆盖 rename 前后与 terminal append 前后的 crash matrix；
2. hostile/cooperative writer 竞态边界的最终真值表；
3. 历史 operation epoch resolver 与同 mutex 全 DAG 验证；
4. 旧 operation chain 缺失/损坏的封存测试；
5. 最终 inventory 冻结、独立只读审计和 S3 总门。
