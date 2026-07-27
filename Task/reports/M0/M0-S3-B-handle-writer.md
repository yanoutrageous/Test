# M0-S3-B Test-only 句柄写入内核检查点报告

- 日期：2026-07-11
- 分支：`agent/m0-m5-local-v1`
- 基线：`892027f5dae5525a27645047cc75ba8f97e4f63c`
- 结论：**S3-B 候选通过，可形成内部检查点；S3、M0 总门均仍为 IN_PROGRESS**

## 1. 边界与本切片交付

本切片只实现 Test-local、安全实验室可用的最小 Windows 句柄写入内核：

- 固定生产工厂逐级打开并立即核对 Test、run、workspace 与 marker 的同一 Win32 handle；
- 所有已取得的根/祖先/父目录 handle 在操作期间保持 deny-delete 围栏；
- 新文件只使用`CREATE_NEW`，append 必须绑定既有长度和 SHA-256；
- 写入、flush、同句柄读回、file ID/volume/reparse/链接数/最终路径后置核验在一次内部操作内完成；
- 票据单次使用、并发操作互斥；close/release 等能力生命周期故障会 seal writer，写后 flush/readback/postcondition 故障则失败返回并保留现场；
- 错误与 receipt 不泄漏原始路径或 Win32 handle 值；
- 静态扫描器 V6 补齐 ctypes/CFFI/mmap/FileIO/import-loader/反射/动态 callable 等 capability provenance 漂移门禁。

生产 facade 仍为`writer_available=false`。本切片没有提供目录创建、rename、树枚举、原子 publish、持久 ledger、Copy、quarantine、数据库迁移或任何真实业务资料处理；这些分别保留给 S3-C—S4。M0 禁止原地 truncate，关键替换只允许后续 staging 加 no-replace publish。

## 2. 句柄安全性质

实现按 fail-closed 顺序执行：词法边界与票据核验，逐级 handle 打开与即时身份核对，直接父目录存在性约束，独占目标 handle，实际写入与 flush，同 handle 有界读回，最后身份/路径/属性/链接数复核，最后才返回无路径 receipt。

验证矩阵包含：合法中文/长路径、缺失直接父目录、父目录与最终分量替换、Junction/reparse/ADS/硬链接、授权后新增硬链接、短写、同长度破坏、flush/close/release 双故障、票据重用、同票据和不同票据并发、seal 后未使用票据释放、marker 读取前同句柄全核验，以及 factory 任意`BaseException`后的全句柄关闭。

真实目录 symlink 测试仍因本机普通账户`WinError 1314`单独 deselect；没有启用 Developer Mode、提权或改变系统策略。Junction、合成 reparse tag 与其他攻击用例不能替代这项实际能力门禁。

## 3. 生产入口 inventory

冻结预览：`RUN-20260711-M0-S3-INVENTORY-012`。

| 项目 | 结果 |
|---|---:|
| 生产源文件 | 46 |
| 写/副作用入口 | 442 |
| 分片 | 18 |
| `UNKNOWN_DYNAMIC_CAPABILITY` | 0 |
| `UNMIGRATED_BLOCKED` | 442 |
| `production_writer_connected` | false |
| `m0_exit_allowed` | false |

冻结锚点：

| 证据 | SHA-256 |
|---|---|
| inventory 文件 | `385d109692c293b227a1d14938aaf506f285cf597769d7fd22564e058cbb29fa` |
| inventory payload | `7d9497c001113671535e9c07025c206eaaaad0fb18c260f870cca817a6efa4f3` |
| source manifest | `cb869f24062e5bb185ad7d05ae292f5db8ff352b7398b0a68840d1c7864cab13` |
| entries | `39eb4415470a71ba921cef2573009fff272bbef7c18911bcadb9bf54b94218e6` |
| generator | `43e49d710ed86409961df1de8b149477098907e600d5d5b46f8a66f022d4fce8` |

V6 扫描器针对受信任、已审阅的仓库源码 inventory 和漂移门禁，不是 hostile native code 的 OS sandbox，也不承诺抵御调用者注入任意运行时对象。独立 canary 复核覆盖 21 类 capability 传播方式，production scan 连续运行保持 442 项且`UNKNOWN=0`。

最终只读复核独立重扫当前`app/`、`scripts/`并逐条对比 manifest/chunks，复算 RUN-009 与 RUN-011 的 JUnit、保护树 payload、数据库及不可变证据；结论为 P0=0、P1=0，可形成 S3-B 内部检查点。

## 4. 冻结测试与证据

定向 writer 回归：`RUN-20260711-M0-S3-WRITER-009`，结果`314 passed, 1 deselected in 27.90s`。完整 M0 回归：

```text
.venv\Scripts\python.exe -B scripts\run_safe_pytest.py --run-id RUN-20260711-M0-S3-B-FULL-011 --mode full --exclude-symlink --timeout-seconds 900
```

结果为`402 passed, 1 deselected in 53.84s`；JUnit 为 402 tests、0 failure、0 error、0 skip。

| 运行门禁 | 结果 |
|---|---|
| pytest / effective exit | 0 / 0 |
| timeout | false |
| Windows Job Object | 完整进程树已终止 |
| 递归运行时 watcher | valid；0 change |
| deny-write/delete 句柄围栏 | valid；37,767 handles |
| 保护树 | 前后 37,767 条；digest 相同 |
| 活动 SQLite | 前后 SHA-256 相同 |
| immutable evidence | marker、snapshot、manifest 前后身份与哈希相同 |
| run tree | safe；无 reparse/非单链接证据异常 |

RUN-011 证据 SHA-256：

- manifest：`167dd8f0d8c258204d277204abd152c0c4dda1905e1ac47d9adb34d2f4ff02bd`
- result：`b959ab702f64e494c30cbb318dc1f9dc0282d65d7c325f6b42697053fe20fe9e`
- JUnit：`cfa8ae1b23e3e2d8c17dc0b5a7896af4e779fcc7a713ae7b97c94e58b3095574`
- protected snapshot：`69e28a66f76efae66e5c735341c87b3e893ceae4c9330b4a5805f93c9bc3402a`
- protected digest：`576f78eec825f4e40263ffb430c69bfb0c9d58404bd845721f26e6caca130f8f`
- 活动数据库：`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`

`RUN-20260711-M0-S3-B-FULL-010`因外层工具等待窗口被错误设为 1 秒，stdout 管道在 pytest 完成前关闭，产生 exit 120 和不完整 JUnit；其保护树、数据库、watcher、句柄围栏和进程树仍全部干净。该失败现场被保留且不作为通过证据。此前 RUN-007 的 10 项失败与 RUN-008 的 1 项异常上下文泄漏也均保留，修正后才取得 RUN-009/011 的通过结果。

## 5. 冻结源码锚点

| 文件 | SHA-256 |
|---|---|
| `app/safety/production_guard.py` | `6a00d10fceecb2b7e3318682cf3063d1b19925ff41e8875a4e1993d22535de90` |
| `app/safety/static_audit.py` | `c7d74a65e46b9999e6fa2b7bc4e5f060ee0d7099a792a7a854b43107a42373c5` |
| `app/safety/windows_handle_writer.py` | `95911f178043087b17c0c269273961fc77a5b9877e300f0342ad59812e5c6fdb` |
| `app/stage8_report.py` | `74277c1eba81a6df5c53b80f96cf9e5629acc6fde5df94f8d77c9c8ccb41b56e` |
| `scripts/run_safe_pytest.py` | `9b05f659412f81378df9dba8ffa8a61b2ea6147f7c205a94703840e9894a3cd7` |
| `tests/test_windows_handle_writer.py` | `c213fc3668fa24cab4fc5e4ece35290ee346cb5c426ef8eae8e1e1eb21221875` |
| `tests/test_write_entry_inventory.py` | `080aa8d7e7e2324fa68b1ab5d5cc0ed50814af07ec41deaa6a93bdcca8f0f2a8` |

## 6. 保留限制与下一切片

不阻塞本 Test-only 检查点、但在生产连接前必须关闭的限制：

- writer 的 spent-ticket 记忆尚未做有界持久生命周期；
- seal 清理多个未使用票据时的次要 release 故障需要形成可恢复证据；
- append 已写入后若 flush/readback/postcondition 失败会正确拒绝成功并保留现场，但当前不保证 seal；S3-C 必须用持久状态机记录并阻断后续写入；
- 当前 128-bit File ID 高位非零时保守拒绝，尚未声明 ReFS/其他卷兼容；
- 扫描器部分聚合 canary 后续应拆成逐案例精确 finding 断言。

下一切片是 S3-C：不可变 segment ledger、key revision、启动全链验证和重启故障恢复。S3-C 通过前，生产 writer 保持断开，442 项入口保持`UNMIGRATED_BLOCKED`，不得处理真实业务资料。
