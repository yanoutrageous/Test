# M0-S1 WorkspaceGuard 候选核心与安全实验室报告

- 日期：2026-07-11
- 分支：`agent/m0-m5-local-v1`
- 基线：`f3ab652970d0c8018b9b3a32cc91a1bd88c5d290`
- 结论：**候选实现通过已授权测试面；M0 安全门禁仍为 IN_PROGRESS**

## 实现结果

本切片新增：

- `app/workspace_guard.py`：无副作用路径候选校验、结构化错误、操作意图、根链和目标身份快照、重验；
- `tests/test_workspace_guard.py`：Test 内攻击矩阵、真实 Junction/硬链接/父目录替换/祖先替换、词法零 I/O、故障注入；
- `scripts/run_safe_pytest.py`：pytest 外部安全启动器，在 pytest 接触 basetemp 前验证唯一 run、marker、全链无 Reparse、目标不存在，并记录命令、环境、源码与数据库哈希；
- `tests/conftest.py`：pytest 早期配置门禁，校验一次性 token、manifest、固定 basetemp/JUnit 和已净化环境，直接运行 pytest 会在临时目录初始化前失败；
- `tests/test_safe_pytest_launcher.py`：run ID 穿越、Test2 前缀、输出固定、basetemp 复用和隐藏 symlink 门禁测试；
- `ADR-2026-002`：明确 Guard 不是生产 writer，并冻结 S2/S3 所需能力边界。

已修复的独立审查问题：

1. 构造后丢失卷根—授权根—workspace 祖先身份，祖先 Junction 可能越界；
2. `workspace_root=""`静默扩大为整个授权根；
3. 字符串枚举绕过类型/意图检查；
4. `CREATE_DIRECTORY`允许现存或非目录目标；
5. 非零`reparse_tag`和缺失稳定文件 ID未失败关闭；
6. pytest 在夹具前处理危险`--basetemp`，内部夹具无法独自保护；
7. 直接 pytest、插件自动加载、`PYTEST_ADDOPTS/PYTHONPATH`和输入祖先 Junction 可绕过外部启动器；
8. Junction 外部进程未固定绝对允许路径、cwd、TEMP/TMP和 timeout；
9. 精确测试链接清理缺少前置 manifest 和事后不存在证明。

## 可复现证据

### 最终完整回归

安全启动命令：

```text
.venv\Scripts\python.exe scripts\run_safe_pytest.py --run-id RUN-20260711-M0-S1-FULL-008 --mode full --exclude-symlink --timeout-seconds 300
```

结果：`163 passed, 1 deselected in 15.61s`。被 deselect 的唯一用例是单独审计的实际目录 symlink 权限门禁，不是行为失败的隐藏。新增 canary 子进程测试证明：即使直接给 pytest 一个已存在且含哨兵的 basetemp，早期钩子也会在删除前拒绝，哨兵哈希不变。

最终运行记录位于忽略的本地实验室：

- `tmp/test_lab/RUN-20260711-M0-S1-FULL-008/run-manifest.json`
- `tmp/test_lab/RUN-20260711-M0-S1-FULL-008/run-result.json`
- `tmp/test_lab/RUN-20260711-M0-S1-FULL-008/junit.xml`

运行时源码 SHA-256：

| 文件 | SHA-256 |
|---|---|
| `app/workspace_guard.py` | `87d7b60ed08c506c2b89b2f263e65eba5a2ab1a0ea6efc4f74ef6b6f6cc829b6` |
| `tests/test_workspace_guard.py` | `acbd86bfbda112c3c783cf112475e80c88e2d1572d52ba59f6a3970d2918a521` |
| `tests/test_safe_pytest_launcher.py` | `7c778b47d59256ac9b425f7480b90624d1f7524931130d549d4febb285d609de` |
| `tests/conftest.py` | `db16789577b6c69fe17aebeb88a88c8d84003c27b5a175a3bc288d1a5e5cf028` |
| `scripts/run_safe_pytest.py` | `882ba1c167b1b287baaf783e285f74f3cb94ea1c76878ca47adf3bad3ee47493` |
| JUnit | `89cd1dd3ce48cfd7e6b90ff4055048982b43ff6ddeeeb07d8121f4d472329cbc` |

活动数据库前后 SHA-256 均为：

```text
1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94
```

按运行开始时间检查，`RUN-008`之外和`.git`之外没有新增或修改的项目文件。启动器清除 pytest/plugin/Python 路径注入变量，禁用第三方插件自动加载，并逐层核对 Python、源码、数据库和实验室输入祖先。安全启动器再次使用既有 run ID 时以退出码 96 拒绝，manifest、result 和 JUnit 哈希均不变；带`..\\Base`的 run ID 同样以退出码 96 在写入前拒绝。

### 实际 symlink 门禁

两次有证据的创建尝试均在 Test 内唯一实验室执行，均返回：

```text
WinError 1314：客户端没有所需的特权
```

第二次合规证据：`RUN-20260711-M0-S1-SYMLINK-003/junit.xml`，1 test / 1 failure；活动数据库哈希不变。按照“同类失败最多两次”规则不再自动重试，也不启用开发者模式或提升权限。

这表示环境前置条件未满足，Guard 的实际 symlink 拒绝分支尚未在本机真实 symlink 上执行。真实 Junction、未知 Reparse tag、合成 symlink tag和祖先 Junction 攻击均已通过，不能替代该未完成门禁。

### 早期诊断运行

- `RUN-...GUARD-001`：43 通过、1 symlink 权限失败；缺少正式 marker，仅保留诊断，不计验收；
- `RUN-...GUARD-002`：63 通过、1 deselected；随后测试安全复审发现外部启动器缺失，因此由 RUN-007 取代；
- `RUN-...FULL-004/005/007`：用于验证旧 88 项兼容和启动器演进，由 RUN-008 取代。

所有实验室均保留，未执行递归或通配符清理。

## 覆盖结果

已覆盖并通过：

- 空/当前目录、变量、`..`、混合分隔符；
- UNC、设备命名空间、其他盘符、盘符相对、根相对；
- ADS、控制字符、非法字符、尾随点/空格、设备保留名；
- Test2、全角 confusable、大小写前缀与合法中文长路径；
- 不存在目标、类型不匹配和全部操作意图的 workspace 根拒绝；
- 真实 Junction、未知 Reparse tag、硬链接变更拒绝；
- Guard 构造后 workspace 祖先被真实 Junction 替换；
- 授权后真实父目录替换、目标出现、workspace 消失；
- PermissionError、通用 OSError 和不稳定身份失败关闭；
- Test 内受控`cmd.exe`、TEMP/TMP/pycache、清理前后 manifest；
- 旧 88 项测试兼容。

后续 M0 切片仍需覆盖：ZIP/Zip Slip、全部`db_path/output_path/project_root`入口、固定生产工厂、保护目录策略、句柄级竞态、原子写、quarantine、Copy 和安全进程包装器。

## 独立审查结论

复审确认根链快照、case 前缀重建、空 workspace、枚举、目录创建、reparse tag和稳定 identity 已修复。复审同时明确：在固定生产工厂、永久保护策略、句柄级 writer、写后核验和审计上下文完成前，当前代码只能称为候选校验核心，不能接入真实生产写入口。

## 门禁状态

| Requirement | 本切片状态 | 说明 |
|---|---|---|
| `M0-SAFE-001` | IN_PROGRESS | 候选 containment 已验证；生产固定根、保护策略和全部入口尚未接入 |
| `M0-SAFE-002` | IN_PROGRESS | Junction/ADS/稳定 TOCTOU 已覆盖；实际 symlink 与句柄级竞态未关闭 |
| `M0-SAFE-003` | IN_PROGRESS | S1 实验室已失败关闭；其他 M0 测试工具尚未全部迁入安全启动器 |

禁止进入真实资料导入、OCR、活动数据库迁移和正式写入。下一安全切片是固定生产工厂、路径能力策略、写入口清单和句柄级 writer 设计/实现。
