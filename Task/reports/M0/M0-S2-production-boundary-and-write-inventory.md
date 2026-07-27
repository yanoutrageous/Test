# M0-S2 固定生产边界与全量写入口清单报告

- 日期：2026-07-11
- 分支：`agent/m0-m5-local-v1`
- 基线：`d0767e79b2709235b1fc0aeadd8db980dc332292`
- 结论：**M0-S2 候选通过并可冻结；M0 总门仍为 IN_PROGRESS**

## 1. 本切片交付

本切片建立了以下安全基础：

- 固定`PROJECT_ROOT`的生产单例边界，禁止依赖注入和配置扩大根；
- 版本化`OperationContext`、caller/purpose/scope/classification；
- `NamespacePolicy` V6 默认拒绝策略及固定 grant 全集；
- HMAC 绑定的单路径候选、发布 pair、quarantine pair、有限 registry 和生命周期；
- 脱敏且失败关闭的候选审计事件；
- AST/SQL 静态扫描器 V5、UTF-8/LF 规范化和确定性分片 inventory；
- `WorkspaceGuard`票据 issuer/MAC/claims/registry 绑定及显式 append/quarantine target 意图；
- Test-local pytest 启动器的 Job Object、递归 watcher、句柄围栏、immutable evidence、硬链接和子进程 bootstrap 防护。

生产 writer 被刻意断开：`writer_available=false`，所有 mutation 只到`CANDIDATE_ONLY`。本切片没有迁移活动库、导入题目、处理原卷、OCR、渲染、导出或启用备份。

## 2. 冻结策略事实

- Policy ID：`LOCAL-EXAM-BANK-WORKSPACE`
- Policy version：`M0-S2-V6`
- Policy digest：`315a036ad41c1ac77379c430fc667de470e03376513d9fd8cb6f92d6ae0110b4`
- Normal exact grants：234；49 个 actor group；7,007 次矩阵尝试无差异。
- Pair exact grants：67；11 个 publish 拓扑、5 个 quarantine 拓扑；2,288 次矩阵尝试无 orphan/差异。
- 内部 metadata 与 grants 精确相等：Copy 读 11/变更 52，job 读 11/变更 59，quarantine 读 4/变更 7。

公开 rule/grant 返回隔离副本；构造输入、同值伪枚举、错误 exact type、grant 增删和内部普通篡改均失败关闭。受限分类不能降级进入 INTERNAL 分区。

## 3. 全量生产入口 inventory

冻结时间：`2026-07-11T14:40:38+08:00`；source HEAD 记录为基线`d0767e79b2709235b1fc0aeadd8db980dc332292`，并显式标记 dirty candidate。

| 项目 | 结果 |
|---|---:|
| 生产源文件 | 45 |
| 写/副作用入口 | 427 |
| 分片 | 18 × 最多 25 项 |
| `UNKNOWN_DYNAMIC_CAPABILITY` | 0 |
| `UNMIGRATED_BLOCKED` | 427 |
| 未授权 Guard 构造 | 0 |
| orphan / missing / reparse / hardlink | 0 |

入口类别：数据库 gateway 74、隐式初始化 48、外部进程 7、文件复制 1、目录创建 21、文件写入 17、网络 2、动态 SQL 42、SQL mutation 52、schema mutation 120、原始 SQLite connect 2、事务 41。

冻结锚点：

| 证据 | SHA-256 |
|---|---|
| inventory 文件 | `15f515798db17f81eeffa7814993d80748831303e6fb3a08e0260874aa3c3482` |
| source manifest digest | `dc8cd3498b2284ff975b16b6abcb46a24f3815302e2cb77ea9fbc4e1dfc011a4` |
| entries digest | `cc29402dcef42c6d433b01f9f64f547708ea448ce29a16d678d8936d51a40dc1` |
| inventory payload digest | `228976d24daafeb25dadcd9c1c127b705627fed13867188f0f4dcfaa75b96230` |
| chunk refs aggregate | `4f5533ea091d89ee8581bbcf059e4f8265cb2f7542d5116344c4407044364cf4` |
| manifest + 18 chunks aggregate | `bc844be3cadee0e665f2920ce67381b444a3bfb8110c6eaf87343347f2aa0d20` |
| 43-file allowlist path-set anchor | `da042e32b9d3d27b7def72c4000d434ae96300c4d11e6752f2177b40007df25f` |

所有 JSON 均为 UTF-8、纯 LF、一个结尾换行、单硬链接普通文件；manifest 最后发布，引用的 canonical/serialized/source 哈希全部复算一致。Production source SHA/size 绑定`UTF8_LF_V1`规范化字节，根`.gitattributes`固定 fresh checkout 行尾，不依赖本机`core.autocrlf`。

## 4. 冻结全量验收

唯一安全入口：

```text
.venv\Scripts\python.exe -B scripts\run_safe_pytest.py --run-id RUN-20260711-M0-S2-EOL-020-FINAL --mode full --exclude-symlink --timeout-seconds 900
```

结果：`354 passed, 1 deselected in 49.29s`。JUnit 实际 testcase 树与汇总均为 354 tests、0 failure、0 error、0 skip；唯一 deselected 是已单独记录 WinError 1314 的真实目录 symlink 权限门禁。

| 运行门禁 | 结果 |
|---|---|
| pytest / effective exit | 0 / 0 |
| timeout | false |
| Windows Job Object 完整进程树 | 已终止；后台 canary PID 均不存在 |
| 递归运行时 watcher | valid；0 change |
| deny-write/delete 句柄围栏 | valid；31,225 handles |
| 保护树 | 前后 31,225 条；digest 相同 |
| 活动 SQLite | 前后 SHA-256 相同 |
| immutable evidence | marker、snapshot、manifest 前后身份与哈希相同 |
| run tree | 0 reparse；0 非单链接文件 |

证据 SHA-256：

- manifest：`ee92293c53432706d00df5bd6da44f0c3532304d39eff93cfee59183addc25df`
- result：`07ef462e6e6b8aa12f8da7fb39e9f8014d54837dd1f59aa4665f3a162b619e3b`
- JUnit：`51e70684e0e2658722d836f8f10dd9fa214ce93dd208081761e49a97d80e308c`
- protected snapshot：`6cfa0e0b5e30e6bc0f54089e81a150c6a28680e4a525886237a22fa51b3feb7b`
- protected digest：`a8c556eacc93b700ee62ce2b28eb0ff364273a52879d2f5da447d33326093957`
- 活动数据库：`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`

测试不是以数量作为完成标准。覆盖面包含：正常候选签发和重验；caller/purpose/scope/classification 全矩阵；伪造上下文/令牌/MAC/evidence；pair 部分失败回滚与 registry 容量恢复；动态 SQL、别名、包装器、进程、网络和 archive 静态 canary；临时创建删除 watcher；硬链接/nt.link/ctypes/native command；`-S/-E/-I`、`-Ic/-Sc/-Ec`、`-W/-X`组合逃逸；子进程树和超时终止；JUnit/immutable evidence 篡改失败关闭。

## 5. 公开生产入口流程

`M0-S2-UJ-001`从公开`get_production_boundary()`执行，没有调用测试私有 factory 或修改数据库：

1. 两次获取为同一固定单例；
2. `writer_available=false`；`require_writer()`返回`WriterUnavailableError`；
3. 调用者构造的未签名上下文请求 Test-local mutation；
4. 返回结构化`INVALID_CONTEXT`，审计 decision 为`DENY`，路径不公开；
5. 活动数据库前后哈希相同。

这一流程的正确用户结果是“安全拒绝”，不是业务功能完成。真实导入、组卷或导出旅程在 writer 接通前禁止执行。

## 6. 独立审计

两路只读审计分别复算 production policy/inventory 与 launcher/bootstrap/run evidence。最终结论均为 P0=0、P1=0，可冻结 M0-S2 候选。审计明确保留以下边界：

- 本机真实 symlink 门禁未通过，不能用 Junction/合成 tag 替代；
- 427 个入口仍未迁移，`m0_exit_allowed=false`；
- `PairEvidence`仍是声明，S3 writer 必须读取实际字节重算；
- 当前 audit sink 在内存中，S3 必须持久化；
- 静态扫描和测试实验室针对受信任、已审阅的仓库源码，不是 hostile native-code OS sandbox。

提交前还使用 Test 内被忽略的 alternate Git index 做显式暂存干跑：请求和 prospective staged 集合均为 43 个 allowlist 文件，额外/缺失/禁止路径均为 0；45 个 staged production source blob 与 V5 canonical source manifest 全部相同，18 个 staged chunk 与 serialized SHA 全部相同，`git diff --cached --check`为空。干跑创建时记录的 index SHA-256 为`0c0200e0cb0f24dc011a2b2865748ce60216c1550b9d0310f50e22416e6e0951`；发布前复审确认 Git 的普通只读查询也可能刷新 index stat cache，因此该二进制哈希只记录创建时事实，不作为不可变门禁，也不再要求当前临时 index 与其相等。最终发布门禁改由真实主索引的精确 staged 路径集合、staged blob、diff、隐私和禁止路径复核证明；临时目录保留在忽略的 Test-local `tmp/git_stage_dry_run`，不进入提交。

## 7. 源码冻结锚点

| 文件 | SHA-256 |
|---|---|
| `app/workspace_guard.py` | `10fb8e1f7c111d0d4ee6674766fc1ce528f029152d01061598a245b50ba7640c` |
| `app/safety/namespace_policy.py` | `f637fd73fbebb093e96457445f3d49d9262afe449ebcd0aeff2dce38ca2fff37` |
| `app/safety/production_guard.py` | `66d50569d213143826a951c53fe255a575c3cda71b5d3a99cd9cb1fc0240ef6d` |
| `.gitattributes` | `f6004389bf38f2f9e750e0376bce4bd23aef2ceb35091df322f500fbe5462331` |
| `app/safety/static_audit.py` | `049e28d48d8bc95cd8cd767004f2b34d0d03150c1ca216467ff7d2d7bd7082c6` |
| `scripts/run_safe_pytest.py` | `75237e49874ad67756405e2148b748507e16807c79befc087aad1782e199ed3e` |
| `tests/conftest.py` | `85ca325b8bdda2395cbaf01e82fef4b2c6891c1da249a0dd1273fdb0a95dfab7` |
| `tests/safe_bootstrap/sitecustomize.py` | `3d728bf1578297da046857f0d546357ce1f2c98d21489800b9327cc7c8dbf592` |
| `tests/test_workspace_policy.py` | `b918a30a96f8f2296bfbe2c207a98483967ef8ad7ea0fcd5b64b6b935a8c0fe2` |
| `tests/test_safe_pytest_launcher.py` | `578553f99210cf308e56308230e7734e7b6bf39097f0021d47e0366b39e5866c` |
| `tests/test_write_entry_inventory.py` | `26cab38f5cc6a99e57383e1a82a1909aeb3622eecb0f1288ff0159719fc9c665` |

## 8. 下一切片

进入 M0-S3 前仍禁止真实业务写入。S3 必须先实现句柄级 writer、持久审计和 evidence 重算，再按 inventory 逐类迁移入口；任何迁移都要保持旧入口`UNMIGRATED_BLOCKED`，直到其正常、边界、失败、恢复和安全路径全部通过。
