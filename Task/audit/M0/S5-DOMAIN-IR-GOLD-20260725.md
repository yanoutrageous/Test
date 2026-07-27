# 高风险变更审计：M0-S5-DOMAIN-IR-GOLD

## 1. 基本信息

- 阶段/切片：M0-S5
- Job ID：`M0-S5-DOMAIN-IR-GOLD`
- 风险等级：D2（合同和初始金标基线冻结）
- 提议/执行/审计：主执行者；确定性校验器、独立哈希统计和安全门二次复核
- 状态：已执行，本地验收通过，生产未激活

## 2. 必要性

- 被阻塞目标：M0 退出门和后续 M1—M5 的精确 revision、IR、模板、视觉与许可依据。
- 若不执行的影响：导入、五类文档和备份会各自解释可变数据，无法证明一致性或回滚。
- 更安全替代方案：只写说明文档而不冻结机器可读 schema；不能提供可执行证据，拒绝。
- 推荐方案及理由：仅在 Test 内冻结版本化合同和逻辑 registry；外部原件只读，不迁移活动库。

## 3. 精确范围

### 读取

| 请求路径 | 解析路径 | Test 外 | Copy ID | SHA-256 |
|---|---|---:|---|---|
| 18 个稳定逻辑 ID | `Task/local/GOLD_SOURCE_MAP.local.json`中的本机映射 | 是/混合 | 未复制，copy-on-use | 63 个成员逐文件记录 |
| 活动 SQLite | `data/db/question_bank.sqlite3` | 否 | 不适用 | `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94` |

外部映射的物理路径和文件名保持 Git 忽略，不写入报告或 registry。只读指纹总计
63 个成员、853,658,555 bytes。

### 新增/修改

| 操作 | 请求路径 | 解析路径 | 预计大小 | 原哈希 |
|---|---|---|---:|---|
| 新增 | `app/domain_models.py`、`app/ir_contracts.py`、`app/gold_registry.py` | Test 内 | 约 105 KiB | 不适用 |
| 新增 | `contracts/m0/*.json`、`gold/m0/*.json` | Test 内 | 小型 JSON | 不适用 |
| 新增 | S5 测试与构建器 | Test 内 | 小型源码 | 不适用 |
| 修改 | safe launcher、基线说明、清单和阶段状态 | Test 内 | 小型文本 | Git 可恢复 |

### 移动/隔离

| 原路径 | 隔离路径 | 文件数 | 字节数 | 恢复方式 |
|---|---|---:|---:|---|
| 14 个被替代 test_lab 运行 | C 盘既有 Codex workspace-relief/S5 目录 | 归档内 19,774 项 | 原目录约 269 MiB | 从 C 恢复区或已验证 tar.gz 恢复 |
| 5 个 inventory 与 2 个 gold preview | C 盘既有恢复区 | 归档内 116 项 | 原目录约 2.6 MiB | 从 C 恢复区或已验证 tar.gz 恢复 |
| 松散 runner 日志 | C 盘既有恢复区 | 7 个日志/状态文件及本地日志目录 | 小型 | 原路径可移动恢复 |

- 总文件/字节预算：外部只读 853,658,555 bytes；Git 只新增小型合同/测试；热运行峰值
  132,750,975 bytes。
- 明确排除目录：活动业务库写入、外部原件复制、字体安装、正式输出、模型和用户资料。

## 4. 边界预检

- [x] 所有项目写目标严格位于 marker 验证的 Test
- [x] 无 UNC/设备路径/ADS/`..`进入合同或 tracked registry
- [x] 受测路径链无 Reparse Point；外部 hardlink/reparse 拒绝
- [x] 未使用禁止命令或永久删除
- [x] 外部资料只登记且保持 copy-on-use，未冒充 Copy
- [x] 构建器 cwd/output 固定在项目内，测试 TEMP/cache 由安全启动器重定向
- [x] 无 PII、密钥、物理路径和原件进入 Git
- [x] 单写者状态保持有效
- [x] 运行前 E 盘约 61 GiB 可用，足以保留候选和恢复点

## 5. 当前状态与检查点

- Git branch/head/status：`agent/m0-m5-local-v1`；
  功能检查点`4a9512beb04546649214ad20560c88d784334d92`
- 活动数据库/state：哈希不变，`user_version=0`，未迁移、未切换
- Backup/Checkpoint ID：Git 功能检查点；S4 SQLite rescue/restore 能力保持可用
- 文件 manifest：RUN-118 inventory、gold registry canonical hash和冷归档 manifest
- 数据库完整性：沿用 S4 `integrity_check=ok`、外键违规 0；S5 全程数据库字节不变
- 恢复 staging：不适用；本切片未修改活动状态
- 回滚触发条件和步骤：合同测试或隐私/许可扫描失败即不发布；普通 Git revert，
  活动库无需恢复
- 恢复演练：IR v0.9↔v1 回滚、revision前驱、金标旧 hash保留均由测试覆盖

## 6. 干跑

- 干跑位置：`tmp/gold_registry_preview/RUN-20260725-M0-S5-GOLD-107`和
  `tmp/inventory_preview/RUN-20260725-M0-S5-INVENTORY-118`
- 命令/API：固定 cwd 的 gold preview builder、静态 inventory preview builder
- 预计/实际差异：18 个逻辑条目、63 个成员、12 个模板族和 462 个写入口均与预期一致
- 是否出现额外路径：否；tracked产物无绝对本机路径或源文件名
- 自动测试：RUN-122为460/460；RUN-123为1105/1105；显式暂存后RUN-125为460/460
- 用户流程：真实外部 Copy 与金标定位保留给 S6；本切片不虚报完成
- 结论：合同与 registry可冻结，生产仍须保持断开

## 7. 独立审计

- 路径/删除风险：构建器只读源且排斥链接；整理只在完整 tar 列表/hash通过后移动到 C，
  没有永久删除
- 数据/迁移风险：活动库前后 SHA-256 完全一致；IR迁移/回滚为内存合成数据
- 外部进程/依赖风险：未安装新依赖；所有 pytest仅由安全启动器运行
- 隐私/许可风险：registry只含逻辑 ID和哈希；2 个`unverified`、3 个`internal`和
  1 个`unknown`继续阻断客户分发
- Git/远端风险：原件、private map、运行证据和大文件均被忽略；显式暂存后普通 push
- 决定：批准本地合同基线；禁止据此激活生产 writer或声明客户可分发
- 附加条件：S6完成 M0真实流程；M1完成真实视觉；M5完成许可/PII发布审计

## 8. 实际执行

- 开始/结束：2026-07-25；最终本地冻结于 14:48:01 +08:00
- 实际操作清单：新增领域/IR/registry验证器、8 个 schema、5 个金标文件、构建器、
  3 组测试和 S5 safe modes；发布 RUN-118 inventory
- 文件/字节数：功能提交 25 个文件、约 9,617 行新增；外部复制 0
- 是否完全符合 manifest：是
- 异常/中止：
  - RUN-105 的页面尺寸断言错误把实测值当理论值，修正测试为真实测量容差；
  - RUN-116 唯一失败为 Windows Job 子进程终止观察竞态，子进程随后已结束；加入有界等待后
    RUN-117和RUN-123通过；
  - RUN-119—121因后台日志错误重定向到受保护树而安全停止，未进入 pytest；改到门禁明确
    排除的证据目录后RUN-122通过。未降低保护。

## 9. 执行后验证

- [x] Test 外项目/运行时写入为 0
- [x] registry、inventory和归档哈希符合预期
- [x] 活动数据库字节不变
- [x] S5和全仓自动测试通过
- [ ] M0真实用户流程通过（S6待完成）
- [ ] 真实视觉回归通过（M1待完成）
- [x] 外部原件未改变；构建器只读复核
- [x] 机器可读确认历史和阶段证据成功
- [x] 旧合同/源哈希和Git恢复点可用

## 10. Git、发布和回滚

- Commit/branch/push：功能提交`4a9512b`、验收提交`ba36cbd`均已普通push；
  本地、origin和ls-remote核验一致
- 暂存隐私扫描：必须在提交前执行 fixed-path/secret/大文件检查
- 是否回滚及结果：未触发；活动状态未改变
- 最终结论与遗留风险：S5本地`ACCEPTED`；M0总门仍未通过，production writer和
  462 个入口继续`UNMIGRATED_BLOCKED`
