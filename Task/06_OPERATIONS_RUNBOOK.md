# 长时间自动化运行手册

## 1. 运行层级

```text
Run
└── Milestone（PRE_M0、M0—M5、COMPLETE）
    └── Stage
        └── Slice
            └── Work Unit
```

每个 Work Unit 必须声明：

- 唯一 ID 和幂等键；
- 输入、输出和允许写入路径；
- 输入、配置和工具链哈希；
- 前置条件；
- 验证命令和验收标准；
- 预计磁盘、内存、时间和并发需求；
- 重试策略；
- 检查点和回滚方式。

幂等键建议：

```text
(run_id, milestone, work_unit_id, input_hash, config_hash, toolchain_hash)
```

相同幂等键已成功完成时不得覆盖重跑；复用已验证结果，或显式创建新 revision。

里程碑枚举固定为`PRE_M0`、`M0`、`M1`、`M2`、`M3`、`M4`、`M5`和`COMPLETE`。`PRE_M0`只用于规划发布、依赖预检和长任务入场，不属于六个交付里程碑；`COMPLETE`只能在 M5 客户验收通过后进入。

## 2. 状态机

正常状态：

```text
PLANNED
→ PREFLIGHT
→ READY
→ RUNNING
→ VERIFYING
→ CHECKPOINTED
→ COMMITTED
→ PUSH_PENDING
→ PUSHED
→ MILESTONE_ACCEPTED
```

异常状态：

```text
WAITING_RESOURCE
WAITING_DECISION
WAITING_REMOTE
FAILED_RETRYABLE
FAILED_SAFE
SECURITY_STOP
ROLLING_BACK
ROLLED_BACK
BLOCKED
```

规则：

- 状态变化追加到事件日志，`RUN_STATE.json`只保存当前快照；
- `RUN_STATE.json.status`必须取自上述正常或异常状态；实现是否开始另记在`implementation_status`，不得自造组合状态；
- 状态文件使用临时写入和原子替换；
- `SECURITY_STOP`、路径越界、哈希不一致、未知删除不得自动重试；
- 只有`MILESTONE_ACCEPTED`才可进入下一里程碑；
- 目标只有 M5 客户交付完成后才可标记 complete。

## 3. 每次启动预检

### 规范和状态

1. 读取`execution_contract.json`及全部 Task 规范；
2. 读取`CURRENT_STATUS.md`和`RUN_STATE.json`；
3. 核对 plan version、milestone、checkpoint 和阻塞项；
4. 读取`AGENTS.md`、`Base/Base.md`及当前切片代码；
5. 不重复已完成且证据仍有效的工作。

### 工作区

- 从受信任`app/project_root.py`位置和`.exam-bank-root.json`解析唯一项目根，验证本地 NTFS、非盘符根、marker 单链接及全链无 Reparse Point；不得从 cwd、环境变量或调用者参数取得生产根；
- 若物理路径、主机或卷与最近一次执行证据不同，先按`01_SAFETY_BOUNDARY.md`完成迁移复核；旧路径上的文件系统/保护树证据只作历史记录，不能直接授权新位置 mutation；
- 记录 Git 分支、HEAD、remote、未提交/未跟踪文件；
- 检查没有 merge/rebase/cherry-pick 中间状态；
- 用户修改与切片重叠时停止，不 stash/reset/覆盖；
- 获取写锁和 job ID；
- 核对活动数据库和上次检查点。

迁移后的`.venv`只可在解释器 home、项目内可执行文件位置、锁定依赖导入和版本全部通过时临时复用；正式恢复点应记录可重建命令。Git 忽略的`Task/local/`路径映射必须在每台电脑单独维护，禁止把外部绝对路径写回受跟踪合同、业务表或客户包。

### 工具

- 只检查当前阶段真正需要的工具；
- 核对 GitHub CLI 认证和授权仓库；
- 服务只绑定`127.0.0.1`/`::1`；
- GPU 只作为优化项，除非阶段 ADR 明确成为门禁；
- 缺依赖按安全规范审计，默认不安装。

### 资源

高 I/O 作业最低可用空间：

```text
minimum_free =
  prechange_checkpoint_size
  + estimated_temp_peak
  + estimated_output_size
  + max(5 GiB, 上述合计的 25%)
```

备份/恢复还必须能同时容纳活动状态、备份、恢复 staging 和救援快照。无法估算时先小样测量，禁止直接全量运行。磁盘健康或空间不足进入`WAITING_RESOURCE`，不得自动删除内容腾空间。

## 4. 单写者锁

写锁位置建议：

```text
Task/state/writer.lock
```

记录：主机、PID、run ID、job ID、阶段、预计范围、开始时间和心跳。

- 有效锁存在时，其他代理只能只读；
- 不删除锁抢占写权限；
- 回收过期锁前先确认 PID、Git、数据库和 staging 状态；
- Git、迁移、活动状态切换、备份发布和正式发布期间必须独占；
- 多代理只能并行互不重叠的只读/分析任务，主执行者统一写入。

## 5. 检查点

必须建立检查点：

- 每次数据库迁移前；
- 批量导入、重绘、索引和视觉基线更新前；
- 每个 Slice 验收后；
- 每个 Milestone commit/push 前；
- 发布和恢复演练前；
- 任何 D2 高风险操作前。

检查点包含：

- run、plan、时间和阶段；
- Git base/head；
- SQLite 一致快照和完整性检查；
- 相关输入/输出 manifest；
- 配置、依赖锁和哈希；
- 已完成 work unit 和继续位置；
- 恢复步骤与活动版本；
- 未提交用户文件的路径摘要，不复制敏感正文。

检查点先在 staging 验证再发布，禁止用`git reset --hard`充当回滚。

## 6. 进度与心跳

- 活跃交互期间至少每 60 秒提供一次简洁状态更新；
- 更新包含当前里程碑、正在做的切片、最近完成、下一步和风险；
- 长命令使用可等待/可恢复机制，不执行超过 60 秒的不可观察 sleep；
- job 事件日志记录开始、心跳、进度、资源、完成和错误；
- 用户插入新消息时判断是替代还是补充任务，并更新 RUN_STATE；
- 上下文压缩或会话续作后从状态和证据自然继续，不重做已完成工作。

## 7. 重试

允许有限重试：

- 短暂文件锁；
- 本地服务端口竞争；
- 可重入渲染器超时；
- GitHub 网络瞬断；
- 明确幂等的只读/派生作业。

同类失败最多两次有依据的修正尝试。每次使用新临时目录并保留失败摘要。第三次仍失败进入`BLOCKED`。

不得重试：

- 路径/写边界异常；
- 输入运行中变化；
- 哈希、数据库完整性或迁移失败；
- 数据丢失、答案泄漏或字体静默替换；
- PII、密钥或 Base 进入暂存区；
- 远端分叉；
- 磁盘不足；
- 未知删除或额外输出。

## 8. 依赖审计流程

缺少工具时先记录`dependency-audit`：

1. 哪个已批准需求被阻塞；
2. 仓库/系统现有工具是否可满足；
3. 是否存在 Test 内便携安装；
4. 候选来源、版本、许可、哈希和支持状态；
5. 安装写入、网络、权限、服务和回滚影响；
6. 安装后如何锁定、离线复现和测试；
7. 不安装的影响。

项目内安装或用户范围无提权安装只有审计通过才可执行。管理员/UAC、服务、驱动、系统策略、未知来源或许可不清进入`WAITING_DECISION`。

禁止为了“可能以后有用”批量安装 OCR、模型、TeX 套件或前端工具。

## 9. 长任务取消与恢复

取消时：

1. 停止接受新 work unit；
2. 请求当前子进程正常退出，超时后只终止本 job 进程树；
3. 关闭数据库事务并回滚未提交事务；
4. 不发布部分 bundle、索引或备份；
5. 保存失败 staging、日志和状态；
6. 写最后安全检查点；
7. 释放锁。

恢复时：

1. 读取最后已验证检查点；
2. 复核输入、配置、工具链、Git SHA 和外部源哈希；
3. 未知/不完整 staging 不冒充成功；
4. 只重跑未完成或证据失效 work unit；
5. 数据恢复先落新 staging，验证后切换；
6. 无法证明安全时进入`FAILED_SAFE`。

## 10. 阶段记录

每个 Slice/Milestone 维护：

- run ID、plan version、时间；
- base/head、分支和远端状态；
- 范围与明确未做项；
- 变更文件、迁移和资产版本；
- 输入类别和脱敏统计；
- 自动测试、首次失败、真实用户流程和视觉结果；
- 安全/网络/外部写入证明；
- 性能和资源峰值；
- ADR、依赖审计和计划变更；
- 未验证项、缺陷和风险；
- 检查点、回滚和恢复结果；
- 阶段结论。

大体积证据位于 Git 忽略的本地 evidence 目录；Task 报告记录相对逻辑路径和哈希。

## 11. 安全停止后的继续策略

- 冻结受影响切片；
- 保留现场，不清理或覆盖；
- 继续没有依赖关系、只读或低风险工作；
- 更新风险、RUN_STATE和用户状态；
- 只有根因和回归验证完成后恢复写入；
- 不能因剩余工作困难或耗时而把目标标记完成。

## 12. M5 结束条件

只有`10_DELIVERY_DEFINITION.md`全部满足、客户旅程在发布提交上断网跑通、恢复演练成功、Test 外写入为 0、远端阶段记录完整，才结束长期运行。否则状态保持进行中、拒绝或阻塞。
