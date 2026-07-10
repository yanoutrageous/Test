# ADR-2026-001：所有生产写入先经过中央 WorkspaceGuard

- 状态：Accepted
- 日期：2026-07-11
- 决策级别：D2
- 影响里程碑：M0—M5
- Requirement IDs：`M0-SAFE-001`、`M0-SAFE-002`、`M0-DB-001`
- 替代 ADR：无

## 背景与已确认事实

现有`connect_database(db_path)`、`get_project_paths(project_root)`、Codex JSONL、报告、导出、PDF 和资产模块存在多个独立路径解析/写入入口。部分入口允许任意绝对路径，且查询路径可能初始化目录或 schema。历史局部`Path.resolve().relative_to()`检查不能覆盖 Windows ADS、设备路径、盘符相对路径、Reparse Point、TOCTOU 或 Test2 前缀混淆。

## 约束与不可变底线

- 真实授权根固定为`D:\AAA命题\Test`；
- 测试只能在该根内部模拟更小 workspace/protected 兄弟目录；
- 路径不确定时失败关闭；
- 不跟随 Reparse Point；
- Guard 通过前不迁移活动库、不加工真实资料；
- 不以 OS 管理员权限或危险删除命令作为沙箱替代。

## 候选方案

### 方案 A：每个模块继续自行检查

- 优点：改动小。
- 风险：规则漂移、遗漏入口，无法统一审计和攻击测试。
- 回滚：不适用。

### 方案 B：中央纯 WorkspaceGuard，逐入口接入

- 优点：单一规则、可属性测试、可在 Test 内攻击实验室验证；支持先建立无副作用核心再迁移入口。
- 风险：需要分批改造历史模块，并显式区分读、写、新目标和现存目标。
- 回滚：每个接入切片可单独 revert，活动数据不变。

### 方案 C：依赖外部容器/系统沙箱

- 优点：额外隔离层。
- 风险：引入系统依赖和权限，仍不能替代应用路径正确性，不符合便携本地目标。
- 回滚：卸载/配置恢复成本高。

## 决定与理由

选择方案 B。

首个实现只提供无副作用的路径授权与检查，不执行写入/删除。Guard 接受：

- `authorization_root`：真实项目根，生产固定为`PROJECT_ROOT`；
- `workspace_root`：生产等于项目根；测试可为`authorization_root/tmp/test_lab/<run>/project`；
- 目标路径和操作意图：existing read、new/existing write、move source/target 等后续逐步扩展。

任何自定义 workspace 必须先证明严格位于 authorization root。目标 containment 使用路径组件比较，不使用字符串前缀。

首批拒绝：空路径、隐式当前目录、未展开变量、`..`、UNC、`\\?\`、`\\.\`、其他盘符、盘符相对、ADS、控制字符、尾随点/空格、Windows 保留名、Test2 前缀、路径链中的 Reparse/Junction/符号链接和不存在目标的链接父目录。

## 安全、数据、许可和客户体验影响

- 安全：先封闭 P0 越界写面；失败时不自动改写路径。
- 数据：首切片不触碰活动数据库和业务文件。
- 许可：无新依赖。
- 客户体验：后续错误统一转成中文可执行提示；当前先提供结构化安全异常。

## 迁移、兼容与回滚

1. 新增 Guard 与攻击测试；
2. 先接`config/database`，提供真正只读连接；
3. 按写入口清单逐模块接入；
4. 静态扫描禁止新增直接写入口；
5. 每个切片在旧测试和新安全测试通过后单独 commit/push。

失败时 revert 当前接入提交；不回滚或覆盖活动数据。

## 验证和真实用户流程

- 所有攻击在 Test 内模拟 project/protected 环境执行；
- protected 哨兵运行前后哈希不变；
- 合法中文深路径正常授权；
- 所有拒绝均无创建、修改、移动或删除副作用；
- 接入后跑旧 88 测试和对应公开入口流程。

## 未决项

- Windows TOCTOU 的最终句柄级缓解需要在核心 API 后单独审计；
- 外部只读参考根与 Copy source 规则在后续 Guard policy 中扩展；
- 原子 writer、quarantine 和安全进程包装器属于后续独立切片。

## 审批/审计

M0 入场事实和独立安全预检支持本决定。任何放宽拒绝规则或允许 Test 外写入的变更必须进入 D3。
