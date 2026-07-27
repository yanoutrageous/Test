# ADR-2026-005：可迁移本机项目根与跨电脑恢复契约

- 状态：Accepted（实现与新位置证据已验证）
- 日期：2026-07-24
- 决策级别：D3（用户已明确要求跨电脑、跨路径迁移）
- 影响里程碑：M0—M5
- Requirement IDs：`M0-SAFE-001`、`M0-SAFE-002`、`M0-SAFE-004`、`M0-SAFE-007`、`M5-PORTABLE-001`
- 补充：`ADR-2026-001`至`ADR-2026-004`

## 背景与已确认事实

仓库从旧电脑的 D 盘路径迁移到当前`E:\AAA命题\Test`。代码、测试启动器、静态审计和执行状态中仍有把旧绝对路径当作生产权限的实现；如果只把字面量改成 E，下一次换电脑会再次失效，并可能让旧主机的 writer lock、保护树证据和本机参考路径被误当成当前事实。

当前 E 卷为 NTFS，项目根和祖先无 Reparse Point；Python 3.12.13 及锁定的 Flask、PyMuPDF、pytest、SQLite 可运行；活动库完整且核心业务表为空；恢复前 Git 与远端 head 一致。既有 S3-F 未提交候选已用聚合哈希冻结并保留，因此可以先重定根而不迁移业务行或覆盖用户内容。

客户交付定义本来就要求“产品根即唯一写根”和相对路径。把开发安全根绑定某个盘符与该终局冲突，所以本修订属于 M0 安全前置条件，不是新增业务范围。

## 决定

1. `PROJECT_ROOT`是逻辑权限，不是固定绝对路径。生产 authority 从受信任`app/project_root.py`模块的物理位置向上找到仓库根，再验证同一根中的受跟踪`.exam-bank-root.json`。
2. marker 使用精确、无绝对路径的 UTF-8/LF 文档：
   - `project_id=YANOUTRAGEOUS-LOCAL-EXAM-BANK`
   - `root_policy=PORTABLE_LOCAL_NTFS_V1`
   - `path_storage=PROJECT_RELATIVE_V1`
   - `schema_version=1.0`
3. 根验证失败关闭：只接受本机盘符下、严格低于盘符根的 NTFS 目录；根、全部祖先、marker 和权限模块链不得含 symlink/Junction/Reparse。marker 与权限模块必须为单链接普通文件，marker 在读取前、句柄读取中和读取后保持同一身份与精确字节。
4. cwd、环境变量、命令行`--project-root`、配置、外部参考映射和调用者提供的`Path`均不能授予生产根。`inspect_project_root(candidate)`只用于只读检查候选副本，不会改变已绑定的生产 authority。
5. `app.config`、生产 boundary、safe pytest launcher、早期 bootstrap、合成外部源策略、静态审计和 inventory 工具必须引用同一已验证根。生产 boundary 仍使用导入时默认参数绑定，测试即使同时 monkeypatch 配置和导出常量也不能扩大根。
6. 数据库、业务表、backup/restore manifest、客户包和 Git 合同只保存项目相对路径或对象 ID。外部参考绝对路径只保存在 Git 忽略的`Task/local/`映射，按稳定逻辑 ID 和源哈希重新绑定。
7. `.venv`、缓存、测试实验室和主机 PID/lock 是每机状态，不是便携交付物。迁移后默认重建虚拟环境；临时复用必须核对解释器 home、项目内 executable、依赖版本和导入。
8. 跨电脑或跨目录恢复必须静止复制整个根，不能拼接不同时间点。新位置先验证 root、依赖、Git、数据库、磁盘和本机映射，再使用新 run ID 重跑保护树、外部零写入及当前切片回归，之后才允许 mutation。
9. 旧路径上的语义测试、提交和历史报告继续保留；其中绑定卷、祖先身份、保护树和外部零写入的结论只对旧运行成立。旧的未使用 run ID 也不转移到新基线。
10. 不自动扫描其他盘符寻找项目或参考资料，不修改注册表/AppData 建立根，不在 marker 中写用户名/物理路径，也不把 Git remote 当作本地写权限。

## 被拒绝方案

### 把所有`D:\...`机械替换为`E:\...`

拒绝。它只能修复本机一次，下一次迁移重新失效，也没有区分权限合同、历史证据和每机映射。

### 允许环境变量或 CLI 选择生产根

拒绝。任意调用者可把写权限扩大到其他目录；测试和配置 monkeypatch 也会成为生产绕过面。

### 从 cwd 或向上搜索任意 marker

拒绝。cwd 可被调用者控制，跨目录搜索会把同名 marker 或无关仓库误认为 authority。根只能来自正在执行的受信任权限模块位置。

### 复制旧`.venv`、writer lock 和安全证据后直接继续

拒绝。venv 可能保存旧解释器/创建路径，lock 的主机/PID 语义已失效，文件系统安全证据不能跨卷继承。

## 安全、数据和客户体验影响

- 唯一写根不放宽，只把“固定物理字符串”替换成“固定验证算法和项目身份”。
- 用户可把完整项目迁到另一普通本机 NTFS 路径，无需改源码；迁移后的第一启动会给出明确失败原因，而不是退回 cwd 或静默创建新库。
- 当前没有业务行需要路径迁移；后续 schema 仍禁止绝对路径进入业务表。
- marker 与代码同属受信任仓库源码边界，不能抵御攻击者同时篡改仓库代码和 marker；M5 仍需 release manifest、哈希/签名、fresh-user 和断网验收。
- 同卷备份仍不能抵御整卷故障；portable root 不等于异卷灾备。

## 迁移、兼容与回滚

兼容路径是整根移动后重新验证，不提供旧固定 D 字面量的运行时 fallback。历史 JSON/Markdown 报告中的绝对路径保留原样作为时间点证据；规范合同和当前状态显式标注其历史性。

若实现需要回滚，只能普通 Git revert 代码与规范；不得把生产 authority 改回当前 E 字面量。回滚期间生产 writer 保持断开，活动库不迁移，S3-F 脏候选继续保留。

## 验证

必须通过：

- 当前根只读 CLI 显示 marker、NTFS、逻辑策略和当前观察路径；
- 中文与空格的 Test-local 模拟迁移根通过；
- 相对路径、盘符根、UNC、非 NTFS、缺失/篡改/硬链接 marker、权限模块位置不一致和 Reparse 失败关闭；
- 配置与导出常量 monkeypatch 不能扩大生产 boundary；
- safe launcher、bootstrap、static audit 与 inventory 使用同一根；
- 活动数据库完整性/哈希不变，保护树与外部写入为 0；
- 固定路径扫描只允许历史证据和明确的攻击测试 fixture。

`RUN-20260724-M0-PORTABLE-LAUNCHER-025`已证明 101,937 个保护对象、watcher、句柄围栏、immutable evidence 和活动数据库未变化；由于调用工具提前关闭标准输出导致 pytest 内部错误，该 run 只能作为失败安全证据，不能作为本 ADR 的功能通过证据。

最终验收运行`RUN-20260724-M0-PORTABLE-FULL-037`在当前 E 根以退出码 0 完成：961 项测试全部通过，126,030 个保护对象前后 digest 均为`2d2d21de9bdde11f05801d5d7fa73f6bafb8b3302d207dcb0792fd0383d74a0b`，运行树、immutable evidence、实时 watcher、句柄围栏、活动数据库和 80 份登记来源终态见证全部通过。静态 inventory V16 覆盖 53 个生产源、464 个入口和 19 个分片，`UNKNOWN=0`且 tracked publication 与实时生成结果相同。

当前电脑的独立真实目录 symlink 能力运行`RUN-20260724-M0-SYMLINK-CAPABILITY-038`仍因 WinError 1314 无法创建测试 symlink；其 134,045 个保护对象、数据库和全部安全证据保持不变。该权限门继续单独记录，不自动提权或修改开发者模式，也不否定本 ADR 的可迁移根验收。

## 未决项

- 新根 full、launcher、S3-F 和静态 inventory 已由 RUN-037 冻结；S3-F 的 Git checkpoint 仍须完成显式暂存审计、提交和普通 push。
- 现有约 7.65 GiB 历史`tmp`使一次完整保护树运行约需二十余分钟；在不降低零外写保证的前提下，需要区分低频完整验收与高频受控回归。未获授权不得清理历史证据。
- 真实目录 symlink 仍受当前普通账户 WinError 1314 限制，不自动提权或更改开发者模式。
- 生产 writer 仍断开；本 ADR 不批准处理真实资料，也不代表 M0 验收通过。
