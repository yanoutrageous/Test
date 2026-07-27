# M0 可迁移项目根与新电脑重建报告（2026-07-24）

## 结论

- 门禁结论：**ACCEPTED**
- 当前电脑的物理观察位置为`E:\AAA命题\Test`，但该字面量不再是生产权限合同。
- 项目根改由受信任`app/project_root.py`位置和根`.exam-bank-root.json`精确字节共同授权；cwd、环境变量、配置、CLI 参数和调用者路径不能扩大根。
- `RUN-20260724-M0-PORTABLE-FULL-037`以最终退出码 0 通过，因此当前状态可以继续 S3-F checkpoint、S3-G 和后续 M0 工作。
- 本报告只验收可迁移根和新机重建基线，不批准连接 production writer、处理真实资料或宣称 M0 已完成。

## 已确认环境

| 项目 | 当前事实 |
|---|---|
| 根路径观察 | `E:\AAA命题\Test` |
| 文件系统 | NTFS；项目根及祖先未发现 Reparse Point |
| Python | 3.12.13 |
| Flask | 3.1.3 |
| PyMuPDF | 1.28.0 |
| pytest | 9.1.1 |
| SQLite | 3.50.4 |
| Git 分支/恢复 HEAD | `agent/m0-m5-local-v1` / `6e225c8e4ba06332a197a1acdcbd1f86edce4d99` |
| 活动数据库 SHA-256 | `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94` |
| 数据库状态 | `integrity_check=ok`、外键违规 0、核心业务表为空 |
| 历史临时工件 | 约 7.65 GiB；未获授权，未清理 |
| E 卷剩余空间（检查时） | 约 29.91 GiB |

现有`.venv`在本机可用，但`pyvenv.cfg`仍保留旧电脑创建信息。因此它只属于本机恢复工具，不属于便携交付物；再次迁移时应按依赖清单重建。

## 根权限实现

1. 根 marker 使用无盘符、无用户名、无绝对路径的精确 UTF-8/LF JSON，策略为`PORTABLE_LOCAL_NTFS_V1`。
2. 根只能从受信任模块位置推导，并验证绝对本机盘符路径、NTFS、严格低于盘符根、祖先无 Reparse、marker 和权限模块为单链接普通文件。
3. marker 采用读取前、句柄读取、读取后三次身份核对和精确 SHA-256；篡改、硬链接、非 NTFS、相对路径和调用者选择根均失败关闭。
4. 配置、生产 boundary、safe launcher、早期 bootstrap、外源只读策略、静态审计和 inventory 工具统一引用该 authority。
5. 业务路径合同改为项目相对路径；本机外部参考绝对路径只保存在 Git 忽略的`Task/local/`映射。

## 验证证据

### 最终成功运行

`RUN-20260724-M0-PORTABLE-FULL-037`

| 门禁 | 结果 |
|---|---|
| pytest/JUnit | 961 passed；0 failure、0 error、0 skipped |
| 最终退出码 | 0 |
| 保护对象 | 前后均 126,030 |
| 保护树 digest | 前后均`2d2d21de9bdde11f05801d5d7fa73f6bafb8b3302d207dcb0792fd0383d74a0b` |
| 活动数据库 | 前后 SHA-256 相同 |
| 运行树 | 单链接、无 Reparse、预算有效 |
| immutable evidence | 前后相同 |
| 实时 watcher | 有效，变化 0 |
| 句柄围栏 | 有效，126,030 个对象 |
| 合成来源见证 | 80 份；终态全部与登记状态相同 |
| 进程树 | 正常终止，无超时 |

### 静态清单

- Scanner：`M0-S3-STATIC-AUDIT-V16`
- 生产源：53
- 副作用入口：464
- 分片：19
- `UNKNOWN_DYNAMIC_CAPABILITY`：0
- 未授权 Guard/authority 构造：0
- inventory payload：`e31de8130346d87eb1b92109f88580cbb5ea33502d0b316a48a27fe7c172659c`
- 464 项仍全部`UNMIGRATED_BLOCKED`，`production_writer_connected=false`，`m0_exit_allowed=false`

### 失败证据保留

- RUN-025：调用工具关闭标准输出导致 pytest 内部错误；保护树和数据库安全，但不能作为功能通过证据。
- RUN-031：定位出 31 项未完成候选/迁移适配失败。
- RUN-034：收敛到 2 项失败，并发现测试攻击硬链接未清理导致运行树拒绝。
- RUN-036：全部安全门通过，剩余 2 项测试导入/时序问题。
- RUN-037：最终全绿并通过全部安全门。

上述运行号均不复用，也未删除现场。

## 当前电脑独立 symlink 门

`RUN-20260724-M0-SYMLINK-CAPABILITY-038`在本机以普通权限创建真实目录 symlink 时返回 WinError 1314。该单测因此 1 项失败；但 134,045 个保护对象、数据库、运行树、watcher、句柄围栏和来源见证均保持安全。

处理决定：

- 不擅自提权；
- 不自动开启 Windows 开发者模式；
- symlink 实物门继续标记为`M0-SYMLINK-CAPABILITY-001`；
- 不依赖该能力的 M0 工作可继续。

## 再次迁移时的强制顺序

1. 静止复制完整项目根，禁止拼接不同时间点内容。
2. 重建虚拟环境；不得把旧`.venv`、PID、writer lock 或旧卷安全证据当作新机事实。
3. 运行`python -B -m app.project_root`验证 marker、NTFS 和根链。
4. 重新绑定 Git 忽略的`Task/local/REFERENCE_PATHS.local.md`，逐项只读核对来源哈希。
5. 核对 Git HEAD/远端、数据库 integrity/hash、磁盘预算和依赖导入。
6. 使用全新 run ID 重跑完整保护树与当前切片回归。
7. 新位置证据通过前，production writer 保持断开。

本次迁移已完成步骤 4 的存在性预检：16 个逻辑参考集、共 25 个明确文件或目录均存在；来源内容哈希仍应在首次进入具体业务切片时按该切片重新核对。

## 风险与下一步

- 当前 E 卷剩余空间约 29.91 GiB；历史`tmp`约 7.65 GiB且全量门耗时较长。不得未经用户授权清理历史证据。
- 当前备份仍在项目根同卷内，不能宣称抵御整卷故障。
- 用户已重新授权并完成新机 GitHub CLI 2.96.0 用户范围安装；Git Credential Manager OAuth 凭据经仅存在于进程环境的桥接通过`gh`API 身份检查，不在仓库或报告中持久化令牌。
- Git checkpoint 已作为`f9756df79d979ef10f54fc4634f15849857019da`完成并通过远端核验；当前进入 S3-G，M0 总门仍未通过。
