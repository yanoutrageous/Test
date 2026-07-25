# M0-S6 真实流程、生产写入口与 M0 总门

## 结论

M0 已通过本机退出门禁，机器可读状态为 `M0_EXIT_ACCEPTED`。本切片接通固定根
production writer，完成 Test 外真实只读来源 Copy、六条 M0 真实流程、420 个生产副作用
入口逐项控制绑定、数据库副本迁移/回滚、金标代表页面定位和最终安全审计。

活动数据库没有迁移、切换或业务写入，仍保持 `user_version=0`；这次通过的是可回滚地基，
不是 M1—M5 产品交付终点。

## 生产写边界

- `app/safety/windows_handle_writer.py`提供固定根、句柄绑定、单次 ticket、无覆盖文件创建、
  可变数据库 lease 和目录 no-replace 发布。
- `app/safety/production_guard.py`只向固定 portable root 暴露一个 production boundary。
- `app/safety/workspace_io.py`是生产代码的窄 I/O 门面；目录、不可变文件、数据库连接和目录
  发布均不能由调用者扩大根。
- 配置、数据库、迁移/备份、导入、导出、资产和阶段报告写入口已迁入该门面。
- `app/safety/external_source.py`与`app/source_copy.py`提供外部只读句柄到
  `Copy/source/<copy_id>`的路径脱敏、最终复核和 no-replace 发布。

最终静态清单：

- scanner：`M0-S6-STATIC-AUDIT-V21`
- 生产源：60
- 入口：420
- 分片：17
- `UNKNOWN_DYNAMIC`：0
- 未迁移入口：0
- 无效绑定：0
- `production_writer_connected=true`
- `m0_exit_allowed=true`
- `global_status=M0_EXIT_ACCEPTED`
- binding 文件 SHA-256：
  `a16232648ebda21e1bf75e5e0c8bea9fd80bf68d04b68a7dc43f0e8b0864aeb7`
- inventory payload SHA-256：
  `d78470cc94bf23eae6871c0e05ff1b839d3de5e4190f3fae87a87cfc040fc778`
- inventory 文件 SHA-256：
  `db4e1ff1fe708b585ddb45c09ea95babfbe616292580a4e5611f2f3263199bd1`

## 六条真实流程

`RUN-20260725-M0-S6-FLOWS-145`一次通过：

1. 在 `PROJECT_ROOT` 内的中文/空格 fresh-state 创建五类目录和 schema v1 SQLite，
   `integrity_check=ok`、外键违规 0。
2. 中文/空格模拟迁移根通过 marker 与 NTFS 验证；缺 marker、篡改 marker、硬链接 marker、
   实际 NTFS Junction、UNC 和盘符根全部失败关闭。Junction 在验证后只移除本轮自建链接，
   目标目录未变化。
3. 从 Test 外读取一个 109,735-byte PDF，通过只读句柄复制到不可变 Copy。来源、Copy 与
   金标 SHA-256 均为
   `7b9baf1e0419d7a8cd31488e3b9092c3e3d055a116fdcdd1bc38a075b1684d5f`；
   provenance 不含物理路径或源文件名。
4. 合法中文/空格项目内写入成功；同级目录、其他本机位置、盘符根、UNC、设备路径、
   `..` 和 ADS 共 7 次越界写入全部拒绝，副作用为 0。
5. 活动 v0 数据库只经 SQLite Backup API 进入 rescue copy；候选副本迁移到 v1，
   再恢复为 v0 并成功启动旧只读查询。三条路径数据计数一致，完整性与外键检查通过。
6. `REF-ANSWER-SHEET-GOLD/MEMBER-001`被定位到 Copy；PyMuPDF 从 Copy 打开 6 页，
   代表第 1 页为 210.009 × 297.004 mm，与 registry 一致。

真实流程证据 SHA-256：
`6af6bd34dd4264cfc1b6449571a6040b6e6458ddbd91ad6d087d2387a32a522c`。

## 门禁与审计

| 证据 | 结果 |
|---|---|
| `RUN-20260725-M0-S6-144` | 93/93；外部 Copy 与核心生产流 |
| `RUN-20260725-M0-S6-GATE-147` | 628/628；S6 阶段组合门 |
| `RUN-20260725-M0-S6-INVENTORY-148` | 60 sources、420 entries、17 chunks、M0 exit accepted |
| `RUN-20260725-M0-S6-EXIT-149` | 34/34；退出证据、清单、崩溃/竞态与生产边界冻结门 |

147 的活动库前后哈希一致；26,870 项保护树前后 digest 一致；82 个登记来源终态全部
匹配；watcher、句柄围栏、运行树、不可变证据和子进程回收全部通过。149 在退出证据加入后
再次验证 30,959 项保护树和活动库不变。

独立审计结果：

- `git diff --check`：0 项；
- 固定本机/父目录绑定：0 项；
- tracked 外部物理 locator：0 项；
- `os.system`、`shell=True`等危险调用：0 项；
- 未披露 P0/P1：0 项；
- `contracts/m0/m0-exit-evidence-v1.json`已绑定生产 source manifest、420-entry digest、
  binding 文件和真实流程报告哈希。

## 活动库与回滚边界

- 活动库 SHA-256：
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`
- 大小：471,040 bytes
- `user_version=0`
- 本轮大小、mtime 和哈希均未变化
- migration v1 只存在于候选 state；rescue/rollback state 均保留且由 Git 忽略
- 后续如切换活动 schema，仍必须作为单独可回滚动作执行，不能把本轮副本演练冒充为已切换

## E 盘整理

- 新增两个压缩归档覆盖 14 个旧/被替代 test runs 和 7 个旧 inventory previews；
  逐成员流式哈希验证覆盖 706,111,924 source bytes，危险路径、重复成员和内容差异均为 0。
- 全部 19 个冷归档在 M0 freeze 时重新计算 SHA-256 并完整列出 238,143 个成员，
  压缩后共 746,034,234 bytes，危险成员为 0。
- 14 个旧 test runs 和 7 个旧 previews 在归档验证后可恢复地移动到既有 C 盘 relief；
  没有永久删除。
- E 盘热目录只保留 147、149 和最终 inventory preview 148；冷归档目录已被 safe launcher
  固定排除，不会在日常门禁中重复枚举。
- 整理后 E 盘可用 84,933,775,360 bytes（约 79.10 GiB）。

后续默认只跑受影响的精确测试或 `*_core`；组合门只在切片候选稳定时运行，全量门只在阶段
冻结、保护边界变化或跨模块风险无法由核心门排除时运行。

## 已披露剩余风险

- 普通账户创建真实目录 symlink 仍受 WinError 1314 限制；本轮实际 NTFS Junction 和所有
  可执行攻击分支已失败关闭，不提权、不修改开发者模式。该主机能力限制不是未披露 P0/P1。
- 活动 schema 切换仍有意延后；M1 只能在独立备份、候选导入和恢复门下推进。
- 字体许可、真实渲染人工叠图、OCR、完整试卷导入、五件套、模板维护和客户恢复旅程分别属于
  M1—M5，不能由 M0 结果代替。

## 阶段决定

M0：`ACCEPTED`。

下一步：形成显式 Git 检查点并普通 push，然后进入 M1 的真实完整试卷 Copy → 导入 →
人工复核 → 正式渲染闭环。
