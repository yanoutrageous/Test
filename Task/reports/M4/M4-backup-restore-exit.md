# M4 备份、恢复、活动状态与回滚阶段报告

## 结论

M4 于 2026-07-25 达到 `ACCEPTED`。正式基线由
`BACKUP-M4-YANYAN-FULL-20260725`、
`BACKUP-M4-YANYAN-INCREMENTAL-20260725` 和
`STATE-M4-YANYAN-RESTORED-20260725` 组成。恢复状态经过 staging 全量校验和固定
用户旅程后才显式激活；随后实际执行回滚、重启检查和重新激活。旧活动 SQLite 没有被
覆盖，SHA-256 始终为
`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。

M4 接受不等于 M5 客户交付。当前备份仍位于产品根所在卷，不能抵御整卷损坏；这一限制
已经进入维护页、机器合同和本报告。

## 已实现

- 用户 UI 与公开 CLI 均可创建 full、incremental 和 rescue 备份、列出/校验备份、恢复
  到 staging、显式激活、回滚和重新激活；
- SQLite 通过 Backup API 生成一致快照；文件使用 SHA-256 内容寻址，manifest 不可变，
  增量备份按父链复用相同内容；
- 固定备份范围覆盖 M1 数据库版本、Copy 原件、M1/M2/M3 已发布资产、模板、taxonomy、
  导出快照、审计头和存在时的前驱活动指针；缓存、临时目录、浏览器状态、受限资料和
  未发布失败产物明确排除；
- 恢复前验证 manifest 结构、哈希、资源上限、路径规范和父链；恢复只进入
  `data/snapshots/<state_id>/files` staging；
- 激活门验证 SQLite 完整性/外键/业务计数、M1/M2/M3 manifest、154 个文件及 6 个
  恢复后公开运行旅程；
- 激活前创建救援备份，并以固定 `data/db/active-state.json` 原子替换切换运行状态；
  切换前和切换后中断均自动恢复旧指针；
- 明确执行一次回滚至 M3 前驱状态、重启旅程和重新激活；最终活动 generation 为 5；
- 路径穿越、旧 schema、缺资产、篡改数据库、资源炸弹和未声明文件 6 类候选全部被拒绝；
- 备份/恢复取消后均从既有 staging 继续，无覆盖发布；低空间在写入/删除前停止；
- 全部核心行为离线，外部网络请求和模型下载均为 0。

## 正式备份与恢复状态

### 全量备份

- 154 个逻辑文件，14,120,090 bytes；
- 126 个唯一内容 blob，实际存储 10,132,126 bytes；
- 数据库 SHA-256：
  `3e91259e4072e088435f9d8884ea3aafecab134b3086cb274633047b30356233`；
- manifest SHA-256：
  `693fcc9f26be9472b30c2635998d714f26880c8e7c83f4646144bfedbd5245e9`。

### 增量备份

- 154/154 个文件从全量父备份复用；
- 新 blob 0、实际新增内容 0 bytes；
- manifest SHA-256：
  `6f70dfaebcf8fd92beb99c134d020be18d13c300d9bad9edb0bd7e726cf02c81`。

### 恢复与活动状态

- state manifest SHA-256：
  `cc0638920af17d4193f308b15f04fc23aad33b468e53613cbf0622ad6b526e35`；
- activation gate SHA-256：
  `6405ea4be7fe40ee0dc733d7f7c5f83c558548c87ead6a8d6357008698d2b7be`；
- verification SHA-256：
  `4168bc5fd057aed5802a9202db8dcf8f59e782060751b27770c8b0657342f6a5`；
- 最终活动指针 SHA-256：
  `a69d77bb8f53568dc94c415938b84ca6a9b206f75c1c9d3a5cd0b63251825ca7`；
- 当前指针引用的救援备份
  `BACKUP-M4-RUNNER-RESCUE-REACTIVATE-20260725` 已在清理后再次完整校验。

## 真实流程与故障恢复

真实流程 `RUN-20260725-M4-REAL-PIPELINE-R1-181` 通过 UJ-060—067 共 8 条旅程：

- 维护页、状态、全量/增量创建、详情和恢复 UI 均返回成功；
- 恢复状态启动后，首页、搜索、题目打开、组卷篮、图形和学生卷导出 6 步均通过；
- 6 个恶意备份候选不可选择；
- 切换前/后故障注入均保持旧状态；
- 取消/续跑与低空间失败关闭通过；
- 回滚、重启、再激活以及再次重启通过；
- 旧活动数据库前后字节和哈希一致。

证据路径为
`tmp/jobs/INTERNAL/JOB-M4-REAL-FLOW-EVIDENCE-R1-20260725/m4-real-flow-evidence.json`，
SHA-256 为
`88d5224b80a423398cea8427ec4fe997758073b6a83abd246447a89deed8c057`。

## 自动验证

- `RUN-20260725-M4-CORE-R2-184`：149/149；
- `RUN-20260725-M4-FULL-R1-185`：561/561；
- failure/error/skip 均为 0；
- 完整门保护树前后均为 7,885 项且 digest 相同；
- runtime watcher、句柄围栏、run tree、不可变证据、来源见证和进程树全部通过；
- inventory `RUN-20260725-M4-INVENTORY-R2-183`：64 个生产源、446 个精确绑定入口、
  18 个分片，unknown/unmigrated/invalid 均为 0；
- M4 仅有两处固定活动指针原子替换，均绑定
  `M4_ACTIVE_STATE_POINTER_ATOMIC_GATE_V1`；
- 首次核心门编号 179 被调用方超时终止，未留下进程；180 已通过但被最终源码上的 184
  取代。179/180 均在验收后可恢复迁出，不代表最终结论。

## E 盘整理

验收后把 33 个被替代目录可恢复地迁到
`${LOCALAPPDATA}/Codex/workspace-relief/yanoutrageous-Test/m4-cleanup-20260725/`：

- 取消/续跑副本和状态；
- 6 个恶意候选；
- 非当前指针依赖的旧救援备份；
- 被替代的激活/回滚临时作业；
- 失败 inventory 182 和旧核心门 179/180。

共迁出 393 个文件、79,302,417 bytes。33 个源目录均不存在、33 个 relief 目标均存在，
迁后逐文件相对路径/大小/SHA-256 清单 digest 为
`212565e90f1e09ce102954f8070a908c4934a7ff17c542d72327c1d282ce3b4e`。
正式 full/incremental、当前 rescue、正式恢复状态、最终 184/185、inventory 183 和真实
流程证据继续保留在 E 盘。整理后 E 盘可用 115,833,139,200 bytes。

## 已知限制与下一步

- 同卷备份只防误操作和逻辑损坏；异卷灾备必须由用户另行授权目标卷；
- M0 旧救援格式不符合 M4 manifest，保留但不会进入可选目录；
- 当前真实数据是已验收的一份 19 题、150 分试卷，不等于 M5 要求的 2020—2025 全目标集；
- M4 活动指针是本地单写者合同，不宣称抵御恶意同进程反射或整机攻击。

下一步进入 M5：构建可迁移离线发布候选、fresh-user 客户流程、许可/SBOM/隐私审计、
release manifest 和最终客户验收。M5 不得把本机 `.venv`、缓存、绝对路径或未授权原始
资料作为交付依赖。
