# 当前状态

更新时间：2026-07-26 06:39 +08:00

## M5 私有本地 RC2 可直接交付状态（2026-07-26）

- 已发布 `output/releases/LOCAL-EXAM-BANK-1.0.0-RC2`，发行 manifest 声明 233 个文件、
  45,769,264 bytes；连同 manifest，发布时物理目录为 234 个文件、45,825,580 bytes。
  manifest SHA-256 为
  `6741008053c30bc8836275b0feaaf284068bda19e980924b02e6a21480c32b5e`，
  tree SHA-256 为
  `8e5010927754eff8a4791569b4bb6d4fbddfd4bb847030b6b63a06afe51cad29`。
- RC2 源码功能提交为 `d8454d6c76ed5b658db40d66c687cf42b567b7a7`。包内固定
  Python 3.12.13 运行时归档为 32,220,167 bytes，不依赖仓库 `.venv`、盘符、
  用户名或开发者 PATH；E 盘整理后再次运行正式 `launcher\verify.cmd`，完整校验
  状态为 `PASS`。
- `E:\AAA命题\排版格式-试卷.docx` 已作为 `REF-TEMPLATE-PAPER` 纳入发行包，
  原件和包内副本均为 25,923 bytes，SHA-256 均为
  `2e6731748a76c7d9661943ca8c9e05bb490bb5390a7dd291afb8369cf2f3f6cf`。
  活动模板为 `TEMPLATE-M3-EDITABLE-B5-REV-002`，学生/教师卷使用 184×260 mm
  页面家族。
- 已增加电子原生 PDF 本地半自动导入：外部文件先复制到产品内 `Copy/source/`，
  记录脱敏来源证明，按指定页和栏提取文本/页面图，自动题目全部进入 `pending`
  复核队列；不实现扫描件 OCR。
- `RUN-20260726-M5-RC2-FRESH-229` 在全新产品副本、无历史状态和无关 cwd 下完成
  56 条公共 HTTP 用户旅程，失败 0、Test 外写入 0、非回环网络成功 0、外部 HTML
  引用 0；1,374 个源保护文件前后完全一致。
- fresh-user 验收实际读取用户授权的 1,207 页电子原生高考 PDF，选择第
  1130—1131 页做三栏切分，导入 22 道 `pending` 题、警告 0，复核其中一题；
  完整备份、staging 恢复、显式激活和重启后，导入题及页面资源继续存在，外部原文件
  大小、时间戳和 SHA-256 前后不变。
- 正式五类 PDF 为：学生卷 4 页、教师卷 15 页、答案册 11 页、解析册 63 页、
  答题卡 6 页；未嵌入字体均为 0，恢复和重启后的五份 SHA-256 与首次生成一致。
- `RUN-20260726-RC2-FULL-228` 最终门禁通过 583/583，failure/error/skip 均为 0；
  活动数据库、20,589 项保护树、runtime watcher、句柄围栏、两份注册源终态、
  不可变证据和进程树全部通过。写入口清单为 65 个生产源、447 个入口、18 个分片，
  unknown/unmigrated/invalid 均为 0。
- 收尾把 91 个被替代目录、8,324 个文件、1,145,431,360 bytes 可恢复地迁到
  `C:\RC2R`，实际释放 E 盘约 1.15 GiB；迁移前后聚合 SHA-256 均为
  `0266642d3116aa90549123761f7a3c6cac0180f2ef33d53f1304815b06441dee`。
  RC2、最终 fresh-user 证据、最终门禁和当前 M2/M3/M4 状态均保留在 E 盘。
- 当前交付判定为 `ACCEPTED_SUPPORTED_PRIVATE_RC_SCOPE`，资料权利人可以直接离线
  使用和整根迁移。严格 M5 保持 `BLOCKED_DISCLOSED`，只剩全目标集人工复核、
  第三方再分发许可和真实打印机验证三项；外部真实 PDF 导入已不再是阻塞项。
- 规范证据见 `contracts/m5/m5-private-local-rc-v1.json` 和
  `Task/reports/M5/M5-private-local-rc-exit.md`。Draft PR #2 保持 Draft，不自动
  合并或误标为第三方公开发行正式版。

下面的 RC1 及更早章节保留为历史记录；若与本节冲突，以 RC2 本节和对应合同为准。

## M5 私有本地 RC1 交付状态（2026-07-26）

- 已发布 `output/releases/LOCAL-EXAM-BANK-1.0.0-RC1`，不可变文件 231 个、
  45,797,102 bytes；release manifest SHA-256 为
  `97652f875c46b7f3ab058ce49b3d1a9e262947904d1c6f186defbd2e77ef574e`，
  tree SHA-256 为
  `92aac135916e0347a21d75325bbe5899e3eb24bccfc7f1b8327d4346d7db60ee`。
- 发布源码提交为 `a4c153cb6ee4be68832dfc6f7a7fd06bf00a8b9f`，本地、origin 与
  `ls-remote` 已核验一致。包内固定 Python 3.12.13 运行时为 32,220,167 bytes，
  不依赖 `.venv`、盘符、用户名或开发者 PATH。
- `RUN-20260726-M5-FRESH-R2-196` 在独立 fresh-user 副本和无关 cwd 中通过 50 条
  公共 HTTP 用户旅程：首次启动、复核/详情、精确/关键词/相似检索、标签、可行与
  不可行蓝图、锁题/换题/排序、图形双轨、模板阻断、五类 PDF、完整备份、staging
  恢复、显式激活、重启和文档哈希保持。失败 0、Test 外写入 0、非回环成功 0、
  外部 HTML 引用 0，源保护树前后 812 项完全一致。
- 五类 PDF 均可打开和渲染，学生卷 4 页、教师卷 15 页、答案册 11 页、解析册
  63 页、答题卡 6 页；未嵌入字体均为 0。恢复和重启后五份 SHA-256 与首次运行一致。
- `RUN-20260726-M5-FINAL-R1-197` 最终门禁通过 581/581，failure/error/skip 均为
  0；活动数据库、11,368 项保护树、runtime watcher、句柄围栏、两份注册源终态、
  不可变证据和进程树全部通过。
- 浏览器视检确认首页和题库复核页布局正常、19 道题完整显示，组卷、工作台和五类
  文档入口可达，浏览器控制台 warning/error 为 0。内置浏览器自身阻止 `/search`
  和 `.json` 直达路径；相同公开 HTTP 路径已由 fresh-user 自动验收成功，不判为产品
  故障。
- 当前交付判定为 `ACCEPTED_SUPPORTED_PRIVATE_RC_SCOPE`：源资料权利人可直接在
  本机使用和整根迁移。严格 M5 仍为 `BLOCKED_DISCLOSED`，因为 2020—2025 全目标集
  尚未生产/人工复核，来源派生内容和嵌入字体没有第三方再分发许可，真实打印机不在
  Test-only 写权限内，外部真实 PDF 的 fresh-user 导入也未纳入此私有包。
- 收尾把 13 个被替代目录、2,785 个文件、331,726,797 bytes 完整迁到 C 盘恢复区，
  E 盘只保留最终 581 项门禁、约 45.8 MB 发布包和小型 fresh-user 报告；迁后 E 盘
  可用 114,989,887,488 bytes。恢复清单 digest 为
  `79feb47763191d8bc1ab9b2db75916b0bb9bc8633f7ab143faecf37f6f177e28`。
- 规范证据见 `contracts/m5/m5-private-local-rc-v1.json` 和
  `Task/reports/M5/M5-private-local-rc-exit.md`。Draft PR #2 保持 Draft，不自动
  合并或误标为严格 M5 正式版。

## M4 备份、恢复、活动状态与回滚验收（2026-07-25）

- M4 已以 `BACKUP-M4-YANYAN-FULL-20260725`、
  `BACKUP-M4-YANYAN-INCREMENTAL-20260725` 和
  `STATE-M4-YANYAN-RESTORED-20260725` 达到 `ACCEPTED`。
- 全量备份覆盖 154 个逻辑文件、14,120,090 bytes，内容寻址后实际存储
  10,132,126 bytes；增量备份 154/154 复用，新 blob 和新增内容均为 0。
- 恢复先进入 staging，验证 SQLite、M1/M2/M3 manifest、154 个文件以及首页、搜索、
  题目、组卷篮、图形和导出 6 步公开旅程后才允许激活。
- UJ-060—067 共 8 条真实流程通过；6 类恶意备份被拒绝，备份/恢复取消续跑、低空间
  预检、切换前/后中断自动回退、显式回滚、重启和重新激活全部通过。
- 最终活动指针为 `data/db/active-state.json` generation 5，SHA-256 为
  `a69d77bb8f53568dc94c415938b84ca6a9b206f75c1c9d3a5cd0b63251825ca7`；
  当前运行根使用恢复状态的项目相对路径。
- 旧活动 SQLite 没有被覆盖，SHA-256 仍为
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。
- 真实流程 `RUN-20260725-M4-REAL-PIPELINE-R1-181`、核心门
  `RUN-20260725-M4-CORE-R2-184`（149/149）和完整门
  `RUN-20260725-M4-FULL-R1-185`（561/561）全部通过；failure/error/skip 均为 0。
- 当前 inventory 为 64 个生产源、446 个精确绑定入口、18 个分片，
  unknown/unmigrated/invalid 均为 0。两处活动指针原子替换只绑定固定
  `M4_ACTIVE_STATE_POINTER_ATOMIC_GATE_V1`。
- 阶段收尾把 33 个被替代目录、393 个文件、79,302,417 bytes 可恢复地迁到 C 盘
  `m4-cleanup-20260725` relief；正式 full/incremental、当前 rescue、正式恢复状态、
  184/185、inventory 183 和真实流程证据继续留在 E 盘。
- 当前备份位于产品根所在卷，只防误操作和逻辑损坏，不宣称防整卷故障；异卷灾备仍需
  用户另行授权。完整事实见 `Task/reports/M4/M4-backup-restore-exit.md`。
- M4 功能与验收已作为 `a62dfc5c9f3dc13142c2c7881922e3e203dead9f` 普通 push；
  本地 HEAD、origin tracking 和 `ls-remote` 三者一致。Draft PR #2 仍为 OPEN/DRAFT，
  当前 head 已核对为该提交。
- 当前进入 M5 离线发布候选、fresh-user 客户流程、许可/SBOM/隐私、release manifest
  和客户验收；M4 `ACCEPTED` 仍不是最终客户交付。

## M3 图形、标签检索与模板闭环验收（2026-07-25）

- M3 已以 `STATE-M3-YANYAN-REV-002` 达到 `ACCEPTED`；三类 FigureIR、原图回退、
  同源 SVG/TikZ、标签审批/失效、混合检索、相似题、组卷篮入口和受控模板激活/回滚
  均已通过真实本地 UI 流程。
- REV-001 在首次流程后的目视检查中发现几何 SVG 坐标占位符错误，已明确标为
  `SUPERSEDED_NOT_ACCEPTED`；REV-002 修复后新增线段坐标、函数采样和统计柱高的数据级
  同源检查，正式几何预览已复核为正确三角形。
- 正式派生状态含 39 个文件、1,294,484 bytes；manifest SHA-256 为
  `57613118c509335496eee1088ef1ac98f18844f307526a73f0c57e089bcc13d9`，
  tree SHA-256 为
  `aa863de6937b625c6fd232ae89e7dc0a499b7f7944a834b9c43651cc2be76958`。
- 23 个标签保持 approved，1 个无证据候选被拒绝，1 个解答变化绑定变为 stale；
  19 题本地索引显式重建稳定，PII 来源 0、模型权重 0 bytes、无需网络。6 个搜索金标
  Hit@3=1.0、MRR=0.833333。
- `TEMPLATE-M3-B5-REV-002` 已激活；4 mm 锚点漂移候选、缺字体和任意 TeX token 均
  失败关闭，静默字体替代 0；基线更新保持独立 D2 审计，不可从编辑路由执行。
- 真实流程 `RUN-20260725-M3-REAL-PIPELINE-R2-175`、核心门
  `RUN-20260725-M3-CORE-R2-176`（79/79）和完整门
  `RUN-20260725-M3-GATE-R2-178`（504/504）全部通过。活动数据库、保护树、watcher、
  句柄围栏、run tree、来源见证和进程树保持不变。
- 当前 inventory 为 63 个生产源、444 个受控入口、18 个分片，unknown/unmigrated/
  invalid 均为 0，`production_writer_connected=true`、`m0_exit_allowed=true`。
- M3 未迁移或切换活动库；活动 SQLite SHA-256 仍为
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。
  当前转入 M4 独立备份、恢复、显式激活和回滚闭环；完整证据见
  `Task/reports/M3/M3-figure-search-template-exit.md`。
- 阶段收尾把 13 个被替代目录（527 个文件、38,336,312 bytes）可恢复地迁到 C 盘
  `m3-cleanup-20260725` relief；保留 M3 176/178、preview 177、R2 真实流程/重建证据和
  REV-002。整理后 E 盘可用 100,280,741,888 bytes。
- M3 功能与验收检查点
  `4588e91ef41771e6e9d8431942cb1c7a40ac1605` 已普通 push；本地 HEAD、origin tracking
  和 `ls-remote` 在检查点核验一致。

## M1—M2 真实生产线与五件套验收（2026-07-25）

- M1 已以 `STATE-M1-YANYAN-REV-002` / `PAPER-YANYAN-202605-REV-002`
  完成一份真实试卷的 Copy、19 题切分、答案/解析关联、逐题 UI 批准和源页高保真正式 PDF；
  `RUN-20260725-M1-GATE-157` 为 466/466。
- M2 已以 `PAPER-M2-YANYAN-FULL-150-REV-002` /
  `EXPORT-M2-YANYAN-FULL-150-REV-002` 验收：确定性蓝图、不可行核心、锁题、换题、排序、
  冻结 PaperRevision 和五件套原子发布均已真实跑通。
- 正式五件套为学生卷 4 页、教师卷 15 页、答案册 11 页、解析册 63 页和 A4 答题卡
  6 页；另有 A3 两页模板。19 题、150 分，跨文档 revision/题号/分值及答题卡映射均为
  100%，学生卷答案/解析泄漏为 0，所有字体内嵌。
- A4 六页与 A3 两页共 8 页已逐页目视确认；五份共 99 页全部通过 96 DPI 打印栅格预检。
  故障注入在解析册输出前中止，partial staging 被发布前门拒绝，正式 failure target 不存在。
- `RUN-20260725-M2-CORE-R2-167` 为 79/79；
  `RUN-20260725-M2-GATE-R2-168` 为 495/495。活动库、保护树、watcher、句柄围栏、来源
  见证与进程树全部不变。
- 当前静态清单为 62 个生产源、444 个受控写入入口、18 个分片，`UNKNOWN=0`、
  未迁移入口 0、`m0_exit_allowed=true`。活动 SQLite SHA-256 仍为
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。
- M2 REV-001 因答题卡只有 A3 一页/A4 两页被标记为历史候选；符合参考基线的 REV-002
  才是正式版本。M2 完整证据见 `Task/reports/M2/M2-real-pipeline-exit.md`。
- M2 功能与验收检查点 `661b6ac7d8d1f895d79fbc5266dbb792c3d5ff9e` 已普通 push，
  本地、origin tracking 和 `ls-remote` 一致。
- 阶段收尾把 18 个旧门禁/预览/故障暂存目录及 20 个历史冷归档移入本机
  `${LOCALAPPDATA}/Codex/workspace-relief/yanoutrageous-Test/`；共迁出 946,426,689 bytes，
  冷归档逐文件 SHA-256 迁移前后完全一致。E 盘热目录现只保留 M2 167/168、preview 166
  和 R3 真实流程证据，`tmp/test_lab` 约 21.12 MiB。
- 当前进入 M3 图形双轨、标签/混合检索和模板维护闭环；M2 `ACCEPTED` 不代表 M5 客户验收。

## M0-S6 与 M0 总门验收（2026-07-25）

- M0 已通过本机总门，机器可读状态为`M0_EXIT_ACCEPTED`；60个生产源、420个副作用入口、
  17个分片全部具备精确控制绑定，`UNKNOWN=0`、未迁移入口0、无效绑定0，
  `production_writer_connected=true`、`m0_exit_allowed=true`。
- `RUN-20260725-M0-S6-FLOWS-145`完成六条真实流程：中文/空格 fresh-state、portable root
  与无效根失败关闭、Test外真实PDF只读Copy、合法/越界写、数据库副本迁移/回滚以及金标
  第1页定位。外部原件物理路径和文件名未进入tracked证据。
- `RUN-20260725-M0-S6-GATE-147`通过628/628；26,870项保护树、82个登记来源、活动库、
  watcher、句柄围栏、run tree、不可变证据和进程树全部干净。
- 加入退出合同与最终清单后，`RUN-20260725-M0-S6-EXIT-149`通过34/34，最终inventory
  `RUN-20260725-M0-S6-INVENTORY-148`的payload为
  `d78470cc94bf23eae6871c0e05ff1b839d3de5e4190f3fae87a87cfc040fc778`。
- 活动SQLite没有迁移或切换，SHA-256仍为
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`，
  大小、mtime不变且`user_version=0`；v1迁移只在rescue副本上验证并已回滚到旧读取路径。
- 19个冷归档已重算哈希并完整列出238,143个成员；14个旧test runs和7个旧preview在
  归档验证后可恢复迁往C盘，没有永久删除。E盘热目录只保留147、149和preview 148，
  可用空间约79.10 GiB。
- M0检查点`fc087f68937479a898af8b093545e9c7e56fbae2`已显式提交并普通push；本地、
  `origin`和`ls-remote`三者一致。M0不是长期终点，当前已进入M1真实完整试卷
  Copy→导入→人工复核→正式渲染闭环。完整证据见
  `Task/reports/M0/M0-S6-real-flows-production-writer-exit.md`。

## M0-S5 本地验收与门禁整理（2026-07-25）

- M0-S5已通过本地功能与安全验收；功能检查点
  `4a9512beb04546649214ad20560c88d784334d92`与验收检查点
  `ba36cbd1847345f35411164855cd24c5ecaf6188`均已普通push。本地、`origin`和`ls-remote`
  已核验同为`ba36cbd1847345f35411164855cd24c5ecaf6188`；PR元数据本轮未冒充复核。
- 已冻结19类不可变领域revision、QuestionIR/FigureIR/PaperIR v1、v0.9迁移/回滚、
  来源坐标/变换、五类文档角色投影和未知字段失败关闭策略。
- 金标registry覆盖18个逻辑条目、63个成员、853,658,555 bytes、8个真值角色和12个模板族；
  外部文件复制为0，tracked产物不含本机绝对路径或源文件名。
- 初始视觉阈值固定为exact-reference页面、0.01 mm表示容差、0.5/1.0 mm主要锚点、
  零裁切、零溢出、零静默字体替代；像素指标只作诊断，不能覆盖人工叠图失败。
- `RUN-20260725-M0-S5-122`为460/460；最终全仓冻结
  `RUN-20260725-M0-S5-FULL-123`为1105/1105，另1个真实目录symlink能力用例按普通账户
  WinError 1314既定边界排除。123的24,859项保护树、80个来源、活动库、watcher、句柄围栏、
  run tree、不可变证据和进程树全部通过。
- 显式暂存后`RUN-20260725-M0-S5-POSTDOC-125`再次通过460/460，并触发17个冷归档的阶段冻结
  复核；该小型运行通过87个文件逐项哈希确认后可恢复迁到C盘。
- 最终inventory为`RUN-20260725-M0-S5-INVENTORY-118`：58个生产源、462个入口、
  19个分片、`UNKNOWN=0`；全部入口仍为`UNMIGRATED_BLOCKED`，production writer和
  `m0_exit_allowed`均为false。
- 活动SQLite仍未迁移或切换，SHA-256保持
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`，
  `user_version=0`。
- 17个冷归档已完整复核704,667,068 bytes、216,332个成员和204个运行根，危险路径、
  重复成员和差异均为0。E盘仅保留最终RUN-123热证据；旧运行/预览/日志经验证后可恢复迁到
  C盘恢复区，当前E盘约62.64 GiB可用。
- 当前切片转入M0-S6真实流程与M0总门；M0仍未验收，production writer和真实业务数据继续
  隔离。完整证据见`Task/reports/M0/M0-S5-domain-ir-gold.md`。

## M0-S4 本地验收与存储收敛（2026-07-25）

- M0-S4 已通过本地功能与安全验收；功能检查点`29602bc1af5001e486e9df8b5568af1b51984d08`与验收报告检查点`51d2a7498eac3955a8ec8a1f1288bd69e0da598a`均已普通 push。本地、`origin`和`ls-remote`已核验同为`51d2a7498eac3955a8ec8a1f1288bd69e0da598a`。本机`gh`未持久登录，因此本轮没有把 PR 元数据冒充为已复核。
- 只读数据库网关、只追加 schema migration、SQLite Backup API、一致快照、暂存恢复、数据库副本迁移和中断恢复均已实现。
- `RUN-20260725-M0-S4-CORE-FIX-100`为 69/69，`RUN-20260725-M0-S4-GATE-102`为 462/462；最终全仓冻结`RUN-20260725-M0-FULL-GATE-103`为 1038/1038，另 1 个真实目录 symlink 能力用例按普通账户 WinError 1314 的既定边界单独排除。
- 103 的保护树前后均为 4,817 项，80 个登记来源全部匹配；活动 SQLite、runtime watcher、句柄围栏、run tree、不可变证据和进程树全部通过。
- 活动 SQLite 从未迁移或切换，SHA-256 仍为`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`，`integrity_check=ok`、外键违规 0、`user_version=0`、`schema_migrations`不存在，25 张表和真实业务状态保持原样。
- 最终 inventory preview 为`RUN-20260725-M0-S4-INVENTORY-101`：55 个生产源、462 个入口、19 个分片、`UNKNOWN=0`；全部入口仍为`UNMIGRATED_BLOCKED`，production writer 与`m0_exit_allowed`均为 false。payload SHA-256 为`c5b306f75aeb7fcb7ba685ddf40160f3f97b450fc53f0fe49dcbeaf3fc571e6f`。
- 14 个冷归档已在阶段冻结时重算 SHA-256 并完整列出 196,442 个成员和 183 个运行根；覆盖、哈希、成员和危险路径差异均为 0。冷归档约 649.03 MiB，日常门禁不再重复枚举。
- `tmp/test_lab`只保留最终全绿 103（约 126.41 MiB），`tmp/inventory_preview`只保留 101（约 0.49 MiB）；被替代原始目录均在校验后可恢复地迁到 C 盘，没有危险递归删除。E 盘当前约 60.33 GiB 可用。
- 当前切片转入 M0-S5 领域模型、IR 与金标基线；M0 总门仍未通过，production writer 和真实业务数据继续保持隔离。完整证据见`Task/reports/M0/M0-S4-sqlite-migration-backup.md`。

## 目标已恢复（2026-07-24）

- 用户已明确回复“现在继续”；当前长期目标已从暂停检查点恢复，规范状态为`RUNNING`、实现状态为`IN_PROGRESS`。
- 恢复审计通过：恢复点的本地/origin HEAD 均为`0ac5c033a44d83ecd4d466a84e954a82d55926ed`，工作区恢复前干净，WIP tree 与六个候选文件哈希全部匹配；portable root、NTFS、全链无 Reparse、依赖导入、活动 SQLite 完整性/哈希、无活动 launcher/mutation 均通过，单写者锁已由当前 Codex 进程重新取得。
- 暂停时的未验收候选曾固化为 WIP 检查点`aec3d7413a06251e4865b601fd680090b466892e`。恢复后已完成修复、核心/组合/静态门、证据整理、精确 Git 检查点和远端核验；S3-G 已发布为`a757e181a64aea9cbbc91669b7ad48b043bbafd6`，当前进入 S3-H。
- 暂停前已确认没有活动的仓库 Python、pytest 或 Git 进程，没有业务 mutation，production writer 仍断开；活动 SQLite SHA-256 仍为`1505BF05BD8E385EADA30642110596363C561C330DA02A40A497072064AD1C94`。
- `RUN-20260724-M0-S3G-S3E-039`因调用方 stdout 管道关闭而以 120 退出，但保护树、数据库、watcher、句柄围栏、run tree 与 source witness 均保持安全；`RUN-20260724-M0-S3G-CORE-040`因重定向日志句柄位于受保护`tmp`而在 pytest 前安全停止。两个编号均不得复用。
- safe launcher 输出捕获、gzip 证据、quarantine 日期分区、原生移动、RESTRICTED 恢复、retained restore、静态 inventory 和 S3-G 验收均已完成；精确提交和远端核验也已通过，S3-H 继续保持 production writer 断开。
- 完整暂停恢复清单与候选文件哈希见`Task/reports/M0/M0-S3-G-pause-20260724.md`。下方其他章节保留为此前基线；如与本节冲突，以本节和`Task/RUN_STATE.json`的最新恢复记录为准。

## S3-H 与 S3 总门本地验收（2026-07-24）

- 历史 operation epoch resolver 已在同一 mutex 内完成有界 no-follow catalog、全部 activated revision 认证和结束时身份/清单复核；Copy rotation 现在验证 Audit → 全部 Operation epoch → 全部历史 Copy source/copy 双链的完整 DAG。
- 九行 crash/race 真值表已冻结；四个真实子进程分别在 rename 前后和 COMMITTED terminal append 前后使用`os._exit(71—74)`，恢复只追加一次 terminal，fresh reopen replay 不增长账本、不重复 mutation。
- `RUN-20260724-M0-S3H-INVENTORY-GATE-078`为 34/34；最终 S3 总门`RUN-20260724-M0-S3H-S3-TOTAL-079`为 997/997，failure/error/skip 均为 0，另有一个本机无权限创建真实目录 symlink 的独立能力用例按既定规则排除。
- 079 的保护树前后均 4,741 项，活动 SQLite、runtime watcher、句柄围栏、run tree、不可变证据、80 个源码见证和进程树全部通过。独立只读复核重新计算 JUnit、19 个 inventory chunk 和 53 个`UTF8_LF_V1`源码哈希，差异为 0。
- 最终 inventory preview 为`RUN-20260724-M0-S3H-INVENTORY-077`：53 个生产源、468 个入口、19 个分片、`UNKNOWN=0`；全部入口仍为`UNMIGRATED_BLOCKED`，production writer 与`m0_exit_allowed`均为 false。payload SHA-256 为`6f9624ecfa941e54cfb1e8f08015952d725785ae15bd1bd9a1a338e27d0d9d9a`。
- 156 个旧测试运行和 4 个被替代的 inventory preview 已进入校验归档并可恢复地迁出热目录；`tmp/test_lab`只保留最终 079（约 104.2 MB），`tmp/inventory_preview`只保留 077（约 0.52 MB）。E 盘当前约 60.63 GiB 可用。
- S3-H/S3 总门检查点已作为`b38dd5e5399cc37dae3fa1086b29c7b5e1385477`显式提交并普通 push；本地 HEAD、origin、远端 refs 与 Draft PR #2 head 已核验一致，PR 为 OPEN/DRAFT/MERGEABLE。下一切片为 M0-S4 SQLite migration/Backup API。完整证据见`Task/reports/M0/M0-S3-H-crash-race-inventory-freeze.md`。
- GitHub 应用可以只读核验 PR，但更新 PR 描述返回 integration 403；本机`gh`没有持久登录。未绕过权限，现有 Draft PR 描述仍是旧基线叙述，须在具备 PR metadata 写权限时更新；这不影响已推分支恢复点。

## S3-G 本地验收与门禁存储整理（2026-07-24）

- safe launcher 子进程输出已改为只写当前排除的 run root；保护树快照候选格式已改为`gzip-canonical-json-v1`、结果 schema `1.2`。`RUN-20260724-M0-S3G-LAUNCHER-046`通过 88/88 项测试，保护树 135,048 项前后一致，活动数据库哈希不变。
- S3-G 已实现自动创建/复用`data/quarantine/{INTERNAL|RESTRICTED}/YYYY-MM-DD`、边界 UTC 日期钉住、live target-parent lease、source-handle no-replace move、RESTRICTED opaque recovery capability 和保留式 restore。Win32 87 证明相对`RootDirectory`假设不成立，最终实现改用同卷固定根内 absolute target 并在调用前复核 parent lease。
- `RUN-20260724-M0-S3G-CORE-053`为 16/16；`RUN-20260724-M0-S3G-GATE-058`与清理后的`RUN-20260724-M0-S3G-POSTCLEAN-059`均为 543/543。两轮的活动数据库、runtime watcher、句柄围栏、run tree、不可变证据、源码见证和进程树全部通过。
- `RUN-20260724-M0-S3G-INVENTORY-057`冻结 53 个生产源、468 个入口、19 个分片、`UNKNOWN=0`；全部入口仍为`UNMIGRATED_BLOCKED`，production writer 与`m0_exit_allowed`均为 false。
- 141 个旧运行已由两个便携 tar.gz 完整覆盖并迁出热目录，只保留最新 POSTCLEAN-059。跨盘迁移阶段 E 盘净增加约 2.24 GiB 可用空间；同一 S3-G 门禁的保护对象由 140,985 降到 8,394，整轮由约 19 分钟降到 4 分 10 秒。归档不进入 Git，迁移时须单独携带并复核 SHA-256。
- 完整实现与存储证据见`Task/reports/M0/M0-S3-G-quarantine-retained-restore.md`、`Task/reports/M0/M0-evidence-storage-20260724.md`和`Task/TEST_GATE_RETENTION.md`。
- S3-G 已显式暂存 20 个准入文件，提交为`a757e181a64aea9cbbc91669b7ad48b043bbafd6`并普通 push；本地 HEAD、origin、远端 refs 与 Draft PR #2 head 已核验一致，PR 保持 OPEN/DRAFT/MERGEABLE。

## 长期执行状态

- 计划版本：1.1.0
- 当前阶段：M0—M4 已验收；M5 私有本地 RC1 已交付，严格 M5 受已披露条件阻塞
- 当前切片：M5 私有本地 RC1 已完成；等待全目标资料、人工复核和分发许可
- M0—M5 实现：M0—M4 `ACCEPTED`；M5 为
  `ACCEPTED_SUPPORTED_PRIVATE_RC_SCOPE` / `BLOCKED_DISCLOSED`
- 本任务有效终点：按用户后续明确要求，连续完成修订后的 M0—M5，直到真实用户流程、恢复演练和客户交付包全部通过；不得把 M0 或代码完成误报为终局
- 当前禁止：把 `.venv`、缓存、绝对路径或未授权资料塞入交付包，跳过 M5 fresh-user
  断网客户旅程，OCR、云同步、未审核标签直接进入正式检索，以及清理已接受 revision
  或未归档证据

## 2026-07-24 新电脑恢复与可迁移根基线

- 当前物理位置观察为`E:\AAA命题\Test`，主机为`炎炎`，卷为健康 NTFS；项目根及祖先没有 Reparse Point。该绝对路径只属于本次运行证据，不再进入生产权限合同。
- 生产根改为`PORTABLE_LOCAL_NTFS_V1`：受信任`app/project_root.py`位置与根`.exam-bank-root.json`精确内容共同授权；marker 不含盘符/用户名/绝对路径，cwd、环境变量、配置和调用者参数不能扩大根。
- Python 3.12.13、Flask 3.1.3、PyMuPDF 1.28.0、pytest 9.1.1、SQLite 3.50.4 均已导入；现有`.venv`可继续验证，但`pyvenv.cfg`保留旧机创建命令，因此不作为未来迁移产物，后续电脑默认按`requirements.txt`重建。
- 活动数据库 SHA-256 仍为`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`，`integrity_check=ok`、外键违规 0，核心业务表仍为空；迁移重定根当前没有业务数据改写风险。
- Git 分支`agent/m0-m5-local-v1`的 S3-H 检查点为`b38dd5e5399cc37dae3fa1086b29c7b5e1385477`；本地、origin、远端 refs 与 Draft PR #2 head 已核验一致，检查点后工作区干净。
- 旧主机 writer lock（`DESKTOP-GU0STBA`/PID 283856）已确认失效；当前由本机 Codex 进程以`RUN-20260724-M0-S3H-COORD-060`持有 Git 忽略的单写者锁，没有业务 mutation。
- `RUN-20260724-M0-PORTABLE-FULL-037`最终退出码 0：JUnit 961 passed，failure/error/skip 均为 0；保护树前后均 126,030 项且 digest 相同，活动数据库、运行树、immutable evidence、watcher、句柄围栏、进程树和 80 个登记合成来源均通过。RUN-025/031/034/036 作为失败收敛证据保留，不再代表当前功能状态。
- `tmp/test_lab`现只保留最终 S3-TOTAL-079，约 104.2 MB；6 个便携归档约 617.1 MiB。156 个归档覆盖的旧测试运行已迁出热目录，保留规则与新电脑迁移规则见`Task/TEST_GATE_RETENTION.md`；完整保护树门仍保留，不降低外部零写入保证。
- 旧 D 路径上的 S1—S3-E 实现、提交和语义测试结果仍是历史证据，但其卷、路径链、保护树和外部零写入结论不能直接授权 E 路径。`RUN-20260713-...-021/022/023`不再作为恢复运行计划使用；新基线只使用 2026-07-24 的新唯一 run ID。
- Git 忽略的`Task/local/REFERENCE_PATHS.local.md`已按本机 E 路径重绑定；外部资料仍只读，任何处理仍需先进入当前`PROJECT_ROOT\Copy`并核对哈希。
- 本机映射中的 16 个逻辑参考集、共 25 个明确文件或目录均已只读确认存在；该存在性只对当前电脑成立，下一次迁移必须重新核对，不进入 Git 合同。

## Git 状态基线

- 仓库：`https://github.com/yanoutrageous/Test.git`
- 长期集成分支：`agent/m0-m5-local-v1`
- 分支基线：规划分支提交`bfd4d35973974a223f465cd08910f303518a8586`
- `Base/高考题原卷/`为用户本地资产，已由根`.gitignore`保护，明确不属于本次提交范围
- 规划发布范围仅为`.gitignore`与`Task`中的可跟踪规范；`Task/local/`本机路径映射被忽略，禁止提交
- 本次及后续提交必须显式暂存文件，禁止`git add -A`

## 当前数据事实

- 活动 SQLite 已有 25 张表；`source_papers`、`questions`、`question_assets`、结构化内容、复核事件和导入批次当前均为 0 条
- 历史质量报告中的题量不能作为当前可复现基线
- 目标 NEW9 PDF 已在 Test 内，但其正文无可提取文字层；视觉回归必须包含整页像素/锚点检查
- 活动 SQLite SHA-256 为`1505bf05...ad1c94`，`integrity_check=ok`、外键违规 0、`user_version=0`，19 个业务表均为 0 行
- 历史“1123 题/阶段 14”报告不是当前可复现事实
- 生产静态 inventory V21 覆盖`app/`和`scripts/`的64个源文件、446个副作用入口和
  18个分片；`UNKNOWN=0`、未迁移入口0、无效绑定0
- production boundary固定portable root并提供handle writer；
  `production_writer_connected=true`、`m0_exit_allowed=true`、`M0_EXIT_ACCEPTED`
- S3-E 最终核心回归`RUN-20260712-M0-S3E-016`为`30 passed`，launcher 门`RUN-20260712-M0-S3E-LAUNCHER-018`为`72 passed`，组合门`RUN-20260712-M0-S3E-COMBINED-019`为`399 passed`；JUnit failure/error/skip 均为 0
- RUN-009 保护树前后均 93,762 条、运行时变更 0、句柄围栏 93,762 个；活动 SQLite 前后 SHA-256 相同。旧结果字段`source inputs unchanged`只是该次已监测保护集的起止/运行时证据，不声称监控整机或未登记外部源
- Scanner V21使用`UTF8_LF_V1`规范化并覆盖portable-root authority、生产handle writer、
  SQLite迁移/备份、外部Copy、领域/IR/gold验证器及M1/M2/M3生产线；当前inventory payload为
  `98a9fd61acfb9e0e4ce38ae3286ef06f7cc8c9f0fa5403079dfc9c1f8718f8c5`，
  生产writer与M0退出合同均已接受

## 工具与发布状态

- 用户已明确授权无交互继续完成交付；新电脑已通过 WinGet 用户范围安装 GitHub CLI 2.96.0。
- 本机 Git 自身可访问远端；Git Credential Manager 中的 GitHub OAuth 凭据经临时`GH_TOKEN`环境桥接后，`gh api user`和`gh auth status`验证账号为`yanoutrageous`。令牌未写入命令、报告或仓库，也未降级保存为明文文件。
- GitHub App 已确认仓库公开且未归档、当前连接具备仓库 push/admin 权限、默认分支为`main`；Draft PR #2 为 OPEN/DRAFT/MERGEABLE，S3-H 检查点 head 为`b38dd5e5399cc37dae3fa1086b29c7b5e1385477`
- 本仓库 Git 作者邮箱已改为 GitHub noreply 地址，未修改全局 Git 配置，避免公开提交暴露个人邮箱
- 规划提交范围、隐私、二进制、大文件、忽略规则和远端同名分支已通过独立只读审计
- 规划契约提交`522393d`及状态提交`bfd4d35`已普通 push 到`agent/long-run-execution-spec`
- 规划草稿 PR：`https://github.com/yanoutrageous/Test/pull/1`
- 长期集成分支首个 M0 审计提交为`f3ab652`，已 push
- M0-S1 候选核心、安全测试启动器与证据提交为`2dc2984`，已 push；远端 SHA 与本地一致
- M0-S2 冻结证据为`RUN-20260711-M0-S2-EOL-020-FINAL`；实现和证据已作为`e82eb507414f9dd7b27282d8496e048016bca4ee`显式提交并普通 push，远端分支和 Draft PR #2 head 已核验一致
- M0-S3-B 冻结证据为`RUN-20260711-M0-S3-WRITER-009`与`RUN-20260711-M0-S3-B-FULL-011`；实现、inventory、ADR 与报告已作为`793fb88055b19ea2de53395a07c4be523eeb5f73`显式提交并普通 push，远端分支和 Draft PR #2 head 已核验一致
- M0-S3-C 冻结证据为`RUN-20260711-M0-S3C-WRITER-016-FINAL`与`RUN-20260711-M0-S3C-FULL-017-FINAL`；实现、inventory、ADR 与报告已作为`a999f32718b0ed22d2683585c7d079a0c9bbb749`显式提交并普通 push，origin、远端 refs 与 Draft PR #2 head 已核验一致
- M0-S3-D 冻结证据为`RUN-20260711-M0-S3D-022`与`RUN-20260711-M0-S3D-WRITER-014`；实现、V8 inventory、ADR 与报告已作为`1b5b9bd9cddcdc472f92146748b6f8ab4f53b6f4`显式提交并普通 push，origin、远端 refs 与 Draft PR #2 head 已核验一致
- 长期草稿 PR：`https://github.com/yanoutrageous/Test/pull/2`（base=`main`，head=`agent/m0-m5-local-v1`）
- 除 GitHub CLI 外，本轮未安装 OCR、TeX、模型、字体或其他项目依赖

## 当前长期执行的首批动作

1. M0-S3-D operation context pin、固定 job staging、不可变 contract、多维预算和 live double-pass tree observation 已作为`1b5b9bd`完成显式提交、普通 push 与远端核验；
2. M0-S3-E exact reservation、独立 operation chain、source-root no-replace publish、target rescan 与只追加恢复真值表已通过本地组合门和独立暂存审计，并作为`39586568a405124417d105d8e876d25ec94e06e6`完成普通 push；
3. portable root 与 S3-F 合成 Copy/双 ledger 已由`RUN-20260724-M0-PORTABLE-FULL-037`验收，并作为`f9756df79d979ef10f54fc4634f15849857019da`完成精确暂存审计、checkpoint commit、普通 push 与远端核验；
4. S3-G quarantine/retained restore 已由 CORE-053、INVENTORY-057、GATE-058 与清理后 POSTCLEAN-059 验收，并作为`a757e181a64aea9cbbc91669b7ad48b043bbafd6`完成精确提交、普通 push 与远端核验；
5. S3-H 历史 operation resolver、完整 DAG、真实 crash/race 矩阵、最终 inventory 和 S3 总门已由 INVENTORY-GATE-078 与 S3-TOTAL-079 验收，并作为`b38dd5e5399cc37dae3fa1086b29c7b5e1385477`完成精确提交、普通 push 与远端核验；
6. M0-S4 SQLite migration/Backup API已由CORE-100、S4-102和FULL-103验收并远端核验；
7. M0-S5领域revision、三类IR、金标registry、模板族和视觉阈值已由S5-122与FULL-123验收；
   当前完成验收提交后进入M0-S6。按长期终点继续完成M0—M5，只有M5客户交付包、真实用户流程
   和恢复演练全部通过后才可结束。

## 历史暂停检查点（已于 2026-07-24恢复）

- 暂停时间：2026-07-13 22:00:02 +08:00；原因：用户要求在最近可恢复安全断点暂停；
- 暂停记录前本地与 origin head 均为`01cfbb12012040b03e82745e828cf3ff85dc1bf1`；没有活动 safe launcher 或 Git 进程，没有进行中的业务 mutation，没有处理真实业务数据；
- 活动 SQLite SHA-256 当时为`1505BF05BD8E385EADA30642110596363C561C330DA02A40A497072064AD1C94`，旧 D 盘当时可用空间为 588,403,019,776 bytes；生产 writer 仍断开，460 个入口仍全部`UNMIGRATED_BLOCKED`；
- 暂停记录前工作区为 36 个 tracked modified 与 7 个 untracked S3-F 文件。不得清理、覆盖或丢弃这些候选；完整恢复入口见`Task/reports/M0/M0-S3-F-pause-20260713.md`；
- `RUN-20260713-M0-S3F-INTEGRATION-020`为修复前历史证据：167 项中 150 通过、17 失败，但安全门保持清洁；对应修复现已由新根`RUN-20260724-M0-PORTABLE-FULL-037`的 961 项全绿回归取代；
- V4 Copy plan/opaque TXN 与异常边界复审的 P0/P1 均已收口；S3-F Git checkpoint 已完成；
- `RUN-20260713-M0-S3F-INTEGRATION-021`、`RUN-20260713-M0-S3F-LAUNCHER-022`、`RUN-20260713-M0-S3F-COMBINED-023`均为 superseded/unused，永不复用。

## 已知限制与未决项

- 精确字体许可尚未审计：不阻塞金标测量，但阻塞“字体完全一比一”的正式声明。
- 当前备份只能位于`PROJECT_ROOT`内：不具备异卷灾备能力，不能对客户宣称可抵御整个产品根所在卷故障。
- 固定权限但物理路径可迁移的 production boundary、Policy V7、Test-only 句柄 writer、
  audit/全部历史 operation epoch/Copy 双账本和 publish/copy/quarantine/recovery 已通过
  当前新机门禁；64 个生产源的 446 个入口均已精确绑定，未知和未迁移入口均为 0。
- S2 `PairEvidence`仍只是候选声明；S3-E 实际 mutation 只在 exact `_ReservedPairLease`和 live observed lease 内执行，声明或 detached 摘要都不能授权 rename。
- audit key revision 位于 Test 内、Git 忽略的本地明文存储；不能抵御已取得 Test 读取权的恶意本机用户；没有外部 witness 时也不能证明完整账本尾部未被一致回滚。
- Test-only writer 的 spent-ticket 记忆和诊断缓存已固定上限；ReFS/128-bit File ID 高位非零兼容、硬件断电语义和业务 operation recovery 仍未声明通过。
- 安全测试实验室针对受信任、已审阅的仓库测试代码，不是 hostile native-code 或 hostile same-process Python 反射/monkeypatch 的 OS/语言沙箱；S3-F 异常 vault 只收窄经密封公开 boundary 的正常调用泄漏面，不能隔离能够绕过 boundary 的恶意同进程代码。
- 普通用户态 Windows 目录 handle/oplock 不能冻结 child namespace；S3-E 已使用最后检查、内核 no-replace、target full rescan 与`IN_DOUBT`/seal，但仍不声明 hostile-writer 原子快照。
- 本机普通账户不能创建实际目录 symlink；独立安全运行`RUN-20260724-M0-SYMLINK-CAPABILITY-038`仅因 WinError 1314 失败，其余保护证据清洁。不自动启用开发者模式或提升权限；该能力门保持 IN_PROGRESS，不否定已排除该能力用例的 S3 总门，但必须在 M0 总门前单独处置或准确接受限制。
