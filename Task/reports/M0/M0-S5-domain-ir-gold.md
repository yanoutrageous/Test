# M0-S5 版本化领域、IR 与金标基线门禁

## 结论

M0-S5 已在本机通过功能与安全验收，功能检查点为
`4a9512beb04546649214ad20560c88d784334d92`。本切片冻结了不可变领域 revision、
QuestionIR/FigureIR/PaperIR v1、v0.9迁移/回滚、来源坐标与变换合同、逻辑金标 registry、
12 个模板族、初始视觉阈值和无 PII 的合成测量夹具。

这不是 M0 总验收，也没有迁移活动库、接通 production writer、复制外部原件、批准正式字体
或生成真实正式 PDF。下一切片是 M0-S6 真实流程与 M0 总门。

## 严格边界

- 外部参考资料只通过 Git 忽略的本机逻辑映射读取并哈希；复制文件数为 0。
- tracked registry不含绝对路径、用户名或源文件名，只含逻辑 ID、成员 ID、结构事实和哈希。
- 活动数据库`data/db/question_bank.sqlite3`在全部门禁前后 SHA-256均为
  `1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。
- 活动数据库仍为`user_version=0`且未迁移/切换。
- 最终 inventory 462 个入口全部为`UNMIGRATED_BLOCKED`，
  `production_writer_connected=false`、`m0_exit_allowed=false`。
- 真实 Copy、生产写入口接线、真实渲染/人工叠图、许可发布决定和客户流程不在本切片声明范围。

## 实现结果

### 不可变领域 revision

- `app/domain_models.py`定义 19 类核心对象的精确字段合同。
- revision ID、schema version、created_at、predecessor、dependencies和payload进入规范哈希。
- 时间必须为真实带时区 UTC 语义；路径必须为项目相对路径；未知字段失败关闭。
- 不提供`latest`别名；活动状态和业务对象分离，消费者必须引用精确 revision。

### QuestionIR、FigureIR 与 PaperIR

- 三类 IR 使用 schema ID/version、canonical JSON bytes和确定性 hash。
- v0.9→v1迁移和v1→v0.9回滚覆盖可表达数据；无法无损回滚的语义明确拒绝。
- 来源区域包含页码、坐标空间、单位、边界和连续 transform chain。
- `QuestionIR`分离设计难度、实测 P、预计用时和实测逐题用时；评分点与图形引用为精确 revision。
- `FigureIR`覆盖几何、函数、统计数据和语义约束。
- `PaperIR`从同一 revision投影学生卷、教师卷、答案、解析和答题卡五类角色；题目和模板引用
  不再运行时解析“最新”。

### 金标、模板和测量学

- `gold/m0/gold-registry-v1.json`登记 18 个逻辑条目、63 个成员，共 853,658,555 bytes。
- registry canonical payload SHA-256：
  `c5cddb1af8662d11d298cff7ea465eb2cbe22ea51f7f306e78fe68a593537b4d`；
  文件 SHA-256：
  `7032f9b0f1cc1801a10a526192465067d9f7bf683ba4fa58c77eeccf5ad3fecb`。
- 真值角色完整覆盖`content/failure/figure/measurement/scoring/tag/template/visual`。
- 12 个模板族区分 176×250、182×257、184×260、A4、A3、长解析、讲义、答题卡、
  五类试卷和图形/质量轨，不把多尺寸合并成一个模板。
- NEW9 登记为 91 页视觉/模板真值，保留实测页面尺寸，不把理论 A4/B5值覆盖原始测量。
- 许可分类为 4 个`local-use-only`、11 个`user-owned`、1 个`synthetic`、2 个
  `unverified`；PII分类为14个`none`、3个`internal`、1个`unknown`。未知/受限项继续阻断发布。
- 合成测量夹具含 8 个匿名对象、4 个题目；精确验证实测 P，且只有整卷时长，
  `observed_item_time_available=false`。

### 初始视觉阈值

- 页面尺寸策略为 exact reference；表示容差不超过 0.01 mm。
- 主要锚点目标偏差不超过 0.5 mm，硬上限 1.0 mm。
- 裁切、溢出、分页偏差和静默字体替代均为零容忍。
- 像素指标只作诊断；不能覆盖锚点、分页、字体清单或人工叠图失败。
- 基线更新必须追加 revision、确认者引用、理由和前一 aggregate hash；禁止原地覆盖。

## 验收证据

| 证据 | 结果 |
|---|---|
| `RUN-20260725-M0-S5-CORE-113` | 65/65；最终核心合同回归 |
| `RUN-20260725-M0-S5-LAUNCHER-117` | 97/97；Windows Job 回收观察竞态修复后通过 |
| `RUN-20260725-M0-S5-INVENTORY-118` | 58 sources、462 entries、19 chunks、`UNKNOWN=0`、462 blocked |
| `RUN-20260725-M0-S5-122` | 460/460；S5阶段门全部安全检查通过 |
| `RUN-20260725-M0-S5-FULL-123` | 1105/1105；另1个真实目录symlink能力用例按既定本机权限边界排除 |
| `RUN-20260725-M0-S5-POSTDOC-125` | 460/460；显式暂存后复核，17个冷归档冻结检查与全部安全门通过 |

最终 inventory：

- source head：`4a9512beb04546649214ad20560c88d784334d92`
- inventory digest：
  `cc828c0925b2d83be7d17e831fa3370585cee8fa2376f4c4989b798f51389b0c`
- manifest文件 SHA-256：
  `4bdc323b5cf763595df3a0632cbc20cf4cca0a852195ec16f113d87395309f51`
- 58 个生产源、462 个入口、19 个分片、`UNKNOWN_DYNAMIC=0`

RUN-123关键安全事实：

- JUnit 1105 tests，failure/error/skip均为 0；pytest用时 789.58 秒。
- 保护树前后均为24,859项且digest相同。
- 80个登记来源终态全部匹配。
- 活动数据库前后 SHA-256相同。
- runtime watcher、句柄围栏、run tree、不可变证据和进程树全部通过。
- 运行树峰值132,750,975 bytes，未触发预算或超时。

被替代或安全停止轮次：

- RUN-105只因测试把理论页面尺寸误写为精确实测值而失败；修正为真实测量合同后由106及后续替代。
- RUN-116为1104通过、1失败；唯一失败是Windows Job终止后的立即观察竞态，子进程实际已终止。
  加入5秒有界等待后RUN-117和RUN-123通过。
- RUN-119—121把后台runner日志误放在受保护树中，门禁在pytest前以Windows error 32安全停止。
  将日志改放到门禁明确排除的证据目录后RUN-122通过；未降低句柄封锁。

## D2、许可与隐私

- D2决策记录：`Task/adr/ADR-2026-006-versioned-domain-ir-gold-baseline.md`。
- 高风险审计：`Task/audit/M0/S5-DOMAIN-IR-GOLD-20260725.md`。
- 本轮没有安装依赖、字体、OCR、TeX或模型，没有上传资料，没有复制外部原件。
- `Task/local/GOLD_SOURCE_MAP.local.json`继续由Git忽略；tracked文件的固定盘符/用户名扫描由
  workspace policy门覆盖。
- registry中的许可和PII值是阻断/路由事实，不是对所有权或可分发性的法律结论。

## 门禁与 E 盘整理

- 17个冷归档均重算SHA-256并流式列出216,332个成员和204个运行根；总计
  704,667,068 bytes（672.02 MiB）。
- 归档文件集合、字节数、成员数和运行根数均与manifest匹配；危险路径、重复成员和校验差异为0。
- 14个旧test_lab运行、5个inventory preview、2个gold preview和松散runner日志，在对应归档
  验证后可恢复地移动到既有C盘workspace-relief目录；没有永久删除。
- E盘热目录只保留`RUN-20260725-M0-S5-FULL-123`（约127.83 MiB）；preview热目录为空；
  POSTDOC-125通过后按87个文件逐项哈希核对并可恢复迁到C盘。
- 整理后E盘可用空间为67,263,180,800 bytes（约62.64 GiB）。
- 日常继续使用`*_core`；`s5`只在切片候选稳定时运行，`full`只在阶段冻结/发布或保护边界变化时
  运行，不会每次都重复13分钟全量门禁。

## 剩余风险

- M0-S6真实流程尚未完成，因此M0总门仍未通过。
- production writer和462个入口仍未迁移；当前合同不能被描述为生产接线完成。
- 真实目录symlink创建受普通账户WinError 1314限制；不提权、不修改开发者模式。
- 真实视觉渲染、字体缺失模拟和人工叠图留给M1；FigureIR生成/安全SVG留给M3。
- 2个许可未验证条目及PII为`internal/unknown`的条目不得进入客户包；M5必须再次审计。

## 复核命令

```powershell
.\.venv\Scripts\python.exe -B scripts\run_safe_pytest.py --run-id <unique> --mode s5_core --timeout-seconds 180
.\.venv\Scripts\python.exe -B scripts\run_safe_pytest.py --run-id <unique> --mode s5 --exclude-symlink --timeout-seconds 600
.\.venv\Scripts\python.exe -B scripts\run_safe_pytest.py --run-id <unique> --mode full --exclude-symlink --timeout-seconds 2400
Get-FileHash data\db\question_bank.sqlite3 -Algorithm SHA256
Get-FileHash tmp\test_lab_archives\*.tar.gz -Algorithm SHA256
```
