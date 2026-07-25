# M0 版本化合同

本目录冻结 M0 的机器可读合同。JSON Schema 负责跨语言的信封、必填字段和基本类型约束；Python 运行时验证器负责类型分支、跨字段不变量、哈希、依赖和迁移语义。二者必须同时通过，不能只依赖其中一层。

## 合同清单

- `domain-revision-v1.schema.json`：19 类领域对象的不可变 revision 信封；
- `question-ir-v1.schema.json`：题面、选项、小问、答案、解析、评分点、来源、难度与时间语义；
- `figure-ir-v1.schema.json`：几何、函数和统计三类语义图形；
- `paper-ir-v1.schema.json`：单一冻结试卷内容及五类文档角色投影；
- `gold-registry-v1.schema.json`：脱敏金标登记；
- `template-families-v1.schema.json`：12 个独立模板族；
- `visual-thresholds-v1.schema.json`：初始视觉门槛。
- `measurement-synthetic-v1.schema.json`：无 PII 的测量字段语义夹具。

权威运行时入口分别是`app.domain_models.validate_domain_revision`、`app.ir_contracts.validate_ir_document`和`app.gold_registry.validate_gold_bundle`。

## 版本和序列化

- 当前版本均为`1.0`，正式 ID 必须引用具体 revision，禁止`latest`别名。
- 规范 JSON 使用 UTF-8、键排序、无 NaN/Infinity、紧凑分隔符；领域 revision 的`content_sha256`绑定除自身外的完整规范内容。
- 顶层和结构字段严格拒绝未知字段；兼容扩展只能进入`extensions`，键必须使用`x-*`命名空间。
- 项目持久路径使用规范化 POSIX 相对路径；本机盘符和私人路径不进入合同。

## IR 迁移、回滚和失效

`app.ir_contracts`登记了唯一旧版`0.9`到`1.0`的迁移：旧信封的`id`改为`ir_id`并增加空`extensions`。迁移前必须是精确旧形状；未知版本失败关闭。

`1.0`可在顶层扩展为空时无损回滚到`0.9`。非空扩展不能静默丢弃，因此回滚会拒绝。迁移后重新运行完整类型验证，重复迁移保持幂等。

IR 的依赖由具体 source、figure、scoring point、question 和 template revision 构成。`assert_dependencies_available`在任何依赖缺失或 stale 时失败；正式输出不能回退到“最新”对象。

## 关键跨字段不变量

- 来源区域显式声明坐标空间、单位、页面边界和 DPI；变换序号连续且输入/输出坐标空间首尾相接。
- `design_difficulty`越大越难，`observed_p`越大越易；逐题实测用时没有可靠来源时必须为空。
- QuestionIR 的分值等于其评分点或小问分值总和，图形 revision 列表与题面图形块精确一致。
- FigureIR 保留原始资产和回退资产，几何引用、函数区间、统计序列均需结构验证。
- PaperIR 只引用冻结 question/template revision；五类文档由同一个 PaperIR 的`document_roles`投影，不分别查询最新题目。

合同升级属于 D2 变更：必须增加迁移/回滚测试、更新本说明和金标证据，不得为当前失败临时放宽。
