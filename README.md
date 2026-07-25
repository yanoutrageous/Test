# 试卷题库系统 MVP

当前主线已经完成 M0—M4，并进入 M5 私有本地发行候选：可在 Windows 11/NTFS
目录中离线启动，使用已审核的一份 19 题、150 分代表卷完成题库复核、条件/关键词/
本地相似检索、蓝图组卷、图形与模板查看、五类 PDF 和备份恢复。客户包自带固定
Python 运行时，不依赖当前电脑的 `.venv`、盘符或用户名。

当前候选只供源资料权利人私有本地使用。2020—2025 全目标集尚未完成逐题人工复核，
来源派生内容和嵌入字体也未取得第三方再分发结论，因此不能描述为全目标集或公开发行版。
完整边界见 `docs/m5/已知限制.md`。

正式候选从干净提交分两步产生：先构建不可覆盖的 staging，再由独立 fresh-user
验收报告授权发布。

```powershell
.\.venv\Scripts\python.exe -B Task\tools\build_m5_release.py --source-commit <COMMIT>
.\.venv\Scripts\python.exe -B Task\tools\run_m5_fresh_user_acceptance.py `
  --run-id <RUN-ID> --source-commit <COMMIT>
.\.venv\Scripts\python.exe -B Task\tools\build_m5_release.py --publish `
  --source-commit <COMMIT> --acceptance-report <REPORT>
```

发布目录中的最终用户入口是 `launcher\start.cmd`，完整哈希与环境检查入口是
`launcher\verify.cmd`。以下内容保留早期 MVP/Stage 7—14 的开发说明，方便追溯旧流程。

## 环境

推荐使用项目内虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

阶段 0 已验证的依赖记录见 `docs/environment.md`。

安全配置：

- `.env`、`.env.*`、`API/*`、`*.key`、`*.pem` 和 `secrets/` 已加入忽略规则。
- `.env.example` 只提供本地示例配置，不包含真实密钥。
- 不读取、不打印、不验证真实 API 密钥内容；阶段 11 不调用外部 AI，也不上传 PDF、题图、截图或题库数据。

## 目标 PDF

导入和扫描通过 `pathlib` 枚举 `Base` 目录下的 `*.pdf` 文件来发现目标 PDF，并要求该目录中恰好存在一个 PDF，或通过 `EXAM_BANK_TARGET_PDF` 显式指定目标 PDF。数据库初始化、Web、HTML 导出和阶段 9 结构化处理不依赖唯一 PDF；健康检查在多 PDF 且未指定目标时会给出 warning，而不把核心运行环境判为失败。代码不会硬编码中文 PDF 文件名。

当前约定：

- 项目根目录：由仓库内 `.exam-bank-root.json` 与当前模块位置共同验证的 `<PROJECT_ROOT>`，可整体迁移到其他本机 NTFS 盘符或普通父目录
- 资料目录：`<PROJECT_ROOT>\Base`
- 本地数据目录：`<PROJECT_ROOT>\data`
- SQLite 数据库：`<PROJECT_ROOT>\data\db\question_bank.sqlite3`
- 题目图片 assets：`<PROJECT_ROOT>\data\assets\question_images`
- 原卷页面 assets：`<PROJECT_ROOT>\data\assets\paper_pages`
- HTML 导出目录：`<PROJECT_ROOT>\data\exports`
- SQLite 一致快照目录：`<PROJECT_ROOT>\backups\<BACKUP_ID>`

数据库只保存结构化字段、JSON 文本和相对路径；图片、PDF、截图等二进制文件应放在文件系统中。

assets 记录分两类：

- `source_paper_assets`：绑定 `source_papers.id`，记录整份源试卷的页面级资产，例如 `asset_kind='page_image'`、`page_no`、`relative_path`、`bbox_json`、`meta_json`。
- `question_assets`：绑定 `questions.id`，记录题目级资产，例如原貌裁切图、题图、缩略图等；同一题最多保留一条 `asset_kind='raw_crop'` 记录。

两类 assets 表都只接受相对路径，不保存图片或 PDF 二进制。

## 运行健康检查

```powershell
.\.venv\Scripts\python.exe -m app.cli health
```

健康检查会输出：

- Flask、PyMuPDF、sqlite3 的导入和版本状态。
- Python SQLite 的连接、FTS5、JSON 函数能力。
- `Base` 目录中唯一目标 PDF 的路径、大小、页数等基本信息。

## 初始化数据库

```powershell
.\.venv\Scripts\python.exe -m app.cli init-db
```

默认生成或复用：

```text
data/db/question_bank.sqlite3
```

该命令会校验 `app/schema.sql` 的已发布迁移哈希，按只追加版本幂等迁移数据库，并确保以下目录存在：

```text
data/assets/question_images/
data/assets/paper_pages/
data/exports/
```

如需初始化到临时路径：

```powershell
.\.venv\Scripts\python.exe -m app.cli init-db --db-path .\tmp\stage2.sqlite3
```

数据库读取与写入已经分离：列表、详情、组卷预览、HTML 下载等 GET
请求只会以 SQLite `mode=ro` 和 `query_only` 打开现有数据库，不会补建目录、
初始化 schema 或刷新派生状态。首次使用必须先显式运行 `init-db`；来源归属、
结构化内容、可用性和导出质量的生成继续由对应 CLI、导入流程或 POST 写操作完成。
这样迁移电脑或只读检查时，不会因为“查看页面”悄悄改动数据库或产生
WAL/SHM/journal 文件。

## 导入源 PDF 原貌页

默认只登记 `Base` 目录中的唯一 PDF，并渲染抽样页 `1,603,1090,1207`，不会默认渲染全部页面：

```powershell
.\.venv\Scripts\python.exe -m app.cli import-pdf
```

指定页码和 DPI；`--pages` 支持逗号、分号和范围语法，例如 `1090-1099,1105`：

```powershell
.\.venv\Scripts\python.exe -m app.cli import-pdf --pages 1,2,3 --dpi 144
```

导入行为：

- 通过 PDF SHA-256 生成稳定 `paper_code`，幂等写入 `source_papers`。
- 页面 PNG 写入 `data/assets/paper_pages/<paper_code>/`。
- `source_paper_assets` 只记录 `asset_kind='page_image'`、`page_no`、`relative_path`、`bbox_json`、`meta_json`。
- 重复运行同一页不会新增重复记录。
- 页码越界会失败并返回错误。
- `import-pdf` 命令不写入 `questions`，不做题目切分或 OCR。

## 只读扫描 PDF 页

阶段 7.2 新增只读扫描命令，用于在写入数据库前评估页码范围质量：

```powershell
.\.venv\Scripts\python.exe -m app.cli scan-pdf-pages --pages 1090-1099
```

扫描行为：

- `--pages` 支持 `1090-1099,1105` 这类范围语法。
- 只读取 PDF 文本层，不写数据库，不渲染页面 PNG，不写 assets。
- 每页输出 `page_no`、`text_length`、`anchor_count`、`first_anchors`、`duplicate_anchor_count`、`candidate_count`、`warning_candidates`、`warning_reasons` 和 `page_flags`。
- `page_flags` 会标记 `empty_text`、`short_text`、`no_anchors`、`few_anchors`、`no_candidates`、`warning_candidates`、`duplicate_anchors`、`question_number_non_contiguous`、`short_candidate_text`、`possible_answer_page`、`possible_toc_page`、`possible_instruction_page` 等信号。

当前 10 页样本选择和扫描统计见 `docs/sample_pages.md`。

## 切分指定页题目候选

阶段 7.2 的切分命令支持指定页码和范围，但默认仍只处理第 `1090` 页，不默认处理全卷：

```powershell
.\.venv\Scripts\python.exe -m app.cli split-questions --pages 1090
```

10 页样本命令：

```powershell
.\.venv\Scripts\python.exe -m app.cli split-questions --pages 1090-1099
```

行为边界：

- 只识别阿拉伯数字题号锚点，例如 `1.`、`17.`。
- 新候选题写入 `questions` 时，`review_status` 为 `pending`。
- `meta_json` 写入 `algorithm_version`、`source_page`、`split_warnings` 和来源 block 编号。
- 题干过短、页内题号不连续等会进入 `split_warnings`。
- 重复运行同一页不会重复插入，会按稳定 `qid` 更新已有 `pending` 或 `rejected` 候选。
- 已人工复核为 `reviewed` 或 `approved` 的题不会被切分命令覆盖，写入结果会计入 `skipped_reviewed`。
- 不写答案解析，不做 OCR/公式 OCR，不自动标记 `approved`。

## 启动本地 Web

```powershell
.\.venv\Scripts\python.exe -m flask --app app.web:create_app run --host 127.0.0.1 --port 5000
```

访问：

```text
http://127.0.0.1:5000/health
http://127.0.0.1:5000/questions
http://127.0.0.1:5000/batches
http://127.0.0.1:5000/structured-review
http://127.0.0.1:5000/paper-basket
http://127.0.0.1:5000/paper-preview
```

题目列表 `/questions`：

- 默认展示 `review_status='pending'` 的题目。
- 支持 `status`、`question_type`、`page_range`、`q` 关键词、`batch_id` 和 `issue_only=1` 异常优先过滤。
- `status=all` 可查看全部状态。
- 每题可加入 session 组卷篮，重复加入不会产生重复题。

题目详情 `/questions/<id>`：

- 展示 `stem_text`、`stem_latex`、`answer_text`、`analysis_latex`、`tags_json`、`meta_json` 和 `review_status`。
- 展示对应 `source_paper_assets` 页面级原貌图，以及题目 `bbox_json`。
- 如已生成 `question_assets.asset_kind='raw_crop'`，同时展示题级裁切图。
- 展示关联的批次页统计，包括候选题数、入库题数、warning 候选和重复锚点数。
- 详情页保留列表筛选上下文，支持上一题、下一题、保存并下一题和 `issue_tags` 问题标签。
- 表单保存会更新 `questions`，依赖现有触发器同步 `question_search_content` 和 `question_fts`，并写入 `question_review_events` 审计事件。
- Web 人工表单可保存为 `pending`、`reviewed`、`approved` 或 `rejected`；自动导入、切分和 AI 建议仍不会自动写入 `approved`。

批次页 `/batches`：

- 展示 `import_batches` 批次列表、状态、页数、异常页和失败页。
- 批次详情 `/batches/<id>` 展示每页 `candidate_count`、`db_question_count`、`warning_candidates`、`duplicate_anchor_count`、`skipped_reviewed` 和 flags。
- 可直接跳转到本批题目或异常优先筛选队列。

结构化复核工作台 `/structured-review`：

- 支持按 `ai_status`、`quality_flags` 片段、`normalized_type`、页码和阶段 10 高风险页筛选。
- 阶段 11 增加按 `usability_status`、`risk_type` 和 `render_mode` 筛选。
- 列表显示题级裁切图、页面图、结构化状态、质量 flags 和题干预览。
- 支持对结构化候选执行 `accept`、`downgrade`、`needs_review`，只更新 `question_structured_contents` 并写入 `question_review_events`，不修改 `questions` 主表。
- 详情页的 Structured Content 区也提供同样的结构化状态操作。

组卷篮 `/paper-basket`：

- 组卷状态保存在 Flask session，不新增组卷数据库表。
- 支持删除题目、上移、下移和清空。
- 只保存题目 ID 顺序，不修改 `questions` 内容。

预览和导出：

- `/paper-preview` 按题型分区展示题干、题型、来源并重新编号，适合浏览器打印。
- `/paper-export` 返回完整 HTML，响应文件名为 `exam-paper.html`。
- `/paper-export/save` 将当前篮子导出为 `data/exports/exam-paper-YYYYMMDD-HHMMSS.html`，同名时自动加序号，不覆盖旧文件。
- 阶段 11 起，正式预览和导出会先经过 `ExportSelectionService`：只输出 `strict_structured` 和 `visual_fallback`，默认排除 `needs_*`、`failed`、`protected` 和未分流题。
- 阶段 12 起，正式预览和导出会先经过 `question_export_quality`：只输出 `export_ready_structured` 和 `export_ready_visual`，默认排除 `export_candidate`、`export_blocked`、`needs_*`、`failed`、`protected` 和未分流题。
- `export_ready_structured` 使用结构化 HTML；`export_ready_visual` 使用题级裁切图，并在 HTML 中明确标记 `source:export_ready_structured` 或 `source:export_ready_visual`。
- 篮子混入非 ready 题时，预览/导出仍排除这些题，并在排除清单中列出 export quality 状态和阻塞原因。
- 阶段 13 起，预览、导出和保存的每道已输出题都会显示 `source_label` 和 `confidence`，不能只显示 qid；缺少精确来源的题会标记为 `inferred` 或 `unknown`。
- 导出 HTML 按单选/多选/填空/解答/其他分区；填空题保留答题线，解答题保留答题区，使用本地数学呈现脚本，不依赖外部 CDN。
- 本阶段不做 PDF 导出、Typst/LaTeX 编译、复杂模板或拖拽排序。

## 阶段 7 质量闭环命令

重建搜索索引：

```powershell
.\.venv\Scripts\python.exe -m app.cli rebuild-search-index
```

行为：

- 从 `questions` 全量重建 `question_search_content`。
- 调用 FTS5 `rebuild` 重建 `question_fts`。
- 可重复运行，目标是让 `questions`、`question_search_content`、`question_fts` 数量一致。

生成题级裁切图：

```powershell
.\.venv\Scripts\python.exe -m app.cli crop-question-assets
```

行为：

- 基于 `questions.bbox_json` 和 `source_paper_assets` 页面 PNG 生成题级 PNG。
- 文件写入 `data/assets/question_images/<paper_code>/`。
- `question_assets` 只记录相对路径、页码、bbox 和 meta，不保存 BLOB。
- `question_assets` 通过 partial unique index 限制同一题最多一条 `asset_kind='raw_crop'` 记录。
- 重复运行会复用已有 PNG 并更新同一题的 `raw_crop` 资产记录，不重复插入同类记录。

一致性检查：

```powershell
.\.venv\Scripts\python.exe -m app.cli check-consistency
```

检查项：

- `questions`、`question_search_content`、`question_fts` 计数同步。
- 数据库路径字段为相对路径。
- `source_paper_assets` 与 `question_assets` 文件存在且非空。
- 搜索表、资产表、审计表无孤儿记录。
- 阶段 13 起检查 `question_source_attributions` 覆盖题目数量、缺失归属和孤儿记录。
- 检查同一题是否存在重复 `raw_crop` 资产。
- 输出题目状态分布。

边界：

- 默认只绑定本地 `127.0.0.1`。
- 不处理全 1207 页，不无审计扩到 300/500/全量。
- 不做 PDF 导出、OCR、公式 OCR、向量检索、账号系统、公网访问或复杂模板；AI 只作为建议层，不自动覆盖题库，不调用外部服务。
- 不覆盖 `reviewed` 或 `approved` 题目。

## 阶段 8 批次化导入

阶段 8 使用批次表记录每次样本扩容的页码、状态、扫描统计、导入/切分/裁切结果、错误和运行前 SQLite 备份路径。

当前阶段 8 已登记和运行的阶梯：

- `stage8-baseline-1090-1099`：10 页基线，登记既有阶段 7 数据，不重复导入。
- `stage8-20-pages`：新增 `1100-1109`，累计 20 页。
- `stage8-50-pages`：新增 `1110-1139`，累计 50 页。
- `stage8-100-pages`：新增 `1140-1189`，累计 100 页。

批次表：

- `import_batches`：记录批次名称、类型、页码范围、算法版本、状态、耗时、备份路径和汇总 JSON。
- `import_batch_pages`：记录每页 `candidate_count`、`db_question_count`、`warning_candidates`、`duplicate_anchor_count`、`page_flags_json`、`skipped_reviewed` 和各步骤详情 JSON。

查看批次：

```powershell
.\.venv\Scripts\python.exe -m app.cli batch-list
.\.venv\Scripts\python.exe -m app.cli batch-show --name stage8-baseline-1090-1099
```

登记已完成的 10 页基线，不重复执行导入、切分或裁切：

```powershell
.\.venv\Scripts\python.exe -m app.cli batch-baseline --name stage8-baseline-1090-1099 --pages 1090-1099
```

创建批次但不运行：

```powershell
.\.venv\Scripts\python.exe -m app.cli batch-create --name stage8-20-pages --pages 1100-1109
```

运行扩容批次，流程为 `scan-pdf-pages -> import-pdf -> split-questions -> crop-question-assets`：

```powershell
.\.venv\Scripts\python.exe -m app.cli batch-run --name stage8-20-pages --pages 1100-1109
```

运行批次会在执行前通过 SQLite Backup API 建立一致快照，完成完整性、外键、业务不变量和实际读取验证后，按无覆盖方式发布到 `backups/<BACKUP_ID>/`；`import_batches.backup_path` 只记录项目相对快照路径。活动 WAL 数据库不再使用直接文件复制。批次执行仍遵守现有保护：不覆盖 `reviewed` 或 `approved` 题，所有新切分题默认进入 `pending`，资产路径只保存相对路径。

生成阶段 8 质量报告：

```powershell
.\.venv\Scripts\python.exe -m app.cli stage8-report
```

报告写入 `docs/stage8_quality_report.md`，包含批次数、累计页数、累计题量、资产量、warning 比例、重复锚点页、失败页、存储体积和下一步风险判断。

## 阶段 7.3 AI 建议层

AI 建议层只写入 `question_ai_suggestions`，不直接覆盖 `questions`。无 AI 配置时命令会清晰跳过：

```powershell
.\.venv\Scripts\python.exe -m app.cli ai-suggest
```

返回示例：

```json
{
  "status": "skipped",
  "reason": "AI is not configured. Use --mock for a local simulated suggestion.",
  "inserted": 0,
  "suggestions": []
}
```

本地模拟建议只用于验证流程，不调用外部 AI 服务：

```powershell
.\.venv\Scripts\python.exe -m app.cli ai-suggest --question-id 1 --mock
```

行为边界：

- 建议输入摘要只记录题干长度、题级裁切图相对路径、`meta_json`、`bbox_json` 等本地信息，不上传资料。
- 建议内容写入 `question_ai_suggestions.suggestion_json`，默认 `status='pending'`。
- Web 详情页展示该题建议，可人工 `Accept` 或 `Reject`。
- `Accept` 才会写回 `questions`，并写入 `question_review_events`，事件类型为 `ai_suggestion_accept`。
- `Reject` 只更新建议状态，不修改 `questions`。
- `reviewed` 或 `approved` 题目不会被 AI 建议接受动作覆盖。

## 阶段 9 结构化校正与渲染

阶段 9 使用 `question_structured_contents` 保存题面的结构化副本，不直接覆盖 `questions` 主表。该表覆盖 `question_id`、`source_text`、`source_latex`、`normalized_type`、`stem_latex`、`options_json`、`blanks_json`、`subquestions_json`、`answer_latex`、`analysis_latex`、`ai_status`、`quality_flags_json`、`confidence` 和 `model_info`。

初始化结构化记录：

```powershell
.\.venv\Scripts\python.exe -m app.cli init-structured-content
.\.venv\Scripts\python.exe -m app.cli structured-status
```

AI 结构化队列：

```powershell
.\.venv\Scripts\python.exe -m app.cli ai-structure-config
.\.venv\Scripts\python.exe -m app.cli ai-structure --limit 25
```

行为边界：

- 无真实 AI provider 配置时，真实库只记录 `ai_provider_unavailable`，保持 `ai_status='unprocessed'`，不会写入伪造 AI 结果。
- 真实 provider 仅支持显式配置的本地 OpenAI-compatible 服务：`EXAM_BANK_STRUCTURED_AI_PROVIDER=local_openai_compatible`、`EXAM_BANK_STRUCTURED_AI_MODEL=<model>`，可选 `EXAM_BANK_STRUCTURED_AI_BASE_URL=http://127.0.0.1:1234/v1`。
- provider URL 必须是 loopback 地址（`127.0.0.1`、`localhost` 或 `::1`），非本机地址会被拒绝，避免把试卷文本或图片上传到外部服务。
- 默认只发送题干文本和相对资产路径；只有设置 `EXAM_BANK_STRUCTURED_AI_INCLUDE_IMAGES=1` 时，才会把本地题级裁切图/页面图作为 base64 图片发送给本地 provider。
- `--mock` 只允许配合显式 `--db-path` 的临时库使用，且拒绝默认真实库。
- AI 输入摘要只记录题级裁切图、页面图、题干、题号、页码和题型候选等本地信息；真实 provider 未配置时不会上传原始 PDF、页面图或题级图。
- AI 输出只能成为 `ai_draft`，不得自动成为 `approved`。

结构化质量验收：

```powershell
.\.venv\Scripts\python.exe -m app.cli validate-structured-content --limit 100
```

校验器覆盖 JSON 形状、LaTeX 基础定界符、题号一致性、选项完整性、填空空位、小问结构、短文本/跨题污染、数字/符号一致性，以及 `x2/a2/y2`、`log20.2`、未转换 Unicode 数学符号等未可靠 LaTeX 化风险。通过严格口径才进入 `ai_verified`，有疑点进入 `needs_review`，无法处理进入 `failed`；校验器不修改 `questions.review_status`。

Codex 代理式校正：

```powershell
.\.venv\Scripts\python.exe -m app.cli codex-structure-export --sample-size 120 --batch-name stage9-codex-120 --output data/exports/stage9_codex_120.jsonl
.\.venv\Scripts\python.exe -m app.cli codex-structure-apply --input data/exports/stage9_codex_120.jsonl --batch-name stage9-codex-120
.\.venv\Scripts\python.exe -m app.cli codex-structure-batch --sample-size 120 --batch-name stage9-codex-120
```

Codex 代理式校正用于本执行线程内的可审计结构化样本推进：导出 JSONL 包、校验 JSONL schema、写入 `question_structured_contents`、再由校验器落到 `ai_verified`、`needs_review` 或 `failed`。该路径不上传 PDF、图片或题干，不依赖外部 provider，不修改 `questions.stem_*`、`questions.review_status`、答案解析或人工复核状态；`reviewed`/`approved` 主记录会被跳过。高风险页、重复锚点、缺少题级裁切图、公式不确定、图片题、选项异常和 LaTeX 质量风险会进入 `needs_review`。

Web 和导出：

- 详情页显示结构化内容区：source_text、JSON/LaTeX、质量状态和预览，并与原页面图、题级裁切图并列查看。
- `/paper-preview` 和 `/paper-export` 对 `ai_verified` 或 `human_reviewed` 结构化内容优先渲染。
- 未验证结构化内容会显示 `candidate:<ai_status>`，不会冒充成品题面。
- 选择题选项按长度自动四列/两列/一列排版；填空题显示空线；解答题显示小问层级。
- 详情页、组卷预览和导出 HTML 内联本地数学呈现脚本，数据库仍只保存 LaTeX 源；保存后的 HTML 不依赖外部 CDN。

生成阶段 9 质量报告：

```powershell
.\.venv\Scripts\python.exe -m app.cli stage9-report
```

报告写入 `docs/stage9_quality_report.md`，包含结构化覆盖率、AI provider 状态、代表性样本、题型分布、LaTeX 基础可渲染率、结构校验统计、质量标记、严格可用口径、专项样例状态、高风险页跟踪和下一步建议。

## 阶段 10 可用性生产化

阶段 10 不新增 PDF 导入批次，不扩页，不修改 `questions.stem_*`、`questions.review_status`、答案解析或人工复核状态。自动处理只写入 `stage10_baseline_questions`、`stage10_page_isolations` 和 `question_structured_contents` 候选侧；人工结构化状态操作会写入 `question_review_events`。

阶段 10 schema：

- `stage10_baseline_questions`：登记阶段 10 基准集，记录题目、页码、结构化题型、风险组和选入原因。
- `stage10_page_isolations`：登记 1098、1100、1128、1148、1168 等 duplicate_anchor 高风险页的候选数、入库数、重复锚点数、隔离数和可复核数。

运行阶段 10 基准、隔离和低风险结构化批处理：

```powershell
.\.venv\Scripts\python.exe -m app.cli stage10-baseline --sample-size 160
.\.venv\Scripts\python.exe -m app.cli stage10-structure-batch --target-verified 100 --max-questions 350 --sample-size 160
```

生成阶段 10 质量报告和导出样张：

```powershell
.\.venv\Scripts\python.exe -m app.cli stage10-report --sample-size 160
.\.venv\Scripts\python.exe -m app.cli stage10-export-sample --limit 14
```

阶段 10 审计修复后，严格可用池需用收紧后的 validator 全量重验：

```powershell
.\.venv\Scripts\python.exe -m app.cli validate-structured-content --status ai_verified --limit 1000
```

当前真实库阶段 10 基线结果：

- `questions` 总数：1123，阶段 10 执行前后主表校验和保持一致。
- `ai_verified`：2 -> 88；初次规则批处理曾到 245，审计修复后按公式/符号风险、`blank_placeholder_inferred`、私有区分段符号、零分母和根号拆分风险全量重验并降级风险候选，阶段 10 目标 100 当前未达标。
- 未达标原因：剩余候选主要受公式结构不可靠、填空空位为规则推断、视觉题/几何图形依赖原貌图、unknown 题型、duplicate_anchor 页隔离、分段函数原文污染和图表题结构污染影响；不得通过放宽 validator 凑数。
- 阶段 10 基准集：160 题，覆盖高风险页 1098、1100、1128、1148、1168；当前样本没有可客观识别的 `multiple_choice` 记录，因此报告中明确为 0，不伪造题型。
- 高风险页隔离：1098/1100/1128/1148/1168 均登记 `needs_review`，不静默合并重复锚点。
- 质量报告：`docs/stage10_quality_report.md`。
- 导出样张：`data/exports/stage10-sample-20260705-160647.html`，包含 Q011/Q012 和若干阶段 10 新增 verified 题。

边界：

- 不调用外部 AI 服务，不读取密钥文件，不上传 PDF、图片或题干。
- 不覆盖 `reviewed`、`approved` 或 `human_reviewed` 的可信结果；`ai_verified` 可经收紧后的 validator 全量重验并在候选侧降级为 `needs_review`，但不修改 `questions` 主表。
- 高风险页、图片题、公式/LaTeX 不确定、选项异常、填空空位不确定、私有区分段符号、零分母、根号拆分和跨题污染风险仍进入 `needs_review` 或 `failed`，不为了数量强行 verified。
- 阶段 10 样张只生成 HTML，不生成 PDF。

## 阶段 11 候选可用化生产线

阶段 11 不扩页、不新增导入批次、不修改 `questions` 主表。新增候选侧 `question_usability_states` 表，把每题的结构化状态、视觉兜底资产和风险 flags 分流为正式可用或专项修复队列。

阶段 11 schema：

- `question_usability_states`：绑定 `questions.id`，记录 `usability_status`、`render_mode`、`primary_issue`、`issue_flags_json`、`export_eligible`、`classification_version` 和 `meta_json`。
- `usability_status` 覆盖 `strict_structured`、`visual_fallback`、`needs_formula_repair`、`needs_blank_repair`、`needs_type_review`、`needs_recut`、`failed`、`protected`。
- `render_mode` 覆盖 `structured_html`、`raw_crop_image`、`candidate_preview`、`none`。

阶段 11 服务层：

- `ReviewEventService`：统一写入 `question_review_events`。
- `StructuredContentService`：结构化候选状态流转，当前 Web 接口保持原路由但写入走服务层。
- `RiskClassifier`：只读 `questions`、`question_structured_contents`、assets 和批次/隔离信息，生成候选侧可用性状态。
- `ExportSelectionService`：正式组卷导出只选择 `strict_structured + visual_fallback`。

命令：

```powershell
.\.venv\Scripts\python.exe -m app.cli stage11-classify-usability
.\.venv\Scripts\python.exe -m app.cli usability-status
.\.venv\Scripts\python.exe -m app.cli stage11-report
.\.venv\Scripts\python.exe -m app.cli stage11-export-sample --limit 24
```

当前真实库阶段 11 结果：

- `questions` 总数：1123，主表校验和保持 `01629a29eea4d24a3e262040caa1ce80758cf699140342a647b0f26fbab79de3`。
- `question_usability_states`：1123，`unclassified=0`。
- 可用性状态：`strict_structured=88`、`visual_fallback=945`、`needs_recut=89`、`protected=1`。
- 正式可导出：`export_usable=1033`。
- 高风险页 1098、1100、1128、1148、1168 全部进入 `needs_recut`，不进入正式导出。
- `strict_structured` 风险扫描命中：0。
- `visual_fallback` 题级图资产失效：0。
- 质量报告：`docs/stage11_quality_report.md`。
- 正式样卷：`data/exports/stage11-formal-sample-20260705-171852.html`，同时包含 `source:strict_structured` 和 `source:visual_fallback`，不包含 `needs_*` 或 `failed` 题。

边界：

- `visual_fallback` 不会把 `ai_status` 改成 `ai_verified`。
- `needs_*`、`failed`、`protected` 默认不进入正式组卷导出。
- 本阶段不做 OCR、公式 OCR、向量检索、账号、云同步、Electron 或外部 AI。

## 阶段 12 正式导出质量生产化

阶段 12 不扩页、不新增导入批次、不修改 `questions` 主表。新增候选侧 `question_export_quality` 表，把阶段 11 的工程可导出结果再细分为质量可控的正式导出状态。

阶段 12 schema：

- `question_export_quality`：绑定 `questions.id`，记录 `export_quality_status`、`render_mode`、`source_usability_status`、`export_eligible`、`blocking_reasons_json`、`quality_flags_json`、`classification_version` 和 `meta_json`。
- `export_quality_status` 覆盖 `export_ready_structured`、`export_ready_visual`、`export_candidate`、`export_blocked`。
- `render_mode` 继续使用 `structured_html`、`raw_crop_image`、`candidate_preview`、`none`。

阶段 12 服务层：

- `VisualQualityInspector`：本地检查题级图路径相对、存在、非空、可读取、尺寸、宽高比、空白占比、低对比度、内容贴边、page/bbox 可信和高风险页。
- `ExportQualityService`：读取 usability 状态、严格结构化 validator 和视觉检查结果，生成导出质量状态。
- `ExportSelectionService`：正式组卷导出只消费 `export_ready_structured + export_ready_visual`。
- `PaperRenderService`：负责正式题面 HTML 组装；structured 用结构化 HTML，visual 用题级裁切图。

命令：

```powershell
.\.venv\Scripts\python.exe -m app.cli stage12-classify-export-quality
.\.venv\Scripts\python.exe -m app.cli export-quality-status
.\.venv\Scripts\python.exe -m app.cli stage12-report
.\.venv\Scripts\python.exe -m app.cli stage12-export-sample --limit 24
```

阶段 12 验证口径：

- `export_ready_structured` 必须来自 `strict_structured`，并重新通过当前 validator，风险命中为 0。
- `export_ready_visual` 必须来自 `visual_fallback`，并通过视觉质量门槛。
- `export_candidate` 和 `export_blocked` 不进入正式导出。
- 高风险 duplicate anchor 页不得进入 ready。
- 保存后的 HTML 使用相对图片路径，不写入任何带盘符或根锚点的绝对路径。

当前真实库阶段 12 结果：

- `questions` 总数：1123，主表校验和保持 `01629a29eea4d24a3e262040caa1ce80758cf699140342a647b0f26fbab79de3`。
- `question_export_quality`：1123，`unclassified=0`。
- 导出质量状态：`export_ready_structured=88`、`export_ready_visual=856`、`export_blocked=179`。
- 正式可导出：`export_ready_total=944`。
- 视觉降级原因：`visual_image_low_contrast=85`、`visual_image_too_small=4`。
- 高风险页 1098、1100、1128、1148、1168 全部进入 `export_blocked`，不进入正式导出。
- `export_ready_structured` 风险扫描命中：0。
- `export_ready_visual` 资产失效：0。
- 质量报告：`docs/stage12_export_quality_report.md`。
- 正式样卷：`data/exports/stage12-formal-sample-20260705-181648.html`。
- 抽样验收：`data/exports/stage12-export-quality-audit-20260705-181711.html`。

## 阶段 13 来源归属与可信导出闭环

阶段 13 不扩页、不新增导入批次、不修改 `questions` 主表。新增候选侧 `question_source_attributions` 表，把每题的来源年份、原卷名、题号、页码、来源标签、置信度和 flags 独立记录下来。

阶段 13 schema：

- `question_source_attributions`：绑定 `questions.id`，记录 `source_year`、`source_paper_name`、`source_region`、`source_stream`、`source_question_no`、`source_page`、`source_label`、`confidence`、`attribution_flags_json`、`source_text` 和 `attribution_version`。
- `confidence` 覆盖 `exact`、`inferred`、`unknown`。
- 表内只保存结构化文本和 JSON，不保存 PDF、图片或 BLOB。

来源置信度口径：

- `exact`：当前题所在 PDF 页可稳定读到页眉年份和原卷名，并同时具备题号。
- `inferred`：当前页无页眉，但可从相邻前页页眉或已有非编纂来源字段推断；不视为精确来源。
- `unknown`：无法确认原始卷名或年份；不会把“真题全编/合集/汇编”等编纂书名伪造成真实原始卷名。

命令：

```powershell
.\.venv\Scripts\python.exe -m app.cli rebuild-source-attributions
.\.venv\Scripts\python.exe -m app.cli source-attribution-status
.\.venv\Scripts\python.exe -m app.cli stage13-report
```

阶段 13 行为边界：

- `SourceAttributionService` 只写 `question_source_attributions`，不修改 `questions.stem_*`、`questions.question_no`、`questions.review_status`、答案或解析。
- Web 题目列表、详情、structured-review、组卷篮、paper-preview、paper-export/save 展示来源标签和置信度。
- 正式导出的每道输出题必须带 `source_label`，图片路径仍使用相对路径。
- 后续任意试卷导入必须先登记来源，再进入切分、复核、质量分流和正式导出链路。

## 阶段 14 质量收敛与可导出池压实

阶段 14 只处理现有题库，不扩页、不新增 PDF、不运行 OCR/AI/向量检索，不自动覆盖 `reviewed`/`approved`，也不修改 `questions` 主表的题干、题号、状态、答案或解析。根目录入口固定为 `<PROJECT_ROOT>\试卷系统.html`，不得依赖具体盘符或父目录，也不得新增其他根目录 HTML 入口。

阶段 14 schema：

- `stage14_quality_queue`：每题一条质量队列记录，主队列包括 `export_ready`、`recut`、`visual_repair`、`structured_repair`、`type_review`、`source_inferred_audit`、`export_blocked`、`protected`；同时用 `queue_tags_json` 保留多标签归因。
- `stage14_page_recut_audits`：记录 1098、1100、1128、1148、1168 等重复锚点高风险页的扫描候选数、入库题数、重复锚点数、warning 和恢复建议。
- `stage14_visual_repair_candidates`：记录视觉修复候选图，候选资产写入 `data/assets/question_images/<paper_code>/stage14_repair/`，并以 `question_assets.asset_kind='other'` 登记，不替换现有 `raw_crop`。
- `stage14_source_audits`：抽查 `confidence='inferred'` 的来源归属样本，记录是否能由前页 header 支撑。

常用命令：

```powershell
.\.venv\Scripts\python.exe -m app.cli stage14-classify-quality --write-report
.\.venv\Scripts\python.exe -m app.cli stage14-visual-repair --write-report
.\.venv\Scripts\python.exe -m app.cli stage14-status
.\.venv\Scripts\python.exe -m app.cli stage14-report
.\.venv\Scripts\python.exe -m app.cli stage14-export-sample --limit 24
```

Web 使用：

- `/questions?status=all&stage14_queue=visual_repair`：按 Stage14 队列过滤复核列表。
- `/structured-review?ai_status=all&stage14_queue=recut`：在结构化复核工作台优先查看高风险 recut 队列。
- 详情页、组卷篮会显示 Stage14 队列、原因、建议动作和候选视觉修复路径。

导出边界：

- 正式样卷仍只通过 `ExportSelectionService` 选择 `export_ready_structured` 与 `export_ready_visual`。
- 每道正式导出题必须带 `source_label`。
- `stage14_visual_repair_candidates` 只生成候选图，不自动提升为正式 `raw_crop`，不改变导出质量门。
- 质量报告写入 `docs/stage14_quality_report.md`；HTML 样卷只写入 `data/exports/`。

## 运行测试

```powershell
.\.venv\Scripts\python.exe -m pytest
```

测试覆盖：

- 项目根目录、`Base` 目录和唯一目标 PDF 发现。
- 目标 PDF 发现函数对 0 个或多个 PDF 的错误处理。
- Flask `/health` 基础行为。
- SQLite schema 幂等初始化。
- 核心表、索引、FTS5 表和触发器存在。
- 示例题插入、更新、删除时 FTS5 同步。
- assets 路径必须是相对路径。
- `question_assets` 中同一题最多一条 `raw_crop` 资产记录。
- 源 PDF 页面资产可插入、随源试卷级联删除，并拒绝绝对路径。
- 源 PDF 登记幂等、抽样页渲染幂等、页码范围解析和页码越界报错。
- `scan-pdf-pages` 只读扫描、质量统计、异常页标记，且不修改数据库。
- 题号锚点识别、页内候选切分、页码范围解析、pending 写入、重复切分幂等、已复核题保护和 FTS 同步。
- AI 建议表、无配置跳过、模拟建议插入、Web 展示、接受写回并审计、拒绝不改题和 reviewed/approved 保护。
- 阶段 9 结构化题面表、初始化幂等、级联删除、状态约束、真实库无配置保护、本地 OpenAI-compatible provider、非本机 URL 拒绝、mock 临时库限制和 AI JSON 输出约束。
- 结构化校验器对选择题、填空题、解答题、unknown、JSON 形状错误、审计发现的公式/分段/零分母风险的 `ai_verified`、`needs_review`、`failed` 状态流转。
- 本地数学渲染器对 `x^2+y^2` 这类连续未加花括号上标不贪婪吞并后续表达。
- 阶段 10 基准集登记、高风险页隔离、低风险结构化批处理、主表校验和不变、阶段 10 报告和导出样张。
- 阶段 14 质量队列分类、视觉修复候选版本化资产、CLI 状态/报告/正式样卷、Web Stage14 队列过滤，并确认不修改 `questions` 主表。
- `/questions` 列表、详情、页面级原貌图访问、字段保存、人工状态流转、搜索过滤、批次筛选、异常优先筛选、保存并下一题和复核审计事件。
- `/structured-review` 工作台按结构化状态、flags、题型、页码筛选，并确认结构化接受/降级/标记只写候选侧和审计事件，不修改 `questions`。
- Web 结构化详情区、组卷预览/HTML 导出优先使用已验收结构化题面，未验证内容显示候选状态，并确认不修改 `questions` 表。
- session 组卷篮添加、去重、排序、删除、清空、按题型分区预览、HTML 导出，并确认不修改 `questions` 表。
- 搜索索引全量重建、复核审计事件、HTML 导出落盘、题级裁切资产、raw_crop 重复检查、阶段 8 批次记录、阶段 9/10 质量报告和一致性检查。
