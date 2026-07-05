# 阶段 7.2 十页样本

## 样本范围

本切片选择 `1090-1099` 共 10 页作为小批量验证样本。

选择理由：

- 第 `1090` 页已经在阶段 4-7.1 中完成导入、切分、复核保护、搜索和题级裁切验证，可作为回归基准页。
- `1090-1099` 是连续页，能验证 `--pages` 范围语法、连续页面渲染、切分和资产生成流程。
- 10 页扫描均存在文本层和题号锚点，没有空文本页或无候选页。
- 样本中保留了带 warning 或疑似说明页标记的页面，用于验证质量统计和异常报告，而不是只挑选完全干净页面。
- 本切片不扩到 50/100 页，不处理全 1207 页。

## 扫描摘要

扫描命令：

```powershell
.\.venv\Scripts\python.exe -m app.cli scan-pdf-pages --pages 1090-1099
```

扫描只读性：扫描前后真实库核心计数完全不变。

| page_no | text_length | anchor_count | duplicate_anchor_count | candidate_count | warning_candidates | warning_reasons | page_flags |
|---:|---:|---:|---:|---:|---:|---|---|
| 1090 | 2461 | 18 | 0 | 18 | 0 |  |  |
| 1091 | 1199 | 5 | 0 | 5 | 0 |  |  |
| 1092 | 2190 | 18 | 0 | 18 | 0 |  |  |
| 1093 | 744 | 5 | 0 | 5 | 0 |  | possible_instruction_page |
| 1094 | 2537 | 18 | 0 | 18 | 0 |  |  |
| 1095 | 762 | 6 | 0 | 6 | 2 | question_number_non_contiguous | warning_candidates, question_number_non_contiguous, possible_instruction_page |
| 1096 | 2075 | 18 | 0 | 18 | 0 |  |  |
| 1097 | 816 | 5 | 0 | 5 | 0 |  |  |
| 1098 | 2635 | 25 | 7 | 25 | 8 | question_number_non_contiguous, stem_too_short | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| 1099 | 1011 | 6 | 0 | 6 | 0 |  | possible_instruction_page |

合计：

- `page_count=10`
- `total_candidates=124`
- `total_warning_candidates=10`

## 异常页说明

- `1093`、`1095`、`1099`：扫描文本包含说明类信号，标记为 `possible_instruction_page`。这些页仍有明确题号锚点和候选题，保留用于验证标记能力。
- `1095`：存在 2 个 warning 候选题，原因是 `question_number_non_contiguous`，保留用于验证 warning 统计。
- `1098`：存在 8 个 warning 候选题和 7 个重复锚点，原因包含 `question_number_non_contiguous` 与 `stem_too_short`。该页保留用于验证重复锚点和短候选文本报告。

本阶段没有排除页；后续进入 20/50/100 页校正时，应优先人工抽查上述标记页。
