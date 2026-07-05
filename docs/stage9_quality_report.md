# 阶段 9 质量报告

生成时间：2026-07-05T05:36:09Z

## 范围

- 阶段 9 目标：AI 题面结构化校正与 LaTeX 渲染闭环。
- 本轮不继续扩页，不处理全 1207 页，不覆盖 `questions.reviewed/approved` 主数据。
- 真实 AI provider 状态：未运行外部 provider 队列
- Codex 代理状态：Codex 代理已写入结构化副本 119 条
- mock AI 仅在 pytest/临时库验证；真实库未写入 mock 草稿。

## 结构化模型覆盖

- questions 总数：1123
- question_structured_contents 总数：1123
- 缺失结构化记录：0
- 初始化本次新增：0
- ai_status 分布：{"ai_verified": 2, "failed": 7, "needs_review": 110, "unprocessed": 1004}
- normalized_type 分布：{"blank": 275, "choice": 329, "solution": 124, "unknown": 395}
- 可直接用于结构化导出的状态占比（ai_verified + human_reviewed）：2/1123 (0.18%)

## 样本

- 代表性样本数量：120
- 样本覆盖题型：{"solution": 18, "choice": 58, "blank": 29, "unknown": 15}
- 样本覆盖状态：{"needs_review": 104, "failed": 7, "unprocessed": 9}
- 高风险页样本覆盖：{"1098": 18, "1100": 18, "1128": 17, "1148": 18, "1168": 18}
- 样本前 20 个 qid：PDF-D02D0F16371FA96F-P1098-Q001, PDF-D02D0F16371FA96F-P1098-Q002, PDF-D02D0F16371FA96F-P1098-Q003, PDF-D02D0F16371FA96F-P1098-Q004, PDF-D02D0F16371FA96F-P1098-Q005, PDF-D02D0F16371FA96F-P1098-Q006, PDF-D02D0F16371FA96F-P1098-Q007, PDF-D02D0F16371FA96F-P1098-Q008, PDF-D02D0F16371FA96F-P1098-Q009, PDF-D02D0F16371FA96F-P1098-Q010, PDF-D02D0F16371FA96F-P1098-Q011, PDF-D02D0F16371FA96F-P1098-Q012, PDF-D02D0F16371FA96F-P1098-Q013, PDF-D02D0F16371FA96F-P1098-Q014, PDF-D02D0F16371FA96F-P1098-Q015, PDF-D02D0F16371FA96F-P1098-Q016, PDF-D02D0F16371FA96F-P1098-Q017, PDF-D02D0F16371FA96F-P1098-Q000, PDF-D02D0F16371FA96F-P1100-Q001, PDF-D02D0F16371FA96F-P1100-Q002, ...

## AI 队列

- provider：none
- 状态：not_run
- 原因：queue run disabled
- provider_config：{"configured": false, "provider": "unconfigured", "model": "none", "local_only": true, "reason": "Structured AI provider is not configured."}
- 本轮考虑样本：0
- 写入不可用标记：0
- 写入 AI 草稿：0

## Codex 代理校正

- Codex 代理写入总数：119
- Codex 代理状态分布：{"ai_verified": 2, "failed": 7, "needs_review": 110}
- Codex 代理批次分布：{"stage9-codex-10": 2, "stage9-codex-120": 117}

## 自动质量验收

- 本轮校验草稿数：0
- 校验结果分布：{}
- LaTeX 基础可渲染性（样本 stem_latex/source_latex 括号与定界符）：117/120 (97.50%)
- 结构化通过率（真实库 ai_verified + human_reviewed / 全部结构化记录）：2/1123 (0.18%)
- 质量标记分布：{"codex_agent_structured": 111, "referenced_raw_crop_image": 111, "page_duplicate_anchors": 89, "page_warning_candidates": 89, "page_flags_present": 90, "page_flag_warning_candidates": 89, "page_flag_duplicate_anchors": 89, "page_flag_question_number_non_contiguous": 89, "page_flag_short_candidate_text": 89, "split_warnings_present": 21, "split_warning_question_number_non_contiguous": 21, "image_question_needs_manual_review": 29, "no_answer_in_source": 111, "formula_uncertain": 77, "blank_placeholder_uncertain": 29, "blank_missing_placeholder": 29, "source_latex_unbalanced_delimiters": 3, "latex_unbalanced_delimiters": 3, "split_warning_stem_too_short": 3, "option_count_anomaly": 5, "short_source_text": 3, "choice_options_incomplete": 5, "empty_or_short_stem_latex": 4, "unknown_question_type": 7, "page_flag_possible_instruction_page": 1, "ai_provider_unavailable": 1, "latex_implicit_exponent_unconverted": 1, "latex_ambiguous_decimal_or_log": 1}

## 严格可用口径

- 已结构化处理数（非 unprocessed）：119
- 严格可直接使用数（ai_verified + human_reviewed）：2
- LaTeX 质量风险标记数：4
- 因 LaTeX 质量风险降级为 needs_review 数：4

## 专项样例状态

- PDF-D02D0F16371FA96F-P1094-Q011: ai_status=ai_verified, normalized_type=choice, flags=["codex_agent_structured", "referenced_raw_crop_image", "no_answer_in_source"]
- PDF-D02D0F16371FA96F-P1094-Q012: ai_status=ai_verified, normalized_type=choice, flags=["codex_agent_structured", "referenced_raw_crop_image", "no_answer_in_source"]

## 高风险页跟踪

- page 1098: candidates=25, db_questions=18, warnings=8, duplicate_anchors=7, flags=["warning_candidates", "duplicate_anchors", "question_number_non_contiguous", "short_candidate_text"]
- page 1100: candidates=25, db_questions=18, warnings=8, duplicate_anchors=7, flags=["warning_candidates", "duplicate_anchors", "question_number_non_contiguous", "short_candidate_text"]
- page 1128: candidates=26, db_questions=17, warnings=11, duplicate_anchors=9, flags=["warning_candidates", "duplicate_anchors", "question_number_non_contiguous", "short_candidate_text"]
- page 1148: candidates=27, db_questions=18, warnings=13, duplicate_anchors=9, flags=["warning_candidates", "duplicate_anchors", "question_number_non_contiguous", "short_candidate_text"]
- page 1168: candidates=24, db_questions=18, warnings=9, duplicate_anchors=6, flags=["warning_candidates", "duplicate_anchors", "question_number_non_contiguous", "short_candidate_text"]

## 资产与审计

- question_assets：1123
- source_paper_assets：103
- question_review_events：2
- question_ai_suggestions：0
- questions 状态分布：{"pending": 1122, "reviewed": 1}

## 判断

- 当前已完成结构化表、AI provider 抽象、无配置真实库保护、程序化校验器、Web 详情/预览/导出接入，以及 Codex 代理式 JSONL 校正闭环。
- Codex 代理只写入 `question_structured_contents`，不覆盖 `questions` 主表；高风险、缺图、公式不确定、选项异常和未可靠 LaTeX 化内容会进入 `needs_review`。
- Web 详情、组卷预览和 HTML 导出已接入本地数学呈现脚本；数据库仍只存 LaTeX 源。
- 不建议自动全量覆盖或进入全卷扩容；建议先人工复核 `needs_review` 与高风险页，再决定是否扩大样本。
