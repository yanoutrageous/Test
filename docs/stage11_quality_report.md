# 阶段 11 质量报告

生成时间：2026-07-05T09:18:23Z

## 总览

- questions 总数：1123
- usability rows：1123
- unclassified：0
- questions 主表校验和：`01629a29eea4d24a3e262040caa1ce80758cf699140342a647b0f26fbab79de3`
- 分类版本：`stage11_usability_v1`
- 可用性状态：{"needs_recut": 89, "protected": 1, "strict_structured": 88, "visual_fallback": 945}
- render_mode：{"none": 90, "raw_crop_image": 945, "structured_html": 88}
- export_usable：1033
- strict_structured：88
- visual_fallback：945
- needs_* 合计：89
- failed：0
- protected：1

## 专项队列

- 公式：264
- 填空：158
- 分段函数/私有区符号：4
- 图表/视觉依赖：1034
- unknown 题型：320
- 重切/重复锚点：89
- 失败：0

## 高风险页

| page | usability_status | count |
| --- | --- | ---: |
| 1098 | needs_recut | 18 |
| 1100 | needs_recut | 18 |
| 1128 | needs_recut | 17 |
| 1148 | needs_recut | 18 |
| 1168 | needs_recut | 18 |

## 主要 flags

- structured_status_not_strict: 1035
- structured_candidate_not_strict: 945
- visual_fallback_ready: 945
- ai_status_unprocessed: 654
- no_answer_in_source: 381
- referenced_raw_crop_image: 381
- ai_status_needs_review: 369
- type_review_queue: 319
- visual_dependency_queue: 292
- stage10_rule_agent: 281
- referenced_page_image: 281
- formula_repair_queue: 203
- blank_placeholder_inferred: 133
- blank_repair_queue: 133
- codex_agent_structured: 100
- latex_implicit_exponent_unconverted: 93
- page_flags_present: 90
- page_duplicate_anchors: 89
- page_warning_candidates: 89
- page_flag_warning_candidates: 89
- page_flag_duplicate_anchors: 89
- page_flag_question_number_non_contiguous: 89
- page_flag_short_candidate_text: 89
- page_flag_stage10_duplicate_anchor_isolated: 89
- page_flag_stage10_duplicate_anchor_isolation: 89
- stage10_high_risk_page: 89
- duplicate_anchor_needs_recut: 89
- stage10_isolation_needs_review: 89
- page_flags_duplicate_anchor: 89
- strict_structured_ready: 88
- formula_uncertain: 71
- latex_sqrt_trailing_number_suspicious: 37
- image_question_needs_manual_review: 31
- blank_placeholder_uncertain: 25
- blank_missing_placeholder: 25
- latex_unicode_math_symbol_unconverted: 24
- latex_pi_trailing_number_suspicious: 23
- latex_unconverted_degree_symbol: 21
- split_warnings_present: 21
- split_warning_question_number_non_contiguous: 21

## 验证口径

- `strict_structured` 只来自当前 `ai_verified` 或 `human_reviewed` 且重新通过 validator 的结构化候选。
- `visual_fallback` 不改变 `ai_status`，只表示题级裁切图存在、非空、路径相对，并且页码与 bbox 关联可信。
- `needs_*` 和 `failed` 默认不进入正式导出；正式导出只选择 `strict_structured` 与 `visual_fallback`。
- duplicate_anchor 高风险页进入 `needs_recut`，不得静默作为正式可用题进入导出。
- strict 风险命中：0
- visual_fallback 资产失效：0
