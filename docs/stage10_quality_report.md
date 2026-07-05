# 阶段 10 质量报告

生成时间：2026-07-05T08:09:25Z

## 总览

- questions 总数：1123
- structured rows：1123
- questions 主表校验和：`01629a29eea4d24a3e262040caa1ce80758cf699140342a647b0f26fbab79de3`
- 结构化状态：{"ai_verified": 88, "failed": 12, "needs_review": 369, "unprocessed": 654}
- 题型分布：{"blank": 275, "choice": 404, "solution": 124, "unknown": 320}
- review_status 分布：{"pending": 1122, "reviewed": 1}
- 严格可用：88
- 阶段 10 严格可用目标：not_met / 100
- 待复核：369
- 失败：12
- 未处理：654
- 受保护：{"reviewed_or_approved_questions": 1, "trusted_structured_rows": 88}
- 阶段 10 新增 ai_verified：86

## 基准集

- 基准集数量：160
- 按题型：{"blank": 37, "choice": 82, "solution": 21, "unknown": 20}
- 按风险：{"duplicate_anchor": 89, "normal": 59, "protected": 12}
- 覆盖高风险页：[1098, 1100, 1128, 1148, 1168]
- 说明：multiple_choice 若为 0，表示当前样本中没有可客观识别的多选题源记录，本阶段不伪造题型。

## 高风险页隔离

| page | candidates | db questions | duplicate anchors | isolated | reviewable | status |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1098 | 25 | 18 | 7 | 7 | 18 | needs_review |
| 1100 | 25 | 18 | 7 | 7 | 18 | needs_review |
| 1128 | 26 | 17 | 9 | 9 | 17 | needs_review |
| 1148 | 27 | 18 | 9 | 9 | 18 | needs_review |
| 1168 | 24 | 18 | 6 | 6 | 18 | needs_review |

## 渲染与导出可用性

- verified/human_reviewed 可渲染：88 / 88
- question assets：1123
- page assets：103
- 绝对资产路径违规：0
- question_review_events：2
- question_ai_suggestions：0
- 导出版式：按单选/多选/填空/解答/其他分区，导出时重新编号，使用本地数学呈现。

## 主要阻塞 flags

- referenced_raw_crop_image: 381
- no_answer_in_source: 381
- stage10_rule_agent: 281
- referenced_page_image: 281
- blank_placeholder_inferred: 133
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
- formula_uncertain: 71
- latex_sqrt_trailing_number_suspicious: 37
- image_question_needs_manual_review: 31
- blank_placeholder_uncertain: 25

## 客观判断

- `ai_verified` 只计入无 validator flags 的严格候选；`blank_placeholder_inferred`、公式结构可疑、未转换符号、私有区分段符号、零分母、根号拆分和重复锚点页均进入 `needs_review`。
- 阶段 10 严格可用目标当前为 not_met；若未达 100，原因是源文本公式结构不可靠、填空空位为规则推断、视觉题/几何图形依赖原貌图、分段/图表题结构污染，不应通过放宽 validator 凑数。
- 高风险 duplicate_anchor 页已登记隔离，不再静默合并；这些页仍需要人工复核或后续切分修复。
- 未处理和 needs_review 仍是主要存量，下一阶段不应直接扩页，除非先确认复核效率和重复锚点处理成本可接受。
