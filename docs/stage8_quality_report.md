# 阶段 8 质量报告

生成时间：2026-07-05T04:04:34

## 总览

- 批次数：4
- 批次页记录数：100
- 去重页数：100
- 批次页扫描候选题数：1185
- 批次页当前入库题数：1123
- warning 候选题数：111
- duplicate_anchor 总数：62
- 题库总题数：1123
- 题级资产数：1123
- 页面资产数：103
- 复核审计事件数：2
- AI 建议数：0
- 状态分布：{"pending": 1122, "reviewed": 1}

## 质量比例

- 候选入库比例：94.77%
- warning 候选比例：9.37%
- duplicate_anchor 锚点/候选比例：5.23%
- 异常页比例：50.0%
- duplicate_anchor 页比例：18.0%
- 估算需优先复核题数：572

## 存储

- SQLite 大小：3252224 bytes
- 页面 PNG 数：103
- 题级 PNG 数：1123
- assets 目录大小：51157865 bytes
- exports HTML 数：6

## 性能

- 扩容批次端到端耗时合计：43791 ms
- 当前历史批次只保存端到端 `duration_ms`；未回填 scan/import/split/crop 分段耗时。

SQLite 轻量查询：

| check | ok | rows | duration_ms | error |
|---|---|---:|---:|---|
| status_count | True | 2 | 0 |  |
| question_list_50 | True | 50 | 0 |  |
| fts_keyword_50 | True | 0 | 0 |  |

Flask test client 响应：

| path | status | bytes | duration_ms |
|---|---:|---:|---:|
| `/questions?status=all&limit=50` | 200 | 42575 | 19 |
| `/batches` | 200 | 3079 | 7 |
| `/paper-basket` | 200 | 1951 | 5 |
| `/questions?status=all&batch_id=4&issue_only=1&limit=50` | 200 | 44857 | 12 |
| `/batches/4` | 200 | 18814 | 10 |
| `/questions/1?status=all&limit=50` | 200 | 6764 | 15 |

## 批次

| id | name | kind | status | pages | duration_ms | backup |
|---:|---|---|---|---:|---:|---|
| 1 | stage8-baseline-1090-1099 | baseline | done | 10 |  |  |
| 2 | stage8-20-pages | expansion | done | 10 | 4792 | data/db/backups/before-batch-stage8-20-pages-20260705-034242.sqlite3 |
| 3 | stage8-50-pages | expansion | done | 30 | 14621 | data/db/backups/before-batch-stage8-50-pages-20260705-034344.sqlite3 |
| 4 | stage8-100-pages | expansion | done | 50 | 24378 | data/db/backups/before-batch-stage8-100-pages-20260705-034438.sqlite3 |

## 异常页

| batch | page | candidates | db_questions | warnings | duplicate_anchors | flags |
|---|---:|---:|---:|---:|---:|---|
| stage8-baseline-1090-1099 | 1093 | 5 | 5 | 0 | 0 | possible_instruction_page |
| stage8-baseline-1090-1099 | 1095 | 6 | 6 | 2 | 0 | warning_candidates, question_number_non_contiguous, possible_instruction_page |
| stage8-baseline-1090-1099 | 1098 | 25 | 18 | 8 | 7 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-baseline-1090-1099 | 1099 | 6 | 6 | 0 | 0 | possible_instruction_page |
| stage8-20-pages | 1100 | 25 | 18 | 8 | 7 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-20-pages | 1103 | 3 | 3 | 0 | 0 | possible_instruction_page |
| stage8-20-pages | 1104 | 18 | 17 | 2 | 1 | warning_candidates, duplicate_anchors, question_number_non_contiguous |
| stage8-20-pages | 1106 | 18 | 17 | 2 | 1 | warning_candidates, duplicate_anchors, question_number_non_contiguous |
| stage8-50-pages | 1111 | 4 | 4 | 0 | 0 | possible_instruction_page |
| stage8-50-pages | 1113 | 6 | 6 | 2 | 0 | warning_candidates, question_number_non_contiguous, short_candidate_text, possible_instruction_page |
| stage8-50-pages | 1115 | 6 | 6 | 2 | 0 | warning_candidates, question_number_non_contiguous |
| stage8-50-pages | 1118 | 18 | 18 | 0 | 0 | possible_instruction_page |
| stage8-50-pages | 1120 | 18 | 18 | 0 | 0 | possible_instruction_page |
| stage8-50-pages | 1122 | 19 | 18 | 2 | 1 | warning_candidates, duplicate_anchors, question_number_non_contiguous |
| stage8-50-pages | 1127 | 3 | 3 | 0 | 0 | possible_instruction_page |
| stage8-50-pages | 1128 | 26 | 17 | 11 | 9 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-50-pages | 1130 | 18 | 18 | 0 | 0 | possible_instruction_page |
| stage8-50-pages | 1132 | 18 | 18 | 0 | 0 | possible_instruction_page |
| stage8-50-pages | 1133 | 5 | 5 | 2 | 0 | warning_candidates, question_number_non_contiguous |
| stage8-50-pages | 1137 | 5 | 5 | 2 | 0 | warning_candidates, question_number_non_contiguous, possible_instruction_page |
| stage8-50-pages | 1138 | 19 | 18 | 2 | 1 | warning_candidates, duplicate_anchors, question_number_non_contiguous, possible_answer_page |
| stage8-100-pages | 1140 | 19 | 19 | 0 | 0 | possible_answer_page |
| stage8-100-pages | 1142 | 22 | 18 | 5 | 4 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-100-pages | 1143 | 6 | 6 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1144 | 23 | 19 | 5 | 4 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-100-pages | 1145 | 5 | 5 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1147 | 3 | 3 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1148 | 27 | 18 | 13 | 9 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-100-pages | 1149 | 4 | 4 | 2 | 0 | warning_candidates, question_number_non_contiguous |
| stage8-100-pages | 1150 | 19 | 19 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1152 | 18 | 18 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1153 | 5 | 5 | 2 | 0 | warning_candidates, question_number_non_contiguous, short_candidate_text, possible_instruction_page |
| stage8-100-pages | 1157 | 4 | 4 | 2 | 0 | warning_candidates, question_number_non_contiguous, possible_instruction_page |
| stage8-100-pages | 1159 | 7 | 7 | 2 | 0 | warning_candidates, question_number_non_contiguous |
| stage8-100-pages | 1163 | 6 | 6 | 2 | 0 | warning_candidates, question_number_non_contiguous, short_candidate_text |
| stage8-100-pages | 1165 | 6 | 6 | 2 | 0 | warning_candidates, question_number_non_contiguous, short_candidate_text |
| stage8-100-pages | 1167 | 3 | 3 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1168 | 24 | 18 | 9 | 6 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-100-pages | 1170 | 21 | 19 | 3 | 2 | warning_candidates, duplicate_anchors, question_number_non_contiguous |
| stage8-100-pages | 1173 | 8 | 5 | 5 | 3 | warning_candidates, duplicate_anchors, question_number_non_contiguous, short_candidate_text |
| stage8-100-pages | 1174 | 20 | 19 | 2 | 1 | warning_candidates, duplicate_anchors, question_number_non_contiguous |
| stage8-100-pages | 1176 | 19 | 18 | 2 | 1 | warning_candidates, duplicate_anchors, question_number_non_contiguous, possible_instruction_page |
| stage8-100-pages | 1178 | 20 | 18 | 3 | 2 | warning_candidates, duplicate_anchors, question_number_non_contiguous |
| stage8-100-pages | 1179 | 5 | 5 | 2 | 0 | warning_candidates, question_number_non_contiguous |
| stage8-100-pages | 1180 | 21 | 19 | 2 | 2 | warning_candidates, duplicate_anchors, question_number_non_contiguous |
| stage8-100-pages | 1181 | 5 | 5 | 2 | 0 | warning_candidates, question_number_non_contiguous |
| stage8-100-pages | 1183 | 4 | 4 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1186 | 18 | 18 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1187 | 3 | 3 | 0 | 0 | possible_instruction_page |
| stage8-100-pages | 1188 | 18 | 17 | 1 | 1 | warning_candidates, duplicate_anchors, question_number_non_contiguous, possible_answer_page |

## 标记统计

- duplicate_anchors: 18
- possible_answer_page: 3
- possible_instruction_page: 24
- question_number_non_contiguous: 31
- short_candidate_text: 12
- warning_candidates: 31

## 失败页

暂无失败页。

## 复核成本估算

- 当前 pending 题数：1122
- 异常页关联题数估算：572
- 粗略人工复核耗时：1556.5~3113.0 分钟（普通题按 45~90 秒/题，异常页题按 2~4 分钟/题估算）。

## 风险判断

- 已出现 duplicate_anchor 页，当前 qid 以页码和题号生成，重复题号候选可能合并为同一入库题，需要人工抽查。
- 当前未记录失败页。
- 阶段 8 不自动批准题目；所有自动切分结果仍应进入人工复核。
- 不建议直接进入 300/500/全量扩容；建议先修正重复锚点合并策略，并优先人工抽查异常页后再决定下一轮样本。
