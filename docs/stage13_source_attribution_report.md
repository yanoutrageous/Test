# 阶段 13 来源归属报告

## 总览

- questions：1123
- question_source_attributions：1123
- missing：0
- orphan：0
- exact：903
- inferred：220
- unknown：0
- attribution_version：source_attribution_v2

## 置信度口径

- `exact`：当前题所在 PDF 页可稳定读到页眉年份和原卷名，并同时具备题号。
- `inferred`：当前页无页眉，但可从相邻前页页眉或已有非编纂来源字段推断；不视为精确来源。
- `unknown`：无法确认原始卷名或年份；不会把编纂书名伪造成真实原卷名。

## 年份分布

- 2019：224
- 2020：292
- 2021：226
- 2022：226
- 2023：155

## Flags

- `compiled_source_pdf`：1123
- `source_header_extracted`：903
- `source_header_inferred_distance_1`：220
- `source_header_inferred_from_previous_page`：220
- `source_label_inferred_from_header_context`：220
- `source_page_traced`：1123
- `source_question_no_traced`：1123

## 样例

### exact
- `PDF-D02D0F16371FA96F-P1090-Q001`：2019 普通高等学校招生考试(全国卷I 理) 第1题 / exact / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_extracted, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1090-Q002`：2019 普通高等学校招生考试(全国卷I 理) 第2题 / exact / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_extracted, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1090-Q003`：2019 普通高等学校招生考试(全国卷I 理) 第3题 / exact / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_extracted, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1090-Q004`：2019 普通高等学校招生考试(全国卷I 理) 第4题 / exact / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_extracted, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1090-Q005`：2019 普通高等学校招生考试(全国卷I 理) 第5题 / exact / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_extracted, source_page_traced, source_question_no_traced

### inferred
- `PDF-D02D0F16371FA96F-P1091-Q019`：2019 普通高等学校招生考试(全国卷I 理) / p1091 / 题号 19 / inferred / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_inferred_distance_1, source_header_inferred_from_previous_page, source_label_inferred_from_header_context, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1091-Q020`：2019 普通高等学校招生考试(全国卷I 理) / p1091 / 题号 20 / inferred / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_inferred_distance_1, source_header_inferred_from_previous_page, source_label_inferred_from_header_context, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1091-Q021`：2019 普通高等学校招生考试(全国卷I 理) / p1091 / 题号 21 / inferred / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_inferred_distance_1, source_header_inferred_from_previous_page, source_label_inferred_from_header_context, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1091-Q022`：2019 普通高等学校招生考试(全国卷I 理) / p1091 / 题号 22 / inferred / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_inferred_distance_1, source_header_inferred_from_previous_page, source_label_inferred_from_header_context, source_page_traced, source_question_no_traced
- `PDF-D02D0F16371FA96F-P1091-Q023`：2019 普通高等学校招生考试(全国卷I 理) / p1091 / 题号 23 / inferred / header: 2019 普通高等学校招生考试(全国卷I 理) / flags: compiled_source_pdf, source_header_inferred_distance_1, source_header_inferred_from_previous_page, source_label_inferred_from_header_context, source_page_traced, source_question_no_traced

### unknown
- none

## 边界

- 本阶段不新增 PDF 导入批次，不扩页，不处理全 1207 页。
- 本阶段只写候选侧来源归属表，不修改 `questions` 主表题干、题号、状态、答案或解析。
- 后续任意试卷导入必须先登记来源，再进入切分、复核和导出链路。
