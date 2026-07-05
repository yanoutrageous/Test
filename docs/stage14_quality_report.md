# Stage 14 Quality Report

Generated at: 2026-07-05T12:45:33+00:00
Version: `stage14_quality_v1`

## Scope

- Current questions: 1123
- Stage14 queue rows: 1123
- Missing queue rows: 0
- Questions checksum: `01629a29eea4d24a3e262040caa1ce80758cf699140342a647b0f26fbab79de3`
- Root HTML files: ["试卷系统.html"]
- Root HTML check: True

Stage14 does not import new PDF pages, does not mutate `questions` content/status fields, and does not promote visual repair candidates automatically.

## Export Quality

- Export quality counts: {"export_blocked": 179, "export_ready_structured": 88, "export_ready_visual": 856}
- Export-ready structured: 88
- Export-ready visual: 856
- Export blocked: 179
- Source confidence: {"exact": 903, "inferred": 220}
- Reviewed/approved: {"reviewed": 1}

## Queues

- Primary queue counts: {"export_ready": 944, "protected": 1, "recut": 98, "visual_repair": 80}
- Queue tag counts: {"export_blocked": 179, "export_ready": 944, "protected": 1, "recut": 311, "source_inferred_audit": 220, "structured_repair": 179, "type_review": 320, "visual_repair": 89}
- Primary reason counts: {"export_ready": 944, "review_status_protected": 1, "usability_needs_recut": 89, "visual_duplicate_anchor_page_stats": 9, "visual_image_low_contrast": 78, "visual_image_too_small": 2}

## Duplicate Anchor / Recut Audit

- Recut audit counts: {"blocked_needs_manual_recut": 5}

| page | candidates | db questions | duplicate anchors | warnings | status | action |
|---:|---:|---:|---:|---:|---|---|
| 1098 | 25 | 18 | 7 | 8 | blocked_needs_manual_recut | manual page-level recut required before export |
| 1100 | 25 | 18 | 7 | 8 | blocked_needs_manual_recut | manual page-level recut required before export |
| 1128 | 26 | 17 | 9 | 11 | blocked_needs_manual_recut | manual page-level recut required before export |
| 1148 | 27 | 18 | 9 | 13 | blocked_needs_manual_recut | manual page-level recut required before export |
| 1168 | 24 | 18 | 6 | 9 | blocked_needs_manual_recut | manual page-level recut required before export |

## Visual Repair Candidates

- Visual repair status counts: {"candidate_failed_visual_check": 48, "candidate_passed_visual_check": 41}
- Stage14 repair PNG files: 89

| qid | status | candidate |
|---|---|---|
| PDF-D02D0F16371FA96F-P1090-Q008 | candidate_passed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1090-Q008-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1091-Q023 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1091-Q023-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1092-Q009 | candidate_passed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1092-Q009-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1093-Q023 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1093-Q023-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1095-Q023 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1095-Q023-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1096-Q018 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1096-Q018-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1097-Q023 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1097-Q023-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1099-Q023 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1099-Q023-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1101-Q023 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1101-Q023-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1103-Q021 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1103-Q021-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1104-Q017 | candidate_passed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1104-Q017-stage14_quality_v1.png |
| PDF-D02D0F16371FA96F-P1105-Q020 | candidate_failed_visual_check | data/assets/question_images/PDF-D02D0F16371FA96F/stage14_repair/PDF-D02D0F16371FA96F-P1105-Q020-stage14_quality_v1.png |

## Inferred Source Audit

- Source audit counts: {"consistent_previous_header": 40}

| qid | page | status | flags |
|---|---:|---|---|
| PDF-D02D0F16371FA96F-P1091-Q019 | 1091 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1091-Q020 | 1091 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1091-Q021 | 1091 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1091-Q022 | 1091 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1091-Q023 | 1091 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1093-Q019 | 1093 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1093-Q020 | 1093 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1093-Q021 | 1093 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1093-Q022 | 1093 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1093-Q023 | 1093 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1095-Q019 | 1095 | consistent_previous_header | ["source_text_matches_previous_header"] |
| PDF-D02D0F16371FA96F-P1095-Q020 | 1095 | consistent_previous_header | ["source_text_matches_previous_header"] |

## Assets And Operations

- DB size bytes: 9695232
- Asset files: 1318
- Asset size bytes: 51879458
- Page PNG count: 103
- Question PNG count: 1212
- Export files: 45
- Review events: 2
- AI suggestions: 0

## Sample Blocked Rows

| qid | queue | reason | page | source | export_quality |
|---|---|---|---:|---|---|
| PDF-D02D0F16371FA96F-P1098-Q001 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q002 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q003 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q004 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q005 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q006 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q007 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q008 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q009 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q010 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q011 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q012 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q013 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q014 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q015 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q016 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q017 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1098-Q000 | recut | usability_needs_recut | 1098 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1100-Q001 | recut | usability_needs_recut | 1100 | exact | export_blocked |
| PDF-D02D0F16371FA96F-P1100-Q002 | recut | usability_needs_recut | 1100 | exact | export_blocked |

## Recommendation

Enter Stage 15 only after the blocked and repair queues are either manually resolved or accepted as excluded. Formal HTML exports must continue to select only `export_ready_*` rows with `source_label`.
