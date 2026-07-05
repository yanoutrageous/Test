# 阶段 12 导出质量报告

生成时间：2026-07-05T10:16:53Z

## 总览

- questions 总数：1123
- export quality rows：1123
- unclassified：0
- questions 主表校验和：`01629a29eea4d24a3e262040caa1ce80758cf699140342a647b0f26fbab79de3`
- 分类版本：`stage12_export_quality_v1`
- 视觉检测版本：`stage12_visual_quality_v1`
- 导出质量状态：{"export_blocked": 179, "export_ready_structured": 88, "export_ready_visual": 856}
- render_mode：{"none": 179, "raw_crop_image": 856, "structured_html": 88}
- export_ready_structured：88
- export_ready_visual：856
- export_candidate：0
- export_blocked：179
- export_ready_total：944

## 视觉降级原因 Top

- visual_image_low_contrast: 85
- visual_image_too_small: 4

## 阻塞原因 Top

- usability_needs_recut: 89
- visual_image_low_contrast: 85
- visual_image_too_small: 4
- usability_protected: 1

## 高风险页

| page | export_quality_status | count |
| --- | --- | ---: |
| 1098 | export_blocked | 18 |
| 1100 | export_blocked | 18 |
| 1128 | export_blocked | 17 |
| 1148 | export_blocked | 18 |
| 1168 | export_blocked | 18 |

## 验证口径

- `export_ready_structured` 只来自 `strict_structured` 且重新通过当前 validator、风险命中为 0。
- `export_ready_visual` 只来自 `visual_fallback` 且题级图路径相对、存在、非空、可读取、尺寸/宽高比/空白率/对比度达标，并且 page/bbox 关联可信。
- `export_candidate`、`export_blocked`、`needs_recut`、`protected` 和 `failed` 不进入正式导出。
- duplicate_anchor 高风险页不得进入 ready。
- ready structured 风险命中：0
- ready visual 失效：0
