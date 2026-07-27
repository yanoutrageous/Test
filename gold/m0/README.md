# M0 金标目录

本目录只包含可提交的脱敏登记、T0 合成夹具、模板族和视觉阈值，不包含外部原卷、私人文件名、绝对路径或真实成绩。

- `gold-source-plan-v1.json`：由项目基线给出的逻辑角色、许可/PII、需求/风险和确认来源；
- `gold-registry-v1.json`：63 个只读成员在 18 个逻辑 ID 下的哈希、大小、页数、尺寸和结构状态；
- `measurement-synthetic-v1.json`：无 PII 的合成测量语义夹具，不代表真实学生结论；
- `template-families-v1.json`：12 个独立模板族；
- `visual-thresholds-v1.json`：精确页面/分页、关键锚点、零裁切/溢出/静默字体替换的初始门槛。

本机绝对路径只保存在 Git 忽略的`Task/local/GOLD_SOURCE_MAP.local.json`。外部资产采用`copy-on-use`，登记生成只读哈希，不复制文件；需要实际转换时仍必须先经过 Copy 安全入口。

生成预览：

```powershell
.\.venv\Scripts\python.exe -B Task\tools\build_gold_registry_preview.py --run-id RUN-YYYYMMDD-M0-S5-GOLD-NNN
```

生成器只写`tmp/gold_registry_preview/<run-id>`并在写入前完成结构、隐私和聚合哈希验证。发布登记是独立步骤；更新任何金标、确认信息或阈值均为 D2 变更，必须保留旧 digest、变更原因和独立审计，不能由被测实现自动接受。
