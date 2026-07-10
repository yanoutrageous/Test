# 当前状态

更新时间：2026-07-11

## 规划状态

- 计划版本：1.0.1
- 当前阶段：PRE-M0 规划发布完成，等待转入 M0
- M0—M5 实现：尚未开始
- 本轮允许内容：仅建立规范、安装本次明确授权的必要发布组件、准备规划提交
- 本轮未进行：数据库迁移、题库导入、OCR、排版实现、正式导出、备份切换和业务文件清理

## Git 状态基线

- 仓库：`https://github.com/yanoutrageous/Test.git`
- 规划分支：`agent/long-run-execution-spec`
- 分支基线：`origin/main`提交`3df22b3`（Update local entry page）
- `Base/高考题原卷/`为用户本地资产，已由根`.gitignore`保护，明确不属于本次提交范围
- 规划发布范围仅为`.gitignore`与`Task`中的可跟踪规范；`Task/local/`本机路径映射被忽略，禁止提交
- 本次及后续提交必须显式暂存文件，禁止`git add -A`

## 当前数据事实

- 活动 SQLite 已有 25 张表；`source_papers`、`questions`、`question_assets`、结构化内容、复核事件和导入批次当前均为 0 条
- 历史质量报告中的题量不能作为当前可复现基线
- 目标 NEW9 PDF 已在 Test 内，但其正文无可提取文字层；视觉回归必须包含整页像素/锚点检查

## 工具与发布状态

- GitHub CLI 2.96.0 已根据用户本轮一次性授权，以用户范围通过 Windows Package Manager 安装
- 安装位置：`%LOCALAPPDATA%\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe`
- GitHub CLI 已认证为授权仓库管理员账号；`gh repo view`确认远端、默认分支和权限正确
- 本仓库 Git 作者邮箱已改为 GitHub noreply 地址，未修改全局 Git 配置，避免公开提交暴露个人邮箱
- 规划提交范围、隐私、二进制、大文件、忽略规则和远端同名分支已通过独立只读审计
- 规划提交`522393d`已普通 push 到`agent/long-run-execution-spec`
- 草稿 PR：`https://github.com/yanoutrageous/Test/pull/1`（base=`main`，head=`agent/long-run-execution-spec`）
- 除 GitHub CLI 外，本轮未安装 OCR、TeX、模型、字体或其他项目依赖

## 当前长期执行的首批动作

1. 提交并 push PRE-M0 发布事实；
2. 从已确认包含规划包的基线创建/恢复`agent/m0-m5-local-v1`长期集成分支并维护草稿 PR；
3. 固化 M0 当前代码、数据库、目标金标、依赖和路径事实基线；
4. 先实现 WorkspaceGuard 和安全测试实验室，再触碰任何业务写入口或真实资料；
5. 只在 M0 门禁完成后进入 M1。

## 已知限制与未决项

- 精确字体许可尚未审计：不阻塞金标测量，但阻塞“字体完全一比一”的正式声明。
- 当前备份只能位于 Test 内：不具备异盘灾备能力，不能对客户宣称可抵御整个 D 盘故障。
