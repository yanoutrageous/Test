# PRE-M0 规划包发布前审计

## 结论

- 规划包内容审计：PASS
- Git 暂存范围审计：PASS（尚未暂存）
- 本机敏感路径脱敏：PASS
- 远端发布：BLOCKED_BY_GITHUB_AUTH
- M0—M5 实现：NOT_STARTED

## 审计范围

允许进入规划提交的范围仅为：

- 根目录`.gitignore`；
- `Task`下 26 个可跟踪规范、状态、模板和审计文件。

明确排除：

- `Base/**`；
- `Task/local/**`本机路径映射；
- `Copy/**`、数据库、备份、输出、运行状态、证据大文件、模型和字体；
- 任何原卷、图片、Office/PDF 原件、PII、凭据或浏览器状态。

## 自动校验

- 27 个 Task 文件均可按 UTF-8 读取，其中 1 个为 Git 忽略的本机映射；
- 26 个公开候选文件约 145 KiB；
- JSON 解析通过；
- `execution_contract.json.required_runtime_documents`全部存在；
- `RUN_STATE.json`的 milestone、status 和 implementation status 均属于合同枚举；
- Markdown 围栏、允许的行尾和引用结构通过；
- 17 个公开参考逻辑 ID 均可在本机忽略映射中解析；
- 公开候选中未发现本机用户名、绝对用户目录、GitHub token 模式或私人参考文件名；
- `.gitignore`已验证保护 Base、本机映射、Copy、备份、输出、运行状态、数据区、模型和字体；
- 工作区候选除`.gitignore`和可跟踪 Task 文件外没有其他未忽略项。

## 独立复核

只读复核最初发现并在本轮修复：

1. 项目唯一写根与依赖安装例外的措辞冲突；
2. `RUN_STATE`使用未定义组合状态；
3. 本机资产和运行目录的 Git 忽略防线不完整；
4. 参考基线含不适合公开提交的私人文件名。

修正后复核结论：四项全部消解。

## Git 与远端

- 分支：`agent/long-run-execution-spec`
- 基线：`origin/main`提交`3df22b3`
- 远端：`https://github.com/yanoutrageous/Test.git`
- GitHub CLI：2.96.0，安装审计见同目录依赖记录
- `gh auth status`：未登录任何 GitHub host

因此本轮不得 commit、push 或创建草稿 PR。下一步由用户完成`gh auth login`；认证成功后重新执行暂存范围、diff、秘密/PII 和远端身份检查，再显式提交上述允许文件并普通 push。

## 安全声明

本轮未实施数据库迁移、OCR、题库导入、排版、索引、备份切换或客户导出；未修改 Test 外业务文件；未把本机参考映射、原卷或派生资产加入 Git。
