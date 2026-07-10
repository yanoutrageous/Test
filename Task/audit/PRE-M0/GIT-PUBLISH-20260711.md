# 高风险变更审计：PRE-M0-GIT-PUBLISH-20260711

## 1. 基本信息

- 阶段/切片：PRE-M0 / planning publication
- Run ID：`RUN-20260711-PRE-M0-001`
- Job ID：`PRE-M0-GIT-PUBLISH`
- 风险等级：D2
- 执行者：`/root`
- 独立审计：`/root/pre_m0_git_audit`（只读）
- 状态：APPROVED_TO_EXECUTE
- 时间：2026-07-11T03:02:53+08:00

## 2. 必要性与替代方案

- 被阻塞目标：按执行合同形成 PRE-M0 远端恢复点和草稿 PR，之后才能进入 M0。
- 不执行影响：规划仅存在本机，违反阶段 push 和远端恢复点要求。
- 更安全替代：只保留本地提交不能满足批准目标；手写 token、替代远端、强推或直接 main 均禁止。
- 决定：在独立范围审计通过后，对唯一授权远端执行普通分支 push，并用 GitHub 连接器创建 Draft PR。

## 3. 已确认 Git 事实

- origin：`https://github.com/yanoutrageous/Test.git`
- 仓库身份：`yanoutrageous/Test`
- 默认分支：`main`
- viewer permission：`ADMIN`
- 规划分支：`agent/long-run-execution-spec`
- HEAD / `origin/main` / 远端 main：`3df22b3ba36c65c7c00ac18e06f300948f2f6d7b`
- 远端规划分支、长期集成分支及对应 PR：均不存在
- merge/rebase/cherry-pick/bisect：均不存在
- 暂存区：空
- GitHub CLI：2.96.0，认证成功
- Git 作者：仓库本地`yanoutrageous <yanoutrageous@users.noreply.github.com>`；未改全局配置

## 4. 精确发布范围

允许提交：

- 根`.gitignore`；
- `Task`下全部可跟踪规范、模板和 PRE-M0 审计文件。

明确排除：

- `Task/local/**`、`Task/state/writer.lock`；
- `Base/**`、`Copy/**`；
- 数据库、备份、输出、证据大文件、模型、字体和缓存；
- 原卷、图片、Office/PDF 原件；
- PII、凭据、token、浏览器状态和其他用户资产。

只使用`git add -- <逐项文件>`；禁止`git add .`和`git add -A`。

## 5. 边界、资源和内容预检

- 项目根、祖先目录和候选 Task 路径均非 Reparse Point；
- D 盘可用空间约 554.8 GiB；
- 所有公开候选均为 UTF-8 文本，无 NUL、二进制或大文件；
- JSON、必需文档、状态枚举、Markdown 围栏和参考逻辑 ID 校验通过；
- 未发现 token、私钥、本机用户目录或私人参考文件名；
- `.gitignore`已验证保护 Base、Task/local、Copy、备份、输出、运行状态、模型和字体；
- 本机私人路径映射仍保留在忽略目录，未进入候选范围。

## 6. 检查点与回滚

- 前置代码检查点：`3df22b3ba36c65c7c00ac18e06f300948f2f6d7b`
- 内容检查点：PRE-M0 规划包自动验证和独立审计结果。
- commit 前失败：不 push，修正后重新完整扫描。
- push 被拒绝或 non-fast-forward：立即停止，不 rebase/force/覆盖。
- push 后发现规划缺陷：使用新的修正/revert commit；不删除分支或改写历史。
- PR 创建失败：保留已推分支，重新核对连接器/认证；不使用未知 API 或替代仓库。

## 7. 独立审计结论

独立只读审计确认认证、远端、分支、基线、中间状态、候选类型、忽略规则和私密扫描满足发布要求。审计指出并已处理：

1. 状态文件中的旧认证事实必须更新；
2. 公开提交不得使用个人 QQ 邮箱，已仅在本仓库改为 GitHub noreply 身份。

结论：完成更新后的重新扫描与 staged diff 审查后，允许普通 commit/push。

## 8. 实际执行

- staged 文件：PENDING
- commit：PENDING
- push：PENDING
- Draft PR：PENDING
- 实际范围是否符合 manifest：PENDING

## 9. 执行后验证

- [ ] staged 文件、类型、大小、diff 重新审查
- [ ] secret/PII/私人文件名扫描通过
- [ ] 普通 commit 成功
- [ ] 普通 push 成功且远端 SHA 一致
- [ ] Draft PR 指向`main`且保持 Draft
- [ ] Base、Task/local 和其他用户资产未进入 commit
- [ ] 发布事实写回 RUN_STATE 和本审计
