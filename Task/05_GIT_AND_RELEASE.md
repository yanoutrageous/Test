# Git、阶段 Push 与发布规范

## 1. 授权仓库

唯一授权远端：

```text
https://github.com/yanoutrageous/Test.git
```

执行 push 前必须同时核对：

- `git remote get-url origin`；
- `gh repo view`返回的仓库身份；
- 当前分支和预期 base；
- `gh auth status`成功；
- staged 内容仅属于当前切片。

任一项不符即停止，不向替代仓库推送，不写入或猜测凭据。

## 2. 分支策略

### 规划阶段

本规范包使用：

```text
agent/long-run-execution-spec
```

### M0—M5 长期实现

为减少长任务等待合并和堆叠分支风险，使用一个长期集成分支：

```text
agent/m0-m5-local-v1
```

该分支从已确认包含本规划包的 base commit 建立。首次 push 后创建一个 Draft PR，M0—M5 持续更新该 PR；每个里程碑通过时建立不可移动的 annotated checkpoint tag。

禁止：

- 直接 commit/push`main`；
- 自动 merge PR；
- `git pull`隐式合并；
- force push或改写已推送历史；
- 删除远端分支/标签；
- 自动 rebase 已推送提交；
- 自动 stash、reset、checkout 覆盖用户工作区；
- 通过 Git 命令清理未跟踪文件。

## 3. 启动和恢复

1. 记录本地 HEAD、`origin/main`、当前分支和工作区；
2. 只执行`git fetch origin`获取事实，不隐式合并；
3. 检查不存在 merge/rebase/cherry-pick 中间状态；
4. 检查用户修改是否与当前切片重叠；
5. 明确记录本次 base SHA；
6. 若远端集成分支存在，只有本地可证明为同一运行且可快进时恢复；
7. 远端分叉时停止，禁止自动 force/rebase/覆盖。

## 4. 提交与 push 节奏

- 每个通过切片验证的独立改动形成一个小提交；
- 失败、半迁移、活动状态损坏或无法恢复的状态不得标记完成；
- 每个已验证切片普通 push 一次，作为远端恢复点；
- 每个 M0—M5 通过全部门禁后：
  1. 生成阶段报告、脱敏 manifest 和安全证明；
  2. 创建里程碑检查点；
  3. 提交报告；
  4. 普通 push；
  5. 创建 annotated checkpoint tag；
  6. 普通推送该标签；
  7. 更新 Draft PR 的验收矩阵。

标签示例：

```text
checkpoint/m0-20260711-<short_sha>
```

标签不得复用或移动。阶段未通过时可以推送明确的检查点提交，但不得创建`accepted`标签或在报告中宣称完成。

提交信息示例：

```text
plan: define long-run execution contract
m0(safety): enforce workspace write boundary
m1(render): add B5 reference profile
m2(export): generate five-document bundle
test(m3): verify diagram fallback user flow
docs(m4): record verified restore drill
release(m5): assemble customer candidate
```

## 5. 显式暂存

只允许：

```text
git add -- <逐项列出的路径>
```

禁止`git add .`和`git add -A`。

PRE_M0 规划提交的唯一允许范围是经审查的根`.gitignore`和`Task`可跟踪规范文件；`Task/local/**`、`Base/**`及其余本机资产必须保持忽略。即使文件已被`.gitignore`保护，仍不得用宽范围暂存代替显式清单。

每次 commit 前必须审查：

- staged 文件清单、类型和大小；
- staged diff；
- 文本秘密/PII 扫描；
- 二进制和大文件清单；
- Test 外绝对路径、本机用户名和私人文件名；
- 当前切片测试和用户流程状态；
- 未跟踪用户文件仍保持未暂存。

## 6. 永不进入 Git 的内容

- `Base/高考题原卷`等用户本地资产；
- `Copy/**`；
- 原始 PDF、DOC/DOCX、XLSX、图片和扫描件；
- 活动 SQLite、备份、恢复 staging 和导出成品；
- 模型权重、embedding、索引和缓存；
- 未确认许可的字体；
- 姓名、学号、手机号、QQ、IP、邮箱等 PII；
- API key、token、cookie、证书、`.env`和浏览器状态；
- 运行日志、临时文件和失败产物；
- 无法说明来源和分发权的二进制夹具。

Git 中的报告只保存脱敏统计、项目内逻辑路径、内容哈希和证据摘要。大体积证据保存在 Test 内 Git 忽略目录。

`Base/Base.md`等已经受控的文本也不能被批量暂存；只有当前切片明确需要且逐文件审查后才可修改。

## 7. GitHub CLI 与 Draft PR

长任务预检要求：

- `git`和`gh`可用；
- Git 身份已明确，不自动伪造或修改全局身份；
- `gh auth status`成功；
- `gh repo view yanoutrageous/Test`成功；
- origin 与授权仓库一致；
- 当前账号对目标分支有写权限。

失败时状态置为`WAITING_REMOTE`：

- 不绕过认证；
- 不写入 token；
- 不使用浏览器脚本或未知 REST 调用；
- 不更换远端；
- 已开始的本地工作只完成安全检查点，不跨入下一里程碑。

Draft PR 规则：

- base 默认`main`，head 为长期集成分支；
- M0—M4 始终保持 Draft；
- PR 描述持续更新变更、原因、测试、真实用户流程、风险和恢复；
- 只有 M5 全部门禁通过后才可标记 Ready for review；
- 合并和 GitHub Release 仍由用户决定；
- 不把原卷、客户数据或生成试卷作为 PR 附件上传。

## 8. 推送失败

- 网络瞬断：保留本地提交，有限重试；
- 认证失败：停止并请求用户完成认证；
- non-fast-forward：fetch 后停止，不自动 rebase/merge/force；
- 远端身份变化：停止并作为安全事件处理；
- secret/PII 扫描失败：取消 commit/push，保留现场并修复；
- 大文件或许可不明：不推送，改为本地 evidence manifest。

推送失败不得改变阶段测试结论，但未形成所需远端恢复点时不得进入下一里程碑。

## 9. 回滚

- 代码回滚：创建新的 revert/fix commit，不重写历史；
- 数据库回滚：从已验证快照恢复到 staging，验证后切换；
- 资产回滚：按 manifest 切换版本指针，失败版本进入隔离区；
- 模板/基线：回到上一批准 revision；
- 远端：普通推送 revert，不删除标签和分支；
- 发布：整体切换上一完整 release，不拼接不同版本。

若 PII、原件或密钥误推远端：立即停止后续 push、通知用户、轮换凭据（如适用），不得自动重写远端历史；由用户明确批准专门清理方案。

## 10. 发布候选

M5 发布候选先生成到：

```text
<PROJECT_ROOT>\output\releases\<version>.staging
```

在该 staging 中完成哈希、启动、离线用户旅程、视觉和恢复验证后，才发布为新的正式版本目录。正式版本不可原地覆盖。
