# M0-S3-F 合成外源 Copy 与双账本验收

## 结论

- 切片结论：**ACCEPTED_PENDING_GIT_CHECKPOINT**
- S3-F 候选已通过当前 E 根的完整语义、安全和恢复回归，可进入显式暂存审计、commit 和普通 push。
- production writer 仍断开；SQLite 通用 Copy、真实资料、quarantine/restore 和 M0 总门均未开放。

## 本切片范围

S3-F 仅处理 safe launcher 当前 run 内、模拟 project 外的合成单文件，输入上限 64 MiB。成功对象固定为：

```text
Copy/source/<copy_id>/payload.bin
Copy/source/<copy_id>/provenance.json
```

RESTRICTED 使用独立目标分区及 HMAC-only locator；活动 SQLite、sidecar、journal、目录输入、ADS、硬链接和不稳定对象均拒绝。

主要实现：

- `app/safety/external_source.py`：单次、owner-thread-bound、同柄只读合成外源能力；
- `app/safety/copy_ledger.py`：独立 source/copy segment 链、epoch/run-scope、HMAC、typed terminal 和交叉祖先；
- `app/safety/copy_operation.py`：Copy PREPARED 到 terminal 状态机、publish 绑定、replay 和只追加恢复；
- production boundary、namespace policy、operation/audit ledger、handle writer、launcher 与静态审计的窄适配。

## 固定安全语义

1. 外源绝对路径、原始名称和 handle 不进入业务记录、receipt、异常或 repr。
2. source handle 在 Copy 生命周期内保持只读并拒绝 write/delete sharing，前后从同一 handle 重验身份、大小、摘要和默认 stream。
3. source/copy 两条账本从同一已激活 audit revision 以不同域派生独立 key；segment 不能跨 store、epoch、kind 或 domain 互换。
4. 目标 mutation 前必须持久`PREPARED`并预留 source/copy/publish operation 三方最坏容量。
5. 发布只复用 S3-E exact reservation、no-replace root rename 和独立 target 全树复核。
6. fresh reopen 使用真实 typed operation terminal 重建完整 Copy HMAC plan，精确核对 transaction、operation、context、manifest、target、classification、budget 和 audit ancestry。
7. 合法终态为`COMMITTED/ABORTED/IN_DOUBT/RECOVERED_COMMIT/RECOVERED_ABORT`；terminal replay 不再次 mutation。
8. 恢复只追加事实，不复制、rename、覆盖、删除或自动清理矛盾现场。

## 回归证据

最终运行：`RUN-20260724-M0-PORTABLE-FULL-037`

- JUnit：961 passed，0 failure、0 error、0 skipped；
- S3-F 直接模块：
  - `tests.test_copy_ledger`：70 passed；
  - `tests.test_copy_operation`：53 passed；
  - `tests.test_external_source`：40 passed；
  - `tests.test_policy_epoch_compatibility`：18 passed；
- 其余 writer、audit/operation ledger、boundary/policy、launcher 和静态门一并通过；
- 保护树前后均 126,030 项且 digest 相同；
- 活动数据库 SHA-256 前后相同；
- 运行树、immutable evidence、watcher、126,030-handle fence、进程树全部通过；
- 80 份登记合成来源的终态 identity/metadata/bytes/default-stream 与登记状态一致。

静态门：

- Scanner V16；
- 53 个生产源、464 个入口、19 个分片；
- `UNKNOWN=0`、未授权安全内核构造 0；
- tracked inventory 与实时生成结果相同；
- 464 项仍全部`UNMIGRATED_BLOCKED`；
- `production_writer_connected=false`、`m0_exit_allowed=false`。

## 边界与未完成项

- 该证据只覆盖受信任仓库测试源码，不是 hostile same-process Python 或 native-code 沙箱。
- 来源见证证明登记点与 session 终态相同，不声称监控整机或证明两点之间从未瞬时变化；Copy 生命周期不变性由同柄和分享模式另行保证。
- 历史 operation epoch 的全 DAG resolver 留给 S3-H。
- quarantine、保留式 restore、冲突恢复属于 S3-G。
- SQLite Backup API、活动数据库迁移属于 S4。
- 真实外部资料旅程必须等 S3-H 安全冻结与 M0 用户流程门。
- 当前电脑真实目录 symlink 权限门仍为 WinError 1314，不自动提权。

## Git 状态

本报告生成时 S3-F 仍是保留的脏工作区候选。下一动作必须：

1. 对精确 allowlist 做 diff、隐私、密钥、二进制和大文件审计；
2. 显式暂存，禁止`git add -A`；
3. 核对 staged blob 与 UTF8/LF inventory；
4. 创建 S3-F checkpoint commit；
5. 普通 push 并核对 origin/远端 PR head；
6. 完成后才进入 S3-G。

### 2026-07-24 新机 checkpoint 只读预审

- 候选共 73 项：60 个 tracked modified、13 个 untracked；本地 HEAD 与 origin 均为`6e225c8e4ba06332a197a1acdcbd1f86edce4d99`。
- 路径白名单检查通过：没有`Base/`、`Copy/`、`data/`、`tmp/`、`Task/local/`、`Task/state/`、`.venv/`、数据库、备份、输出、模型、字体或用户资产。
- tracked diff 为 60 个文件、11,530 行新增、2,111 行删除；没有文件删除、重命名或二进制 diff。
- 13 个 untracked 文件均为`.json`、`.md`或`.py`文本；全部候选均小于 1 MiB。
- 对 tracked 新增行和 untracked 全文共 30,849 行执行常见 GitHub/AWS token、私钥、Bearer token 和高风险 secret assignment 扫描，结果为 0。
- 绝对路径命中仅为当前 E 根的运行观察、ADR 历史示例和测试合成 D 路径；`app/`与`scripts/`不存在固定 D/E 生产根字面量。
- V16 manifest 的 53 个`UTF8_LF_V1`生产源码哈希与大小全部匹配，19 个 inventory 分片的序列化文件 SHA-256 全部匹配。
- 新电脑已安装 GitHub CLI 2.96.0，并以 Git Credential Manager OAuth 凭据的临时环境桥接通过账号/API 检查；现在进入实际 staging。

### 实际 staged 审计

- 使用 73 个逐项解析且通过 allowlist 的显式路径执行`git add -- <paths>`，未使用`git add -A`。
- staged 结果为 73 个文件、30,871 行新增、2,111 行删除；工作区未暂存项 0、未跟踪项 0。
- `git diff --cached --check`通过；越界路径、二进制、删除、重命名、超过 1 MiB 文件均为 0。
- 扫描 staged 新增内容 30,864 行，常见 token、私钥、Bearer token 和高风险 secret assignment 命中 0。
- staged `.exam-bank-root.json`SHA-256 为`5a8010438f974544be816df10eac8adbd13b172373fa8f680a31932a5745c405`。
- staged V16 的 53 个生产源码哈希/大小与 19 个 inventory 分片文件哈希全部匹配；inventory payload 仍为`e31de8130346d87eb1b92109f88580cbb5ea33502d0b316a48a27fe7c172659c`。
