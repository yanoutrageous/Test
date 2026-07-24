# M0 门禁证据存储整理（2026-07-24）

## 结论

- 整理只涉及 Git 忽略的测试实验室、清单预览和工具缓存；没有触碰原始试卷、`Base/`、活动数据库、业务资产、凭据或用户资料。
- 156 个旧门禁运行已由四个无损测试归档完整覆盖；`tmp/test_lab`只保留最新全绿的`RUN-20260724-M0-S3H-S3-TOTAL-079`。
- 当前执行环境禁止递归删除。已归档旧运行因此被安全迁移到仓库外的本机可恢复暂存，而不是绕过限制删除；该暂存不是规范证据或迁移交付物。
- 跨盘迁移阶段 E 盘可用空间由 19,009,196,032 bytes 增至 21,416,464,384 bytes，净增加 2,407,268,352 bytes（约 2.24 GiB）。此前 NTFS 原位压缩阶段曾单独增加约 4.96 GiB；因卷上存在仓库外活动，两阶段数值不相加。
- 同一 S3-G 门禁的保护对象由 140,985 降至 8,394；S3-H 最终门在再次整理后只枚举 4,741 个保护对象。后续门禁不再重复枚举整段历史。
- 便携规则已固化到`Task/TEST_GATE_RETENTION.md`，不依赖当前盘符、用户名或电脑。

## 整理前空间事实

- `tmp/`：约 8.414 GiB 逻辑大小。
- `tmp/test_lab/`：约 8.404 GiB 逻辑大小，占当时仓库逻辑大小约 98%。
- 主要负担来自历史门禁证据，不是契约代码：`.venv/`约 0.096 GiB，`Base/`约 0.068 GiB，源码与测试约数 MiB。
- 旧快照未压缩时单轮常约 114 MiB；历史目录累计 136 个运行、47,206 个文件。

## 便携无损归档

归档由根`.gitignore`中的`tmp/`规则忽略，不进入 Git。

### 基础归档

```text
tmp/test_lab_archives/test-lab-history-through-RUN-20260724-M0-S3G-CORE-050.tar.gz
```

- 大小：579,609,191 bytes。
- SHA-256：`1ad25c3bed0f3595ea7938110a6f26ee6f81a7e360e44e330c2d7fc1352093c6`。
- 顶层运行：136。
- 文件：47,206。
- tar 成员：130,617。
- 绝对路径、盘符路径或`..`逃逸成员：0。
- `tar -tzf`完整清单校验退出码：0。

### S3-G 增量归档

```text
tmp/test_lab_archives/test-lab-increment-RUN-20260724-M0-S3G-CORE-051-through-GATE-058.tar.gz
```

- 大小：45,124,925 bytes。
- SHA-256：`8406233724602cb8a341aa6fe767e63f37d2a14785a46451dde448cbd4980485`。
- 顶层运行：5，精确覆盖 CORE-051/052/053、COMBINED-056 和 GATE-058。
- tar 成员：8,739。
- 绝对路径、盘符路径或`..`逃逸成员：0。
- `tar -tzf`完整清单校验退出码：0。

### S3-G 清理后至 S3-H POLICY-067

```text
tmp/test_lab_archives/test-lab-increment-RUN-20260724-M0-S3G-POSTCLEAN-059-through-S3H-POLICY-067.tar.gz
```

- 大小：8,005,286 bytes。
- SHA-256：`f226a3b9bcdbd0e84a4088db38b7533d627cee9c2444c3bb119e4dd1d98d3400`。
- 顶层运行：8，精确覆盖 POSTCLEAN-059、RESOLVER-061、CORE-062/063/064、STATIC-065、LAUNCHER-066 和 POLICY-067。
- tar 成员：6,471。
- 绝对路径、盘符路径或`..`逃逸成员：0。
- `tar -tzf`完整清单校验退出码：0。

### S3-H 最终收敛运行

```text
tmp/test_lab_archives/test-lab-RUN-20260724-M0-S3H-070-through-078.tar.gz
```

- 大小：14,103,077 bytes。
- SHA-256：`5bdc4786012e69488f5c40d279333bd464a905ee7e1ea9d80f470c6cbf02d30d`。
- 顶层运行：7，精确覆盖 INVENTORY-GATE-070/074/078、TOTAL-071/075、CORE-072 和 LAUNCHER-076。
- tar 成员：20,312，源集合复算成员数与归档完全相等。
- 绝对路径、盘符路径或`..`逃逸成员：0。
- `tar -tzf`完整清单校验退出码：0。

### Inventory preview 归档

```text
tmp/test_lab_archives/inventory-previews-RUN-20260724-M0-S3G-INVENTORY-057-and-S3H-INVENTORY-068.tar.gz
tmp/test_lab_archives/inventory-previews-RUN-20260724-M0-S3H-069-and-073.tar.gz
```

- 大小分别为 98,676 和 98,736 bytes。
- SHA-256 分别为`25c99dcb47eb6c89d0c121dcadc72ea8a651e0f0c318163a9446adb9fb7615bc`和`f99715af4e60b46a58b47964cac94fc0cc2dc9ee069382c8e7b55b40a0bf1e74`。
- 每包 2 个 preview、44 个成员；逃逸成员均为 0。
- 当前热目录只保留最终`RUN-20260724-M0-S3H-INVENTORY-077`。

相邻的本地`tmp/test_lab_archives/archive-manifest.json`记录两个归档的哈希、大小、成员数和热保留项。最终覆盖复核结果为：

- 测试归档覆盖运行：156。
- 仓库外可恢复暂存与本轮待迁出集合完全相等。
- 热目录运行：1（S3-TOTAL-079，尚未归档，留作当前最新证据）。
- 覆盖差异：0。

迁移时必须单独携带`tmp/test_lab_archives/`并复核哈希；Git clone 本身不包含这些二进制证据。

## 门禁存储修订

`scripts/run_safe_pytest.py`已把保护树前后快照从未压缩 JSON 改为确定性 gzip canonical JSON：

- 结果 schema：`1.2`。
- 格式标识：`gzip-canonical-json-v1`。
- gzip `mtime=0`，写入后立即解压回读并逐字节核对。
- `RUN-20260724-M0-S3G-LAUNCHER-046`通过 88/88 项；保护树 135,048 项前后一致，活动数据库哈希不变。
- `RUN-20260724-M0-S3G-GATE-058`的两份保护树快照各 4,660,418 bytes，完整运行树 10,617,771 bytes；清理后的 POSTCLEAN-059 完整运行树为 2,074,395 bytes。

本机还启用了`tmp/test_lab`的 NTFS 压缩继承。NTFS 压缩只是当前卷的物理优化；跨电脑仍以 gzip 格式和归档 SHA-256 为便携合同。

## 仓库整理结果

- 156 个归档覆盖的旧运行迁出后，`tmp/test_lab`只保留 S3-TOTAL-079，运行树约 104.2 MB。
- 当前 6 个便携`tar.gz`合计 647,039,891 bytes（约 617.1 MiB），是仓库内主要的可迁移测试证据。
- 此前 26 个旧 inventory preview 已迁出；本轮又归档并迁出 057/068/069/073，只保留最终`RUN-20260724-M0-S3H-INVENTORY-077`，约 0.52 MB。
- 仓库外的旧`__pycache__`、`.pytest_cache`、Git stage dry-run 和遗留 stdout/stderr 缓存已迁出；`.venv`保留，因为后续门禁仍需使用。
- 原始题卷和本机参考资料未移动、未压缩、未删除。
- S3-H 最终门完成后的 E 盘可用空间约 60.63 GiB；本轮没有用危险递归删除换取空间。

## 保留与迁移规则

1. 活动门禁运行期间禁止归档、压缩、移动或删除其运行目录。
2. 每个验收切片结束、累计 10 个运行、热目录达到 1 GiB 或磁盘低于门禁预算时整理。
3. 归档必须先校验源根、无 Reparse、无活动 launcher、完整成员清单、顶层运行集合、逃逸成员为 0 和 SHA-256。
4. 热目录保留最近一次已验收全绿运行；失败运行在原因、替代轮次和安全门状态进入报告与归档后迁出。
5. safe launcher 不自动清理历史，避免测试运行与证据维护并发。
6. 恢复归档只能解压到新的空目录，不得覆盖活动`tmp/test_lab`。
7. `.venv`、仓库外本机暂存和物理盘符不是迁移交付物；在新电脑按`requirements.txt`重建环境。

只读复核：

```powershell
Get-FileHash tmp/test_lab_archives/*.tar.gz -Algorithm SHA256
tar -tzf tmp/test_lab_archives/test-lab-history-through-RUN-20260724-M0-S3G-CORE-050.tar.gz
tar -tzf tmp/test_lab_archives/test-lab-increment-RUN-20260724-M0-S3G-CORE-051-through-GATE-058.tar.gz
tar -tzf tmp/test_lab_archives/test-lab-increment-RUN-20260724-M0-S3G-POSTCLEAN-059-through-S3H-POLICY-067.tar.gz
tar -tzf tmp/test_lab_archives/test-lab-RUN-20260724-M0-S3H-070-through-078.tar.gz
```

## 未改变的安全事实

- 活动 SQLite SHA-256 仍为`1505bf05bd8e385eada30642110596363c561c330da02a40a497072064ad1c94`。
- production writer 仍断开，没有执行真实业务 mutation。
- `RUN-20260724-M0-S3G-GATE-058`最终退出码 0：543 项测试、0 failure/error/skip；保护树前后 140,985 项与 digest 一致，活动数据库、运行时 watcher、句柄围栏、run tree、不可变证据、源码见证和进程树全部通过。
- `RUN-20260724-M0-S3G-POSTCLEAN-059`再次以 543/543 和最终退出码 0 通过；保护树前后 8,394 项一致，其他安全门同样全部通过。运行时间为 20:59:32—21:03:42，共 4 分 10 秒。
- 历史失败轮次 CORE-052 与 COMBINED-056 的功能失败和干净安全门均已保留在增量归档；它们不再代表当前功能状态。
- `RUN-20260724-M0-S3H-S3-TOTAL-079`最终退出码 0：997 项测试、0 failure/error/skip；保护树前后均 4,741 项，活动数据库、runtime watcher、句柄围栏、run tree、不可变证据、80 个源码见证和进程树全部通过。
- S3-H 失败轮次 TOTAL-071（旧静态样例未迁到 multi-epoch scope）与 TOTAL-075（Job Object 异步终止竞态）均已记录原因、保留干净安全门并由 079 替代。
