# M0 入场审计

## 1. 结论

- 入场结论：`PREFLIGHT_ACCEPTED`
- M0 门禁：`NOT_ACCEPTED`
- 当前可做：安全层、测试实验室、写入口收口、迁移/IR/金标的候选实现
- 当前禁止：活动数据库迁移、真实资料加工、批量导入、正式模板激活和 M1 功能开发

路径链、磁盘、Git、GitHub 和活动 SQLite 完整性均无入场硬阻塞。现有代码仍无法证明 Test 外写入为零，因此 M0 的第一条关键路径必须是统一 WorkspaceGuard，而不是导入、OCR 或排版。

## 2. 基线身份

- Run：`RUN-20260711-M0-001`
- 分支：`agent/m0-m5-local-v1`
- 规划基线：`bfd4d35973974a223f465cd08910f303518a8586`
- 事实 manifest：`Task/reports/M0/M0-entry-baseline.json`
- 规划 PR：`https://github.com/yanoutrageous/Test/pull/1`
- 活动数据库：只读检查，哈希和元数据未变化
- 参考资料：仅只读哈希/结构检查，未调用副作用工具

## 3. 已确认环境

- `D:\`、`REFERENCE_ROOT`、`PROJECT_ROOT`及 Test 树内未发现 Reparse Point；
- D 盘健康，可用约 554.82 GiB，足够 M0 当前小型候选和检查点；
- 项目虚拟环境为 Python 3.12.13，现有 Flask/PyMuPDF/pytest 可用；
- GitHub 已认证，规划分支和 Draft PR 已建立；
- TeX、OCR、语义模型等缺失不是 M0 入场阻塞，当前不安装。

## 4. 现有产品事实

历史实现是 Flask + SQLite + PyMuPDF 的平面单体，已有题目复核、FTS、组卷篮和 HTML 导出路径，但没有正式 PDF、蓝图、五类文档、图形双轨、模板/字体仪表盘或恢复 UI。

活动 SQLite：

- `integrity_check=ok`，外键违规为 0；
- `user_version=0`，没有可靠迁移锚点；
- 19 个业务表全部为 0 行；
- 历史文档中的“1123 题/阶段 14”只能作为旧资料，不能作为当前事实或验收证据。

## 5. 安全缺口

### P0

- `connect_database(db_path)`会为任意路径创建父目录和数据库；
- `get_project_paths(project_root)`和多个输出参数可指向任意根；
- 部分导出路径允许任意绝对路径；
- 没有 WorkspaceGuard、路径链 Reparse/ADS/TOCTOU 防护或统一写审计。

### P1

- 若干查询/GET 路径会隐式初始化 schema 或派生状态；
- 活动 SQLite 备份使用文件复制，不保证 WAL 一致性，也没有恢复产品流程；
- 无迁移账本、版本化领域对象、IR、Copy 台账、原子发布和 quarantine；
- 现有 88 个测试没有路径攻击、迁移恢复、真实浏览器、正式 PDF、视觉、断网或 fresh-user 客户旅程。

## 6. 基线测试

使用 Test 内安全实验室运行旧测试：

```text
88 passed in 15.15s
```

TEMP、TMP、pycache 和 pytest basetemp 均位于`Test/tmp/test_lab/RUN-20260711-M0-BASELINE`。模拟 protected 哨兵和活动数据库哈希前后不变。

该结果只证明旧功能没有在入场时退化，不能用于关闭任何 M0 安全风险。

## 7. M0 首批切片

1. `M0-S1`：实现纯 WorkspaceGuard 与 Test 内攻击实验室；
2. `M0-S2`：接入 database/config/codex/export/report/PDF/asset 等全部生产写入口，并分离真正只读连接；
3. `M0-S3`：实现 atomic writer、job staging、文件审计、Copy ledger、quarantine 和安全外部进程包装；
4. `M0-S4`：建立只追加迁移框架、SQLite Backup API 和旧库副本往返演练；
5. `M0-S5`：建立版本化领域对象、IR schema、金标 registry 和视觉阈值；
6. `M0-S6`：跑完整 M0 真实流程、独立安全审计、恢复演练和阶段门禁。

任何切片失败都保留活动库和原件不变。只有 S1 通过攻击矩阵后，才允许逐步接入真实写入口。

## 8. 下一步

按`ADR-2026-001`实现最小无副作用 WorkspaceGuard 核心和攻击测试；不安装新依赖，不操作活动数据库，不读取 Test 外业务资料正文。
