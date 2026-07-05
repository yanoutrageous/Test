# 阶段 0 环境检查报告

检查时间：2026-07-04 20:30:54 +08:00  
工作目录：`D:\Test`

## 结论

本机可以支撑当前个人本地 MVP 的阶段 0 开发准备：

- Python 可运行，项目内 `.venv` 已创建。
- `Flask`、`PyMuPDF`、`pytest` 已安装到 `.venv`，并可导入或运行。
- Python 内置 `sqlite3` 可用，SQLite 版本为 `3.50.4`，FTS5 与 JSON 函数测试通过。
- SQLite CLI `sqlite3` 未在 PATH 中找到；这不阻塞 Python 侧 SQLite 开发，但若后续希望直接用命令行操作数据库，需要单独补装 SQLite CLI 或继续使用 Python 脚本。
- 本阶段未安装 OCR、AI、向量检索、Electron，也未开发 Web 页面、PDF 导入或数据库业务模型。

## 系统与工具链

| 项目 | 检查结果 |
|---|---|
| OS | Microsoft Windows 11 家庭版 中文版 `10.0.26200`，Build `26200`，64 位 |
| PowerShell | `5.1.26100.8655`，Desktop |
| Python | `Python 3.14.0`，路径 `C:\Python314\python.exe` |
| pip | `pip 25.2`，系统路径 `C:\Python314\Lib\site-packages\pip` |
| Git | `git version 2.49.0.windows.1`，路径 `D:\Git\cmd\git.exe` |
| Git 仓库状态 | `D:\Test` 当前不是 Git 仓库 |
| SQLite CLI | 未找到，`sqlite3 --version` 返回 CommandNotFoundException |
| Python sqlite3 | SQLite `3.50.4` |
| 磁盘 C | 可用 `11.7 GB`，已用 `183.61 GB` |
| 磁盘 D | 可用 `104.9 GB`，已用 `175.35 GB` |

## 虚拟环境与依赖

项目内虚拟环境：`D:\Test\.venv`

| 项目 | 结果 |
|---|---|
| `.venv` Python | `Python 3.14.0` |
| `.venv` pip | `pip 25.2` |
| Flask | `3.1.3` |
| PyMuPDF | `1.28.0` |
| pytest | `9.1.1` |

安装命令：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install Flask PyMuPDF pytest
```

安装结果：成功。pip 提示存在新版 `26.1.2`，本阶段未升级 pip，因为当前 `25.2` 已满足依赖安装和验证。

## SQLite 能力验证

使用系统 Python 与 `.venv` Python 均验证了 SQLite 能力；关键结果如下：

| 检查项 | 结果 |
|---|---|
| `sqlite3.sqlite_version` | `3.50.4` |
| FTS5 建表 | 通过：`CREATE VIRTUAL TABLE fts_test USING fts5(content)` |
| FTS5 查询 | 通过：`MATCH 'alpha'` 返回 `1` |
| JSON 函数 | 通过：`json_extract('{"a":1}', '$.a')` 返回 `1` |
| SQLite 文件创建/打开 | 通过：临时 `.sqlite3` 文件可建表、插入、查询，验证后已删除 |

## 依赖导入验证

验证命令：

```powershell
@'
import flask
import fitz
import sqlite3

print('flask=' + flask.__version__)
print('pymupdf=' + fitz.__doc__.splitlines()[0])
print('sqlite3_module=ok')
print('sqlite=' + sqlite3.sqlite_version)
'@ | .\.venv\Scripts\python.exe -
```

结果：

```text
flask=3.1.3
pymupdf=PyMuPDF 1.28.0: Python bindings for the MuPDF 1.29.0 library.
sqlite3_module=ok
sqlite=3.50.4
```

备注：Flask 对 `flask.__version__` 输出了弃用警告，建议后续代码用 `importlib.metadata.version("flask")` 获取版本；这不影响导入验证。

`pytest` 验证：

```powershell
.\.venv\Scripts\python.exe -m pytest --version
```

结果：

```text
pytest 9.1.1
```

## 已运行命令摘要

```powershell
Get-Content -LiteralPath 'D:\Test\AGENTS.md' -Encoding UTF8
Get-Content -LiteralPath 'D:\Test\Base\Base.md' -Encoding UTF8
rg --files
Get-ChildItem -Force -LiteralPath 'D:\Test'
Test-Path -LiteralPath 'D:\Test\.venv'
Test-Path -LiteralPath 'D:\Test\docs\environment.md'
Get-CimInstance Win32_OperatingSystem
$PSVersionTable.PSVersion.ToString()
python --version
pip --version
git --version
sqlite3 --version
Get-PSDrive -PSProvider FileSystem
python -m venv .venv
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip --version
.\.venv\Scripts\python.exe -m pip install Flask PyMuPDF pytest
.\.venv\Scripts\python.exe -m pytest --version
.\.venv\Scripts\python.exe -m pip list --format=freeze
git rev-parse --is-inside-work-tree
```

另运行了 Python 脚本片段验证：

- `import flask`
- `import fitz`
- `import sqlite3`
- SQLite FTS5
- SQLite JSON
- SQLite 临时文件建表、插入、查询、删除

## 未通过项

- `sqlite3 --version` 未通过：系统 PATH 中没有 SQLite CLI。
- `D:\Test` 不是 Git 仓库：Git 命令本身可用，但当前目录未初始化仓库。

## 未验证项

- 未验证 Flask 服务启动，因为阶段 0 不开发 Web 页面或应用入口。
- 未验证 PyMuPDF 打开真实 PDF，因为阶段 0 不做 PDF 导入。
- 未验证 OCR、AI、向量检索、Electron，均不属于当前切片范围。

## 下一步建议

阶段 1 可以在不引入业务功能的前提下建立项目骨架：`app/`、`data/`、`tests/`、依赖说明和一个最小 Flask 健康检查入口。SQLite CLI 可暂不安装；如果阶段 2 需要频繁手动检查数据库，再补装轻量 SQLite CLI。
