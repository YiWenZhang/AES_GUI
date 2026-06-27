# AES 加密 GUI 工具

基于 PySide6 和 C++ AES 动态链接库的桌面加密工具，支持软件注册、用户登录、文本加解密、文件加解密、完整性校验和操作审计。

## 功能特性

- **软件注册授权**：根据本机硬件信息生成注册码，并将授权信息写入 Windows 注册表。
- **用户注册与登录**：用户密码通过 AES 动态链接库加密后保存到注册表。
- **文本加解密**：支持手动输入文本，也支持导入 TXT / Word 文档内容进行加解密。
- **文件加解密**：支持任意文件加密为 `.enc` 文件，并可解密还原。
- **文件拖拽**：文件加解密页面支持直接拖入文件，自动生成输出路径。
- **密码强度检测**：注册用户时实时显示密码强度和安全建议。
- **SHA-256 完整性校验**：支持计算源文件和输出文件摘要，用于验证文件是否一致或被篡改。
- **操作审计日志**：记录注册、登录、文本/文件加解密、摘要校验等操作，不记录密码、密钥和明文内容。
- **验收报告导出**：可一键导出 HTML 格式的验收测试报告。

## 项目结构

```text
AES_GUI/
├── AES_DLL.dll              # C++ AES-256-CBC 动态链接库
├── main.py                  # 程序入口
├── src/
│   ├── aes_adapter.py       # ctypes DLL 适配层
│   ├── auth_manager.py      # 软件注册与用户认证
│   ├── text_cipher.py       # 文本加解密业务逻辑
│   ├── file_cipher.py       # 文件加解密业务逻辑
│   ├── password_strength.py # 密码强度检测
│   ├── integrity.py         # SHA-256 完整性校验
│   ├── audit_log.py         # 操作审计日志
│   ├── report_exporter.py   # 验收报告导出
│   ├── app_paths.py         # 日志/报告路径配置
│   ├── main_window.py       # 主窗口与导航
│   ├── ui_register.py       # 软件注册页面
│   ├── ui_login.py          # 用户登录/注册页面
│   ├── ui_text.py           # 文本加解密页面
│   ├── ui_file.py           # 文件加解密页面
│   └── ui_audit.py          # 审计与报告页面
├── test_aes.py              # DLL 基础功能测试
├── test_aesdll.py           # aesdll 包接口测试
├── verify_online.py         # 在线 AES 验证辅助脚本
└── compare_online.py        # 在线对比辅助脚本
```

## 运行环境

- Windows 10 / 11 x64
- Python 3.12+
- PySide6
- python-docx（用于 Word 文档导入）

## 安装依赖

建议使用虚拟环境：

```bash
cd AES_GUI
python -m venv .venv
.venv\Scripts\activate
pip install PySide6 python-docx
```

如果需要打包为 exe：

```bash
pip install pyinstaller
```

## 运行程序

```bash
cd AES_GUI
.venv\Scripts\python.exe main.py
```

如果需要写入 `HKEY_LOCAL_MACHINE\SOFTWARE\AES_Tool`，请以管理员权限运行终端或导出的 exe。

## 注册表存储

程序使用以下注册表路径保存软件注册和用户密文密码：

```text
HKEY_LOCAL_MACHINE\SOFTWARE\AES_Tool
```

其中：

- `RegistrationCode`：软件注册码
- `User_<用户名>`：用户密码经 AES 加密后的十六进制密文

## 打包导出

在仓库根目录执行：

```bash
AES_GUI\.venv\Scripts\python.exe -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --windowed ^
  --name AES加密工具 ^
  --distpath export ^
  --workpath build ^
  --specpath . ^
  --add-binary "AES_GUI\AES_DLL.dll;." ^
  AES_GUI\main.py
```

导出结果位于：

```text
export\AES加密工具\AES加密工具.exe
```

请保留整个 `export\AES加密工具` 文件夹，不要只复制 exe。

## 测试

运行 DLL 基础测试：

```bash
cd AES_GUI
.venv\Scripts\python.exe test_aes.py
```

运行包接口测试：

```bash
cd AES_GUI
.venv\Scripts\python.exe test_aesdll.py
```

运行在线验证辅助脚本：

```bash
cd AES_GUI
.venv\Scripts\python.exe verify_online.py
```

## 注意事项

- 日志文件默认生成在 `AES_GUI/logs/` 或导出 exe 同级目录的 `logs/` 中。
- 验收报告默认生成在 `reports/` 目录中。
- 审计日志不会保存用户密码、AES 密钥和文本明文。
- 写入 HKLM 注册表需要管理员权限。
