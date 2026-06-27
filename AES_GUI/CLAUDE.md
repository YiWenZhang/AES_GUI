# AES 加密 GUI 工具

加密动态链接库设计及应用实训项目 (Week 3) — PySide6 桌面应用。

## 启动方式

```bash
# 1. 激活虚拟环境
cd D:/Desktop/AES/AES_GUI/AES_GUI
.venv/Scripts/activate

# 2. 运行主程序
python main.py
```

## 调试方式

```bash
# 使用 Python 直接运行
cd D:/Desktop/AES/AES_GUI/AES_GUI
.venv/Scripts/python.exe main.py

# 如需查看 ctypes DLL 调用详情
.venv/Scripts/python.exe -X dev main.py
```

## 目录结构

- `main.py` — 入口
- `AES_DLL.dll` — C++ AES-256-CBC 加密动态链接库
- `src/main_window.py` — 主窗口 (QMainWindow)
- `src/aes_adapter.py` — ctypes DLL 适配器
- `src/auth_manager.py` — 注册表存储/软件注册/用户认证
- `src/ui_register.py` — 软件注册 Tab
- `src/ui_login.py` — 用户登录 Tab
- `src/ui_text.py` — 文本加解密 Tab
- `src/ui_file.py` — 文件加解密 Tab
- `src/text_cipher.py` — 文本加解密逻辑
- `src/file_cipher.py` — 文件加解密逻辑
- `test_aes.py` — DLL 正确性测试
- `test_aesdll.py` — aesdll 包功能测试
- `compare_online.py` — 在线对比脚本
- `verify_online.py` — 在线验证脚本
