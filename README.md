

# 📱 SafeVault Android (Flet 版)

> 一个基于 Python + Flet 构建的现代化、零依赖、高安全性的本地安卓密码管理器。

[](https://www.google.com/search?q=https://github.com/USERNAME/REPO_NAME/actions/workflows/build_apk.yml)
**SafeVault Android** 是桌面版安全密码管理器的移动端移植版本。它利用 Flet 框架将 Python 代码转化为原生的安卓应用体验，旨在为用户提供一个完全离线、数据自我掌控的密码存储方案。

## ✨ 核心特性

* **🔐 零信任安全架构**：
* **主密码保护**：使用 `PBKDF2-HMAC-SHA256` 进行 10 万次迭代哈希，绝不存储明文主密码。
* **本地强加密**：所有敏感数据在写入手机存储前，均使用基于会话密钥派生的自定义流加密算法进行加密。
* **完全离线**：应用无需联网权限，数据只存在于你的手机本地。


* **📱 移动端原生体验**：
* 采用 Material Design 设计风格。
* 底部/顶部标签页导航（"录入" 与 "密码库"）。
* 适配手机竖屏操作，支持触摸交互。
* 支持自定义应用图标。


* **⚡ 便捷功能**：
* **一键生成**：内置高强度随机密码生成器。
* **快速复制**：在列表页点击按钮即可复制账号或密码到剪贴板。
* **即时搜索**：支持按备注或用户名快速过滤记录。
* **SnackBar 反馈**：操作成功或失败时提供友好的底部弹窗提示。



## 📸 应用截图



## 🛠️ 技术栈

* **核心语言**：Python 3.x
* **UI 框架**：[Flet](https://flet.dev/) (基于 Flutter)
* **加密库**：Python 标准库 (`hashlib`, `base64`, `os`, `json`)
* **打包工具**：Flet CLI & Flutter SDK
* **CI/CD**：GitHub Actions (用于云端自动化构建 APK)

## 📂 项目结构

```text
SafeVault-Android/
├── .github/workflows/
│   └── build_apk.yml    # GitHub Actions 云端打包脚本
├── assets/
│   └── icon.png         # 应用图标 (必须放在这里!)
├── main.py              # 核心源代码 (逻辑层 + Flet UI层)
├── requirements.txt     # Python 依赖项 (flet)
└── README.md            # 项目说明文档

```

## 🚀 如何构建 APK (云端打包)

本项目设计为使用 **GitHub Actions** 进行自动化云端打包，你无需在本地配置复杂的 Java/Android SDK 环境。

### 前提条件

确保你的 GitHub 仓库包含以下文件，并且路径正确：

1. `main.py` (程序入口)
2. `requirements.txt` (包含 `flet`)
3. `assets/icon.png` (你的应用图标，建议 192x192 PNG)
4. `.github/workflows/build_apk.yml` (打包工作流脚本)

### 构建步骤

1. **推送代码**：将任何修改提交并推送到 GitHub 仓库的 `main` 分支。
2. **触发构建**：推送操作会自动触发 GitHub Actions 开始构建流程。你可以点击仓库顶部的 **Actions** 标签页查看进度。
* *注意：首次构建可能需要 10-15 分钟来下载依赖环境。*


3. **下载 APK**：
* 当构建任务显示绿色的 ✅ 时，点击进入该任务详情。
* 向下滚动到 **Artifacts** 区域。
* 点击下载 `SafeVault-Release` 压缩包。


4. **安装**：解压下载的文件，将 `app-release.apk` 发送到安卓手机进行安装即可。

## 💻 本地开发与调试

如果你想在电脑上快速预览界面效果（模拟器模式）：

1. 安装 Python 3.x。
2. 安装依赖：
```bash
pip install flet

```


3. 运行应用：
```bash
flet run main.py

```


*(这将启动一个模拟手机窗口，供你调试 UI 和逻辑。)*

## ⚠️ 重要安全提示

* **主密码是唯一的钥匙**：由于采用了强加密技术，**一旦丢失主密码，你将永远无法解密你的数据**。没有后门，也没有找回机制。请务必牢记！
* **数据备份**：建议定期导出或备份手机应用目录下的 `data.json` 文件（如果你的手机允许访问该目录），以防手机丢失或损坏。

## 📄 许可证

MIT License
