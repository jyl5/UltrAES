UltrAES - C++原生高性能文件加密工具
![C++ 17](https://img.shields.io/badge/C++-17-blue.svg)
![MIT License](https://img.shields.io/badge/license-MIT-green.svg)
![Windows Platform](https://img.shields.io/badge/platform-Windows-lightblue.svg)
![Visual Studio 2022](https://img.shields.io/badge/Visual%20Studio-2022-purple.svg)

🚀 项目概述
UltrAES 是一个完全使用 C++ 原生开发的高性能文件加密工具，基于工业级 AES-256 加密算法实现。无需任何外部依赖，提供卓越的加密性能和最小的内存占用。

✨ 核心特性
🔐 安全加密引擎
纯原生 AES-256 实现：手工优化的 C++ AES 实现，无第三方库依赖

硬件加速优化：利用 AES-NI 指令集（如可用）提升性能

内存安全：使用安全内存管理，防止敏感数据泄露

⚡ 极致性能
零拷贝技术：直接内存映射文件操作，减少内存开销

并行处理：多线程加密大文件，充分利用多核 CPU

SIMD 优化：使用 SSE/AVX 指令集加速哈希计算

实时进度反馈：显示加密进度和性能统计

📊 完整性验证
原生哈希算法：

CRC32 - 快速完整性检查

MD5 - 标准文件校验

SHA-1/256/512 - 安全哈希实现

并行哈希计算：多线程同时计算多种哈希值

🛠️ 开发特性
纯 Win32 API：无 MFC、无 .NET 依赖

现代 C++14：使用现代 C++ 特性编写

Unicode 支持：完全 Unicode 兼容

最小依赖：仅需 Windows SDK

📦 构建与部署
系统要求
操作系统：Windows 7/8/8.1/10/11 (64位)

开发环境：Visual Studio 2022 (v143 工具集)

C++标准：C++14 或更高

内存需求：4GB RAM（建议）

构建步骤
方法一：使用 Visual Studio 2022
克隆仓库或下载源代码

打开 UltrAES.sln 解决方案文件

选择构建配置（Debug/Release）

构建解决方案（F7）

在项目目录找到生成的可执行文件

方法二：命令行构建
powershell
# 使用 MSBuild
msbuild UltrAES.sln /p:Configuration=Release /p:Platform=x64
🖥️ 使用指南
图形界面操作
启动程序：双击 UltrAES.exe

选择文件：点击"浏览"或拖放文件到窗口

配置加密：

填写输入/输出文件

选择加密模式（密码/密钥文件）

开始处理：点击"加密"或"解密"按钮

批量处理脚本
示例脚本：下载链接

命令行界面（CLI）
powershell
# 基本语法
UltrAES.exe [命令] [参数]

# 批量处理
UltrAES.exe batch -s "script.txt"
配置文件
程序自动生成 UltrAES.ini 保存用户设置：

ini
[startup]
UsePwd = true
WindowOnTop = true
🏗️ 项目架构
技术栈
核心语言：ISO C++14

UI框架：纯 Win32 API + 自定义控件

编译系统：MSBuild (Visual Studio)

调试工具：Visual Studio Debugger, WinDbg

性能分析：VTune, Windows Performance Toolkit

算法实现特点
AES 核心：
查表法优化的 SubBytes/ShiftRows

有限域乘法优化 MixColumns

预计算的轮密钥

性能优化：
循环展开和指令重排

内存对齐访问（alignas）

缓存友好的数据结构

安全特性：
敏感数据零初始化

防止时序攻击的比较函数

堆栈保护 /GS 编译选项

📈 性能基准
操作	文件大小	单线程	4线程	加速比
AES-256 加密	1GB	45s	12s	3.75x
SHA-256 计算	1GB	8s	3s	2.67x
批量加密（10×100MB）	1GB	52s	15s	3.47x
*测试环境：Intel i7-12700K, 32GB DDR4, NVMe SSD*

📋 版本历史
版本 V1.1.0 (Build 162) - 当前版本
✨ 新增脚本执行引擎：支持复杂的批量处理脚本

✨ 拖放文件支持：增强用户体验和生产力

✨ 智能路径填充：自动生成输出文件名和路径

✨ 配置持久化系统：自动保存和恢复用户设置

⚡ 性能优化：改进多线程同步，减少锁竞争

🛡️ 改进安全内存清理机制

🔧 开发指南
代码规范
遵循 Google C++ 风格指南

使用 Doxygen 格式注释

所有公共 API 必须有单元测试

关键路径代码必须有性能测试

构建自定义版本
powershell
# 1. 克隆仓库
git clone https://github.com/jyl5/UltrAES.git

# 2. 配置构建选项
#   设置优化级别、启用指令集扩展等

# 3. 自定义编译
msbuild UltrAES.sln /p:Configuration=Release /p:Platform=x64 /p:UseAESNI=true

# 4. 运行测试
.\x64\Release\UltrAES.exe
📚 文档资源
API 参考 - 详细类和方法说明

算法白皮书 - AES 实现细节和优化技巧

性能指南 - 调优和基准测试指南

安全审计 - 安全实现细节和审计结果

🤝 贡献指南
欢迎提交 Pull Request！开发前请阅读：

贡献指南

编码规范

测试要求

主要开发方向：

算法优化（ARM NEON 支持）

新加密模式（XTS、OCB）

用户界面改进

🐛 问题与支持
已知问题
Windows 7 需要安装特定更新才能使用 AES-NI

32位版本有内存限制（最大 2GB 文件）

某些防病毒软件可能误报（已签名版本无此问题）

获取帮助
GitHub Issues

电子邮件：support@ultraes.example.com

文档：查阅 docs/ 目录和代码注释

⚠️ 重要声明
安全提醒
永远备份原始文件：加密前务必备份重要数据

强密码策略：使用至少 12 位混合字符密码

定期更换密钥：长期使用建议定期更换加密密钥

物理安全：密钥文件与加密数据分开存储

免责声明
本软件按"原样"提供，不提供任何明示或暗示的担保。用户应自行承担使用风险，开发者不对数据丢失或安全漏洞负责。

许可协议
UltrAES 采用 MIT 许可证发行，允许自由使用、修改和分发，详见 LICENSE 文件。

🙏 致谢
特别感谢以下项目和资源：

Intel AES-NI 白皮书 - 硬件加速参考

NIST FIPS 197 - AES 标准规范

Windows SDK 团队 - 开发工具支持

所有测试者和贡献者 - 质量改进反馈

高性能 · 零依赖 · 专业级安全

最后编译：Build 162 (Visual Studio 2022)
发布日期：2026年1月
