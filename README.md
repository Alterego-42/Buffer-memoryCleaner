# Buffer 内存清理工具

Buffer是一个基于Qt6开发的C++桌面应用程序，主要功能监控系统内存使用情况，并提供强劲的内存清理功能。

## 功能特点

- 实时监控CPU、内存、GPU使用情况
- 在系统托盘中运行，占用资源少
- 提供内存使用趋势图表
- 支持一键清理内存
- 显示占用内存最多的应用程序列表
- 根据内存使用率自动清理
- 集成了windows清理内存的主要方法，不使用内存压缩方案

## 技术栈

- **编程语言**: C++17
- **框架**: Qt6 (Core, Widgets, Charts, Concurrent)
- **构建系统**: CMake 3.21+
- **平台**: Windows 10+

## 编译方法

1. 确保已安装Qt6、CMake
2. 在项目根目录执行：
   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build .
   ```
3. windeployqt生成的可执行文件

## 使用方法

运行Buffer.exe，应用程序将在系统托盘中运行。双击托盘图标可显示主窗口，右键托盘图标可访问菜单。

## 效果参考图
![运行前截图](https://cdn.jsdelivr.net/gh/Alterego-42/image-hosting@main/Buffer/Pre.png)
_运行前_

![运行后截图](https://cdn.jsdelivr.net/gh/Alterego-42/image-hosting@main/Buffer/Later.png)
_运行后_

## 关于Qt

确保导入了如下文件或目录
- Qt6Cored.dll
- Qt6Widgetsd.dll
- Qt6Guid.dll
- Qt6Chartsd.dll
- Qt6OpenGLd.dll
- Qt6OpenGLWidgetsd.dll
- styles/
- platforms/
- generic/
