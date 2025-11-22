# Buffer 内存清理工具

Buffer是一个基于Qt6开发的C++桌面应用程序，主要功能是监控系统内存使用情况，并提供异常强劲的内存清理功能。

## 功能特点

- 实时监控CPU、内存、GPU使用情况
- 在系统托盘中运行，占用资源少
- 提供内存使用趋势图表
- 支持一键清理内存
- 显示占用内存最多的应用程序列表
- 根据内存使用率自动清理

## 技术栈

- **编程语言**: C++17
- **框架**: Qt6 (Core, Widgets, Charts, Concurrent)
- **构建系统**: CMake 3.21+
- **平台**: Windows 10+

## 编译方法

1. 确保已安装Qt6、CMake和Visual Studio
2. 确保OpenHardwareMonitor项目已编译生成OpenHardwareMonitorLib.dll
3. 在项目根目录执行：
   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build .
   ```
4. 运行生成的可执行文件

## 使用方法

运行Buffer.exe，应用程序将在系统托盘中运行。双击托盘图标可显示主窗口，右键托盘图标可访问菜单。

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
