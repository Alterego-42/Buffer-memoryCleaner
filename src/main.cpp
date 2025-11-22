#include <QApplication>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include "MainWindow.hpp"
#include <iostream>
#include <Windows.h>
#include <shellapi.h>

// 检查是否以管理员权限运行
bool IsRunAsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;

    // 创建管理员组的SID
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &pAdministratorsGroup)) {
        // 检查当前进程的令牌中是否包含管理员组SID
        if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
            fIsRunAsAdmin = FALSE;
        }
        FreeSid(pAdministratorsGroup);
    }

    return fIsRunAsAdmin == TRUE;
}

// 重新以管理员权限运行程序
bool RelaunchAsAdmin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        // 使用ShellExecute以管理员权限重新启动程序
        HINSTANCE hResult = ShellExecuteW(NULL, L"runas", szPath, NULL, NULL, SW_SHOWNORMAL);
        return (int)hResult > 32;  // 成功时返回值大于32
    }
    return false;
}

int main(int argc, char *argv[]) {
    // 检查是否以管理员权限运行
    if (!IsRunAsAdmin()) {
        // 如果没有以管理员权限运行，询问用户是否需要提权
        int response = QMessageBox::question(nullptr, "权限不足",
                                             "内存清理功能需要管理员权限才能发挥最佳效果。\n"
                                             "是否以管理员权限重新运行程序？",
                                             QMessageBox::Yes | QMessageBox::No);
        if (response == QMessageBox::Yes) {
            if (RelaunchAsAdmin()) {
                return 0;  // 退出当前进程，启动新的管理员进程
            } else {
                QMessageBox::warning(nullptr, "提权失败", "无法以管理员权限启动程序。某些功能可能受限。");
            }
        } else {
            // 用户选择了"No"，显示信息并继续运行
            QMessageBox::information(nullptr, "权限警告", "程序将以普通权限运行，内存清理效果可能有限。");
            // 继续执行，不退出程序
        }
    } else {
        // 如果已经以管理员权限运行，显示确认信息
        std::cout << "程序以管理员权限运行" << std::endl;
    }

    // 设置控制台编码为UTF-8
    SetConsoleOutputCP(65001);

    QApplication app(argc, argv);

    app.setApplicationName("Buffer Memory Cleaner");
    app.setApplicationVersion("1.0");
    // 重要：设置为关闭最后一个窗口时不退出程序
    app.setQuitOnLastWindowClosed(false);

    std::cout << "应用程序初始化开始..." << std::endl;

    // 检查系统托盘是否可用
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        // 如果系统托盘不可用，仍然继续运行程序，不询问用户
        std::cout << "系统托盘不可用，程序将在无托盘模式下运行..." << std::endl;
        // 注意：即使托盘不可用，程序也应该继续运行
    } else {
        std::cout << "系统托盘可用" << std::endl;
    }

    std::cout << "创建主窗口..." << std::endl;

    try {
        MainWindow window;
        std::cout << "主窗口创建成功" << std::endl;

        // 显示主窗口并确保它保持在前台
        window.show();
        window.raise();
        window.activateWindow();
        std::cout << "主窗口已显示，进入事件循环..." << std::endl;

        // 进入Qt事件循环
        return app.exec();
    }
    catch (const std::exception& e) {
        std::cout << "程序启动异常: " << e.what() << std::endl;
        QMessageBox::critical(nullptr, "启动错误",
                              QString("程序启动失败: %1").arg(e.what()));
        return 1;
    }
}