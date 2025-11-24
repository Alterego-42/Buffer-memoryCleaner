// src/MainWindow.cpp
#include "MainWindow.hpp"
#include "SystemInfo.hpp"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QMessageBox>
#include <QDateTime>
#include <QLabel>
#include <QPalette>
#include <QTimer>
#include <QtConcurrent/QtConcurrent>
#include <iostream>
#include <Windows.h>

// 常量定义
const int WINDOW_WIDTH = 1200;
const int WINDOW_HEIGHT = 700;
const int APP_LIST_SIZE = 10;
const int CHART_MIN_HEIGHT = 300;
const int APP_LIST_MIN_WIDTH = 350;
const int UPDATE_INTERVAL_MS = 1000;  // 主要信息更新间隔
const int APP_UPDATE_INTERVAL_MS = 3000;  // 应用列表更新间隔
const int CHART_TIME_SPAN = 60;  // 图表时间跨度（秒）
const int CHART_TICK_COUNT = 11;  // 图表刻度数量
const int TRAY_MESSAGE_DURATION = 3000;  // 托盘消息持续时间
const int CLEANUP_CHECK_INTERVAL = 2000;  // 清理检查间隔

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), timeCounter(0) {
    // 设置控制台编码为UTF-8
    SetConsoleOutputCP(65001);

    // 防止隐藏窗口时程序退出[6](@ref)
    setWindowFlags(Qt::Tool);

    // 初始化成员变量
    trayIcon = nullptr;
    trayMenu = nullptr;
    centralWidget = nullptr;
    cpuLabel = nullptr;
    memoryLabel = nullptr;
    gpuLabel = nullptr;
    privilegeLabel = nullptr;  // 权限状态标签
    memoryBar = nullptr;
    chartView = nullptr;
    chart = nullptr;
    memorySeries = nullptr;
    axisX = nullptr;
    axisY = nullptr;
    updateTimer = nullptr;
    appUpdateTimer = nullptr;  // 应用列表更新定时器
    isMainWindowVisible = true;  // 初始设为可见
    cleanFrequencyCounter = 0;  // 初始化清理频率计数器

    setupUI();
    createTrayIcon();
    createChart();

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &MainWindow::updateSystemInfo);
    connect(updateTimer, &QTimer::timeout, this, &MainWindow::updateChart);
    updateTimer->start(UPDATE_INTERVAL_MS);  // 每秒更新一次，使图表更平滑

    // 设置应用列表更新定时器
    appUpdateTimer = new QTimer(this);
    connect(appUpdateTimer, &QTimer::timeout, this, &MainWindow::updateAppList);
    appUpdateTimer->start(APP_UPDATE_INTERVAL_MS);  // 每3秒更新一次应用列表

    // 连接自动清理设置的信号
    connect(thresholdSlider, &QSlider::valueChanged, this, &MainWindow::onThresholdChanged);
    connect(frequencySlider, &QSlider::valueChanged, this, &MainWindow::onFrequencyChanged);

    updateSystemInfo();

    // 初始化硬件监控器（使用Windows API替代C++/CLI）
    Buffer::InitializeHardwareMonitor();

    // 调试信息
    std::cout << "MainWindow 初始化完成" << std::endl;
}

void MainWindow::updateAppList() {
    // 仅在主窗口可见时更新应用列表
    if (!isMainWindowVisible) {
        return;  // 后台时暂停获取信息
    }

    // 更新应用内存占用列表
    auto topApps = Buffer::GetTopMemoryConsumingApps(APP_LIST_SIZE);
    for (int i = 0; i < appLabels.size(); ++i) {
        if (i < topApps.size()) {
            double memoryMB = topApps[i].memoryUsage / (1024.0 * 1024.0); // 转换为MB
            appLabels[i]->setText(QString("%1: %2 MB")
                                  .arg(QString::fromStdString(topApps[i].name))
                                  .arg(memoryMB, 0, 'f', 1));
        } else {
            appLabels[i]->setText(""); // 清空多余的标签
        }
    }
}

MainWindow::~MainWindow() {
    if (trayIcon && trayIcon->isVisible()) {
        trayIcon->hide();
    }
}

void MainWindow::setupUI() {
    setWindowTitle("Buffer 内存清理工具");
    setFixedSize(WINDOW_WIDTH, WINDOW_HEIGHT);  // 增加窗口大小以容纳应用列表

    centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);  // 改为水平布局

    // 左侧：主要信息区域
    QVBoxLayout *leftLayout = new QVBoxLayout();

    // 系统信息显示区域
    QGroupBox *infoGroup = new QGroupBox("系统状态", this);
    QVBoxLayout *infoLayout = new QVBoxLayout(infoGroup);

    cpuLabel = new QLabel("CPU使用率: --%", infoGroup);
    memoryLabel = new QLabel("内存使用: --/-- MB (--%)", infoGroup);
    
    // 添加权限状态标签
    privilegeLabel = new QLabel("", infoGroup);
    privilegeLabel->setStyleSheet("QLabel { color: #0066CC; font-weight: bold; }"); // 设置样式

    memoryBar = new QProgressBar(infoGroup);
    memoryBar->setRange(0, 100);
    memoryBar->setFormat("%p%");

    gpuLabel = new QLabel("GPU: 未检测到", infoGroup);

    infoLayout->addWidget(cpuLabel);
    infoLayout->addWidget(memoryLabel);
    infoLayout->addWidget(privilegeLabel);  // 添加权限状态标签
    infoLayout->addWidget(memoryBar);
    infoLayout->addWidget(gpuLabel);

    leftLayout->addWidget(infoGroup);

    // 图表区域
    QGroupBox *chartGroup = new QGroupBox("内存使用趋势", this);
    QVBoxLayout *chartLayout = new QVBoxLayout(chartGroup);

    // 在创建图表前确保chartView已创建
    chartView = new QChartView(chartGroup);
    chartView->setMinimumHeight(CHART_MIN_HEIGHT);  // 设置图表最小高度
    chartLayout->addWidget(chartView);

    leftLayout->addWidget(chartGroup, 1);  // 给图表区域分配更多空间

    // 右侧：垂直布局包含应用列表和自动清理设置
    QVBoxLayout *rightLayout = new QVBoxLayout();

    // 应用内存占用列表组
    QGroupBox *appListGroup = new QGroupBox("内存占用应用", this);
    appListLayout = new QVBoxLayout(appListGroup);
    appListGroup->setMinimumWidth(APP_LIST_MIN_WIDTH);  // 设置最小宽度

    // 创建应用标签列表（最多显示APP_LIST_SIZE个应用）
    for (int i = 0; i < APP_LIST_SIZE; ++i) {
        QLabel *appLabel = new QLabel(QString("应用%1: -- MB").arg(i+1), appListGroup);
        appLabels.append(appLabel);
        appListLayout->addWidget(appLabel);
    }

    appListLayout->addStretch(); // 添加弹性空间以填充剩余区域
    rightLayout->addWidget(appListGroup); // 将应用列表添加到右侧布局

    // 自动清理设置组
    autoCleanGroup = new QGroupBox("自动清理设置", this);
    autoCleanGroup->setMinimumWidth(APP_LIST_MIN_WIDTH);  // 设置最小宽度
    QVBoxLayout *autoCleanLayout = new QVBoxLayout(autoCleanGroup);

    // 阈值设置
    thresholdLabel = new QLabel("内存清理阈值:", autoCleanGroup);
    thresholdSlider = new QSlider(Qt::Horizontal, autoCleanGroup);
    thresholdSlider->setRange(10, 100); // 10% 到 100%
    thresholdSlider->setValue(80); // 默认80%
    thresholdValueLabel = new QLabel("80%", autoCleanGroup);
    thresholdValueLabel->setAlignment(Qt::AlignRight);

    QHBoxLayout *thresholdLayout = new QHBoxLayout();
    thresholdLayout->addWidget(thresholdLabel);
    thresholdLayout->addWidget(thresholdSlider);
    thresholdLayout->addWidget(thresholdValueLabel);
    autoCleanLayout->addLayout(thresholdLayout);

    // 频率设置
    frequencyLabel = new QLabel("清理频率 (秒):", autoCleanGroup);
    frequencySlider = new QSlider(Qt::Horizontal, autoCleanGroup);
    frequencySlider->setRange(1, 30); // 1秒到30秒
    frequencySlider->setValue(1); // 默认1秒
    frequencyValueLabel = new QLabel("1秒", autoCleanGroup);
    frequencyValueLabel->setAlignment(Qt::AlignRight);

    QHBoxLayout *frequencyLayout = new QHBoxLayout();
    frequencyLayout->addWidget(frequencyLabel);
    frequencyLayout->addWidget(frequencySlider);
    frequencyLayout->addWidget(frequencyValueLabel);
    autoCleanLayout->addLayout(frequencyLayout);

    rightLayout->addWidget(autoCleanGroup); // 将自动清理设置添加到右侧布局

    // 将左右两部分添加到主布局
    mainLayout->addLayout(leftLayout, 1);  // 左侧占用1份空间
    mainLayout->addLayout(rightLayout);    // 右侧包含应用列表和设置组
}

void MainWindow::createChart() {
    // 确保chartView已初始化
    if (!chartView) {
        std::cout << "错误：chartView未初始化" << std::endl;
        return;
    }

    chart = new QChart();
    chart->setTitle("内存使用率趋势");
    chart->setTheme(QChart::ChartThemeDark);
    chart->legend()->setVisible(true);  // 显示图例
    chart->legend()->setAlignment(Qt::AlignBottom);  // 图例位置

    memorySeries = new QLineSeries();
    memorySeries->setName("内存使用率 (%)");

    chart->addSeries(memorySeries);

    axisX = new QValueAxis();
    axisX->setTitleText("时间 (秒)");
    axisX->setRange(0, CHART_TIME_SPAN);  // 初始范围
    axisX->setLabelFormat("%d");  // 显示整数时间值
    axisX->setTickCount(CHART_TICK_COUNT);  // 设置刻度数量，避免标签过于密集

    axisY = new QValueAxis();
    axisY->setTitleText("使用率 (%)");
    axisY->setRange(0, 100);
    axisY->setLabelFormat("%d");

    chart->addAxis(axisX, Qt::AlignBottom);
    chart->addAxis(axisY, Qt::AlignLeft);
    memorySeries->attachAxis(axisX);
    memorySeries->attachAxis(axisY);

    chartView->setChart(chart);
    chartView->setRenderHint(QPainter::Antialiasing);
    chart->setAnimationOptions(QChart::NoAnimation);  // 禁用动画以获得更流畅的实时更新
}

void MainWindow::createTrayIcon() {
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        trayMenu = new QMenu(this);

        QAction *showAction = new QAction("显示主窗口", this);
        QAction *cleanAction = new QAction("立即清理内存", this);
        QAction *exitAction = new QAction("退出", this);

        connect(showAction, &QAction::triggered, this, &MainWindow::onShowWindow);
        connect(cleanAction, &QAction::triggered, this, &MainWindow::onCleanNow);
        connect(exitAction, &QAction::triggered, this, &MainWindow::onExit);

        trayMenu->addAction(showAction);
        trayMenu->addAction(cleanAction);
        trayMenu->addSeparator();
        trayMenu->addAction(exitAction);

        trayIcon = new QSystemTrayIcon(this);
        trayIcon->setContextMenu(trayMenu);
        // 初始化时获取内存状态来设置适当的图标
        auto memStatus = Buffer::GetMemoryStatus();
        if (memStatus.memoryUsage < 40.0) {
            trayIcon->setIcon(QIcon(":/icons/icon_cold.png"));
        } else if (memStatus.memoryUsage < 70.0) {
            trayIcon->setIcon(QIcon(":/icons/icon.png"));
        } else if (memStatus.memoryUsage < 80.0) {
            trayIcon->setIcon(QIcon(":/icons/icon_hot.png"));
        } else {
            trayIcon->setIcon(QIcon(":/icons/icon_red.png"));
        }
        if (trayIcon->icon().isNull()) {
            // 尝试加载备用图标
            trayIcon->setIcon(QIcon(":/icons/icon.ico"));
            if (trayIcon->icon().isNull()) {
                std::cout << "错误：图标加载失败！请检查资源文件路径。" << std::endl;
            } else {
                std::cout << "图标加载成功（备用图标）。" << std::endl;
            }
        } else {
            std::cout << "图标加载成功。" << std::endl;
        }
        trayIcon->setToolTip("Buffer 内存清理工具");

        connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayIconActivated);

        trayIcon->show();

        // 显示托盘提示消息[8](@ref)
        trayIcon->showMessage("Buffer", "内存清理工具已启动在系统托盘", QSystemTrayIcon::Information, TRAY_MESSAGE_DURATION);
    } else {
        std::cout << "系统托盘不可用" << std::endl;
    }
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        onShowWindow();
    }
}

void MainWindow::onShowWindow() {
    show();
    raise();
    activateWindow();
}

void MainWindow::onCleanNow() {
    // 在后台线程执行内存清理以避免UI卡顿
    QFuture<bool> result = QtConcurrent::run([]() -> bool {
        return Buffer::PerformMemoryClean();
    });

    // 显示清理中提示
    trayIcon->showMessage("内存清理", "正在执行内存清理，请稍候...", QSystemTrayIcon::Information, CLEANUP_CHECK_INTERVAL);

    // 异步等待结果并更新UI
    QTimer *timer = new QTimer(this);
    timer->setSingleShot(true);
    timer->setInterval(CLEANUP_CHECK_INTERVAL);  // 每秒检查一次清理是否完成
    connect(timer, &QTimer::timeout, this, [this, timer, result]() mutable {
        if (result.isFinished()) {
            bool success = result.result();
            if (success) {
                trayIcon->showMessage("内存清理", "内存清理完成！", QSystemTrayIcon::Information, CLEANUP_CHECK_INTERVAL);
            } else {
                trayIcon->showMessage("内存清理", "内存清理失败！", QSystemTrayIcon::Critical, CLEANUP_CHECK_INTERVAL);
            }
            timer->deleteLater();  // 清理定时器
        }
    });
    timer->start();  // 启动定时器
}

void MainWindow::onExit() {
    if (trayIcon) {
        trayIcon->hide();
    }
    QApplication::quit();
}

void MainWindow::updateSystemInfo() {
    auto memStatus = Buffer::GetMemoryStatus();
    double usedMB = (memStatus.totalPhys - memStatus.availPhys) / (1024.0 * 1024.0);
    double totalMB = memStatus.totalPhys / (1024.0 * 1024.0);

    memoryLabel->setText(QString("内存使用: %1/%2 MB (%3%)")
                                 .arg(QString::number(usedMB, 'f', 1))
                                 .arg(QString::number(totalMB, 'f', 1))
                                 .arg(QString::number(memStatus.memoryUsage, 'f', 1)));
    memoryBar->setValue(static_cast<int>(memStatus.memoryUsage));

    // 根据内存使用率更新托盘图标
    if (trayIcon) {
        // 设置托盘图标根据内存使用率变化
        if (memStatus.memoryUsage < 40.0) {
            trayIcon->setIcon(QIcon(":/icons/icon_cold.png"));
        } else if (memStatus.memoryUsage < 70.0) {
            trayIcon->setIcon(QIcon(":/icons/icon.png"));
        } else if (memStatus.memoryUsage < 80.0) {
            trayIcon->setIcon(QIcon(":/icons/icon_hot.png"));
        } else {
            trayIcon->setIcon(QIcon(":/icons/icon_red.png"));
        }

        trayIcon->setToolTip(QString("内存使用率: %1%").arg(memStatus.memoryUsage, 0, 'f', 1));
    }

    // 更新CPU信息
    auto cpuInfo = Buffer::GetCPUInfo();
    if (cpuInfo.usage >= 0) {
        cpuLabel->setText(QString("CPU: %1\nCPU使用率: %2% (%3核心)")
                                  .arg(QString::fromStdString(cpuInfo.name))
                                  .arg(QString::number(cpuInfo.usage, 'f', 1))
                                  .arg(cpuInfo.coreCount));
    } else {
        cpuLabel->setText("CPU使用率: 初始化中...");
    }

    // 更新权限状态显示
    if (IsRunAsAdmin()) {
        privilegeLabel->setText("权限状态: 管理员权限 (内存清理效果最佳)");
        privilegeLabel->setStyleSheet("QLabel { color: #00AA00; font-weight: bold; }"); // 绿色表示管理员权限
    } else {
        privilegeLabel->setText("权限状态: 普通权限 (内存清理效果受限)");
        privilegeLabel->setStyleSheet("QLabel { color: #FF6600; font-weight: bold; }"); // 橙色表示普通权限
    }

    // 更新GPU信息（仅显示名称）
    auto gpus = Buffer::GetGPUInfo();
    if (!gpus.empty()) {
        QString gpuText = "";
        for (size_t i = 0; i < gpus.size(); ++i) {
            if (i > 0) gpuText += "\n";
            gpuText += QString("GPU%1: %2")
                              .arg(i + 1)
                              .arg(QString::fromStdString(gpus[i].name));
        }
        gpuLabel->setText(gpuText);
    } else {
        gpuLabel->setText("GPU: 未检测到");
    }

    // 检查是否需要自动清理内存（根据频率控制）
    if (memStatus.memoryUsage > Buffer::GetCleanThreshold()) {
        // 获取当前设置的频率值
        int currentFrequency = frequencySlider->value();
        cleanFrequencyCounter++;
        if (cleanFrequencyCounter >= currentFrequency) {  // 只在达到频率间隔时执行清理
            // 在后台线程执行内存清理以避免UI卡顿
            QFuture<bool> result = QtConcurrent::run([]() -> bool {
                return Buffer::PerformMemoryClean();
            });

            // 显示清理中提示
            if (trayIcon) {
                trayIcon->showMessage("内存清理", "正在执行自动内存清理，请稍候...", QSystemTrayIcon::Information, CLEANUP_CHECK_INTERVAL);
            }

            // 异步等待结果并更新UI
            QTimer *timer = new QTimer(this);
            timer->setSingleShot(true);
            timer->setInterval(CLEANUP_CHECK_INTERVAL);  // 每秒检查一次清理是否完成
            connect(timer, &QTimer::timeout, this, [this, timer, result]() mutable {
                if (result.isFinished()) {
                    bool success = result.result();
                    if (trayIcon) {  // 检查 trayIcon 是否有效
                        if (success) {
                            trayIcon->showMessage("内存清理", "自动内存清理已完成！", QSystemTrayIcon::Information, CLEANUP_CHECK_INTERVAL);
                        } else {
                            trayIcon->showMessage("内存清理", "自动内存清理失败！", QSystemTrayIcon::Critical, CLEANUP_CHECK_INTERVAL);
                        }
                    }
                    cleanFrequencyCounter = 0;  // 重置计数器
                    timer->deleteLater();  // 清理定时器
                }
            });
            timer->start();  // 启动定时器
        }
    } else {
        // 如果内存使用率低于阈值，重置计数器
        cleanFrequencyCounter = 0;
    }

    // 应用列表更新由单独的定时器处理，这里不再更新
}

void MainWindow::updateChart() {
    auto memStatus = Buffer::GetMemoryStatus();

    // 使用当前时间作为X轴坐标（以秒为单位）
    qint64 currentTime = QDateTime::currentDateTime().toMSecsSinceEpoch() / 1000;
    
    // 如果是第一次添加数据点，初始化起始时间
    static qint64 startTime = currentTime;
    if (timeCounter == 0) {
        startTime = currentTime;
    }

    // 使用相对于开始时间的偏移量作为X轴值
    double relativeTime = currentTime - startTime;
    // 使用QPointF添加数据点
    memorySeries->append(QPointF(relativeTime, memStatus.memoryUsage));

    // 保持显示最近CHART_TIME_SPAN秒的数据
    if (memorySeries->count() > CHART_TIME_SPAN) {
        memorySeries->remove(0); // 移除第一个点
    }

    // 更新X轴范围以显示最近CHART_TIME_SPAN秒的数据
    axisX->setRange(relativeTime - CHART_TIME_SPAN, relativeTime);

    timeCounter++;
}

bool MainWindow::IsRunAsAdmin() {
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

void MainWindow::showEvent(QShowEvent *event) {
    QMainWindow::showEvent(event);
    isMainWindowVisible = true;
}

void MainWindow::hideEvent(QHideEvent *event) {
    QMainWindow::hideEvent(event);
    isMainWindowVisible = false;
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (trayIcon && trayIcon->isVisible()) {
        hide();
        event->ignore();
        // 显示提示消息[7](@ref)
        trayIcon->showMessage("Buffer", "程序已最小化到系统托盘", QSystemTrayIcon::Information, TRAY_MESSAGE_DURATION);
    } else {
        event->accept();
    }
}

// 处理阈值变化的槽函数
void MainWindow::onThresholdChanged(int value) {
    Buffer::SetCleanThreshold(value);
    thresholdValueLabel->setText(QString("%1%").arg(value));
}

// 处理频率变化的槽函数
void MainWindow::onFrequencyChanged(int value) {
    // 更新计数器将由更新定时器控制
    // 只更新显示的值
    frequencyValueLabel->setText(QString("%1秒").arg(value));
}