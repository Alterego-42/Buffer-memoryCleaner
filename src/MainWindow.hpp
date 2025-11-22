// src/MainWindow.hpp
#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QCloseEvent>
#include <QChartView>
#include <QChart>
#include <QLineSeries>
#include <QValueAxis>
#include <QLabel>
#include <QProgressBar>
#include <QTimer>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QList>

QT_BEGIN_NAMESPACE
class QChartView;
class QChart;
class QLineSeries;
class QValueAxis;
QT_END_NAMESPACE

namespace Buffer {
    struct MemoryStatus;
}

class MainWindow : public QMainWindow {
Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent *event) override;
    void showEvent(QShowEvent *event) override;
    void hideEvent(QHideEvent *event) override;

private slots:
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onShowWindow();
    void onCleanNow();
    void onExit();
    void updateSystemInfo();
    void updateChart();
    void updateAppList();

private:  // 添加IsRunAsAdmin函数声明
    bool IsRunAsAdmin();

private:
    void createTrayIcon();
    void createChart();
    void setupUI();

    // 成员变量声明
    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;

    QWidget *centralWidget;
    QLabel *cpuLabel;
    QLabel *memoryLabel;
    QLabel *gpuLabel;
    QLabel *privilegeLabel;  // 权限状态标签
    QProgressBar *memoryBar;
    QChartView *chartView;
    QChart *chart;
    QLineSeries *memorySeries;
    QValueAxis *axisX;
    QValueAxis *axisY;

    // 内存占用应用列表相关
    QWidget *appListWidget;
    QVBoxLayout *appListLayout;
    QList<QLabel*> appLabels;

    // 异步处理相关
    QTimer *updateTimer;
    QTimer *appUpdateTimer;
    int timeCounter;
    bool isMainWindowVisible;
};

#endif // MAINWINDOW_HPP