// src/SystemInfo.hpp
#ifndef BUFFER_SYSTEMINFO_HPP
#define BUFFER_SYSTEMINFO_HPP

#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <memory>  // 为 std::unique_ptr 添加

namespace Buffer {
    struct MemoryStatus {
        unsigned long long totalPhys;
        unsigned long long availPhys;
        double memoryUsage;
    };

    struct CPUInfo {
        std::string name;
        double usage;
        int coreCount;
        double temperature;                  // CPU温度
    };

    struct GPUInfo {
        std::string name;
        unsigned long long totalMemory;      // 总显存
        unsigned long long availableMemory;  // 可用显存
        double memoryUsage;                  // 显存使用率
        double usage;                        // GPU使用率
        double temperature;                  // GPU温度
        bool supportsCUDA;                   // 是否支持CUDA
        int cudaDeviceCount;                 // CUDA设备数量
    };

    // 内存监控函数
    MemoryStatus GetMemoryStatus();
    void PrintMemoryInfo();

    // CPU监控函数
    double GetCPUUsage();
    CPUInfo GetCPUInfo();

    // GPU监控函数
    std::vector<GPUInfo> GetGPUInfo();
    bool HasCUDA();

    // 内存清理函数
    bool PerformMemoryClean();
    void SetCleanThreshold(double threshold);
    double GetCleanThreshold();
    
    // 硬件监控初始化函数
    bool InitializeHardwareMonitor();

    // 应用内存占用信息
    struct AppMemoryInfo {
        std::string name;
        unsigned long long memoryUsage;  // 以字节为单位
    };
    std::vector<AppMemoryInfo> GetTopMemoryConsumingApps(int count = 10);
}

// 添加全局变量的 extern 声明
extern double g_cleanThreshold;
extern int g_ineffectiveCount;

#endif