#include "SystemInfo.hpp"
#define NOMINMAX  // 禁用Windows头文件中的min/max宏定义
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <setupapi.h>
#include <devguid.h>
#include <algorithm>  // 为了使用 std::sort

// 常量定义
const size_t TEMP_MEMORY_SIZE = 128 * 1024 * 1024;  // 128MB 临时内存大小
const size_t PAGE_SIZE = 4096;  // 页面大小
const size_t MAX_CPU_NAME_LENGTH = 256;  // CPU名称最大长度
const size_t MAX_DEVICE_DESC_LENGTH = 256;  // 设备描述最大长度
const int MAX_TEMP_STRING_SIZE = 260;  // 临时字符串大小

// 为SetupAPI定义GUID（如果未定义）
#ifndef GUID_DEVCLASS_DISPLAY
DEFINE_GUID(GUID_DEVCLASS_DISPLAY, 0x4d36e968, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18);
#endif

// 包含WMI头文件
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

// 初始化COM库和WMI
HRESULT InitializeWMI(IWbemLocator **pLoc, IWbemServices **pSvc) {
    HRESULT hres;

    // 初始化COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        return hres;
    }

    // 设置安全级别
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, 
                                RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
        CoUninitialize();
        return hres;
    }

    // 获取WMI定位器
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return hres;
    }

    // 连接到WMI服务
    hres = (*pLoc)->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, pSvc);
    if (FAILED(hres)) {
        (*pLoc)->Release();
        CoUninitialize();
        return hres;
    }

    // 设置安全上下文
    hres = CoSetProxyBlanket(*pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, 
                             RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        (*pSvc)->Release();
        (*pLoc)->Release();
        CoUninitialize();
        return hres;
    }

    return S_OK;
}

// 全局变量定义
double g_cleanThreshold = 80.0;
int g_ineffectiveCount = 0;

// 实现 GetMemoryStatus 函数
Buffer::MemoryStatus Buffer::GetMemoryStatus() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);

    Buffer::MemoryStatus status = {};

    if (GlobalMemoryStatusEx(&statex)) {
        status.totalPhys = statex.ullTotalPhys;
        status.availPhys = statex.ullAvailPhys;
        status.memoryUsage = static_cast<double>(statex.dwMemoryLoad);
    }
    return status;
}

// 实现 GetCPUUsage 函数
double Buffer::GetCPUUsage() {
    FILETIME idleTime, kernelTime, userTime;
    ULARGE_INTEGER currentCPU, currentSysCPU, currentUserCPU;

    // 获取CPU时间
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return -1.0; // 获取失败
    }

    // 将FILETIME转换为ULARGE_INTEGER
    currentCPU.QuadPart = ((ULARGE_INTEGER*)&kernelTime)->QuadPart + ((ULARGE_INTEGER*)&userTime)->QuadPart;
    currentSysCPU.QuadPart = ((ULARGE_INTEGER*)&idleTime)->QuadPart;
    currentUserCPU.QuadPart = ((ULARGE_INTEGER*)&userTime)->QuadPart;

    // 初始化
    static bool bInitialized = false;
    static ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU;
    if (!bInitialized) {
        bInitialized = true;
        lastCPU = currentCPU;
        lastSysCPU = currentSysCPU;
        lastUserCPU = currentUserCPU;
        return -1.0; // 第一次调用，返回无效值
    }

    // 计算CPU使用率
    double percent = 0.0;
    if (currentCPU.QuadPart != lastCPU.QuadPart) {
        percent = (double)((currentCPU.QuadPart - lastCPU.QuadPart) - (currentSysCPU.QuadPart - lastSysCPU.QuadPart)) * 100.0 / (currentCPU.QuadPart - lastCPU.QuadPart);
    }

    // 更新上一次的值
    lastCPU = currentCPU;
    lastSysCPU = currentSysCPU;
    lastUserCPU = currentUserCPU;

    return percent < 0 ? 0 : percent;
}

// 实现 PerformMemoryClean 函数
bool Buffer::PerformMemoryClean() {
    std::cout << "执行极致内存清理操作..." << std::endl;

    // 提权部分 - 获取额外权限
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid1, luid2;
        LookupPrivilegeValue(NULL, L"SeProfileSingleProcessPrivilege", &luid1);
        LookupPrivilegeValue(NULL, L"SeIncreaseQuotaPrivilege", &luid2);

        TOKEN_PRIVILEGES tokenPrivileges1;
        tokenPrivileges1.PrivilegeCount = 1;
        tokenPrivileges1.Privileges[0].Luid = luid1;
        tokenPrivileges1.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        TOKEN_PRIVILEGES tokenPrivileges2;
        tokenPrivileges2.PrivilegeCount = 1;
        tokenPrivileges2.Privileges[0].Luid = luid2;
        tokenPrivileges2.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges1, 0, NULL, NULL);
        AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges2, 0, NULL, NULL);
        CloseHandle(hToken);
    }

    // 方法1: 使用NtSetSystemInformation进行系统级内存清理
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        typedef enum _SYSTEM_INFORMATION_CLASS {
            SystemMemoryListInformation = 80,
            SystemFileCacheInformation = 81,
            SystemCombinePhysicalMemoryInformation = 130,
            SystemRegistryReconciliationInformation = 155
        } SYSTEM_INFORMATION_CLASS;

        typedef NTSTATUS (WINAPI *PNtSetSystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, 
                                                          PVOID SystemInformation, ULONG SystemInformationLength);
        PNtSetSystemInformation pNtSetSystemInformation = (PNtSetSystemInformation)GetProcAddress(hNtdll, "NtSetSystemInformation");
        
        if (pNtSetSystemInformation) {
            // SystemMemoryListInformation - MemoryEmptyWorkingSets (2) - 清空工作集
            int info = 2;
            pNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)80, &info, sizeof(info));
            std::cout << "清空工作集完成" << std::endl;

            // SystemMemoryListInformation - MemoryFlushModifiedList (3) - 刷新修改列表
            info = 3;
            pNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)80, &info, sizeof(info));
            std::cout << "刷新修改列表完成" << std::endl;

            // SystemMemoryListInformation - MemoryPurgeStandbyList (4) - 清除待机列表
            info = 4;
            pNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)80, &info, sizeof(info));
            std::cout << "清除待机列表完成" << std::endl;

            // SystemMemoryListInformation - MemoryPurgeLowPriorityStandbyList (5) - 清除低优先级待机列表
            info = 5;
            pNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)80, &info, sizeof(info));
            std::cout << "清除低优先级待机列表完成" << std::endl;

            // SystemFileCacheInformation - 清理文件缓存
            struct SYSTEM_FILECACHE_INFORMATION {
                ULONG_PTR CurrentSize;
                ULONG_PTR PeakSize;
                ULONG PageFaultCount;
                ULONG_PTR MinimumWorkingSet;
                ULONG_PTR MaximumWorkingSet;
                ULONG_PTR CurrentSizeIncludingTransitionInPages;
                ULONG_PTR PeakSizeIncludingTransitionInPages;
                ULONG TransitionRePurposeCount;
                ULONG Flags;
            } scfi = {0};
            scfi.MaximumWorkingSet = (ULONG_PTR)-1;  // -1 表示最大值
            scfi.MinimumWorkingSet = (ULONG_PTR)-1;  // -1 表示最大值
            pNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)81, &scfi, sizeof(scfi));
            std::cout << "清理文件缓存完成" << std::endl;

            // SystemCombinePhysicalMemoryInformation - 合并物理内存信息
            struct MEMORY_COMBINE_INFORMATION_EX {
                HANDLE Handle;
                ULONG_PTR PagesCombined;
                ULONG Flags;
            } combineInfoEx = {0};
            pNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)130, &combineInfoEx, sizeof(combineInfoEx));
            std::cout << "合并物理内存信息完成" << std::endl;

            // SystemRegistryReconciliationInformation - 注册表调和信息
            pNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)155, NULL, 0);
            std::cout << "注册表调和完成" << std::endl;
        }
    }

    // 方法2: 清理当前进程工作集
    HANDLE hProcess = GetCurrentProcess();
    if (SetProcessWorkingSetSize(hProcess, (SIZE_T)-1, (SIZE_T)-1)) {
        std::cout << "当前进程工作集清理完成" << std::endl;
    } else {
        std::cout << "当前进程工作集清理失败" << std::endl;
    }

    // 方法3: 使用psapi.dll中的EmptyWorkingSet函数清理系统缓存
    HMODULE hPsapi = LoadLibrary(L"psapi.dll");
    if (hPsapi) {
        BOOL (WINAPI *pEmptyWorkingSet)(HANDLE) = (BOOL (WINAPI*)(HANDLE))GetProcAddress(hPsapi, "EmptyWorkingSet");
        if (pEmptyWorkingSet) {
            // 遍历系统进程并尝试清理（需要相应权限）
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        // 跳过关键系统进程
                        if (wcscmp(pe32.szExeFile, L"System") != 0 && 
                            wcscmp(pe32.szExeFile, L"winlogon.exe") != 0 &&
                            wcscmp(pe32.szExeFile, L"csrss.exe") != 0 &&
                            wcscmp(pe32.szExeFile, L"smss.exe") != 0 &&
                            wcscmp(pe32.szExeFile, L"services.exe") != 0 &&
                            wcscmp(pe32.szExeFile, L"lsass.exe") != 0 &&
                            wcscmp(pe32.szExeFile, L"svchost.exe") != 0 &&
                            wcscmp(pe32.szExeFile, L"explorer.exe") != 0) {  // 避免影响explorer
                            
                            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                            if (hProc != NULL) {
                                pEmptyWorkingSet(hProc);
                                CloseHandle(hProc);
                            }
                        }
                    } while (Process32Next(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
            std::cout << "系统进程工作集清理完成" << std::endl;
        }
        FreeLibrary(hPsapi);
    }

    // 方法4: 尝试刷新系统缓存
    typedef DWORD (WINAPI *PZwFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
    HMODULE hNtdll2 = GetModuleHandle(L"ntdll.dll");
    if (hNtdll2) {
        PZwFlushInstructionCache pZwFlushInstructionCache = (PZwFlushInstructionCache)GetProcAddress(hNtdll2, "ZwFlushInstructionCache");
        if (pZwFlushInstructionCache) {
            pZwFlushInstructionCache(GetCurrentProcess(), NULL, 0);
        }
    }

    // 方法5: 尝试使用VirtualAlloc和VirtualFree清理内存碎片
    // 分配并立即释放大量内存，促使系统整理内存
    char* tempMemory = (char*)VirtualAlloc(NULL, TEMP_MEMORY_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (tempMemory) {
        // 使用内存以确保分配
        for (size_t i = 0; i < TEMP_MEMORY_SIZE; i += PAGE_SIZE) { // 按页大小写入
            tempMemory[i] = 1;
        }
        VirtualFree(tempMemory, 0, MEM_RELEASE);
        std::cout << "内存碎片整理完成" << std::endl;
    }

    std::cout << "极致内存清理操作完成" << std::endl;
    return true;
}

// 实现 SetCleanThreshold 函数
void Buffer::SetCleanThreshold(double threshold) {
    g_cleanThreshold = threshold;
    std::cout << "清理阈值设置为: " << threshold << "%" << std::endl;
}

// 实现 GetCleanThreshold 函数
double Buffer::GetCleanThreshold() {
    return g_cleanThreshold;
}

// 实现 PrintMemoryInfo 函数
void Buffer::PrintMemoryInfo() {
    auto status = GetMemoryStatus();
    std::cout << "=== 内存信息 ===" << std::endl;
    std::cout << "总内存: " << status.totalPhys / (1024 * 1024) << " MB" << std::endl;
    std::cout << "可用内存: " << status.availPhys / (1024 * 1024) << " MB" << std::endl;
    std::cout << "使用率: " << status.memoryUsage << "%" << std::endl;
}

// 实现 GetCPUInfo 函数
Buffer::CPUInfo Buffer::GetCPUInfo() {
    CPUInfo info;
    info.name = "Unknown";
    info.usage = GetCPUUsage();
    info.coreCount = 0;
    info.temperature = -1.0; // -1表示无法获取温度，暂不支持
    
    // 获取CPU核心数
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.coreCount = sysInfo.dwNumberOfProcessors;
    
    // 获取CPU名称
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                     TEXT("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"), 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char cpuName[MAX_CPU_NAME_LENGTH] = {0};  // 初始化为0
        DWORD size = sizeof(cpuName);
        DWORD type;
        if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, &type, (LPBYTE)cpuName, &size) == ERROR_SUCCESS) {
            // 确保字符串正确终止并去除可能的填充字符
            cpuName[sizeof(cpuName)-1] = '\0';  // 确保字符串终止
            info.name = std::string(cpuName);
        }
        RegCloseKey(hKey);
    }
    
    // 如果获取不到CPU使用率，则使用计算的值
    if (info.usage < 0) {
        info.usage = GetCPUUsage();
    }
    
    // 尝试获取CPU温度 (使用WMI查询)
    // 大概率不可用，接口已挂起
    IWbemServices *pSvc = NULL;
    IWbemLocator *pLoc = NULL;
    HRESULT hres = InitializeWMI(&pLoc, &pSvc);
    if (SUCCEEDED(hres)) {
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT CurrentTemperature FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (SUCCEEDED(hres)) {
            IWbemClassObject *pclsObj = NULL;
            ULONG uReturn = 0;
            while (pEnumerator) {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;
                
                VARIANT vtProp;
                hr = pclsObj->Get(L"CurrentTemperature", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hr)) {
                    if (vtProp.vt == VT_I4) {
                        // 温度值通常以十分之一开尔文为单位，转换为摄氏度
                        info.temperature = (double)(vtProp.lVal - 2732) / 10.0;  // 转换为摄氏度
                    }
                    VariantClear(&vtProp);
                }
                pclsObj->Release();
            }
            pEnumerator->Release();
        }
        pSvc->Release();
        pLoc->Release();
    }
    
    return info;
}

// 实现 GetGPUInfo 函数
std::vector<Buffer::GPUInfo> Buffer::GetGPUInfo() {
    std::vector<GPUInfo> gpus;
    
    // 检查CUDA支持
    bool cudaSupport = HasCUDA();
    int cudaDeviceCount = 0;
    if (cudaSupport) {
        // 尝试获取CUDA设备数量
        HMODULE hCuda = LoadLibrary(L"nvcuda.dll");
        if (hCuda) {
            // 获取cudaGetDeviceCount函数指针
            typedef int (APIENTRY * CudaGetDeviceCount)(int*);
            CudaGetDeviceCount pCudaGetDeviceCount = (CudaGetDeviceCount)GetProcAddress(hCuda, "cuDeviceGetCount");
            if (pCudaGetDeviceCount) {
                pCudaGetDeviceCount(&cudaDeviceCount);
            }
            FreeLibrary(hCuda);
        }
    }
    
    // 使用SetupAPI枚举显示适配器
    HDEVINFO hDevInfo = SetupDiGetClassDevs((GUID*)&GUID_DEVCLASS_DISPLAY, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devInfo;
        devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); i++) {
            // 获取设备描述
            char deviceDesc[MAX_DEVICE_DESC_LENGTH];
            DWORD size = sizeof(deviceDesc);
            DWORD dataType;
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfo, SPDRP_DEVICEDESC, 
                                                 &dataType, (PBYTE)deviceDesc, size, &size)) {
                GPUInfo gpu;
                gpu.name = std::string(deviceDesc);
                gpu.totalMemory = 0;
                gpu.availableMemory = 0;
                gpu.memoryUsage = 0.0;
                gpu.usage = 0.0;  // 使用WMI获取GPU使用率
                gpu.temperature = -1.0; // -1表示无法获取温度
                std::string gpuName = gpu.name;
                gpu.supportsCUDA = cudaSupport && (gpuName.find("NVIDIA") != std::string::npos || gpuName.find("GeForce") != std::string::npos || gpuName.find("Quadro") != std::string::npos);
                gpu.cudaDeviceCount = gpu.supportsCUDA ? cudaDeviceCount : 0;
                gpus.push_back(gpu);
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
    
    // 如果没有找到GPU，添加一个默认条目
    if (gpus.empty()) {
        GPUInfo gpu;
        gpu.name = "Unknown GPU";
        gpu.totalMemory = 0;
        gpu.availableMemory = 0;
        gpu.memoryUsage = 0.0;
        gpu.usage = 0.0;
        gpu.temperature = -1.0; // -1表示无法获取温度
        gpu.supportsCUDA = cudaSupport;
        gpu.cudaDeviceCount = cudaDeviceCount;
        gpus.push_back(gpu);
    }
    
    // 尝试使用WMI获取GPU信息
    IWbemServices *pSvc = NULL;
    IWbemLocator *pLoc = NULL;
    HRESULT hres = InitializeWMI(&pLoc, &pSvc);
    if (SUCCEEDED(hres)) {
        IEnumWbemClassObject* pEnumerator = NULL;
        // 查询显卡信息
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_VideoController"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (SUCCEEDED(hres) && pEnumerator) {
            IWbemClassObject *pclsObj = NULL;
            ULONG uReturn = 0;
            int gpuIndex = 0;
            while (gpuIndex < gpus.size()) {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;
                
                // 获取适配器RAM（显存信息）
                VARIANT vtProp;
                hr = pclsObj->Get(L"AdapterRAM", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
                    gpus[gpuIndex].totalMemory = (unsigned long long)vtProp.lVal;
                    // 假设使用了一半显存，实际无法通过此方法获取精确使用量
                    gpus[gpuIndex].availableMemory = gpus[gpuIndex].totalMemory / 2;
                    gpus[gpuIndex].memoryUsage = 50.0; // 假设50%使用率
                }
                
                // 获取GPU名称
                hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                    // 使用WMI查询结果更新GPU名称
                    _bstr_t bstrName(vtProp.bstrVal, false);
                    std::string wmiName = (char*)bstrName;
                    if (!wmiName.empty()) {
                        gpus[gpuIndex].name = wmiName;
                    }
                }
                VariantClear(&vtProp);
                
                pclsObj->Release();
                gpuIndex++;
            }
            pEnumerator->Release();
        }
        pSvc->Release();
        pLoc->Release();
    }
    
    return gpus;
}

// 实现 HasCUDA 函数，接口已挂起
bool Buffer::HasCUDA() {
    // 尝试加载CUDA DLL以检测CUDA是否可用
    HMODULE hCuda = LoadLibrary(L"nvcuda.dll");
    if (hCuda) {
        // 检查CUDA是否真正可用
        typedef int (APIENTRY * CudaInit)(int);
        CudaInit pCudaInit = (CudaInit)GetProcAddress(hCuda, "cuInit");
        if (pCudaInit) {
            int result = pCudaInit(0);  // 0表示初始化CUDA
            FreeLibrary(hCuda);
            return (result == 0);  // CUDA_SUCCESS is 0
        }
        FreeLibrary(hCuda);
    }
    return false;
}

// 获取内存占用最高的应用程序列表
std::vector<Buffer::AppMemoryInfo> Buffer::GetTopMemoryConsumingApps(int count) {
    std::vector<AppMemoryInfo> apps;
    std::vector<std::pair<std::string, unsigned long long>> appMemList;

    // 创建进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return apps;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            // 跳过系统关键进程，只显示用户应用
            if (processEntry.th32ProcessID != 0 && processEntry.th32ProcessID != 4) { // 0是空进程，4是系统进程
                // 打开进程以获取内存信息
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
                if (hProcess != NULL) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        // 添加到列表中 (使用工作集大小作为内存使用量)
                        // 将宽字符转换为多字节字符串
                        char buffer[MAX_TEMP_STRING_SIZE];
                        size_t converted = 0;
                        wcstombs_s(&converted, buffer, sizeof(buffer), processEntry.szExeFile, _TRUNCATE);
                        std::string processName(buffer);
                        appMemList.push_back(std::make_pair(processName, pmc.WorkingSetSize));
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);

    // 按内存使用量降序排序
    std::sort(appMemList.begin(), appMemList.end(),
              [](const std::pair<std::string, unsigned long long>& a,
                 const std::pair<std::string, unsigned long long>& b) {
                  return a.second > b.second;
              });

    // 取前 count 个应用
    int actualCount = (std::min)(count, (int)appMemList.size());  // 使用括号避免与Windows宏冲突
    for (int i = 0; i < actualCount; ++i) {
        AppMemoryInfo appInfo;
        appInfo.name = appMemList[i].first;
        appInfo.memoryUsage = appMemList[i].second;
        apps.push_back(appInfo);
    }

    return apps;
}

// 实现 InitializeHardwareMonitor 函数
bool Buffer::InitializeHardwareMonitor() {
    // 由于移除了C++/CLI包装器，此函数现在仅作为占位符
    // 保留此函数是为了与MainWindow保持兼容
    std::cout << "硬件监控器初始化 (使用Windows API替代)" << std::endl;
    return true;
}
