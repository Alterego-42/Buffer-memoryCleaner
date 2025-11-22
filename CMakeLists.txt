cmake_minimum_required(VERSION 3.21)

# 检测是否为Visual Studio编译器，因为C++/CLI仅在MSVC中可用
if(MSVC)
    project(Buffer LANGUAGES CXX C)
else()
    project(Buffer LANGUAGES CXX)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找Qt6库
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Charts Concurrent)

# 设置自动处理MOC、UIC、RCC
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

if (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUNICODE -D_UNICODE")

    if (MSVC)
        add_compile_options("/utf-8")
        # 设置异常处理和运行时检查
        set(CMAKE_CXX_FLAGS_DEBUG "/EHsc /RTC1 /Zi /Ob0 /Od")
        set(CMAKE_CXX_FLAGS_RELEASE "/EHsc /O2 /DNDEBUG")
    endif()
endif ()

# 包含头文件目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# 查找源文件（包括新的硬件监控模块）
set(ALL_SOURCES)
file(GLOB_RECURSE ALL_SOURCES "src/*.cpp")

# 创建可执行文件
add_executable(Buffer ${ALL_SOURCES} resources.qrc)

# 为C++文件设置选项（在添加到目标后设置属性）
if(MSVC)
    set_source_files_properties(${ALL_SOURCES} PROPERTIES
        COMPILE_FLAGS "/EHsc"
    )
endif()

# 然后为已创建的目标链接库
target_link_libraries(Buffer PRIVATE Qt6::Core Qt6::Widgets Qt6::Charts Qt6::Concurrent)
# 添加额外需要的Windows库
target_link_libraries(Buffer PRIVATE Psapi Advapi32 Shell32 Setupapi Wbemuuid)

# 设置为Windows应用程序
set_target_properties(Buffer PROPERTIES
    WIN32_EXECUTABLE TRUE
)

# 添加Qt6运行时路径到环境变量（用于部署）
set_target_properties(Buffer PROPERTIES
    QT_QMAKE_EXECUTABLE ${Qt6_DIR}/../../../bin/qmake.exe
)