cmake_minimum_required(VERSION 3.12)
project(http_scanner C)

# 设置C标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -DDEBUG")

# 查找必要的库
find_package(PkgConfig)

# 尝试使用pkg-config查找Hyperscan库
if(PkgConfig_FOUND)
    pkg_check_modules(HYPERSCAN hyperscan)
endif()

# 如果pkg-config失败，尝试手动查找
if(NOT HYPERSCAN_FOUND)
    message(STATUS "pkg-config未找到hyperscan，尝试手动查找...")

    # 查找Hyperscan头文件
    find_path(HYPERSCAN_INCLUDE_DIR
        NAMES hs/hs.h
        PATHS /usr/include /usr/local/include
        DOC "Hyperscan include directory"
    )

    # 查找Hyperscan库文件
    find_library(HYPERSCAN_LIBRARY
        NAMES hs hyperscan
        PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib
        DOC "Hyperscan library"
    )

    if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIBRARY)
        set(HYPERSCAN_FOUND TRUE)
        set(HYPERSCAN_INCLUDE_DIRS ${HYPERSCAN_INCLUDE_DIR})
        set(HYPERSCAN_LIBRARIES ${HYPERSCAN_LIBRARY})
        message(STATUS "手动找到Hyperscan:")
        message(STATUS "  头文件: ${HYPERSCAN_INCLUDE_DIR}")
        message(STATUS "  库文件: ${HYPERSCAN_LIBRARY}")
    else()
        message(WARNING "未找到Hyperscan库，程序将使用备用模式")
        set(HYPERSCAN_FOUND FALSE)
    endif()
endif()

# 检查是否找到libpcap库
find_library(PCAP_LIBRARY NAMES pcap pcap)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)

if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
    set(PCAP_FOUND TRUE)
    message(STATUS "找到libpcap:")
    message(STATUS "  库文件: ${PCAP_LIBRARY}")
    message(STATUS "  头文件: ${PCAP_INCLUDE_DIR}")
else()
    message(WARNING "未找到libpcap库，将禁用pcap文件处理功能")
    set(PCAP_FOUND FALSE)
endif()

# 包含目录
set(INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/../../target/include
)

if(HYPERSCAN_FOUND)
    list(APPEND INCLUDE_DIRS ${HYPERSCAN_INCLUDE_DIRS})
endif()

if(PCAP_FOUND)
    list(APPEND INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
endif()

include_directories(${INCLUDE_DIRS})

# 链接目录
link_directories(
    ${CMAKE_SOURCE_DIR}/../../target/release
)

# 源文件
set(SOURCES
    src/main.c
)

# 创建可执行文件
add_executable(http_scanner ${SOURCES})

# 设置库依赖
set(LINK_LIBS
    web_scan_rust
    pthread
    m
    dl
)

if(HYPERSCAN_FOUND)
    list(APPEND LINK_LIBS ${HYPERSCAN_LIBRARIES})
endif()

if(PCAP_FOUND)
    list(APPEND LINK_LIBS ${PCAP_LIBRARY})
endif()

target_link_libraries(http_scanner ${LINK_LIBS})

# 设置头文件依赖
target_include_directories(http_scanner PRIVATE ${INCLUDE_DIRS})

# 编译时定义
set(COMPILE_DEFS)

if(PCAP_FOUND)
    list(APPEND COMPILE_DEFS "HAVE_PCAP=1")
    message(STATUS "启用libpcap支持")
else()
    list(APPEND COMPILE_DEFS "HAVE_PCAP=0")
    message(STATUS "禁用libpcap支持")
endif()

if(HYPERSCAN_FOUND)
    list(APPEND COMPILE_DEFS "HAVE_HYPERSCAN=1")
    message(STATUS "启用Hyperscan支持")
else()
    list(APPEND COMPILE_DEFS "HAVE_HYPERSCAN=0")
    message(STATUS "禁用Hyperscan支持")
endif()

target_compile_definitions(http_scanner PRIVATE ${COMPILE_DEFS})

# 安装规则
install(TARGETS http_scanner DESTINATION bin)

# 创建规则目录的软链接（如果需要）
execute_process(
    COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_SOURCE_DIR}/rules
    ${CMAKE_BINARY_DIR}/rules
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# 打印配置信息
message(STATUS "项目配置信息:")
message(STATUS "  编译类型: ${CMAKE_BUILD_TYPE}")

if(HYPERSCAN_FOUND)
    message(STATUS "  Hyperscan库: ${HYPERSCAN_LIBRARIES}")
    message(STATUS "  Hyperscan包含目录: ${HYPERSCAN_INCLUDE_DIRS}")
else()
    message(STATUS "  Hyperscan: 未找到，使用备用模式")
endif()

if(PCAP_FOUND)
    message(STATUS "  PCAP库: ${PCAP_LIBRARY}")
    message(STATUS "  PCAP包含目录: ${PCAP_INCLUDE_DIR}")
else()
    message(STATUS "  PCAP: 未找到，pcap功能将被禁用")
endif()

# 创建启动脚本
configure_file(
    ${CMAKE_SOURCE_DIR}/run_scanner.sh.in
    ${CMAKE_BINARY_DIR}/run_scanner.sh
    @ONLY
)

# 设置脚本为可执行
execute_process(
    COMMAND chmod +x ${CMAKE_BINARY_DIR}/run_scanner.sh
)