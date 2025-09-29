cmake_minimum_required(VERSION 3.10)
project(tls_ja4_examples)

# 设置C标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置C++标准（如果需要）
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# 查找Rust库
find_library(TLS_JA4_LIB 
    NAMES tls_ja4
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../target/debug
          ${CMAKE_CURRENT_SOURCE_DIR}/../target/release
    NO_DEFAULT_PATH
)

if(NOT TLS_JA4_LIB)
    message(FATAL_ERROR "Could not find tls_ja4 library. Please build the Rust library first with 'cargo build'")
endif()

# 查找头文件
find_path(TLS_JA4_INCLUDE_DIR
    NAMES tls_ja4.h
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../include
    NO_DEFAULT_PATH
)

if(NOT TLS_JA4_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find tls_ja4.h header file")
endif()

# 包含头文件目录
include_directories(${TLS_JA4_INCLUDE_DIR})

# 创建可执行文件
add_executable(vpp_integration_example vpp_integration_example.c)

# 链接库
target_link_libraries(vpp_integration_example 
    ${TLS_JA4_LIB}
    pthread
    dl
    m
)

# 设置RPATH以便运行时找到库
set_target_properties(vpp_integration_example PROPERTIES
    INSTALL_RPATH_USE_LINK_PATH TRUE
    INSTALL_RPATH "${CMAKE_CURRENT_SOURCE_DIR}/../target/debug;${CMAKE_CURRENT_SOURCE_DIR}/../target/release"
)

# 添加自定义目标来构建Rust库
add_custom_target(build_rust_lib
    COMMAND cargo build
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
    COMMENT "Building Rust tls_ja4 library"
)

# 确保Rust库在C示例之前构建
add_dependencies(vpp_integration_example build_rust_lib)

# 安装目标
install(TARGETS vpp_integration_example
    RUNTIME DESTINATION bin
)

# 打印配置信息
message(STATUS "TLS_JA4_LIB: ${TLS_JA4_LIB}")
message(STATUS "TLS_JA4_INCLUDE_DIR: ${TLS_JA4_INCLUDE_DIR}")
message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
