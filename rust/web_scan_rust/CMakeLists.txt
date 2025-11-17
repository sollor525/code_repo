cmake_minimum_required(VERSION 3.10)
project(web_scan_rust_integration)

# 设置 C 标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 查找必要的库
find_package(PkgConfig REQUIRED)

# 查找 Hyperscan
pkg_check_modules(HYPERSCAN REQUIRED libhs)

# 添加 Hyperscan 的包含路径和库
include_directories(${HYPERSCAN_INCLUDE_DIRS})
link_directories(${HYPERSCAN_LIBRARY_DIRS})

# 设置 Rust 库的路径
set(RUST_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/target/release")
set(RUST_INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/target/include")

# 包含 Rust 头文件
include_directories(${RUST_INCLUDE_PATH})

# 添加链接目录
link_directories(${RUST_LIB_PATH})

# 创建 C 集成测试可执行文件
add_executable(c_integration_test examples/c_integration.c)

# 链接必要的库
target_link_libraries(c_integration_test
    web_scan_rust
    ${HYPERSCAN_LIBRARIES}
    pthread
    dl
    m
)

# 设置编译选项
target_compile_options(c_integration_test PRIVATE ${HYPERSCAN_CFLAGS_OTHER})

# 添加 RPATH 以便找到动态库
set_target_properties(c_integration_test PROPERTIES
    INSTALL_RPATH "${RUST_LIB_PATH}"
    BUILD_WITH_INSTALL_RPATH TRUE
)
