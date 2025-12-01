# CMakeLists.txt - 直接链接所有librte_*.a库
cmake_minimum_required(VERSION 3.12)
project(dpdk_ring_demo VERSION 1.0.0 LANGUAGES C)

# 基本设置
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -D_GNU_SOURCE -Wall -Wextra")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -DDEBUG")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif()

# DPDK路径配置
set(DPDK_DEBUG_PATH "/root/workspace/qt/npatch_all_in_one/fp-vpp/vpp/build-root/install-vpp_debug-native")
set(DPDK_RELEASE_PATH "/root/workspace/qt/npatch_all_in_one/fp-vpp/vpp/build-root/install-vpp-native")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DPDK_ROOT ${DPDK_DEBUG_PATH})
else()
    set(DPDK_ROOT ${DPDK_RELEASE_PATH})
endif()

message(STATUS "DPDK路径: ${DPDK_ROOT}")

# 设置包含目录
set(DPDK_INCLUDE_DIRS
    ${DPDK_ROOT}/external/include
    ${DPDK_ROOT}/external/include/dpdk
)

# 库目录
set(DPDK_LIB_DIR ${DPDK_ROOT}/external/lib)

# 查找所有librte_*.a库（排除libdpdk.a）
file(GLOB DPDK_RTE_LIBS ${DPDK_LIB_DIR}/librte_*.a)
file(GLOB DPDK_OTHER_LIBS 
    ${DPDK_LIB_DIR}/libIPSec_MB.a
    ${DPDK_LIB_DIR}/libccan.a
    ${DPDK_LIB_DIR}/libibverbs.a
    ${DPDK_LIB_DIR}/libmlx4.a
    ${DPDK_LIB_DIR}/libmlx5.a
    ${DPDK_LIB_DIR}/libpicotls-core.a
    ${DPDK_LIB_DIR}/libpicotls-openssl.a
    ${DPDK_LIB_DIR}/libquicly.a
    ${DPDK_LIB_DIR}/librdma_util.a
)

# 组合所有库
set(DPDK_LIBRARIES ${DPDK_RTE_LIBS} ${DPDK_OTHER_LIBS})

# 按依赖顺序排序（重要！）
# 将基础库放在前面，驱动库放在后面
function(sort_dpdk_libraries)
    set(sorted_libs)
    
    # 第一组：核心基础库
    foreach(pattern 
        librte_eal.a
        librte_kvargs.a
        librte_ring.a
        librte_mempool.a
        librte_mbuf.a
        librte_hash.a
        librte_net.a
        librte_ethdev.a
        librte_pci.a
        librte_bus_pci.a
    )
        foreach(lib ${DPDK_LIBRARIES})
            get_filename_component(libname ${lib} NAME)
            if(${libname} STREQUAL ${pattern})
                list(APPEND sorted_libs ${lib})
            endif()
        endforeach()
    endforeach()
    
    # 第二组：其他所有库
    foreach(lib ${DPDK_LIBRARIES})
        if(NOT lib IN_LIST sorted_libs)
            list(APPEND sorted_libs ${lib})
        endif()
    endforeach()
    
    set(DPDK_LIBRARIES ${sorted_libs} PARENT_SCOPE)
endfunction()

sort_dpdk_libraries()

message(STATUS "找到 ${DPDK_RTE_LIBS} 个DPDK库")
message(STATUS "前10个库:")
list(LENGTH DPDK_LIBRARIES lib_count)
math(EXPR show_count "10")
if(${lib_count} LESS ${show_count})
    set(show_count ${lib_count})
endif()

foreach(i RANGE 0 ${show_count})
    list(GET DPDK_LIBRARIES ${i} lib)
    if(lib)
        get_filename_component(libname ${lib} NAME)
        message(STATUS "  ${libname}")
    endif()
endforeach()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 创建可执行文件
add_executable(${PROJECT_NAME}
    main.c
    src/dpdk_utils.c
)

# 包含目录
target_include_directories(${PROJECT_NAME} PRIVATE
    ${DPDK_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 链接所有DPDK库（使用组解决循环依赖）
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    # 使用--start-group和--end-group解决循环依赖
    target_link_options(${PROJECT_NAME} PRIVATE
        -Wl,--start-group
    )
endif()

# 逐个链接库
foreach(lib ${DPDK_LIBRARIES})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${lib})
endforeach()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_link_options(${PROJECT_NAME} PRIVATE
        -Wl,--end-group
    )
endif()

# 系统库
find_package(Threads REQUIRED)

# 查找系统库
find_library(NUMA_LIB numa)
find_library(ATOMIC_LIB atomic)
find_library(CRYPT_LIB crypt)
find_library(RT_LIB rt)
find_library(DL_LIB dl)
find_library(M_LIB m)
find_library(PTHREAD_LIB pthread)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${CMAKE_THREAD_LIBS_INIT}
)

if(NUMA_LIB)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${NUMA_LIB})
endif()
if(ATOMIC_LIB)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${ATOMIC_LIB})
endif()
if(CRYPT_LIB)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${CRYPT_LIB})
endif()
if(RT_LIB)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${RT_LIB})
endif()
if(DL_LIB)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${DL_LIB})
endif()
if(M_LIB)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${M_LIB})
endif()
if(PTHREAD_LIB)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${PTHREAD_LIB})
endif()

# 额外的链接器选项
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_link_options(${PROJECT_NAME} PRIVATE
        -Wl,--no-as-needed
        -Wl,--copy-dt-needed-entries
    )
endif()

# 安装目标
install(TARGETS ${PROJECT_NAME} DESTINATION bin)

# 测试
enable_testing()
add_test(NAME test_basic
    COMMAND sudo $<TARGET_FILE:${PROJECT_NAME}> --help
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)