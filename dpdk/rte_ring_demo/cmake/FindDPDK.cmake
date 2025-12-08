# cmake/FindDPDK.cmake
include(CheckLibraryExists)

# 查找DPDK包含目录
find_path(DPDK_INCLUDE_DIR
    NAMES rte_config.h
    PATHS ${DPDK_ROOT}
    PATH_SUFFIXES
        external/include
        include
    NO_DEFAULT_PATH
)

if(NOT DPDK_INCLUDE_DIR)
    message(FATAL_ERROR "未找到DPDK包含目录，请检查DPDK_ROOT路径: ${DPDK_ROOT}")
endif()

# 设置包含目录
set(DPDK_INCLUDE_DIRS
    ${DPDK_INCLUDE_DIR}
    ${DPDK_INCLUDE_DIR}/dpdk
)

# 查找库目录
find_path(DPDK_LIBRARY_DIR
    NAMES libdpdk.a
    PATHS ${DPDK_ROOT}
    PATH_SUFFIXES
        external/lib
        lib
    NO_DEFAULT_PATH
)

if(NOT DPDK_LIBRARY_DIR)
    message(FATAL_ERROR "未找到DPDK库目录，请检查DPDK_ROOT路径: ${DPDK_ROOT}")
endif()

# 自动检测需要的库
function(find_dpdk_library lib_name)
    find_library(${lib_name}_LIBRARY
        NAMES ${lib_name}
        PATHS ${DPDK_LIBRARY_DIR}
        NO_DEFAULT_PATH
    )
    
    if(${lib_name}_LIBRARY)
        message(STATUS "找到DPDK库: ${${lib_name}_LIBRARY}")
        list(APPEND DPDK_LIBRARIES ${${lib_name}_LIBRARY})
        set(DPDK_LIBRARIES ${DPDK_LIBRARIES} PARENT_SCOPE)
    else()
        message(STATUS "未找到DPDK库: ${lib_name}")
    endif()
endfunction()

# 必须的DPDK库
set(DPDK_REQUIRED_LIBS
    rte_eal
    rte_ring
    rte_mempool
    rte_mbuf
    rte_kvargs
    rte_hash
    rte_net
    rte_ethdev
    rte_bus_pci
    rte_pci
    rte_bus_vdev
    rte_pmd_virtio
)

# 可选的DPDK库
set(DPDK_OPTIONAL_LIBS
    rte_malloc
    rte_timer
    rte_cmdline
    rte_metrics
    rte_telemetry
)

# 查找库
set(DPDK_LIBRARIES)
foreach(lib ${DPDK_REQUIRED_LIBS})
    find_dpdk_library(${lib})
endforeach()

# 检查是否找到必要库
if(NOT DPDK_LIBRARIES)
    message(FATAL_ERROR "未找到任何必要的DPDK库")
endif()

# 尝试添加libdpdk.a（如果存在）
find_library(DPDK_MAIN_LIB dpdk
    PATHS ${DPDK_LIBRARY_DIR}
    NO_DEFAULT_PATH
)

if(DPDK_MAIN_LIB)
    message(STATUS "找到libdpdk.a: ${DPDK_MAIN_LIB}")
    # 将libdpdk.a放在链接列表的开头
    set(DPDK_LIBRARIES ${DPDK_MAIN_LIB} ${DPDK_LIBRARIES})
endif()

# 移除可能的重复项
if(DPDK_LIBRARIES)
    list(REMOVE_DUPLICATES DPDK_LIBRARIES)
endif()

# 设置库目录
set(DPDK_LIBRARY_DIRS ${DPDK_LIBRARY_DIR})

# 处理结果
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DPDK
    REQUIRED_VARS
        DPDK_INCLUDE_DIR
        DPDK_LIBRARY_DIR
        DPDK_LIBRARIES
    VERSION_VAR DPDK_VERSION
)

# 打印总结
message(STATUS "DPDK配置总结:")
message(STATUS "  包含目录: ${DPDK_INCLUDE_DIRS}")
message(STATUS "  库目录:   ${DPDK_LIBRARY_DIRS}")
message(STATUS "  找到库数: ${DPDK_LIBRARIES}")