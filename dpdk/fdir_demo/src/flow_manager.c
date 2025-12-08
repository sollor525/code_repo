/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_jhash.h>
#include "flow_manager.h"
#include "fdir_core.h"
#include "dpdk_utils.h"

/* 内部函数声明 */
static uint32_t fdir_flow_manager_get_index(struct fdir_flow_manager *mgr,
                                           uint32_t rule_id);
static int fdir_flow_manager_set_index(struct fdir_flow_manager *mgr,
                                      uint32_t rule_id, uint32_t index);
static void fdir_flow_manager_clear_index(struct fdir_flow_manager *mgr,
                                         uint32_t index);
static int fdir_flow_manager_create_rte_flow(struct fdir_flow_manager *mgr,
                                            struct fdir_flow_config *rule);
static int fdir_flow_manager_destroy_rte_flow(struct fdir_flow_manager *mgr,
                                             uint32_t index);
static bool fdir_flow_manager_is_rule_valid(const struct fdir_flow_config *rule);

/**
 * 初始化Flow管理器
 */
int fdir_flow_manager_init(struct fdir_flow_manager *mgr, uint16_t port_id,
                           uint32_t max_rules)
{
    if (!mgr || max_rules == 0) {
        printf("Error: Invalid parameters for flow manager init\n");
        return FDIR_INVALID_PARAM;
    }

    memset(mgr, 0, sizeof(*mgr));
    mgr->port_id = port_id;
    mgr->max_rules = max_rules;

    /* 分配规则数组 */
    mgr->rules = (struct fdir_flow_config *)rte_zmalloc(
        "flow_rules", max_rules * sizeof(struct fdir_flow_config), 0);
    if (!mgr->rules) {
        printf("Error: Failed to allocate memory for flow rules\n");
        return FDIR_NO_MEMORY;
    }

    /* 分配rte_flow对象数组 */
    mgr->rte_flows = (struct rte_flow **)rte_zmalloc(
        "rte_flows", max_rules * sizeof(struct rte_flow *), 0);
    if (!mgr->rte_flows) {
        printf("Error: Failed to allocate memory for rte flows\n");
        rte_free(mgr->rules);
        return FDIR_NO_MEMORY;
    }

    /* 分配规则ID映射表 */
    mgr->rule_id_map = (uint32_t *)rte_zmalloc(
        "rule_id_map", max_rules * sizeof(uint32_t), 0);
    if (!mgr->rule_id_map) {
        printf("Error: Failed to allocate memory for rule ID map\n");
        rte_free(mgr->rules);
        rte_free(mgr->rte_flows);
        return FDIR_NO_MEMORY;
    }

    /* 初始化映射表 */
    for (uint32_t i = 0; i < max_rules; i++) {
        mgr->rule_id_map[i] = 0xFFFFFFFF; /* 表示无效 */
    }

    /* 初始化读写锁 */
    if (pthread_rwlock_init(&mgr->lock, NULL) != 0) {
        printf("Error: Failed to initialize flow manager lock\n");
        rte_free(mgr->rules);
        rte_free(mgr->rte_flows);
        rte_free(mgr->rule_id_map);
        return FDIR_ERROR;
    }

    mgr->initialized = true;

    printf("Flow manager initialized for port %u with max %u rules\n",
           port_id, max_rules);

    return FDIR_SUCCESS;
}

/**
 * 清理Flow管理器
 */
int fdir_flow_manager_cleanup(struct fdir_flow_manager *mgr)
{
    if (!mgr || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    /* 销毁所有rte_flow */
    pthread_rwlock_wrlock(&mgr->lock);
    for (uint32_t i = 0; i < mgr->max_rules; i++) {
        if (mgr->rte_flows[i]) {
            struct rte_flow_error error;
            rte_flow_destroy(mgr->port_id, mgr->rte_flows[i], &error);
            mgr->rte_flows[i] = NULL;
        }
    }
    pthread_rwlock_unlock(&mgr->lock);

    /* 销毁读写锁 */
    pthread_rwlock_destroy(&mgr->lock);

    /* 释放内存 */
    rte_free(mgr->rules);
    rte_free(mgr->rte_flows);
    rte_free(mgr->rule_id_map);

    memset(mgr, 0, sizeof(*mgr));

    printf("Flow manager cleanup completed\n");
    return FDIR_SUCCESS;
}

/**
 * 添加Flow规则
 */
int fdir_flow_manager_add_rule(struct fdir_flow_manager *mgr,
                              const struct fdir_flow_config *rule)
{
    uint32_t index, rule_id;
    int ret;

    if (!mgr || !rule || !mgr->initialized) {
        printf("Error: Invalid parameters for add rule\n");
        return FDIR_INVALID_PARAM;
    }

    if (!fdir_flow_manager_is_rule_valid(rule)) {
        printf("Error: Invalid flow rule configuration\n");
        return FDIR_INVALID_PARAM;
    }

    if (mgr->rule_count >= mgr->max_rules) {
        printf("Error: Flow manager reached maximum rule count\n");
        return FDIR_NO_MEMORY;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    /* 检查规则ID是否已存在 */
    if (fdir_flow_manager_get_index(mgr, rule->rule_id) != 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: Rule ID %u already exists\n", rule->rule_id);
        return FDIR_ALREADY_EXISTS;
    }

    /* 查找空闲位置 */
    for (index = 0; index < mgr->max_rules; index++) {
        if (mgr->rule_id_map[index] == 0xFFFFFFFF) {
            break;
        }
    }

    if (index >= mgr->max_rules) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: No free slot for new rule\n");
        return FDIR_NO_MEMORY;
    }

    /* 创建rte_flow */
    ret = fdir_flow_manager_create_rte_flow(mgr, (struct fdir_flow_config *)rule);
    if (ret != FDIR_SUCCESS) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: Failed to create rte flow for rule %u\n", rule->rule_id);
        return ret;
    }

    /* 复制规则配置 */
    rte_memcpy(&mgr->rules[index], rule, sizeof(*rule));
    mgr->rules[index].port_id = mgr->port_id; /* 确保端口ID正确 */

    /* 设置映射 */
    rule_id = rule->rule_id;
    fdir_flow_manager_set_index(mgr, rule_id, index);

    mgr->rule_count++;

    pthread_rwlock_unlock(&mgr->lock);

    printf("Flow rule added: ID=%u, Type=%s, Queue=%u\n",
           rule_id, fdir_flow_type_to_string(rule->type), rule->action.queue);

    return FDIR_SUCCESS;
}

/**
 * 删除Flow规则
 */
int fdir_flow_manager_del_rule(struct fdir_flow_manager *mgr, uint32_t rule_id)
{
    uint32_t index;
    int ret;

    if (!mgr || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    /* 查找规则索引 */
    index = fdir_flow_manager_get_index(mgr, rule_id);
    if (index == 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: Rule ID %u not found\n", rule_id);
        return FDIR_NOT_FOUND;
    }

    /* 销毁rte_flow */
    ret = fdir_flow_manager_destroy_rte_flow(mgr, index);
    if (ret != FDIR_SUCCESS) {
        printf("Warning: Failed to destroy rte flow for rule %u\n", rule_id);
        /* 继续执行，清理本地数据 */
    }

    /* 清理规则数据 */
    memset(&mgr->rules[index], 0, sizeof(mgr->rules[index]));
    fdir_flow_manager_clear_index(mgr, index);

    mgr->rule_count--;

    pthread_rwlock_unlock(&mgr->lock);

    printf("Flow rule deleted: ID=%u\n", rule_id);
    return FDIR_SUCCESS;
}

/**
 * 更新Flow规则
 */
int fdir_flow_manager_update_rule(struct fdir_flow_manager *mgr,
                                 const struct fdir_flow_config *rule)
{
    uint32_t index;
    int ret;

    if (!mgr || !rule || !mgr->initialized) {
        printf("Error: Invalid parameters for update rule\n");
        return FDIR_INVALID_PARAM;
    }

    if (!fdir_flow_manager_is_rule_valid(rule)) {
        printf("Error: Invalid flow rule configuration\n");
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    /* 查找规则索引 */
    index = fdir_flow_manager_get_index(mgr, rule->rule_id);
    if (index == 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: Rule ID %u not found\n", rule->rule_id);
        return FDIR_NOT_FOUND;
    }

    /* 销毁旧的rte_flow */
    ret = fdir_flow_manager_destroy_rte_flow(mgr, index);
    if (ret != FDIR_SUCCESS) {
        printf("Warning: Failed to destroy old rte flow for rule %u\n",
               rule->rule_id);
    }

    /* 创建新的rte_flow */
    ret = fdir_flow_manager_create_rte_flow(mgr, (struct fdir_flow_config *)rule);
    if (ret != FDIR_SUCCESS) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: Failed to create new rte flow for rule %u\n",
               rule->rule_id);
        return ret;
    }

    /* 更新规则配置 */
    rte_memcpy(&mgr->rules[index], rule, sizeof(*rule));
    mgr->rules[index].port_id = mgr->port_id;

    pthread_rwlock_unlock(&mgr->lock);

    printf("Flow rule updated: ID=%u, Type=%s, Queue=%u\n",
           rule->rule_id, fdir_flow_type_to_string(rule->type),
           rule->action.queue);

    return FDIR_SUCCESS;
}

/**
 * 获取Flow规则
 */
int fdir_flow_manager_get_rule(struct fdir_flow_manager *mgr, uint32_t rule_id,
                               struct fdir_flow_config *rule)
{
    uint32_t index;

    if (!mgr || !rule || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&mgr->lock);

    /* 查找规则索引 */
    index = fdir_flow_manager_get_index(mgr, rule_id);
    if (index == 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_NOT_FOUND;
    }

    /* 复制规则 */
    rte_memcpy(rule, &mgr->rules[index], sizeof(*rule));

    pthread_rwlock_unlock(&mgr->lock);

    return FDIR_SUCCESS;
}

/**
 * 列出所有Flow规则
 */
int fdir_flow_manager_list_rules(struct fdir_flow_manager *mgr,
                                struct fdir_flow_config *rules,
                                uint32_t *count)
{
    uint32_t i, out_count = 0;

    if (!mgr || !count || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&mgr->lock);

    /* 统计规则数量 */
    if (!rules) {
        *count = mgr->rule_count;
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_SUCCESS;
    }

    /* 复制规则 */
    for (i = 0; i < mgr->max_rules && out_count < *count; i++) {
        if (mgr->rule_id_map[i] != 0xFFFFFFFF) {
            rte_memcpy(&rules[out_count], &mgr->rules[i], sizeof(*rules));
            out_count++;
        }
    }

    *count = out_count;

    pthread_rwlock_unlock(&mgr->lock);

    return FDIR_SUCCESS;
}

/**
 * 启用Flow规则
 */
int fdir_flow_manager_enable_rule(struct fdir_flow_manager *mgr, uint32_t rule_id)
{
    uint32_t index;

    if (!mgr || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    /* 查找规则索引 */
    index = fdir_flow_manager_get_index(mgr, rule_id);
    if (index == 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_NOT_FOUND;
    }

    /* 检查是否已经启用 */
    if (mgr->rules[index].active) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_SUCCESS; /* 已经启用 */
    }

    /* 创建rte_flow */
    if (fdir_flow_manager_create_rte_flow(mgr, &mgr->rules[index]) != FDIR_SUCCESS) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_ERROR;
    }

    mgr->rules[index].active = true;

    pthread_rwlock_unlock(&mgr->lock);

    printf("Flow rule enabled: ID=%u\n", rule_id);
    return FDIR_SUCCESS;
}

/**
 * 停用Flow规则
 */
int fdir_flow_manager_disable_rule(struct fdir_flow_manager *mgr, uint32_t rule_id)
{
    uint32_t index;

    if (!mgr || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    /* 查找规则索引 */
    index = fdir_flow_manager_get_index(mgr, rule_id);
    if (index == 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_NOT_FOUND;
    }

    /* 检查是否已经停用 */
    if (!mgr->rules[index].active) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_SUCCESS; /* 已经停用 */
    }

    /* 销毁rte_flow */
    fdir_flow_manager_destroy_rte_flow(mgr, index);

    mgr->rules[index].active = false;

    pthread_rwlock_unlock(&mgr->lock);

    printf("Flow rule disabled: ID=%u\n", rule_id);
    return FDIR_SUCCESS;
}

/**
 * 批量添加规则
 */
int fdir_flow_manager_bulk_add(struct fdir_flow_manager *mgr,
                               const struct fdir_flow_bulk_op *bulk_op)
{
    uint32_t i;
    int ret = FDIR_SUCCESS;

    if (!mgr || !bulk_op || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    /* 检查是否有足够空间 */
    if (mgr->rule_count + bulk_op->rule_count > mgr->max_rules) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: Not enough space for bulk add\n");
        return FDIR_NO_MEMORY;
    }

    /* 逐个添加规则 */
    for (i = 0; i < bulk_op->rule_count; i++) {
        /* 检查规则是否有效 */
        if (!fdir_flow_manager_is_rule_valid(&bulk_op->rules[i])) {
            if (bulk_op->results) {
                bulk_op->results[i].success = false;
                bulk_op->results[i].error_code = FDIR_INVALID_PARAM;
                snprintf(bulk_op->results[i].error_msg,
                        sizeof(bulk_op->results[i].error_msg),
                        "Invalid rule configuration");
            }
            continue;
        }

        /* 检查规则ID是否已存在 */
        if (fdir_flow_manager_get_index(mgr, bulk_op->rules[i].rule_id) != 0xFFFFFFFF) {
            if (bulk_op->results) {
                bulk_op->results[i].success = false;
                bulk_op->results[i].error_code = FDIR_ALREADY_EXISTS;
                snprintf(bulk_op->results[i].error_msg,
                        sizeof(bulk_op->results[i].error_msg),
                        "Rule ID already exists");
            }
            continue;
        }

        /* 创建rte_flow */
        if (fdir_flow_manager_create_rte_flow(mgr, &bulk_op->rules[i]) != FDIR_SUCCESS) {
            if (bulk_op->results) {
                bulk_op->results[i].success = false;
                bulk_op->results[i].error_code = FDIR_ERROR;
                snprintf(bulk_op->results[i].error_msg,
                        sizeof(bulk_op->results[i].error_msg),
                        "Failed to create rte flow");
            }
            continue;
        }

        /* 添加到管理器 */
        /* 这里需要实际的添加逻辑，简化处理 */
        mgr->rule_count++;

        if (bulk_op->results) {
            bulk_op->results[i].success = true;
            bulk_op->results[i].rule_id = bulk_op->rules[i].rule_id;
        }
    }

    pthread_rwlock_unlock(&mgr->lock);

    return ret;
}

/**
 * 批量删除规则
 */
int fdir_flow_manager_bulk_delete(struct fdir_flow_manager *mgr,
                                  const uint32_t *rule_ids, uint32_t count)
{
    uint32_t i;
    int ret = FDIR_SUCCESS;

    if (!mgr || !rule_ids || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    for (i = 0; i < count; i++) {
        ret = fdir_flow_manager_del_rule(mgr, rule_ids[i]);
        if (ret != FDIR_SUCCESS) {
            printf("Warning: Failed to delete rule %u\n", rule_ids[i]);
        }
    }

    pthread_rwlock_unlock(&mgr->lock);

    return ret;
}

/**
 * 获取规则统计信息
 */
int fdir_flow_manager_get_stats(struct fdir_flow_manager *mgr,
                                uint32_t rule_id, struct rte_flow_query_count *stats)
{
    uint32_t index;
    struct rte_flow_error error;
    struct rte_flow_action_count action_count = {0};
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &action_count },
        { .type = RTE_FLOW_ACTION_TYPE_END }
    };

    if (!mgr || !stats || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&mgr->lock);

    /* 查找规则索引 */
    index = fdir_flow_manager_get_index(mgr, rule_id);
    if (index == 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_NOT_FOUND;
    }

    /* 检查是否有计数器 */
    if (!mgr->rules[index].action.counter_id) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_NOT_SUPPORTED;
    }

    /* 查询统计 */
    if (rte_flow_query(mgr->port_id, mgr->rte_flows[index],
                      actions, stats, &error) < 0) {
        pthread_rwlock_unlock(&mgr->lock);
        printf("Error: Failed to query flow stats: %s\n", error.message);
        return FDIR_ERROR;
    }

    pthread_rwlock_unlock(&mgr->lock);

    return FDIR_SUCCESS;
}

/**
 * 重置规则统计信息
 */
int fdir_flow_manager_reset_stats(struct fdir_flow_manager *mgr, uint32_t rule_id)
{
    uint32_t index;

    if (!mgr || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&mgr->lock);

    /* 查找规则索引 */
    index = fdir_flow_manager_get_index(mgr, rule_id);
    if (index == 0xFFFFFFFF) {
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_NOT_FOUND;
    }

    /* 重置统计信息 */
    /* DPDK的计数器通常不支持直接重置，需要重新创建flow */
    /* 这里简化处理 */

    pthread_rwlock_unlock(&mgr->lock);

    return FDIR_SUCCESS;
}

/**
 * 验证规则
 */
int fdir_flow_manager_validate_rule(struct fdir_flow_manager *mgr,
                                    const struct fdir_flow_config *rule,
                                    struct rte_flow_error *error)
{
    if (!mgr || !rule || !error || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    /* 检查基本参数 */
    if (rule->port_id != mgr->port_id) {
        error->message = "Port ID mismatch";
        return FDIR_INVALID_PARAM;
    }

    /* 检查队列索引 */
    if (rule->action.queue >= FDIR_MAX_QUEUES) {
        error->message = "Invalid queue index";
        return FDIR_INVALID_PARAM;
    }

    /* 检查优先级 */
    if (rule->priority > 0xFFFF) {
        error->message = "Priority too high";
        return FDIR_INVALID_PARAM;
    }

    /* 检查IP地址和掩码 */
    if (rule->match.src_ipv4.enabled && !rule->match.src_ipv4.addr) {
        error->message = "Source IPv4 address required";
        return FDIR_INVALID_PARAM;
    }
    if (rule->match.dst_ipv4.enabled && !rule->match.dst_ipv4.addr) {
        error->message = "Destination IPv4 address required";
        return FDIR_INVALID_PARAM;
    }

    /* 检查端口 */
    if (rule->match.src_port.enabled && !rule->match.src_port.port) {
        error->message = "Source port required";
        return FDIR_INVALID_PARAM;
    }
    if (rule->match.dst_port.enabled && !rule->match.dst_port.port) {
        error->message = "Destination port required";
        return FDIR_INVALID_PARAM;
    }

    return FDIR_SUCCESS;
}

/**
 * 根据名称查找规则
 */
int fdir_flow_manager_find_by_name(struct fdir_flow_manager *mgr,
                                   const char *name, uint32_t *rule_id)
{
    uint32_t i;

    if (!mgr || !name || !rule_id || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&mgr->lock);

    for (i = 0; i < mgr->max_rules; i++) {
        if (mgr->rule_id_map[i] != 0xFFFFFFFF) {
            if (strcmp(mgr->rules[i].name, name) == 0) {
                *rule_id = mgr->rules[i].rule_id;
                pthread_rwlock_unlock(&mgr->lock);
                return FDIR_SUCCESS;
            }
        }
    }

    pthread_rwlock_unlock(&mgr->lock);

    return FDIR_NOT_FOUND;
}

/**
 * 根据类型查找规则
 */
int fdir_flow_manager_find_by_type(struct fdir_flow_manager *mgr,
                                   enum fdir_flow_type type,
                                   uint32_t *rule_ids, uint32_t *count)
{
    uint32_t i, found = 0;

    if (!mgr || !count || !mgr->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&mgr->lock);

    /* 统计数量 */
    if (!rule_ids) {
        for (i = 0; i < mgr->max_rules; i++) {
            if (mgr->rule_id_map[i] != 0xFFFFFFFF) {
                if (mgr->rules[i].type == type) {
                    found++;
                }
            }
        }
        *count = found;
        pthread_rwlock_unlock(&mgr->lock);
        return FDIR_SUCCESS;
    }

    /* 查找规则 */
    for (i = 0; i < mgr->max_rules && found < *count; i++) {
        if (mgr->rule_id_map[i] != 0xFFFFFFFF) {
            if (mgr->rules[i].type == type) {
                rule_ids[found] = mgr->rules[i].rule_id;
                found++;
            }
        }
    }

    *count = found;

    pthread_rwlock_unlock(&mgr->lock);

    return FDIR_SUCCESS;
}

/* 内部函数实现 */

/**
 * 获取规则索引
 */
static uint32_t fdir_flow_manager_get_index(struct fdir_flow_manager *mgr,
                                           uint32_t rule_id)
{
    for (uint32_t i = 0; i < mgr->max_rules; i++) {
        if (mgr->rule_id_map[i] == rule_id) {
            return i;
        }
    }
    return 0xFFFFFFFF;
}

/**
 * 设置规则索引
 */
static int fdir_flow_manager_set_index(struct fdir_flow_manager *mgr,
                                      uint32_t rule_id, uint32_t index)
{
    if (index >= mgr->max_rules) {
        return FDIR_INVALID_PARAM;
    }
    mgr->rule_id_map[index] = rule_id;
    return FDIR_SUCCESS;
}

/**
 * 清理规则索引
 */
static void fdir_flow_manager_clear_index(struct fdir_flow_manager *mgr,
                                         uint32_t index)
{
    if (index < mgr->max_rules) {
        mgr->rule_id_map[index] = 0xFFFFFFFF;
    }
}

/**
 * 创建rte_flow
 */
static int fdir_flow_manager_create_rte_flow(struct fdir_flow_manager *mgr,
                                            struct fdir_flow_config *rule)
{
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[16];
    struct rte_flow_action actions[8];
    struct rte_flow_error error;
    struct rte_flow *flow;
    int idx = 0;

    /* 初始化属性 */
    memset(&attr, 0, sizeof(attr));
    attr.ingress = rule->ingress;
    attr.egress = rule->egress;
    attr.priority = rule->priority;

    /* 初始化模式和动作 */
    memset(pattern, 0, sizeof(pattern));
    memset(actions, 0, sizeof(actions));

    /* 构建模式 */
    /* Ethernet */
    if (rule->match.src_mac.enabled || rule->match.dst_mac.enabled) {
        struct rte_flow_item_eth eth_spec = {0};
        struct rte_flow_item_eth eth_mask = {0};

        if (rule->match.src_mac.enabled) {
            rte_memcpy(&eth_spec.src.addr_bytes,
                      &rule->match.src_mac.addr.addr_bytes, 6);
            memset(&eth_mask.src.addr_bytes, 0xFF, 6);
        }
        if (rule->match.dst_mac.enabled) {
            rte_memcpy(&eth_spec.dst.addr_bytes,
                      &rule->match.dst_mac.addr.addr_bytes, 6);
            memset(&eth_mask.dst.addr_bytes, 0xFF, 6);
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_ETH;
        pattern[idx].spec = &eth_spec;
        pattern[idx].mask = &eth_mask;
        idx++;
    }

    /* VLAN */
    if (rule->match.vlan.enabled) {
        struct rte_flow_item_vlan vlan_spec = {0};
        struct rte_flow_item_vlan vlan_mask = {0};

        vlan_spec.tci = htons(rule->match.vlan.tci);
        vlan_mask.tci = htons(rule->match.vlan.mask);

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_VLAN;
        pattern[idx].spec = &vlan_spec;
        pattern[idx].mask = &vlan_mask;
        idx++;
    }

    /* IPv4 */
    if (rule->match.src_ipv4.enabled || rule->match.dst_ipv4.enabled ||
        rule->match.protocol.enabled) {
        struct rte_flow_item_ipv4 ipv4_spec = {0};
        struct rte_flow_item_ipv4 ipv4_mask = {0};

        if (rule->match.src_ipv4.enabled) {
            ipv4_spec.hdr.src_addr = htonl(rule->match.src_ipv4.addr);
            ipv4_mask.hdr.src_addr = rule->match.src_ipv4.mask;
        }
        if (rule->match.dst_ipv4.enabled) {
            ipv4_spec.hdr.dst_addr = htonl(rule->match.dst_ipv4.addr);
            ipv4_mask.hdr.dst_addr = rule->match.dst_ipv4.mask;
        }
        if (rule->match.protocol.enabled) {
            ipv4_spec.hdr.next_proto_id = rule->match.protocol.protocol;
            ipv4_mask.hdr.next_proto_id = rule->match.protocol.mask;
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_IPV4;
        pattern[idx].spec = &ipv4_spec;
        pattern[idx].mask = &ipv4_mask;
        idx++;
    }

    /* TCP */
    if (rule->match.src_port.enabled || rule->match.dst_port.enabled ||
        rule->match.tcp_flags.enabled) {
        struct rte_flow_item_tcp tcp_spec = {0};
        struct rte_flow_item_tcp tcp_mask = {0};

        if (rule->match.src_port.enabled) {
            tcp_spec.hdr.src_port = htons(rule->match.src_port.port);
            tcp_mask.hdr.src_port = htons(rule->match.src_port.mask);
        }
        if (rule->match.dst_port.enabled) {
            tcp_spec.hdr.dst_port = htons(rule->match.dst_port.port);
            tcp_mask.hdr.dst_port = htons(rule->match.dst_port.mask);
        }
        if (rule->match.tcp_flags.enabled) {
            tcp_spec.hdr.tcp_flags = rule->match.tcp_flags.flags;
            tcp_mask.hdr.tcp_flags = rule->match.tcp_flags.mask;
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_TCP;
        pattern[idx].spec = &tcp_spec;
        pattern[idx].mask = &tcp_mask;
        idx++;
    }

    /* UDP */
    if (rule->match.src_port.enabled || rule->match.dst_port.enabled) {
        struct rte_flow_item_udp udp_spec = {0};
        struct rte_flow_item_udp udp_mask = {0};

        if (rule->match.src_port.enabled) {
            udp_spec.hdr.src_port = htons(rule->match.src_port.port);
            udp_mask.hdr.src_port = htons(rule->match.src_port.mask);
        }
        if (rule->match.dst_port.enabled) {
            udp_spec.hdr.dst_port = htons(rule->match.dst_port.port);
            udp_mask.hdr.dst_port = htons(rule->match.dst_port.mask);
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_UDP;
        pattern[idx].spec = &udp_spec;
        pattern[idx].mask = &udp_mask;
        idx++;
    }

    /* 结束模式 */
    pattern[idx].type = RTE_FLOW_ITEM_TYPE_END;

    /* 构建动作 */
    idx = 0;

    /* 队列动作 */
    struct rte_flow_action_queue queue = { .index = rule->action.queue };
    actions[idx].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    actions[idx].conf = &queue;
    idx++;

    /* 标记动作 */
    if (rule->action.mark) {
        struct rte_flow_action_mark mark = { .id = rule->action.mark };
        actions[idx].type = RTE_FLOW_ACTION_TYPE_MARK;
        actions[idx].conf = &mark;
        idx++;
    }

    /* 计数动作 */
    if (rule->action.counter_id) {
        actions[idx].type = RTE_FLOW_ACTION_TYPE_COUNT;
        idx++;
    }

    /* 结束动作 */
    actions[idx].type = RTE_FLOW_ACTION_TYPE_END;

    /* 创建flow */
    flow = rte_flow_create(mgr->port_id, &attr, pattern, actions, &error);
    if (!flow) {
        printf("Error: Failed to create flow: %s\n", error.message);
        return FDIR_ERROR;
    }

    /* 保存flow对象 */
    /* 这里需要找到对应的索引保存，简化处理 */
    for (uint32_t i = 0; i < mgr->max_rules; i++) {
        if (mgr->rule_id_map[i] == rule->rule_id) {
            mgr->rte_flows[i] = flow;
            break;
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 销毁rte_flow
 */
static int fdir_flow_manager_destroy_rte_flow(struct fdir_flow_manager *mgr,
                                             uint32_t index)
{
    if (index >= mgr->max_rules || !mgr->rte_flows[index]) {
        return FDIR_SUCCESS;
    }

    struct rte_flow_error error;
    if (rte_flow_destroy(mgr->port_id, mgr->rte_flows[index], &error) < 0) {
        printf("Error: Failed to destroy flow: %s\n", error.message);
        return FDIR_ERROR;
    }

    mgr->rte_flows[index] = NULL;
    return FDIR_SUCCESS;
}

/**
 * 检查规则是否有效
 */
static bool fdir_flow_manager_is_rule_valid(const struct fdir_flow_config *rule)
{
    if (!rule) {
        return false;
    }

    /* 检查规则名称 */
    if (strlen(rule->name) == 0) {
        return false;
    }

    /* 检查规则ID */
    if (rule->rule_id == 0) {
        return false;
    }

    /* 检查动作 */
    if (rule->action.queue >= FDIR_MAX_QUEUES) {
        return false;
    }

    /* 检查匹配条件 */
    /* 至少需要一个匹配条件 */
    if (!rule->match.src_mac.enabled && !rule->match.dst_mac.enabled &&
        !rule->match.vlan.enabled && !rule->match.src_ipv4.enabled &&
        !rule->match.dst_ipv4.enabled && !rule->match.src_port.enabled &&
        !rule->match.dst_port.enabled && !rule->match.protocol.enabled) {
        return false;
    }

    return true;
}

/* 工具函数 */

/**
 * Flow类型转字符串
 */
const char *fdir_flow_type_to_string(enum fdir_flow_type type)
{
    switch (type) {
    case FDIR_FLOW_TYPE_IPV4:
        return "IPv4";
    case FDIR_FLOW_TYPE_IPV6:
        return "IPv6";
    case FDIR_FLOW_TYPE_TCP:
        return "TCP";
    case FDIR_FLOW_TYPE_UDP:
        return "UDP";
    case FDIR_FLOW_TYPE_VLAN:
        return "VLAN";
    case FDIR_FLOW_TYPE_HTTP:
        return "HTTP";
    case FDIR_FLOW_TYPE_TLS:
        return "TLS";
    case FDIR_FLOW_TYPE_ICMP:
        return "ICMP";
    case FDIR_FLOW_TYPE_CUSTOM:
        return "Custom";
    default:
        return "Unknown";
    }
}

/**
 * Flow动作转字符串
 */
const char *fdir_flow_action_to_string(enum fdir_flow_action action)
{
    switch (action) {
    case FDIR_FLOW_ACTION_QUEUE:
        return "Queue";
    case FDIR_FLOW_ACTION_DROP:
        return "Drop";
    case FDIR_FLOW_ACTION_MARK:
        return "Mark";
    case FDIR_FLOW_ACTION_COUNT:
        return "Count";
    case FDIR_FLOW_ACTION_RSS:
        return "RSS";
    case FDIR_FLOW_ACTION_PASSTHRU:
        return "Passthru";
    default:
        return "Unknown";
    }
}

/**
 * 匹配模式转字符串
 */
const char *fdir_flow_match_mode_to_string(enum fdir_flow_match_mode mode)
{
    switch (mode) {
    case FDIR_FLOW_MATCH_EXACT:
        return "Exact";
    case FDIR_FLOW_MATCH_PREFIX:
        return "Prefix";
    case FDIR_FLOW_MATCH_RANGE:
        return "Range";
    case FDIR_FLOW_MATCH_WILDCARD:
        return "Wildcard";
    case FDIR_FLOW_MATCH_MASK:
        return "Mask";
    default:
        return "Unknown";
    }
}

/**
 * 字符串转Flow类型
 */
enum fdir_flow_type fdir_flow_string_to_type(const char *str)
{
    if (!str) {
        return FDIR_FLOW_TYPE_MAX;
    }

    if (strcasecmp(str, "ipv4") == 0) {
        return FDIR_FLOW_TYPE_IPV4;
    } else if (strcasecmp(str, "ipv6") == 0) {
        return FDIR_FLOW_TYPE_IPV6;
    } else if (strcasecmp(str, "tcp") == 0) {
        return FDIR_FLOW_TYPE_TCP;
    } else if (strcasecmp(str, "udp") == 0) {
        return FDIR_FLOW_TYPE_UDP;
    } else if (strcasecmp(str, "vlan") == 0) {
        return FDIR_FLOW_TYPE_VLAN;
    } else if (strcasecmp(str, "http") == 0) {
        return FDIR_FLOW_TYPE_HTTP;
    } else if (strcasecmp(str, "tls") == 0) {
        return FDIR_FLOW_TYPE_TLS;
    } else if (strcasecmp(str, "icmp") == 0) {
        return FDIR_FLOW_TYPE_ICMP;
    } else if (strcasecmp(str, "custom") == 0) {
        return FDIR_FLOW_TYPE_CUSTOM;
    }

    return FDIR_FLOW_TYPE_MAX;
}

/**
 * 字符串转Flow动作
 */
enum fdir_flow_action fdir_flow_string_to_action(const char *str)
{
    if (!str) {
        return FDIR_FLOW_ACTION_MAX;
    }

    if (strcasecmp(str, "queue") == 0) {
        return FDIR_FLOW_ACTION_QUEUE;
    } else if (strcasecmp(str, "drop") == 0) {
        return FDIR_FLOW_ACTION_DROP;
    } else if (strcasecmp(str, "mark") == 0) {
        return FDIR_FLOW_ACTION_MARK;
    } else if (strcasecmp(str, "count") == 0) {
        return FDIR_FLOW_ACTION_COUNT;
    } else if (strcasecmp(str, "rss") == 0) {
        return FDIR_FLOW_ACTION_RSS;
    } else if (strcasecmp(str, "passthru") == 0) {
        return FDIR_FLOW_ACTION_PASSTHRU;
    }

    return FDIR_FLOW_ACTION_MAX;
}

#if FDIR_DEBUG
/**
 * 调试：打印所有规则
 */
void fdir_flow_manager_print_rules(struct fdir_flow_manager *mgr)
{
    if (!mgr || !mgr->initialized) {
        printf("Flow manager not initialized\n");
        return;
    }

    printf("\n=== Flow Manager Rules ===\n");
    printf("Total rules: %u / %u\n", mgr->rule_count, mgr->max_rules);
    printf("Port ID: %u\n", mgr->port_id);

    pthread_rwlock_rdlock(&mgr->lock);

    for (uint32_t i = 0; i < mgr->max_rules; i++) {
        if (mgr->rule_id_map[i] != 0xFFFFFFFF) {
            printf("\nRule %u:\n", i);
            printf("  ID: %u\n", mgr->rules[i].rule_id);
            printf("  Name: %s\n", mgr->rules[i].name);
            printf("  Type: %s\n", fdir_flow_type_to_string(mgr->rules[i].type));
            printf("  Priority: %u\n", mgr->rules[i].priority);
            printf("  Queue: %u\n", mgr->rules[i].action.queue);
            printf("  Active: %s\n", mgr->rules[i].active ? "Yes" : "No");
            printf("  Description: %s\n", mgr->rules[i].description);
        }
    }

    pthread_rwlock_unlock(&mgr->lock);
    printf("===========================\n\n");
}

/**
 * 调试：打印规则配置
 */
void fdir_flow_print_config(const struct fdir_flow_config *rule)
{
    if (!rule) {
        printf("Rule config is NULL\n");
        return;
    }

    printf("\n=== Flow Rule Config ===\n");
    printf("Rule ID: %u\n", rule->rule_id);
    printf("Name: %s\n", rule->name);
    printf("Description: %s\n", rule->description);
    printf("Type: %s\n", fdir_flow_type_to_string(rule->type));
    printf("Priority: %u\n", rule->priority);
    printf("Port ID: %u\n", rule->port_id);
    printf("Active: %s\n", rule->active ? "Yes" : "No");
    printf("Ingress: %s\n", rule->ingress ? "Yes" : "No");
    printf("Egress: %s\n", rule->egress ? "Yes" : "No");

    printf("\nMatch Conditions:\n");
    if (rule->match.src_mac.enabled) {
        printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               rule->match.src_mac.addr.addr_bytes[0],
               rule->match.src_mac.addr.addr_bytes[1],
               rule->match.src_mac.addr.addr_bytes[2],
               rule->match.src_mac.addr.addr_bytes[3],
               rule->match.src_mac.addr.addr_bytes[4],
               rule->match.src_mac.addr.addr_bytes[5]);
    }
    if (rule->match.dst_mac.enabled) {
        printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               rule->match.dst_mac.addr.addr_bytes[0],
               rule->match.dst_mac.addr.addr_bytes[1],
               rule->match.dst_mac.addr.addr_bytes[2],
               rule->match.dst_mac.addr.addr_bytes[3],
               rule->match.dst_mac.addr.addr_bytes[4],
               rule->match.dst_mac.addr.addr_bytes[5]);
    }
    if (rule->match.vlan.enabled) {
        printf("  VLAN: %u\n", rule->match.vlan.tci);
    }
    if (rule->match.src_ipv4.enabled) {
        printf("  Src IPv4: %08x\n", rule->match.src_ipv4.addr);
    }
    if (rule->match.dst_ipv4.enabled) {
        printf("  Dst IPv4: %08x\n", rule->match.dst_ipv4.addr);
    }
    if (rule->match.src_port.enabled) {
        printf("  Src Port: %u\n", rule->match.src_port.port);
    }
    if (rule->match.dst_port.enabled) {
        printf("  Dst Port: %u\n", rule->match.dst_port.port);
    }
    if (rule->match.protocol.enabled) {
        printf("  Protocol: %u\n", rule->match.protocol.protocol);
    }

    printf("\nActions:\n");
    printf("  Queue: %u\n", rule->action.queue);
    printf("  Mark: %u\n", rule->action.mark);
    printf("  Counter ID: %lu\n", rule->action.counter_id);

    printf("========================\n\n");
}
#endif /* FDIR_DEBUG */