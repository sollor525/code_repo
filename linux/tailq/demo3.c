#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/queue.h>

/* TAILQ_HEAD定义和队列元素定义 */
#ifndef TAILQ_END
#define TAILQ_END(head) (NULL)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, next) \
for ((var) = TAILQ_FIRST(head);                 \
        (var) != TAILQ_END(head) &&             \
        ((next) = TAILQ_NEXT(var, field), 1); (var) = (next))
#endif

typedef struct test_event {
    int value;
    TAILQ_ENTRY(test_event) tailq_entry;
} test_event_t;

TAILQ_HEAD(tailq_head, test_event) g_tailq;
/* ====== end ====== */

int main(int argc, char const *argv[])
{
    int i;
    test_event_t *event = NULL; /* 声明队列元素 */
    test_event_t *new_event = NULL; /* 声明队列元素 */
    test_event_t *next = NULL; /* 声明队列元素 */

    TAILQ_INIT(&g_tailq); /* 初始化队列 */

    /* 在在队列尾部插入元素 */
    for (i = 0; i < 5; i++) {
        event = (test_event_t *)malloc(sizeof(test_event_t));
        event->value = i;
        TAILQ_INSERT_TAIL(&g_tailq, event, tailq_entry);
    }

    /* 判断队列空 */
    if (TAILQ_EMPTY(&g_tailq)) {
        printf("empty\n");
    }

    /* 遍历队列元素 */
    TAILQ_FOREACH(event, &g_tailq, tailq_entry) {
        printf("event->value:%d\n", event->value);
    }

    /* 指定位置插入元素 */
    TAILQ_FOREACH(event, &g_tailq, tailq_entry) {
        /* 在 value == 1 元素之前插入元素 */
        if (event->value == 1) {
            new_event = (test_event_t *)malloc(sizeof(test_event_t));
            new_event->value = 10;
            TAILQ_INSERT_BEFORE(event, new_event, tailq_entry);
        }
        /* 在 value == 3 元素之后插入元素 */
        if (event->value == 3) {
            new_event = (test_event_t *)malloc(sizeof(test_event_t));
            new_event->value = 30;
            TAILQ_INSERT_AFTER(&g_tailq, event, new_event, tailq_entry);
        }
    }

    /* 获取队列第一个元素 */
    event = TAILQ_FIRST(&g_tailq);
    printf("first event->value: %d\n", event->value);

    /* 获取队列最后一个元素 */
    event = TAILQ_LAST(&g_tailq, tailq_head);
    printf("last event->value: %d\n", event->value);

    /* 从队列中移除元素，此段参考 http://www.cnblogs.com/chenyuejun/p/3867846.html */
    TAILQ_FOREACH_SAFE(event, &g_tailq, tailq_entry, next) {
        TAILQ_REMOVE(&g_tailq, event, tailq_entry);
        free(event);
    }

    return 0;
}