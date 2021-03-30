#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>    /* for offsetof */
#include <sys/time.h>

#define container_of(ptr, type, member) ({            \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})


#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)


#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member) \
    list_entry((ptr)->prev, type, member)

#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member) \
    list_entry((pos)->member.prev, typeof(*(pos)), member)
    
#define list_for_each_entry(pos, head, member)                \
    for (pos = list_first_entry(head, typeof(*pos), member);    \
         &pos->member != (head);                    \
         pos = list_next_entry(pos, member))

#define list_for_each_entry_reverse(pos, head, member)            \
    for (pos = list_last_entry(head, typeof(*pos), member);        \
         &pos->member != (head);                     \
         pos = list_prev_entry(pos, member))
         
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

struct list_head {
    struct list_head *next, *prev;
};
static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new,
                  struct list_head *prev,
                  struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}

struct QUEUE_ITEM{
    int value;
    struct list_head node;
};

LIST_HEAD(queue_head);

#define ITEM_NUM 5000000
#define TRAVERSAL 20

int main()
{
    int i = 0;
    struct QUEUE_ITEM *item;
    long long totaltime = 0;
    struct timeval start,end;
    long long metric[TRAVERSAL];
    
    for(i=1;i<ITEM_NUM;i+=1){
        item=malloc(sizeof(struct QUEUE_ITEM));
        item->value = i;
        INIT_LIST_HEAD(&item->node);
        list_add(&item->node, &queue_head);
    }
    
    for (i = 0; i < TRAVERSAL; i++)
    {
        gettimeofday(&start,NULL);
        list_for_each_entry_reverse(item, &queue_head, node)
        {
            item->value++;
        }   

        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
   
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }

    printf("list traversal time is %lld us\n", totaltime/TRAVERSAL);
    
    for (i = 0; i < TRAVERSAL; i++)
    {
        gettimeofday(&start,NULL);
        list_for_each_entry(item, &queue_head, node)
        {
            item->value++;
        }   

        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
   
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }

    printf("list list traversal time is %lld us\n", totaltime/TRAVERSAL);

    return 0;

}