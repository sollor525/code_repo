/* 哈希表的C实现
  查找使用的方法是“除留余数法”，解决冲突使用的方法是“链地址法”。
*/
#include <stdio.h>
#include <malloc.h> //malloc
#include <string.h> //memset

#define FALSE 0
#define TRUE 1
#define HASHSIZE 10

typedef int STATUS;

//定义哈希表和基本数据节点
typedef struct _NODE
{
    int data;
    struct _NODE *next;
} NODE;

typedef struct _HASH_TABLE
{
    NODE *value[HASHSIZE];
} HASH_TABLE;


//创建哈希表
HASH_TABLE *create_hash_table()
{
    HASH_TABLE *pHashTbl = (HASH_TABLE *)malloc(sizeof(HASH_TABLE));
    memset(pHashTbl, 0, sizeof(HASH_TABLE));
    return pHashTbl;
}

//在哈希表中查找数据
NODE *find_data_in_hash(HASH_TABLE *pHashTbl, int data)
{
    NODE *pNode;
    if (NULL == pHashTbl)
        return NULL;

    if (NULL == (pNode = pHashTbl->value[data % HASHSIZE]))
        return NULL;

    while (pNode)
    {
        if (data == pNode->data)
            return pNode;
        pNode = pNode->next;
    }
    return NULL;
}

//在哈希表中插入数据
STATUS insert_data_into_hash(HASH_TABLE *pHashTbl, int data)
{
    NODE *pNode;
    if (NULL == pHashTbl)
        return FALSE;

    if (NULL == pHashTbl->value[data % HASHSIZE])
    {
        pNode = (NODE *)malloc(sizeof(NODE));
        memset(pNode, 0, sizeof(NODE));
        pNode->data = data;
        pHashTbl->value[data % HASHSIZE] = pNode;
        return TRUE;
    }

    if (NULL != find_data_in_hash(pHashTbl, data))
        return FALSE;

    pNode = pHashTbl->value[data % HASHSIZE];
    while (NULL != pNode->next)
        pNode = pNode->next;

    pNode->next = (NODE *)malloc(sizeof(NODE));
    memset(pNode->next, 0, sizeof(NODE));
    pNode->next->data = data;
    return TRUE;
}

//从哈希表中删除数据
STATUS delete_data_from_hash(HASH_TABLE *pHashTbl, int data)
{
    NODE *pHead;
    NODE *pNode;
    if (NULL == pHashTbl || NULL == pHashTbl->value[data % HASHSIZE])
        return FALSE;

    if (NULL == (pNode = find_data_in_hash(pHashTbl, data)))
        return FALSE;

    if (pNode == pHashTbl->value[data % HASHSIZE])
    {
        pHashTbl->value[data % HASHSIZE] = pNode->next;
        free(pNode);
        return TRUE;
    }

    pHead = pHashTbl->value[data % 10];
    while (pNode != pHead->next)
        pHead = pHead->next;
    pHead->next = pNode->next;
}

int main(void)
{
    HASH_TABLE *hashtable = create_hash_table();

    insert_data_into_hash(hashtable, 1);
    //insert_data_into_hash(hashtable,4);
    insert_data_into_hash(hashtable, 11);
    insert_data_into_hash(hashtable, 21);
    insert_data_into_hash(hashtable, 31);

    NODE *node1 = find_data_in_hash(hashtable, 11);
    NODE *node2 = find_data_in_hash(hashtable, 21);
    NODE *node3 = find_data_in_hash(hashtable, 31);
    printf("hashtable 1 : %d \n", hashtable->value[1]->data);

    if (hashtable->value[2] == NULL)
        printf("hashtable 2 is null\n");
    printf("hashtable 1 : %d \n", node1->data);
    printf("hashtable 1 : %d \n", node2->data);
    printf("hashtable 1 : %d \n", node3->data);

    delete_data_from_hash(hashtable, 21);
    NODE *node4 = find_data_in_hash(hashtable, 21);
    if (node4 == NULL)
        printf("21 is cancel\n");
    else
        printf("hashtable 1 : %d \n", node4->data);

    node1 = find_data_in_hash(hashtable, 11);
    node2 = find_data_in_hash(hashtable, 21);
    node3 = find_data_in_hash(hashtable, 31);
    printf("hashtable 1 : %d \n", hashtable->value[1]->data);

    if (hashtable->value[2] == NULL)
        printf("hashtable 2 is null\n");
    printf("hashtable 1 : %d \n", node1->data);
    if (node2 != NULL)
        printf("hashtable 1 : %d \n", node2->data);
    else
        printf("21 is cancel\n");
    printf("hashtable 1 : %d \n", node3->data);
}
