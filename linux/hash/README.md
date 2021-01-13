# hash #

1. hash1.c: hash散列表。表长为HASHSIZE，采用除留余数法，除数为表长。
   冲突采用的是在hash表中循环向后放。
2. hash2.c: hash表。表长为HASHSIZE,采用的除留余数法做hash，除数为表长。
   冲突采用的是链地址法，构造的冲突链是单链表。
