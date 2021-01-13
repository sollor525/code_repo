/*threadsig.c*/
/* 此文件主要是多线程和多线程中处理信号的 demo */
/* 主要使用了： pthread_create , pthread_kill , pthread_join , sigaction , 
sigemptyset , sigaddset , pthread_sigmask */


#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
void sighandler(int signo);
 
void *
thr1_fn(void *arg)
{
    struct sigaction    action;
    action.sa_flags = 0;
    action.sa_handler = sighandler;
       
    sigaction(SIGINT, &action, NULL);
    
    pthread_t   tid = pthread_self();
    int     rc;
 
    printf("thread 1 with tid:%lu\n", tid);
    rc = sleep(60);
    if (rc != 0)
        printf("thread 1... interrupted at %d second\n", 60 - rc);
    printf("thread 1 ends\n");
    return NULL;
}
 
void *
thr2_fn(void *arg)
{
    struct sigaction    action;
    pthread_t       tid = pthread_self();
    int         rc, __attribute__((__unused__))err;
   
    printf("thread 2 with tid:%lu\n", tid);
     
    action.sa_flags = 0;
    action.sa_handler = sighandler;
       
    err = sigaction(SIGALRM, &action, NULL);
     
    rc = sleep(60);
    if (rc != 0)
        printf("thread 2... interrupted at %d second\n", 60 - rc);
    printf("thread 2 ends\n");
    return NULL;
}
 
void *
thr3_fn(void *arg)
{
    pthread_t   tid = pthread_self();
    sigset_t    mask;
    int     rc=0, err=0;
   
    printf("thread 3 with tid:%lu\n", tid);
 
     
    sigemptyset(&mask); /* 初始化mask信号集 */
   
    //此处增加 pthread_sigmask 之后，由于参数是 SIG_BLOCK ，会导致信号被屏蔽。因此sleep过程不会被信号打断
    sigaddset(&mask, SIGALRM);
    err = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (err != 0)
    {
        printf("%d, %s/n", rc, strerror(rc));
        return NULL;
    }
   
    rc = sleep(20);
    if (rc != 0)
        printf("thread 3... interrupted at %d second\n", 60 - rc);
    
    //此处的 pthread_sigmask ，由于参数是 SIG_UNBLOCK ，会解除被屏蔽信号
    err = pthread_sigmask( SIG_UNBLOCK,&mask,NULL );

    if ( err != 0 )
    {
        printf("unblock %d, %s/n", rc, strerror(rc));
        return NULL;
    }
    
    rc = sleep(10);
    if (rc != 0)
        printf("thread 3... interrupted at %d second after unblock\n", 60 - rc);

    printf("thread 3 ends\n");
    return NULL;
}
 
int
main(void)
{
    int     rc=0, err=0;
    pthread_t   thr1, thr2, thr3, thrm = pthread_self();
 
    printf("thread main with pid %lu\n",thrm);
    err = pthread_create(&thr1, NULL, thr1_fn, NULL);
    if (err != 0) {
        printf("error in creating pthread:%d\t%s\n",err, strerror(rc));
        exit(1);
    }
 
     
/*  pthread_kill(thr1, SIGALRM);    send a SIGARLM signal to thr1 before thr2 set the signal handler, then the whole process will be terminated*/
    err = pthread_create(&thr2, NULL, thr2_fn, NULL);
    if (err != 0) {
        printf("error in creating pthread:%d\t%s\n",err, strerror(rc));
        exit(1);
    }
     
    err = pthread_create(&thr3, NULL, thr3_fn, NULL);
    if (err != 0) {
        printf("error in creating pthread:%d\t%s\n",err, strerror(rc));
        exit(1);
    }
 
    sleep(10);
    //内部产生的信号，只有指定的线程能收到，因此要向所有线程发送
    printf("send SIGALRM to pthread 1\n");
    pthread_kill(thr1, SIGALRM);
    printf("send SIGALRM to pthread 2\n");
    pthread_kill(thr2, SIGALRM);
    printf("send SIGALRM to pthread 3\n");
    pthread_kill(thr3, SIGALRM);
    //printf("send SIGALRM to pthread 3\n");
    //pthread_kill(thr3, SIGALRM);
    //printf("send SIGALRM to pthread 3\n");
    //pthread_kill(thr3, SIGALRM);
    sleep(6);
    pthread_join(thr1, NULL);   /*wait for the threads to complete.*/
    pthread_join(thr2, NULL);
    pthread_join(thr3, NULL);
    printf("main ends\n");
    return 0;
}
 
void
sighandler(int signo)
{
    pthread_t   tid = pthread_self();
     
    printf("thread with pid:%lu receive signo:%d\n", tid, signo);
    return;
}
