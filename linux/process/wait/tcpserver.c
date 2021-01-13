/******************************************************************************************************
等待子进程结束

#include <sys/types.h>
#include <sys/wait.h>

pid_t wait(int * status)                  //暂停执行，直到一个子进程结束，成功返回进程pid，否则返回-1
pid_t waitpid(pid_t pid,int *status,int options)     //等待指定子进程结束，options指定等待方式

返回值：若设置了WNOHANG且未发现子进程则返回0,出错则返回-1

pid的意义:
pid<-1     等待pid所代表的进程组中的进程
pid=-1     等待任何子进程
pid=0      等待与该进程同组的进程
pid>0      等待的进程标识

options的意义:
WNOHANG      //表示不阻塞
WUNTRACED   //当有子进程结束时返回
******************************************************************************************************/

//一个回声服务器服务端例子 tcpserver.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/wait.h>


#define PORT 4008
#define BACKLOG 10
#define BUFSIZE 4096


int main(int argc,char* argv[])
{
    int lsockfd,rsockfd;
    struct sockaddr_in lsocket,rsocket;
    if((lsockfd=socket(AF_INET,SOCK_STREAM,0))<0)
    {
        perror("socket");   
        exit(1);  
    }  
    
    lsocket.sin_family=AF_INET;
    lsocket.sin_port=htons(PORT);
    lsocket.sin_addr.s_addr=INADDR_ANY;
    bzero(&(lsocket.sin_zero),8);

    if(bind(lsockfd,(struct sockaddr *)&lsocket,sizeof(struct sockaddr))<0)
    {
        perror("bind");
        exit(1);
    }

    if(listen(lsockfd,BACKLOG)<0)
    {
        perror("listen");
        exit(1);
    }

    socklen_t  sin_size=sizeof(struct sockaddr);
    int count=0;
    while(1)
    {
        printf("wait for connecting!\n");
        if((rsockfd=accept(lsockfd,(struct sockaddr *)&rsocket,&sin_size))<0)
        {
            perror("accept");
            continue;
        }
        count++;
        printf("someone connect!,current people %d\n",count);

        if(!fork())
        {
            char str[BUFSIZE];
            int numbytes=0;
            while(1)
            {
            if((numbytes=recv(rsockfd,str,BUFSIZE-1,0))<0)
            {
                perror("recv");
                break;
            }
            str[numbytes]='\0';
            if(strcmp(str,"quit")==0)
            {
                printf("client quit!\n");
                break;
            }
            
            printf("receive a message: %s\n",str);
            if(send(rsockfd,str,strlen(str),0)<0)
            {
                perror("send");
                break;
            }
            }
            close(rsockfd);
            exit(0);
            
        }
        while(waitpid(-1,NULL,WNOHANG)>0) //此处不会阻塞若第三个参数为WUNTRACED则会阻塞
        {
            count--;
            printf("someone quit!,current people have %d\n",count);
        }   
        
    }   
    return 0;
}
