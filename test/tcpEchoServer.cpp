#include "src/posix.h"
#include <iostream>
#include <stdio.h>      
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char** argv){
    int serverfd;
    char *port;
    if(argc !=2){
        std::cerr<<"usage: <port>"<<std::endl;
        return 0;
    }
    port = argv[1];
    const char* host = "10.100.2.2";
    serverfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    std::cout<<"I am going to bind!"<<std::endl;
    struct sockaddr_in mysock;
    bzero(&mysock,sizeof(mysock));  //初始化结构体
    mysock.sin_family = AF_INET;  //设置地址家族
    mysock.sin_port = htons((uint16_t)(atoi(port)));  //设置端口
    mysock.sin_addr.s_addr = inet_addr(host);  //设置地址
    bind(serverfd, (struct sockaddr *)&mysock, sizeof(sockaddr));
    std::cout<<"I am going to listen!"<<std::endl;
    listen(serverfd, 2);

    char writebuf[1000];
    char readbuf[1000];
    while (1)
    {
        memset(writebuf,0,sizeof(writebuf));
        memset(readbuf,0,sizeof(readbuf));
        int fd = accept(serverfd, NULL,NULL);
        read(fd, readbuf, 1000);
        printf("%s", readbuf);
        write(fd, readbuf, strlen(readbuf));
        close(fd);
        std::cout<<"One client served!"<<std::endl;  
    }
    
    return 0;
}