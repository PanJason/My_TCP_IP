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
    int clientfd;
    char* host, *port;
    if(argc !=3){
        std::cerr<<"usage: <host> <port>"<<std::endl;
        return 0;
    }
    host = argv[1];
    port = argv[2];
    struct sockaddr_in mysock;
    bzero(&mysock,sizeof(mysock));  //初始化结构体
    mysock.sin_family = AF_INET;  //设置地址家族
    mysock.sin_port = htons((uint16_t)(atoi(port)));  //设置端口
    mysock.sin_addr.s_addr = inet_addr(host);  //设置地址
    
    char writebuf[1000];
    char readbuf[1000];
    while (1)
    {
        std::cout<<"Please type in: "<<std::endl;
        memset(writebuf,0,sizeof(writebuf));
        memset(readbuf,0,sizeof(readbuf));
        //scanf("%s",writebuf);
        std::cin.getline(writebuf, 1000);
        clientfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        //std::cout<<"I am going to connect!"<<std::endl;
        connect(clientfd, (struct sockaddr *)&mysock, sizeof(sockaddr_in));
        //std::cout<<"I am going to send!"<<std::endl;
        write(clientfd, writebuf, strlen(writebuf));
        read(clientfd, readbuf, 1000);
        printf("%s", readbuf);
        close(clientfd);  
        //std::cout<<"One turn finished!"<<std::endl;
    }
    return 0;
}