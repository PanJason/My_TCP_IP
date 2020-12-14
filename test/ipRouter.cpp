#include "src/posix.h"
#include <iostream>
#include <stdio.h>      
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <signal.h>
#include <string>

int main(int argc, char** argv){
    int routerfd =  socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    std::string s;
    while(1){
        std::cout<<"If you want to quit router, press q or quit"<<std::endl;
        std::cin>>s;
        if(s== "q"||s=="quit"){
            break;
        }
    }
    return 0;
}