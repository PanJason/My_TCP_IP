#define __SOCK_TEST_
#include "socket.h"
#include "core_data.h"
#include <unistd.h>
#include <time.h>
#include <iostream>
#include <thread>
#include "wrap_function.h"
#include <unistd.h>

namespace pan_protocol_stack{
namespace tcp{
bool typecheck_ipv4(const char *node){
    uint32_t t1,t2,t3,t4;
    return (sscanf(node,"%d.%d.%d.%d",&t1,&t2,&t3,&t4)==4);
}
bool typecheck_port(const char *service){
    uint32_t t1;
    return (sscanf(service, "%d",&t1)==1);
}

bool TCP_stack::hasFD(int fd){
    auto iter = fdMap.find(fd);
    return iter!= fdMap.end();
}
TCP_stack::TCP_stack(){
    null_fd = dup(STDOUT_FILENO);
    if(null_fd < 0){
        std::cerr<<"can not create null fd!"<<std::endl;
    }
}
SocketStruct *TCP_stack::socketLookUp(int fd){
    auto iter = fdMap.find(fd);
    if(iter == fdMap.end()) return nullptr;
    else
    {
        return iter->second.get();
    }
}

void TCP_stack::removeSocket(int fd){
    fdMap.erase(fd);
}

int TCP_stack::_socket(int domain, int type, int protocol){
    if(domain != AF_INET) return __real_socket(domain, type, protocol);
    if(type != SOCK_STREAM) return __real_socket(domain, type, protocol);
    if(protocol!=0 && protocol != IPPROTO_TCP) __real_socket(domain, type, protocol);
    srand((unsigned)time(NULL));
    int fd = dup(null_fd);
    tcp::SocketPort randPort = rand()%(65536-45152)+45152;
    SocketAddress socketAddr(
        core_data::get().devices[0]->ip_addrs[0], //Here may not exist. Construct function needed. Mutex may be necessary.
        randPort
    );
    fdMap[fd] = std::make_unique<SocketStruct>(socketAddr);
    return fd;
}
int TCP_stack::_bind(int socket, const struct sockaddr *address,socklen_t address_len){
    if(!hasFD(socket)){
        return __real_bind(socket,address,address_len);
    }
    std::lock_guard<std::mutex> lk(mtx);
    SocketAddress socketAddr(address, address_len); //Construction function needed;
    SocketStruct *socketStruct = socketLookUp(socket);
    socketStruct->bindAddress = socketAddr; //Operator = to be reloaded.
    return 0;
}
int TCP_stack::_listen(int socket, int backlog){
    if(!hasFD(socket)){
        return __real_listen(socket, backlog);
    }
    if(backlog <=0) backlog = 1;
    std::lock_guard<std::mutex> lk(mtx);
    SocketStruct *socketStruct = socketLookUp(socket);
    if(socketStruct->type!=SocketStruct::SocketType::UNSPECIFIED){
        //already been used 
        return -1;
    }
    else
    {
        socketStruct->type = SocketStruct::SocketType::PASSIVE;
        socketStruct->backlog = backlog;
        std::lock_guard<std::mutex> lkListen(mutexListen);
        listenList.emplace_back(socketStruct->bindAddress, socketStruct);
        return 0;
    }
}
int TCP_stack::_connect(int socket, const struct sockaddr *address, socklen_t address_len){
    if(!hasFD(socket)){
        return __real_connect(socket,address, address_len);
    }
    std::lock_guard<std::mutex> lk(mtx);
    SocketStruct *socketStruct = socketLookUp(socket);
    if(socketStruct->type == SocketStruct::SocketType::PASSIVE){
        return -1;
    }
    if(socketStruct->type == SocketStruct::SocketType::ACTIVE){
        return -1;
    }
    SocketAddress peerSocketAddr(address, address_len);
    socketStruct->type = SocketStruct::SocketType::ACTIVE;
    socketStruct->session = std::move(
        std::make_unique<tcp::SocketSession>(
            peerSocketAddr,
            socketStruct->bindAddress
        )
    );
    socketStruct->session->setCallback(socketStruct);
    std::lock_guard<std::mutex> lkEstab(mutexEstab);
    establishedList.emplace_back(peerSocketAddr,socketStruct->bindAddress, socketStruct->session.get());
    socketStruct->session->open();
    return 0;
}
int TCP_stack::_accept(int socket, struct sockaddr *address, socklen_t *address_len){
    if(!hasFD(socket)){
        return __real_accept(socket, address, address_len);
    }
    std::unique_lock<std::mutex> lk(mtx);
    SocketStruct *socketStruct = socketLookUp(socket);
    if(socketStruct->type != SocketStruct::SocketType::PASSIVE){
        return -1;
    }
    while (1)
    {
        socketStruct->waitMessage(lk);
        if(!socketStruct->pendingSessions.empty()){
            int fd = dup(null_fd);
            //Create a new child socket struct;
            std::unique_ptr<SocketStruct> childSocket = std::make_unique<SocketStruct>(
                socketStruct->pendingSessions.back()->getLocalAddr()
            );
            childSocket->type = SocketStruct::SocketType::ACTIVE;
            childSocket->session = std::move(socketStruct->pendingSessions.back());
            childSocket->session->setCallback(childSocket.get());
            socketStruct->pendingSessions.pop_back();
            fdMap[fd] = std::move(childSocket);
            #ifdef __SOCK_TEST_
            std::cout<<"I am able to read now!"<<std::endl;
            #endif
            return fd;
        }
    }
    return 0;
}
ssize_t TCP_stack::_read(int fildes, void* buf, size_t nbyte){
    if(!hasFD(fildes)){
        return __real_read(fildes, buf, nbyte);
    }
    std::unique_lock<std::mutex> lk(mtx);
    SocketStruct *socketStruct = socketLookUp(fildes);
    if(socketStruct->type != SocketStruct::SocketType::ACTIVE){
        return 0;
    }
    size_t rv = socketStruct->session->receive((char*)buf, nbyte);
    if(rv>0) {
        #ifdef __SOCK_TEST_
        std::cout<<"read successfully!"<<std::endl; 
        #endif
        return rv;}
    if(socketStruct->session->isClosed())
    return 0;
    while (1)
    {
        socketStruct->waitMessage(lk);
        if(socketStruct->_message & tcp::SocketSession::READABLE){
            size_t rv = socketStruct->session->receive((char*)buf, nbyte);
            if(rv>0) {
                #ifdef __SOCK_TEST_
                std::cout<<"read successfully!"<<std::endl;
                #endif
                 return rv;}
        }
        if(socketStruct->closing){
            socketStruct->closing =false;
            return 0;
        }
    }
    return 0;
}
ssize_t TCP_stack::_write(int fildes, const void *buf, size_t nbyte){
    if(!hasFD(fildes)){
        return __real_write(fildes, buf, nbyte);
    }
    std::unique_lock<std::mutex> lk(mtx);
    SocketStruct *socketStruct = socketLookUp(fildes);
    if(socketStruct->type != SocketStruct::SocketType::ACTIVE){
        return 0;
    }
    size_t rv = socketStruct->session->send((char*)buf, nbyte);
    if(rv>0) {
        #ifdef __SOCK_TEST_
        std::cout<<"write successfully! Bytes: "<<(unsigned)rv<<std::endl;
        #endif
        return rv;}
    while (1)
    {
        socketStruct->waitMessage(lk);
        if(socketStruct->_message & tcp::SocketSession::WRITABLE){
            size_t rv = socketStruct->session->send((char*)buf, nbyte);
            if(rv>0) {
                #ifdef __SOCK_TEST_
                std::cout<<"write successfully! Bytes: "<<(unsigned)rv<<std::endl;
                #endif
                 return rv;}
        }
    }
    return 0;
}
int TCP_stack::_close(int fildes){
    if(!hasFD(fildes)){
        return __real_close(fildes);
    }
    std::lock_guard<std::mutex> lk(mtx);
    //std::cout<<"Lookup bug"<<std::endl;
    SocketStruct *socketStruct = socketLookUp(fildes);
    //std::cout<<"Switch bug"<<std::endl;
    switch (socketStruct->type)
    {
    case SocketStruct::SocketType::PASSIVE:
        for (auto &s: socketStruct->pendingSessions){
            s->close(); 
            garbage.emplace_back(std::move(s));
            deleteGarbage();
        }
        break;
    case SocketStruct::SocketType::ACTIVE:
        socketStruct->session->close(); //Close session
        garbage.emplace_back(std::move(socketStruct->session));
        deleteGarbage();
        break;
    case SocketStruct::SocketType::UNSPECIFIED:
        break;
    default:
        std::cerr<<"Unknown socket type"<<std::endl;
        break;
    }
    //std::cout<<"remove bug"<<std::endl;
    removeSocket(fildes);
    return 0;
}
int TCP_stack::_getaddrinfo(const char *node, const char*service,const struct addrinfo *hints,struct addrinfo **res){
    if((node && !typecheck_ipv4(node))||(service && !typecheck_port(service))||(hints && (hints->ai_family != AF_INET || hints->ai_socktype != SOCK_STREAM|| hints->ai_protocol != IPPROTO_TCP || hints->ai_flags != 0))){
        return __real_getaddrinfo(node, service, hints, res);
    }
    //To do sth?
    return __real_getaddrinfo(node, service, hints, res);
}
int TCP_stack::TCPSegmentReceiveCallback(char *buffer, size_t len, ip::ip_addr ipAddressFrom, ip::ip_addr ipAddressTo){
    std::unique_ptr<tcp::tcpPacket> packet = tcp::parsePacket(buffer,len);
    #ifdef __SOCK_TEST_
    printTcpPacket(packet.get());
    #endif
    SocketAddress from(ipAddressFrom, packet->portFrom);
    SocketAddress to(ipAddressTo,packet->portTo);
    SocketStruct* sockStr=nullptr;
    tcp::SocketSession* sockSess;
    if(packet->isSYN()){
        sockStr = lookupListen(to);
    }
    if(sockStr == nullptr)
    {
        
        sockSess = lookupEstablished(from, to);
        if(sockSess == nullptr){
            if(packet->isACK()){
                //send packet <SEQ = SEG.ACK><CTL = RST>
                auto packetPtr = (uint8_t *)malloc(20);
                uint16_t *srcPort = (uint16_t*)packetPtr;
                uint16_t *dstPort =(uint16_t *)(packetPtr+2);
                uint32_t *seqNum = (uint32_t *)(packetPtr+4);
                uint32_t *ackNum = (uint32_t *)(packetPtr+8);
                uint8_t *offset = (uint8_t *)(packetPtr+12);
                uint8_t *flag = (uint8_t *)(packetPtr + 13);
                uint16_t *window = (uint16_t*)(packetPtr +14);
                uint16_t *checksum = (uint16_t*)(packetPtr +16);
                uint16_t *urgentPointer = (uint16_t*)(packetPtr +18);
                *srcPort = htons(to.port());
                *dstPort = htons(from.port());
                *seqNum = htonl(packet->ack);
                *ackNum = 0;
                *offset = 0x50;
                *flag = 0x04;
                *window =htons(65535);
                *checksum =0;
                *urgentPointer =0;
                //checksum not implemented yet;
                *checksum = htons(TCPchecksum(to.ipAddress(), from.ipAddress(),
                (uint16_t *)packetPtr, 20));
                uint16_t id = (genSeq() & 0xffff);
                ip::sendIPPacket(to.ipAddress(),from.ipAddress(),
                6,0,id,2,0,64,packetPtr,20);
                free(packetPtr);
            }
            else
            {
                //send packet <SEQ = 0><ACK = SEG.SEQ + SEG.LEN> <CTL = RST|ACK>
                auto packetPtr = (uint8_t *)malloc(20);
                uint16_t *srcPort = (uint16_t*)packetPtr;
                uint16_t *dstPort =(uint16_t *)(packetPtr+2);
                uint32_t *seqNum = (uint32_t *)(packetPtr+4);
                uint32_t *ackNum = (uint32_t *)(packetPtr+8);
                uint8_t *offset = (uint8_t *)(packetPtr+12);
                uint8_t *flag = (uint8_t *)(packetPtr + 13);
                uint16_t *window = (uint16_t*)(packetPtr +14);
                uint16_t *checksum = (uint16_t*)(packetPtr +16);
                uint16_t *urgentPointer = (uint16_t*)(packetPtr +18);
                *srcPort = htons(to.port());
                *dstPort = htons(from.port());
                *seqNum = 0;
                *ackNum = htonl(packet->seq+packet->dataLen);
                *offset = 0x50;
                *flag = 0x04|0x10;
                *window =htons(65535);
                *checksum =0;
                *urgentPointer =0;
                //checksum not implemented yet;
                *checksum = htons(TCPchecksum(to.ipAddress(), from.ipAddress(),
                (uint16_t *)packetPtr, 20));
                uint16_t id = (genSeq() & 0xffff);
                ip::sendIPPacket(to.ipAddress(),from.ipAddress(),
                6,0,id,2,0,64,packetPtr,20);
                free(packetPtr);
                //Do not wait for ack
            }
        }
        else
        {
            //std::cout<<"Packet: "<<(unsigned)packet->seq<<" "<<(unsigned)packet->ack<<std::endl;
            sockSess->onReceiveDispatcher(std::move(packet));
        }
    }
    else
    {
       if(sockStr->backlog<=sockStr->pendingSessions.size()){
           std::cerr<<"To many connections!"<<std::endl;
       }
       sockStr->pendingSessions.push_back(std::make_unique<tcp::SocketSession>(
           from,
           to
       ));
       sockStr->pendingSessions.back()->open(std::move(packet));
       std::lock_guard<std::mutex> lkEstab(mutexEstab);
       establishedList.emplace_back(from,to, sockStr->pendingSessions.back().get());
       std::cout<<"Placed to the established"<<std::endl;
       sockStr->cond.notify_one();
       return 0;
    }
    return -1;
}
void TCP_stack::deleteGarbage(){
    std::vector<std::unique_ptr<tcp::SocketSession> >::iterator it;
    std::lock_guard<std::mutex> lkEstab(mutexEstab);
    for(it = garbage.begin();it!=garbage.end();){
        if((*it)->isClosed()){
            for(auto item = establishedList.begin();item!=establishedList.end();){
                if((*it)->getRemoteAddr() == std::get<0>(*item)&&
                (*it)->getLocalAddr() == std::get<1>(*item)){
                    item = establishedList.erase(item);
                }
                else
                {
                    item++;
                }
            }
            it = garbage.erase(it);
        }
        else
        {
            it++;
        }
    }
}
SocketStruct* TCP_stack::lookupListen(const SocketAddress &sa){
    std::lock_guard<std::mutex> lkListen(mutexListen);
    for(auto &item: listenList){
    if((sa.port() == std::get<0>(item).port()) &&
    (std::get<0>(item).ipAddress() == 0 ||
    std::get<0>(item).ipAddress() == sa.ipAddress())
    )
    {return std::get<1>(item);}
    }
    return nullptr;
}
tcp::SocketSession* TCP_stack::lookupEstablished(const SocketAddress &saFrom, const SocketAddress &saTo){
    std::lock_guard<std::mutex> lkEstab(mutexEstab);
    for(auto &item: establishedList){
        if(saFrom == std::get<0>(item) &&
        saTo == std::get<1>(item)
        ){return std::get<2>(item);}
    }
    return nullptr;
}
void SocketStruct::onMessage(int message){
    _message |= message;
    if(message == SocketSession::CLOSING){
        closing = true;
    }
    cond.notify_one();
}

void SocketStruct::waitMessage(std::unique_lock<std::mutex> &mut){
    _message = 0;
    cond.wait(mut);
}
SocketStruct::SocketStruct(const SocketAddress &address):backlog(0),bindAddress(address),type(SocketType::UNSPECIFIED){}


TCP_stack& run(){
    if(core_data::get().runningTCP == nullptr){
        device::epoll_server_init();
        for (auto &it :core_data::get().devices){
        std::cout<<it->device_name<<std::endl;
        }
        core_data::get().runningTCP = new TCP_stack();
        std::thread(device::epoll_server,1000).detach();
    }
    return *(core_data::get().runningTCP);
}


}
}