#include "tcp.h"
#include "ip.h"
#include <iostream>
#include <chrono>
#include <stdlib.h>
#include <memory>
#include <cstring>
#include <random>
#include <thread>
#include <arpa/inet.h>

namespace pan_protocol_stack{
namespace tcp{
uint16_t TCPchecksum(ip::ip_addr src, ip::ip_addr dst, uint16_t *addr, int count){
    uint32_t sum = 0;
    uint32_t srcN = htonl(src);
    uint32_t dstN = htonl(dst);
    uint16_t lenN = htons((uint16_t)(count));
    sum += (srcN &0xffff);
    sum += (srcN >> 16);
    sum += (dstN &0xffff);
    sum += (dstN >> 16);
    sum += lenN;
    sum += (0x0600);
    while( count > 1  )  {
        /*  This is the inner loop */
        sum += *(uint16_t*)addr++;

        count -= 2;
    }   
    if( count > 0 ) { 
        char left_over[2] = {0};
        left_over[0] = *addr;
        sum += * (uint16_t*) left_over;
    }   
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);
   return ~sum;
}

SocketAddress::SocketAddress(ip::ip_addr ipAddr, tcp::SocketPort tcpPort){
    _ipAddress = ipAddr;
    _port = tcpPort;
}
SocketAddress::SocketAddress(const sockaddr* saddr, socklen_t len){
    if ((saddr->sa_family != AF_INET)||(len<(socklen_t)(sizeof(sockaddr)))){
        std::cerr<<"Failed to build Socket Address! Type incompatible!"<<std::endl;
    }
    else
    {
        const sockaddr_in *p = (const sockaddr_in*)saddr;
        _ipAddress = ntohl(p->sin_addr.s_addr);
        _port = ntohs(p->sin_port);
    }
}

tcpPacket::~tcpPacket(){
    if(ownBuf){
        delete[] buf;
    }
}

std::unique_ptr<tcpPacket> parsePacket(char* buffer, size_t len){
    auto rv = std::make_unique<tcpPacket>();
    uint16_t *srcPort = (uint16_t*)buffer;
    uint16_t *dstPort =(uint16_t *)(buffer+2);
    uint32_t *seqNum = (uint32_t *)(buffer+4);
    uint32_t *ackNum = (uint32_t *)(buffer+8);
    uint8_t *offset = (uint8_t *)(buffer+12);
    uint8_t *flag = (uint8_t *)(buffer + 13);
    uint16_t *window = (uint16_t*)(buffer +14);
    rv->portFrom = ntohs(*srcPort);
    rv->portTo = ntohs(*dstPort);
    rv->seq = ntohl(*seqNum);
    rv->ack = ntohl(*ackNum);
    rv->dataLen = len - ((*offset)>>2);
    rv->flag = *flag;
    rv->window = ntohs(*window);
    rv->ownBuf = 0;
    rv->buf = buffer + ((*offset)>>2);
    return rv;

}
std::unique_ptr<tcpPacket> createPacket(SocketPort srcPort, SocketPort dstPort,uint32_t seq, uint32_t ack, uint8_t flag, char* buf, size_t len){
    auto rv = std::make_unique<tcpPacket>();
    rv->portFrom = srcPort;
    rv->portTo = dstPort;
    rv->seq = seq;
    rv->ack = ack;
    rv->dataLen = len;
    rv->flag = flag;
    rv->window = 65535;
    rv->ownBuf = 0;
    rv->buf = buf;
    return rv;  
}
std::unique_ptr<tcpPacket> createPacket(SocketPort srcPort, SocketPort dstPort,uint32_t seq, uint32_t ack, uint8_t flag){
    return createPacket(srcPort, dstPort,seq,ack,flag,nullptr,0);
}
uint32_t genSeq(){
  unsigned seed1 = std::chrono::system_clock::now().time_since_epoch().count();
  std::mt19937 g1(seed1);  // mt19937 is a standard mersenne_twister_engine
  uint32_t u32Random = g1();
  return u32Random;
}
SocketAddress SocketSession::getLocalAddr(){
    return localSocketAddress;
}
SocketAddress SocketSession::getRemoteAddr(){
    return remoteSocketAddress;
}
SocketSession::SocketSession(SocketAddress remote, SocketAddress local)
{
    localSocketAddress = local;
    remoteSocketAddress = remote;
    state_ = State::CLOSED;
    callback_ = nullptr;
    retransThread = std::thread(&SocketSession::retransmission,this);
}
SocketSession::~SocketSession(){
    retransmissionQueue.push(nullptr);
    retransThread.join();
    while (!receiveBuffer.empty())
    {
        receiveBuffer.pop();
    }
    auto it = packetUnack.begin();
    while(it!=packetUnack.end()){
        it = packetUnack.erase(it);
    }
}
void SocketSession::signalMessage(int message){
    if(callback_!=nullptr){
        callback_->onMessage(message);
    }
}
void SocketSession::setCallback(Callback *callback){
    callback_ = callback;
}

int SocketSession::sendPacket(std::unique_ptr<tcpPacket> packet){
    //Send packet via SendIPpacket
    auto packetPtr = (uint8_t *)malloc(packet->dataLen+20);
    uint16_t *srcPort = (uint16_t*)packetPtr;
    uint16_t *dstPort =(uint16_t *)(packetPtr+2);
    uint32_t *seqNum = (uint32_t *)(packetPtr+4);
    uint32_t *ackNum = (uint32_t *)(packetPtr+8);
    uint8_t *offset = (uint8_t *)(packetPtr+12);
    uint8_t *flag = (uint8_t *)(packetPtr + 13);
    uint16_t *window = (uint16_t*)(packetPtr +14);
    uint16_t *checksum = (uint16_t*)(packetPtr +16);
    uint16_t *urgentPointer = (uint16_t*)(packetPtr +18);
    *srcPort = htons(packet->portFrom);
    *dstPort = htons(packet->portTo);
    *seqNum = htonl(packet->seq);
    *ackNum = htonl(packet->ack);
    *offset = 0x50;
    *flag = packet->flag;
    *window =htons(65535);
    *checksum =0;
    *urgentPointer =0;
    //checksum not implemented yet;
    memcpy(packetPtr+20, packet->buf,packet->dataLen);
    uint16_t id = (genSeq() & 0xffff);
    *checksum = htons(TCPchecksum(localSocketAddress.ipAddress(), remoteSocketAddress.ipAddress(),(uint16_t*) packetPtr, (int)(packet->dataLen + 20)));
    ip::sendIPPacket(localSocketAddress.ipAddress(),remoteSocketAddress.ipAddress(),
    6,0,id,2,0,64,packetPtr,packet->dataLen + 20);
    free(packetPtr);
    if(packet->flag!=tcpPacket::ACK && (packet->flag & tcpPacket::RST == 0)){
        tcpPacket *p = packet.release();
        auto ti = retransmissionQueue.setTimeout(p,2000);
        std::lock_guard<std::mutex> lk(mutexUnack);
        packetUnack[p->seq+p->dataLen-mySend.initial] = ti;
    }
    return 0;
}
void SocketSession::retransmission(){
    while (1)
    {
       tcpPacket *packet = retransmissionQueue.pop();
       if(packet == nullptr) return;
       std::cout<<"RETRANS!"<<std::endl;
       std::unique_ptr<tcpPacket> p1(packet);
       sendPacket(std::move(p1));
    }
    
}
void SocketSession::ackPacket(uint32_t adjAck){
    auto it = packetUnack.begin();
    while(it!=packetUnack.end()){
        if(it->first<=adjAck){
            retransmissionQueue.clearTimeout(it->second);
            it = packetUnack.erase(it);
        }
        else
        {
            it++;
        }
    }
}

void SocketSession::open(){
    if(state_ !=State::CLOSED){
        std::cerr<<"Already open!"<<std::endl;
        return;
    }
    mySend.initial = genSeq();
    mySend.unack = mySend.initial;
    mySend.next = mySend.unack+1;
    std::unique_ptr<tcpPacket> packet = createPacket(localSocketAddress.port(),
    remoteSocketAddress.port(),mySend.initial,0,tcpPacket::SYN);
    sendPacket(std::move(packet));
    state_ = State::SYN_SENT;
    
}
void SocketSession::open(std::unique_ptr<tcpPacket> packet){
    if(state_!=State::CLOSED){
        std::cerr<<"Already open!"<<std::endl;
        return;
    }
    state_ = State::LISTEN;
    onReceiveDispatcher(std::move(packet));
    return;
}
void SocketSession::close(){
    callback_ = nullptr;
    if(state_ == State::LISTEN || state_==State::SYN_SENT){
        state_ == State::CLOSED;
        return;
    }
    if(state_ == State::SYN_RECEIVED||state_ == State::ESTABLISHED){
        std::unique_ptr<tcpPacket> packet = createPacket(localSocketAddress.port(),
        remoteSocketAddress.port(),mySend.next,0,tcpPacket::FIN|tcpPacket::ACK);
        sendPacket(std::move(packet));
        state_ = State::FIN_WAIT_1;
        return;
    }
    if(state_ == State::CLOSE_WAIT){
        std::unique_ptr<tcpPacket> packet = createPacket(localSocketAddress.port(),
        remoteSocketAddress.port(),mySend.next,0,tcpPacket::FIN|tcpPacket::ACK);
        sendPacket(std::move(packet));
        state_ = State::LAST_ACK;
        return;
    }
    if(state_ == State::CLOSED){
        return;
    }
    std::cerr<<"Why are you here CLOSE?"<<std::endl;
}
size_t SocketSession::send(char *buffer, size_t len){
    if(state_ == State::ESTABLISHED ||state_ == State::CLOSE_WAIT){
        size_t consume = 0;
        while (len > 0)
        {
            size_t packetLen = std::min(len, MAXSEGMENTLEN);
            std::unique_ptr<tcpPacket> packet = createPacket(localSocketAddress.port(),
            remoteSocketAddress.port(),mySend.next,myReceive.next,tcpPacket::ACK,buffer,packetLen);
            sendPacket(std::move(packet));
            consume += packetLen;
            len -= packetLen;
            mySend.next +=packetLen;
            buffer +=packetLen;
        }
        return consume;
    }
    else if(state_ == State::CLOSED){
        signalMessage(NOTEXIST);
        return 0;}
        else
        {
            signalMessage(NOSERVICE);
            return 0;
        }
}
size_t SocketSession::receive(char *buffer, size_t len){
    if(state_ == State::CLOSED){
        signalMessage(NOTEXIST);
        return 0;
    }
    if(state_ == State::LISTEN||
    state_== State::SYN_SENT||
    state_ == State::SYN_RECEIVED||
    state_ == State::ESTABLISHED||
    state_ == State::FIN_WAIT_1||
    state_ == State::FIN_WAIT_2){
        if(receiveBuffer.empty()) return 0;
        else
        {
            size_t i=0;
            while (i<len && !receiveBuffer.empty())
            {
                *(buffer+i) = receiveBuffer.front();
                receiveBuffer.pop();
                i++;
            }
            return i; 
        }
    }
    if(state_ == State::CLOSING||
    state_ == State::LAST_ACK||
    state_ == State::TIME_WAIT){
        signalMessage(CLOSING);
        return 0;
    }
    if(state_ == State::CLOSE_WAIT){
        if(!receiveBuffer.empty()){
            size_t i=0;
            while (i<len && !receiveBuffer.empty())
            {
                *(buffer+i) = receiveBuffer.front();
                receiveBuffer.pop();
                i++;
            }
            return i; 
        }
        else
        {
            signalMessage(CLOSING);
            return 0;
        }
    }
    return 0;
}
void SocketSession::onReceiveDispatcher(std::unique_ptr<tcpPacket> packet){
    switch (state_)
    {
    case State::CLOSED:
        onReceive_CLOSED(std::move(packet));
        break;
    case State::LISTEN:
        onReceive_LISTEN(std::move(packet));
        break;
    case State::SYN_SENT:
        onReceive_SYS_SENT(std::move(packet));
        break;
    default:
        onReceive_DEFAULT(std::move(packet));
        break;
    }
}
void SocketSession::onReceive_CLOSED(std::unique_ptr<tcpPacket> packet){
/*
    If the state is CLOSED (i.e., TCB does not exist) then
    all data in the incoming segment is discarded. An incoming
    segment containing a RST is discarded. An incoming segment not
    containing a RST causes a RST to be sent in response. The
    acknowledgment and sequence field values are selected to make the
    reset sequence acceptable to the TCP that sent the offending
    segment.
    If the ACK bit is off, sequence number zero is used,
    <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
    If the ACK bit is on,
    <SEQ=SEG.ACK><CTL=RST>
    Return.
*/
    if(packet->isRST()) return;
    if(packet->isACK()){
        if(!fromFIN){
            std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
            remoteSocketAddress.port(),packet->ack,0,tcpPacket::RST);
            sendPacket(std::move(p));
        }
    }
    else
    {
        //send packet <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
        remoteSocketAddress.port(),0,packet->seq+packet->dataLen,tcpPacket::RST|tcpPacket::ACK);
        sendPacket(std::move(p));
    }
}
void SocketSession::onReceive_LISTEN(std::unique_ptr<tcpPacket> packet){
/*
third check for a SYN
If the SYN bit is set, check the security. If the
security/compartment on the incoming segment does not exactly
match the security/compartment in the TCB then send a reset and
return.
<SEQ=SEG.ACK><CTL=RST>
[If the SEG.PRC is greater than the TCB.PRC then if allowed by
the user and the system set TCB.PRC<-SEG.PRC, if not allowed
send a reset and return.
<SEQ=SEG.ACK><CTL=RST>
If the SEG.PRC is less than the TCB.PRC then continue.
Here we did not implement security and compartment so skip

Note that any other 
incoming control or data (combined with SYN) will be processed
in the SYN-RECEIVED state, but processing of SYN and ACK should
not be repeated. If the listen was not fully specified (i.e.,
the foreign socket was not fully specified), then the
unspecified fields should be filled in now.

fourth other text or control
Any other control or text-bearing segment (not containing SYN)
must have an ACK and thus would be discarded by the ACK
processing. An incoming RST segment could not be valid, since
it could not have been sent in response to anything sent by this
incarnation of the connection. So you are unlikely to get here,
but if you do, drop the segment, and return.
*/
if(packet->isRST()) return;
if(packet->isACK()){
    //send packet <SEQ=SEG.ACK><CTL=RST>
    std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
    remoteSocketAddress.port(),packet->ack,0,tcpPacket::RST);
    sendPacket(std::move(p));
    return;
}
if(packet->isSYN()){
    myReceive.next = packet->seq+1;
    myReceive.initial = packet->seq;
    mySend.initial = genSeq();
    //send packet <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
    std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
    remoteSocketAddress.port(),mySend.initial,myReceive.next,tcpPacket::SYN|tcpPacket::ACK);
    //std::cout<<(unsigned)p->flag<<std::endl;
    sendPacket(std::move(p));
    mySend.next =mySend.initial+1;
    mySend.unack = mySend.initial;
    //std::cout<<"Transit to SYN_RECEIVED!"<<std::endl;
    state_ = State::SYN_RECEIVED;
}
return;
}
void SocketSession::onReceive_SYS_SENT(std::unique_ptr<tcpPacket> packet){
/*
third check the security and precedence
no security and precedence skip.
*/
bool acceptable =0;
if(packet->isACK()){
    
    if(moduloCompare(packet->ack,mySend.initial, mySend.initial,"<=")||
    moduloCompare(packet->ack,mySend.next,mySend.initial,">")){
        //send packet <SEQ=SEG.ACK><CTL=RST>
        std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
        remoteSocketAddress.port(),packet->ack,0,tcpPacket::RST);
        sendPacket(std::move(p));
    }
    if(moduloCompare(packet->ack,mySend.unack,mySend.initial,">=")&&
    moduloCompare(packet->ack,mySend.next, mySend.initial,"<=")){
        acceptable = 1;
    }
}
if(packet->isRST()){
    if(acceptable){
        signalMessage(RESET);
        state_ = State::CLOSED;
        return;
    }
    return;
}
if((acceptable || !packet->isACK())&& !packet->isRST()){
    if(packet->isSYN()){
        myReceive.next = packet->seq+1;
        myReceive.initial = packet->seq;
        if(packet->isACK()){
            mySend.unack = packet->ack;
            ackPacket(packet->ack - mySend.initial);
        }
        if(moduloCompare(mySend.unack,mySend.initial,mySend.initial,">")){
            state_ = State::ESTABLISHED;
            //Send packet <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
            remoteSocketAddress.port(),mySend.next,myReceive.next,tcpPacket::ACK);
            sendPacket(std::move(p));
            signalMessage(WRITABLE);
        }
        else
        {
            state_ = State::SYN_RECEIVED;
            //send packet <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
            remoteSocketAddress.port(),mySend.initial,myReceive.next,tcpPacket::ACK|tcpPacket::SYN);
            sendPacket(std::move(p));
        }
    }
}
    

if(!packet->isSYN()&&!packet->isRST()){
    return;
    }
}
void SocketSession::onReceive_DEFAULT(std::unique_ptr<tcpPacket> packet){
    //Receive window not considered
    //Assume receive window is infinity
    bool acceptable = false;
    if(packet->dataLen == 0){
        acceptable = moduloCompare(packet->seq, myReceive.next,myReceive.initial, ">=");
    }
    if(packet->dataLen>0){
        acceptable = moduloCompare(packet->seq, myReceive.next,myReceive.initial, ">=") ||
        moduloCompare(packet->seq+packet->dataLen-1, myReceive.next,myReceive.initial, ">=");
    }
    if(!acceptable){
        if(!packet->isRST()){
            //Send packet <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
            remoteSocketAddress.port(),mySend.next,myReceive.next,tcpPacket::ACK);
            sendPacket(std::move(p));
            return;
        }
        else {return;}
    }
    if (packet->isRST()){
        if(state_==State::SYN_RECEIVED){
            /*
            If this connection was initiated with a passive OPEN (i.e.,
            came from the LISTEN state), then return this connection to
            LISTEN state and return. The user need not be informed.
            just treat each it from active state.
            */
           signalMessage(REFUSED);
           state_ = State::CLOSED;
           return;
        }
        if(state_ == State::ESTABLISHED||
        state_ == State::FIN_WAIT_1||
        state_ == State::FIN_WAIT_2||
        state_ == State::CLOSE_WAIT){
            signalMessage(RESET);
            state_ = State::CLOSED;
            return;
        }
        if(state_ == State::CLOSING||
        state_ == State::LAST_ACK||
        state_ == State::TIME_WAIT){
            state_ = State::CLOSED;
            return;
        }
    }
    //third check security and precedence
    //skip
    if(packet->isSYN()){
        if(state_ == State::SYN_RECEIVED||
        state_ == State::ESTABLISHED||
        state_ == State::FIN_WAIT_1||
        state_ == State::FIN_WAIT_2||
        state_ == State::CLOSE_WAIT||
        state_ == State::CLOSING||
        state_ == State::LAST_ACK||
        state_ == State::TIME_WAIT){
            if(moduloCompare(packet->seq, myReceive.next,myReceive.initial,">=")){
                signalMessage(RESET);
                state_ = State::CLOSED;
                return;
            }
        }
    }

    if(!packet->isACK()){
        return;
    }
    if(packet->isACK()){
        switch (state_)
        {
        case State::SYN_RECEIVED:
            //std::cout<<"Should be here"<<std::endl;
            if(moduloCompare(packet->ack,mySend.unack,mySend.initial,">=")||
            moduloCompare(packet->ack, mySend.next,mySend.initial,"<=")){
                state_ =State::ESTABLISHED;
                signalMessage(WRITABLE);
            }
            else
            {
                //send Packet <SEQ=SEG.ACK><CTL=RST>
                std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
                remoteSocketAddress.port(),packet->ack,0,tcpPacket::RST);
                sendPacket(std::move(p));
            }
            //continue processing
        case State::ESTABLISHED:
        case State::FIN_WAIT_1:
        case State::FIN_WAIT_2:
        case State::CLOSE_WAIT:
        case State::CLOSING:
            if(moduloCompare(packet->ack, mySend.unack, mySend.initial,">")||
            moduloCompare(packet->ack, mySend.next, mySend.initial,">=")){
                mySend.unack = packet->ack;
                //Remove from sending queue up to packet->ack;
                ackPacket(packet->ack - mySend.initial);
                signalMessage(WRITABLE);
            }
            /*
            If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
            updated. If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
            SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
            SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
            Skip flow control
            */
           if(state_== State::FIN_WAIT_1){
               if(moduloCompare(packet->ack,mySend.next,mySend.initial,">=")){
                   state_=State::FIN_WAIT_2;
               }
           }
           if(state_ == State::FIN_WAIT_2){
               if(retransmissionQueue.empty()){ //If retransmission queue is empty;
               signalMessage(CLOSED);
               }
               
           }
           if(state_ == State::CLOSING){
               if(moduloCompare(packet->ack, mySend.next,mySend.initial,">=")){
                   state_ = State::CLOSED;
               }
           }
           break;
        case State::LAST_ACK:
            //if(moduloCompare(packet->ack, mySend.next, mySend.initial,">=")){
            state_ =State::CLOSED;
            return;
            //}

        case State::TIME_WAIT:
            //Send packet <SEQ = SND.NXT><ACK=SEG.SEQ><CTL=ACK>
            {std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
            remoteSocketAddress.port(),mySend.next,packet->seq,tcpPacket::ACK);
            sendPacket(std::move(p));
            //RESTART the 2MSL timeout.
            state_=State::CLOSED;
            break;}
        default:
            break;
        }
    }

    //sixth, check the URG bit, skip

    if(state_ == State::ESTABLISHED||
    state_ == State::FIN_WAIT_1||
    state_ ==State::FIN_WAIT_2){
        if(packet->dataLen >0 && acceptable){
            if(moduloCompare(packet->seq, myReceive.next, myReceive.initial,"<=")){
                size_t offset = myReceive.next - packet->seq;
                //place message in the buffer;
                size_t i = 0;
                while(i<packet->dataLen - offset){
                    receiveBuffer.push(*(packet->buf + offset + i));
                    i++;
                }
                myReceive.next += i;
                signalMessage(READABLE);
                //Send packet <SEQ=SND.NXT><ARQ=RCV.NXT><CTL=ACK>
                std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
                remoteSocketAddress.port(),mySend.next,myReceive.next,tcpPacket::ACK);
                sendPacket(std::move(p));
            }
            //else don't ack wait for retransmission.
        }
    }

    if(packet->isFIN()){
        //std::cout<<"Parse FIN"<<std::endl;
        std::unique_ptr<tcpPacket> p = createPacket(localSocketAddress.port(),
        remoteSocketAddress.port(),mySend.next,packet->seq+packet->dataLen,tcpPacket::ACK);
        sendPacket(std::move(p));
        if(state_ == State::CLOSED||
        state_ == State::LISTEN||
        state_ == State::SYN_SENT){
            return;
        }
        if(state_ == State::SYN_RECEIVED||
        state_ == State::ESTABLISHED){
            
            state_ = State::CLOSE_WAIT;
        }
        if(state_ == State::FIN_WAIT_1){
            if(packet->isACK() && (packet->ack, mySend.next,mySend.initial,">=")){
                state_ = State::CLOSED;
                fromFIN = 1;
                //To do Start 2MSL time wait
            }
            else
            {
                state_ = State::CLOSING;
            }
        }
        if(state_ == State::FIN_WAIT_2){
            fromFIN = 1;
            state_ = State::CLOSED;
            //To do Start 2MSL time wait
        }
        if(state_ == State::TIME_WAIT){
            fromFIN = 1;
            state_ = State::CLOSED;
            //To do Restart 2MSL time wait
        }
    }
}
bool moduloCompare(uint32_t a, uint32_t b, uint32_t initial,std:: string s){
    if(s == "=="){return ((a - initial) == (b-initial));}
    if(s == "<"){return ((a - initial) < (b-initial));}
    if(s == "<="){return ((a - initial) <= (b-initial));}
    if(s == ">"){return ((a - initial) > (b-initial));}
    if(s == ">="){return ((a - initial) >= (b-initial));}
    return 0;
}
void printTcpPacket(tcpPacket* packet){
    std::cout<<"Src Port: "<<(unsigned)packet->portFrom
    <<" Dst Port: "<<(unsigned)packet->portTo
    <<" Seq: "<<(unsigned)packet->seq
    <<" Ack: "<<(unsigned)packet->ack
    <<" FIN: "<<packet->isFIN()
    <<" SYN: "<<packet->isSYN()
    <<" RST: "<<packet->isRST()
    <<" PSH: "<<packet->isPSH()
    <<" ACK: "<<packet->isACK()
    <<" URG: "<<packet->isURG()
    <<" TCP packet finished!"<<std::endl;
}

}
}