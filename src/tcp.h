#ifndef __TCP_H_
#define __TCP_H_
#include <memory>
#include <string>
#include <queue>
#include "ip.h"
#include "messagequeue.hpp"
#include <thread>

namespace pan_protocol_stack{
namespace tcp{
using SocketPort=uint16_t;
static const size_t MAXSEGMENTLEN = 1460;
 
uint32_t genSeq();

enum class State{
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED,
};
struct receive_{
    uint32_t next;
    uint32_t initial;
};
struct send_{
    uint32_t unack;
    uint32_t next;
    uint32_t initial;
    uint32_t last_seq;
    uint32_t last_ack;
};

class tcpPacket{
public:
enum{
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
};
bool isURG(){return flag&0x20;}
bool isACK(){return flag&0x10;}
bool isPSH(){return flag&0x08;}
bool isRST(){return flag&0x04;}
bool isSYN(){return flag&0x02;}
bool isFIN(){return flag&0x01;}
uint32_t seq;
uint32_t ack;
SocketPort portFrom;
SocketPort portTo;
uint16_t window;
size_t dataLen;
uint8_t flag;
bool ownBuf;
char* buf;
tcpPacket() = default;
~tcpPacket();

};

class SocketAddress{
public:
    SocketAddress() = default;
    SocketAddress(ip::ip_addr ipAddr, tcp::SocketPort tcpPort);
    SocketAddress(const sockaddr* saddr, socklen_t len);
    SocketAddress(const SocketAddress &SA) = default;
    SocketAddress& operator=(const SocketAddress &SA) = default;
    SocketAddress& operator=(SocketAddress&& other) = default;
    friend bool operator==(SocketAddress SA1, SocketAddress SA2){
        return SA1.port()==SA2.port() && SA1.ipAddress() ==SA2.ipAddress();
    }
    inline tcp::SocketPort port() const
    {
        return _port;
    }
    inline ip::ip_addr ipAddress() const
    {
        return _ipAddress;
    }
private:
    ip::ip_addr _ipAddress;
    tcp::SocketPort _port;
};


class SocketSession{
public:
enum{
    READABLE = 0x01,
    WRITABLE = 0x02,
    CLOSED   = 0x04,
    CLOSING  = 0x08,
    RESET    = 0x10,
    REFUSED  = 0x20,
    NOTEXIST = 0x40,
    NOSERVICE= 0x80,
};
class Callback {
public:
Callback() = default;
~Callback() = default;
virtual void onMessage(int message) = 0;
};
SocketSession(SocketAddress remote, SocketAddress local);
~SocketSession();
void open();
void open(std::unique_ptr<tcpPacket> packet);
void close();
bool isClosed(){return state_ == State::CLOSED;}
size_t send(char *buffer, size_t len);
size_t receive(char *buffer, size_t len);
inline State get_state(){return state_;}
SocketAddress getLocalAddr();
SocketAddress getRemoteAddr();
void onReceiveDispatcher(std::unique_ptr<tcpPacket> packet);
void onReceive_LISTEN(std::unique_ptr<tcpPacket> packet);
void onReceive_SYS_SENT(std::unique_ptr<tcpPacket> packet);
void onReceive_CLOSED(std::unique_ptr<tcpPacket> packet);
void onReceive_DEFAULT(std::unique_ptr<tcpPacket> packet);
void setCallback(Callback *callback);
void signalMessage(int message);
int sendPacket(std::unique_ptr<tcpPacket> packet);
void ackPacket(uint32_t acknowledge);
void retransmission();
std::mutex mutexUnack;
std::mutex mutexLive;
bool fromFIN = 0;
private:
std::thread retransThread;
State state_;
SocketAddress localSocketAddress;
SocketAddress remoteSocketAddress;
Callback *callback_;

send_ mySend;
receive_ myReceive;
std::queue<char> receiveBuffer;
std::map<uint32_t, timer_index> packetUnack;
messagequeue< tcpPacket* > retransmissionQueue;


};
bool moduloCompare(uint32_t a, uint32_t b, uint32_t initial,std:: string s);
std::unique_ptr<tcpPacket> parsePacket(char *buffer, size_t len);
std::unique_ptr<tcpPacket> createPacket(SocketPort srcPort, SocketPort dstPort,uint32_t seq, uint32_t ack, uint8_t flag, char* buf, size_t len);
std::unique_ptr<tcpPacket> createPacket(SocketPort srcPort, SocketPort dstPort,uint32_t seq, uint32_t ack, uint8_t flag);
void printTcpPacket(tcpPacket* packet);
uint16_t TCPchecksum(ip::ip_addr src, ip::ip_addr dst, uint16_t *addr, int count);
}
}
#endif