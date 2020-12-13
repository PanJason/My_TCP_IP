#ifndef __SOCKET_H_
#define __SOCKET_H_
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <mutex>
#include <condition_variable>
#include <map>
#include <memory>
#include <vector>
#include <deque>
#include <sys/socket.h>
#include "tcp.h"
#include "ip.h"

namespace pan_protocol_stack{
namespace tcp{
class SocketStruct : public SocketSession::Callback{
public:
    enum class SocketType{
    PASSIVE,
    ACTIVE,
    UNSPECIFIED,
    };
    SocketType type;
    SocketAddress bindAddress;
    //Active
    std::unique_ptr<tcp::SocketSession> session;
    //Passive
    int backlog;
    std::deque<std::unique_ptr<tcp::SocketSession> > pendingSessions;

    std::condition_variable cond;

    bool closing = false;
    void onMessage(int message);
    void waitMessage(std::unique_lock<std::mutex> &mut);
    int _message;
    explicit SocketStruct(const SocketAddress &address);

};
class TCP_stack{
public:
    int _socket(int domain, int type, int protocol);
    int _bind(int socket, const struct sockaddr *address,
    socklen_t address_len);
    int _listen(int socket, int backlog);
    int _connect(int socket, const struct sockaddr *address,
    socklen_t address_len);
    int _accept(int socket, struct sockaddr *address,
    socklen_t *address_len);
    ssize_t _read(int fildes, void *buf, size_t nbyte);
    ssize_t _write(int fildes, const void *buf, size_t nbyte);
    int _close(int fildes);
    int _getaddrinfo(const char *node, const char*service,const struct addrinfo *hints, struct addrinfo **res);
    int TCPSegmentReceiveCallback(char *buffer, size_t len, ip::ip_addr ipAddressFrom, ip::ip_addr ipAddressTo);
    void deleteGarbage();
    SocketStruct* lookupListen(const SocketAddress &sa);
    tcp::SocketSession* lookupEstablished(const SocketAddress &saFrom, const SocketAddress &saTo);
    using listenSocket = std::tuple<SocketAddress, SocketStruct*>;
    std::vector<listenSocket> listenList;
    using establishedSocket = std::tuple<SocketAddress, SocketAddress, tcp::SocketSession*>;
    std::vector<establishedSocket> establishedList;
    TCP_stack();
    ~TCP_stack();
private:

    std::mutex mtx;
    std::mutex mutexEstab;
    std::mutex mutexListen;
    std::map<int, std::unique_ptr<SocketStruct> > fdMap;
    std::vector<std::unique_ptr<tcp::SocketSession> > garbage;

    int null_fd;
    bool hasFD(int fd);
    SocketStruct *socketLookUp(int fd);
    void removeSocket(int fd);

};





bool typecheck_ipv4(const char *node);
bool typecheck_port(const char *service);
TCP_stack &run();
}
}

#endif