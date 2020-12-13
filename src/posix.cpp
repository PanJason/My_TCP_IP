#include "posix.h"
#include "socket.h"

int __wrap_socket(int domain, int type, int protocol){
    return pan_protocol_stack::tcp::run()._socket(domain, type, protocol);
}
int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len){
    return pan_protocol_stack::tcp::run()._bind(socket, address, address_len);
}
int __wrap_listen(int socket, int backlog){
    return pan_protocol_stack::tcp::run()._listen(socket,backlog);
}
int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len){
    return  pan_protocol_stack::tcp::run()._connect(socket, address, address_len);
}
int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len){
    return pan_protocol_stack::tcp::run()._accept(socket, address, address_len);
}
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte){
    return pan_protocol_stack::tcp::run()._read(fildes,buf,nbyte);
}
ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte){
    return pan_protocol_stack::tcp::run()._write(fildes,buf,nbyte);
}
int __wrap_close(int fildes){
    return pan_protocol_stack::tcp::run()._close(fildes);
}
int __wrap_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res)
    {
        return pan_protocol_stack::tcp::run()._getaddrinfo(
            node, service,hints,res);
    }