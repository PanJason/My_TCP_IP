#ifndef __WRAP_H_
#define __WRAP_H_

extern "C"{
int __real_socket(int domain, int type, int protocol);

int __real_bind(int socket, const struct sockaddr *address,
                socklen_t address_len);

int __real_listen(int socket, int backlog);

int __real_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len);

int __real_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len);

ssize_t __real_read(int fildes, void *buf, size_t nbyte);

ssize_t __real_write(int fildes, const void *buf, size_t nbyte);

int __real_close(int fildes);

int __real_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);
}
#endif