#define _POSIX_C_SOURCE 200809L
#include "proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     /* close */
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdint.h>

/* FIXED: Replaced sys/select.h with poll.h */
#include <poll.h>

#include "cbrutekrag.h"
#include "log.h"

#ifndef BTKG_PROXY_DEFAULT_TIMEOUT
#define BTKG_PROXY_DEFAULT_TIMEOUT 5
#endif

/* helper: set socket non-blocking */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -1;
    return flags;
}

/* helper: restore flags */
static int restore_flags(int fd, int flags) {
    if (fcntl(fd, F_SETFL, flags) == -1) return -1;
    return 0;
}

/* 
 * FIXED: connect_with_timeout using poll() instead of select().
 * select() crashes (buffer overflow) if sockfd >= 1024.
 */
static int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int orig_flags = set_nonblocking(sockfd);
    if (orig_flags == -1) {
        return -1;
    }

    int rc = connect(sockfd, addr, addrlen);
    if (rc == 0) {
        /* immediately connected */
        restore_flags(sockfd, orig_flags);
        return 0;
    }

    if (errno != EINPROGRESS) {
        /* immediate error */
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    /* FIXED: Use poll() structure */
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLOUT; /* We wait for writing (connection established) */

    /* poll timeout is in milliseconds */
    rc = poll(&pfd, 1, timeout_sec * 1000);

    if (rc == -1) {
        /* poll error */
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    if (rc == 0) {
        /* timeout */
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    /* Check for socket error using getsockopt */
    int so_err = 0;
    socklen_t len = sizeof(so_err);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0) {
        restore_flags(sockfd, orig_flags);
        return -1;
    }
    if (so_err != 0) {
        /* Connection failed asynchronously */
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    /* connected */
    restore_flags(sockfd, orig_flags);
    return 0;
}

/* helper: fully write buffer */
static ssize_t write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        left -= (size_t)n;
    }
    return (ssize_t)len;
}

/* helper: read exactly n bytes */
static int recv_all(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = recv(fd, p, left, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1; /* peer closed */
        p += r;
        left -= (size_t)r;
    }
    return 0;
}

/* FIXED: Supports Hostnames (DNS) and IPs using getaddrinfo */
int btkg_proxy_socks5_connect(btkg_context_t *context,
                              const char *proxy_ip, uint16_t proxy_port,
                              const char *dest_host, uint16_t dest_port,
                              int *out_fd)
{
    if (proxy_ip == NULL || dest_host == NULL || out_fd == NULL) {
        log_error("proxy_socks5_connect: invalid args");
        return -1;
    }

    int timeout = BTKG_PROXY_DEFAULT_TIMEOUT;
    if (context != NULL) {
        if (context->options.proxy_timeout)
            timeout = context->options.proxy_timeout;
        else if (context->options.timeout)
            timeout = context->options.timeout;
    }

    int sock = -1;
    struct addrinfo hints, *res, *rp;
    char port_str[6];

    /* Convert port to string for getaddrinfo */
    snprintf(port_str, sizeof(port_str), "%u", proxy_port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      /* Force IPv4 for now (easier for SOCKS5) */
    hints.ai_socktype = SOCK_STREAM;

    /* 1. Resolve Proxy Hostname (Thread-Safe) */
    int gai_err = getaddrinfo(proxy_ip, port_str, &hints, &res);
    if (gai_err != 0) {
        log_error("proxy_socks5_connect: could not resolve proxy '%s': %s", 
                  proxy_ip, gai_strerror(gai_err));
        return -1;
    }

    /* 2. Try to connect to one of the resolved addresses */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;

        if (connect_with_timeout(sock, rp->ai_addr, rp->ai_addrlen, timeout) == 0) {
            break; /* Success */
        }

        close(sock); /* Failed, try next */
        sock = -1;
    }

    freeaddrinfo(res); /* Free memory allocated by getaddrinfo */

    if (sock == -1) {
        log_debug("proxy_socks5_connect: failed to connect to proxy %s:%u", 
                  proxy_ip, (unsigned)proxy_port);
        return -1;
    }

    /* --- SOCKS5 handshake (no auth) --- */
    unsigned char greeting[3];
    greeting[0] = 0x05; 
    greeting[1] = 0x01; 
    greeting[2] = 0x00; 

    if (write_all(sock, greeting, sizeof(greeting)) != (ssize_t)sizeof(greeting)) {
        close(sock);
        return -1;
    }

    unsigned char method_sel[2];
    if (recv_all(sock, method_sel, sizeof(method_sel)) != 0) {
        close(sock);
        return -1;
    }
    if (method_sel[0] != 0x05 || method_sel[1] != 0x00) {
        close(sock);
        return -1;
    }

    /* --- SOCKS5 CONNECT request --- */
    unsigned char req[512];
    size_t req_len = 0;

    req[0] = 0x05; 
    req[1] = 0x01; /* CONNECT */
    req[2] = 0x00; 

    /* Resolve destination to see if it is IP or Hostname */
    struct in_addr dest_addr;
    if (inet_pton(AF_INET, dest_host, &dest_addr) == 1) {
        /* IPv4: Pass raw bytes to proxy */
        req[3] = 0x01; 
        memcpy(req + 4, &dest_addr.s_addr, 4); 
        uint16_t netport = htons(dest_port);
        memcpy(req + 8, &netport, 2);
        req_len = 10;
    } else {
        /* Hostname: Let the PROXY server resolve it (Remote DNS) */
        size_t hn = strlen(dest_host);
        if (hn > 255) {
            log_error("proxy_socks5_connect: dest hostname too long");
            close(sock);
            return -1;
        }
        req[3] = 0x03; 
        req[4] = (unsigned char)hn;
        memcpy(req + 5, dest_host, hn);
        uint16_t netport = htons(dest_port);
        memcpy(req + 5 + hn, &netport, 2);
        req_len = 5 + hn + 2;
    }

    if (write_all(sock, req, req_len) != (ssize_t)req_len) {
        close(sock);
        return -1;
    }

    /* read reply header */
    unsigned char reply_hdr[4];
    if (recv_all(sock, reply_hdr, sizeof(reply_hdr)) != 0) {
        close(sock);
        return -1;
    }

    if (reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00) {
        close(sock);
        return -1;
    }

    /* Consume the rest of the response */
    if (reply_hdr[3] == 0x01) {
        unsigned char addrbuf[6];
        recv_all(sock, addrbuf, sizeof(addrbuf));
    } else if (reply_hdr[3] == 0x03) {
        unsigned char lenb;
        if (recv_all(sock, &lenb, 1) == 0) {
            size_t name_len = (size_t)lenb;
            unsigned char tmpbuf[256];
            recv_all(sock, tmpbuf, name_len);
            unsigned char portbuf[2];
            recv_all(sock, portbuf, 2);
        }
    } else if (reply_hdr[3] == 0x04) {
        unsigned char tmp[18];
        recv_all(sock, tmp, sizeof(tmp));
    }

    *out_fd = sock;
    return 0;
}
