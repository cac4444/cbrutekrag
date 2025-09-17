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
#include <sys/select.h>
#include <stdint.h>

#include "cbrutekrag.h" /* for btkg_context_t definition in your project */
#include "log.h"        /* project logging helpers */

/* default timeout in seconds if context==NULL or option not set */
#ifndef BTKG_PROXY_DEFAULT_TIMEOUT
#define BTKG_PROXY_DEFAULT_TIMEOUT 5
#endif

/* helper: set socket non-blocking, return previous flags on success, -1 on error */
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

/* helper: perform non-blocking connect with timeout (seconds).
 * returns 0 on success (connected), -1 on failure (socket closed by caller)
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

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sockfd, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    rc = select(sockfd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) {
        /* timeout or select error */
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    /* check for socket error */
    int so_err = 0;
    socklen_t len = sizeof(so_err);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0) {
        restore_flags(sockfd, orig_flags);
        return -1;
    }
    if (so_err != 0) {
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    /* connected */
    restore_flags(sockfd, orig_flags);
    return 0;
}

/* helper: fully write buffer (handles partial writes) */
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

/* helper: read exactly n bytes (or fail). returns 0 on success, -1 on error */
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
        /* prefer proxy_timeout if set, else fall back to general timeout */
        if (context->options.proxy_timeout)
            timeout = context->options.proxy_timeout;
        else if (context->options.timeout)
            timeout = context->options.timeout;
    }

    int sock = -1;
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(proxy_port);
    if (inet_pton(AF_INET, proxy_ip, &sa.sin_addr) != 1) {
        log_error("proxy_socks5_connect: invalid proxy IP '%s'", proxy_ip);
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("proxy_socks5_connect: socket() failed: %s", strerror(errno));
        return -1;
    }

    /* connect with timeout */
    if (connect_with_timeout(sock, (struct sockaddr *)&sa, sizeof(sa), timeout) != 0) {
        log_error("proxy_socks5_connect: connect to proxy %s:%u failed", proxy_ip, (unsigned)proxy_port);
        close(sock);
        return -1;
    }

    /* --- SOCKS5 handshake (no auth) --- */
    unsigned char greeting[3];
    greeting[0] = 0x05; /* VER */
    greeting[1] = 0x01; /* NMETHODS */
    greeting[2] = 0x00; /* METHOD = NO AUTH */

    if (write_all(sock, greeting, sizeof(greeting)) != (ssize_t)sizeof(greeting)) {
        log_error("proxy_socks5_connect: failed to send greeting");
        close(sock);
        return -1;
    }

    unsigned char method_sel[2];
    if (recv_all(sock, method_sel, sizeof(method_sel)) != 0) {
        log_error("proxy_socks5_connect: failed to read method selection");
        close(sock);
        return -1;
    }
    if (method_sel[0] != 0x05 || method_sel[1] != 0x00) {
        log_error("proxy_socks5_connect: proxy does not accept NO AUTH (VER=%u, METHOD=%u)", method_sel[0], method_sel[1]);
        close(sock);
        return -1;
    }

    /* --- SOCKS5 CONNECT request --- */
    /* Build request buffer dynamically depending on dest_host form */
    unsigned char req[512];
    size_t req_len = 0;

    req[0] = 0x05; /* VER */
    req[1] = 0x01; /* CMD = CONNECT */
    req[2] = 0x00; /* RSV */

    /* check if dest_host is IPv4 numeric */
    struct in_addr dest_addr;
    if (inet_pton(AF_INET, dest_host, &dest_addr) == 1) {
        /* IPv4 */
        req[3] = 0x01; /* ATYP = IPv4 */
        memcpy(req + 4, &dest_addr.s_addr, 4); /* network byte order already */
        uint16_t netport = htons(dest_port);
        memcpy(req + 8, &netport, 2);
        req_len = 10;
    } else {
        /* Domain name */
        size_t hn = strlen(dest_host);
        if (hn > 255) {
            log_error("proxy_socks5_connect: dest hostname too long");
            close(sock);
            return -1;
        }
        req[3] = 0x03; /* ATYP = DOMAIN NAME */
        req[4] = (unsigned char)hn;
        memcpy(req + 5, dest_host, hn);
        uint16_t netport = htons(dest_port);
        memcpy(req + 5 + hn, &netport, 2);
        req_len = 5 + hn + 2;
    }

    if (write_all(sock, req, req_len) != (ssize_t)req_len) {
        log_error("proxy_socks5_connect: failed to send connect request");
        close(sock);
        return -1;
    }

    /* read reply: first 4 bytes (VER, REP, RSV, ATYP) */
    unsigned char reply_hdr[4];
    if (recv_all(sock, reply_hdr, sizeof(reply_hdr)) != 0) {
        log_error("proxy_socks5_connect: failed to read reply header");
        close(sock);
        return -1;
    }

    if (reply_hdr[0] != 0x05) {
        log_error("proxy_socks5_connect: invalid reply ver %u", reply_hdr[0]);
        close(sock);
        return -1;
    }

    if (reply_hdr[1] != 0x00) {
        log_error("proxy_socks5_connect: proxy reply error code %u", reply_hdr[1]);
        close(sock);
        return -1;
    }

    /* read BND.ADDR based on ATYP, then BND.PORT (2 bytes) */
    if (reply_hdr[3] == 0x01) {
        /* IPv4: 4 bytes addr + 2 bytes port */
        unsigned char addrbuf[6];
        if (recv_all(sock, addrbuf, sizeof(addrbuf)) != 0) {
            log_error("proxy_socks5_connect: failed to read bnd.addr IPv4");
            close(sock);
            return -1;
        }
        /* ignore values */
    } else if (reply_hdr[3] == 0x03) {
        /* domain: first length, then name, then 2 bytes port */
        unsigned char lenb;
        if (recv_all(sock, &lenb, 1) != 0) {
            log_error("proxy_socks5_connect: failed to read bnd.addr domain len");
            close(sock);
            return -1;
        }
        size_t name_len = (size_t)lenb;
        if (name_len > 0) {
            unsigned char tmpbuf[256];
            if (recv_all(sock, tmpbuf, name_len) != 0) {
                log_error("proxy_socks5_connect: failed to read bnd.addr domain name");
                close(sock);
                return -1;
            }
        }
        unsigned char portbuf[2];
        if (recv_all(sock, portbuf, 2) != 0) {
            log_error("proxy_socks5_connect: failed to read bnd.port");
            close(sock);
            return -1;
        }
    } else if (reply_hdr[3] == 0x04) {
        /* IPv6 (16 bytes) + port(2) - consume */
        unsigned char tmp[18];
        if (recv_all(sock, tmp, sizeof(tmp)) != 0) {
            log_error("proxy_socks5_connect: failed to read bnd.addr IPv6");
            close(sock);
            return -1;
        }
    } else {
        log_error("proxy_socks5_connect: unknown ATYP %u", reply_hdr[3]);
        close(sock);
        return -1;
    }

    /* success */
    *out_fd = sock;
    return 0;
}
