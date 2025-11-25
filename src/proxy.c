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
#include <poll.h>       /* Required for thread-safe timeouts */

#include "cbrutekrag.h"
#include "log.h"

#ifndef BTKG_PROXY_DEFAULT_TIMEOUT
#define BTKG_PROXY_DEFAULT_TIMEOUT 5
#endif

/* --- Helper Functions (Same as before) --- */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -1;
    return flags;
}

static int restore_flags(int fd, int flags) {
    if (fcntl(fd, F_SETFL, flags) == -1) return -1;
    return 0;
}

/* Uses poll() to avoid buffer overflow crashes with high thread counts */
static int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int orig_flags = set_nonblocking(sockfd);
    if (orig_flags == -1) return -1;

    int rc = connect(sockfd, addr, addrlen);
    if (rc == 0) {
        restore_flags(sockfd, orig_flags);
        return 0;
    }

    if (errno != EINPROGRESS) {
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLOUT;

    rc = poll(&pfd, 1, timeout_sec * 1000);

    if (rc <= 0) {
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    int so_err = 0;
    socklen_t len = sizeof(so_err);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0 || so_err != 0) {
        restore_flags(sockfd, orig_flags);
        return -1;
    }

    restore_flags(sockfd, orig_flags);
    return 0;
}

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

static int recv_all(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = recv(fd, p, left, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        p += r;
        left -= (size_t)r;
    }
    return 0;
}

/* --- Main Proxy Logic --- */

int btkg_proxy_socks5_connect(btkg_context_t *context,
                              const char *proxy_ip, uint16_t proxy_port,
                              const char *proxy_user, const char *proxy_pass,
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

    snprintf(port_str, sizeof(port_str), "%u", proxy_port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* Force IPv4 */
    hints.ai_socktype = SOCK_STREAM;

    /* Resolve Proxy Address (Thread-safe) */
    int gai_err = getaddrinfo(proxy_ip, port_str, &hints, &res);
    if (gai_err != 0) {
        log_error("proxy_socks5_connect: could not resolve proxy '%s': %s", 
                  proxy_ip, gai_strerror(gai_err));
        return -1;
    }

    /* Try to connect */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;

        if (connect_with_timeout(sock, rp->ai_addr, rp->ai_addrlen, timeout) == 0) {
            break; 
        }

        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock == -1) {
        return -1;
    }

    /* --- SOCKS5 Handshake: Greeting --- */
    unsigned char greeting[4];
    size_t greeting_len;

    /* Check if we have credentials to send */
    int has_auth = (proxy_user != NULL && proxy_pass != NULL && 
                   strlen(proxy_user) > 0 && strlen(proxy_pass) > 0);

    if (has_auth) {
        /* Offer Method 0x00 (No Auth) AND 0x02 (Username/Password) */
        greeting[0] = 0x05; // Version
        greeting[1] = 0x02; // Number of methods
        greeting[2] = 0x00; // Method: No Auth
        greeting[3] = 0x02; // Method: User/Pass
        greeting_len = 4;
    } else {
        /* Offer only Method 0x00 (No Auth) */
        greeting[0] = 0x05;
        greeting[1] = 0x01;
        greeting[2] = 0x00;
        greeting_len = 3;
    }

    if (write_all(sock, greeting, greeting_len) != (ssize_t)greeting_len) {
        close(sock);
        return -1;
    }

    /* Read Server Choice */
    unsigned char method_sel[2];
    if (recv_all(sock, method_sel, sizeof(method_sel)) != 0) {
        close(sock);
        return -1;
    }
    if (method_sel[0] != 0x05) {
        close(sock);
        return -1;
    }

    unsigned char chosen_method = method_sel[1];

    /* --- SOCKS5 Handshake: Authentication (if requested) --- */
    if (chosen_method == 0x02) {
        if (!has_auth) {
            /* Server wants auth, but we didn't provide any? Should be impossible based on greeting. */
            close(sock);
            return -1;
        }

        size_t ulen = strlen(proxy_user);
        size_t plen = strlen(proxy_pass);
        
        if (ulen > 255 || plen > 255) {
            log_error("proxy_socks5_connect: credentials too long");
            close(sock);
            return -1;
        }

        /* Build Auth Request: [0x01][ULEN][USER][PLEN][PASS] */
        unsigned char auth_req[515]; // Max size
        size_t idx = 0;
        auth_req[idx++] = 0x01;       // Sub-negotiation Version
        auth_req[idx++] = (unsigned char)ulen;
        memcpy(&auth_req[idx], proxy_user, ulen);
        idx += ulen;
        auth_req[idx++] = (unsigned char)plen;
        memcpy(&auth_req[idx], proxy_pass, plen);
        idx += plen;

        if (write_all(sock, auth_req, idx) != (ssize_t)idx) {
            close(sock);
            return -1;
        }

        /* Read Auth Response: [0x01][STATUS] */
        unsigned char auth_resp[2];
        if (recv_all(sock, auth_resp, sizeof(auth_resp)) != 0) {
            close(sock);
            return -1;
        }

        if (auth_resp[1] != 0x00) {
            log_debug("proxy_socks5_connect: authentication failed for %s", proxy_user);
            close(sock);
            return -1;
        }

    } else if (chosen_method != 0x00) {
        /* Server rejected our methods (0xFF) or wants unsupported method */
        close(sock);
        return -1;
    }

    /* --- SOCKS5 CONNECT Request --- */
    unsigned char req[512];
    size_t req_len = 0;

    req[0] = 0x05; 
    req[1] = 0x01; /* CONNECT */
    req[2] = 0x00; 

    struct in_addr dest_addr;
    if (inet_pton(AF_INET, dest_host, &dest_addr) == 1) {
        req[3] = 0x01; /* IPv4 */
        memcpy(req + 4, &dest_addr.s_addr, 4); 
        uint16_t netport = htons(dest_port);
        memcpy(req + 8, &netport, 2);
        req_len = 10;
    } else {
        size_t hn = strlen(dest_host);
        if (hn > 255) {
            close(sock);
            return -1;
        }
        req[3] = 0x03; /* Domain */
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

    /* Read Reply Header */
    unsigned char reply_hdr[4];
    if (recv_all(sock, reply_hdr, sizeof(reply_hdr)) != 0) {
        close(sock);
        return -1;
    }

    if (reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00) {
        close(sock);
        return -1;
    }

    /* Consume Remainder */
    if (reply_hdr[3] == 0x01) {
        unsigned char buf[6];
        recv_all(sock, buf, 6);
    } else if (reply_hdr[3] == 0x03) {
        unsigned char lenb;
        if (recv_all(sock, &lenb, 1) == 0) {
            unsigned char buf[256 + 2];
            recv_all(sock, buf, lenb + 2);
        }
    } else if (reply_hdr[3] == 0x04) {
        unsigned char buf[18];
        recv_all(sock, buf, 18);
    }

    *out_fd = sock;
    return 0;
}
