#ifndef PROXY_H
#define PROXY_H

#include <stdint.h>

/* include the project header that defines btkg_context_t (complete type) */
#include "cbrutekrag.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Establish a TCP connection to `proxy_ip:proxy_port`, perform SOCKS5 handshake
 * (supporting optional Username/Password authentication) and request a CONNECT 
 * to `dest_host:dest_port`.
 *
 * On success, returns 0 and stores the connected socket FD in *out_fd 
 * (the caller is responsible for close()).
 *
 * On any failure returns -1 and closes any created socket.
 *
 * Notes:
 *  - proxy_ip can be an IPv4/IPv6 numeric string or a hostname (DNS resolution is supported).
 *  - dest_host may be an IP string or a domain name (resolved remotely by the proxy).
 *  - proxy_user and proxy_pass can be NULL if no authentication is required.
 *  - Uses context->options.proxy_timeout (if context != NULL) or falls back to default.
 */
int btkg_proxy_socks5_connect(btkg_context_t *context,
                              const char *proxy_ip, uint16_t proxy_port,
                              const char *proxy_user, const char *proxy_pass,
                              const char *dest_host, uint16_t dest_port,
                              int *out_fd);

/* Optional: the two-step helpers described previously */
int btkg_proxy_tcp_connect(const char *proxy_ip, uint16_t proxy_port, int *out_fd);
int btkg_proxy_socks5_request_connect(int sockfd, const char *dest_host, uint16_t dest_port);

#ifdef __cplusplus
}
#endif

#endif /* PROXY_H */
