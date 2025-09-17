#ifndef PROXY_H
#define PROXY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* forward-declare context to avoid forcing header inclusion */
typedef struct btkg_context_s btkg_context_t;

/*
 * Establish a TCP connection to `proxy_ip:proxy_port`, perform SOCKS5 handshake
 * and request a CONNECT to `dest_host:dest_port`. On success, returns 0 and
 * stores the connected socket FD in *out_fd (the caller is responsible for close()).
 *
 * On any failure returns -1 and closes any created socket.
 *
 * Notes:
 *  - proxy_ip must be an IPv4 numeric string (e.g. "1.2.3.4").
 *  - dest_host may be an IPv4 string or a domain name.
 *  - Uses context->options.timeout (seconds) as timeout if context != NULL.
 */
int btkg_proxy_socks5_connect(btkg_context_t *context,
                              const char *proxy_ip, uint16_t proxy_port,
                              const char *dest_host, uint16_t dest_port,
                              int *out_fd);

#ifdef __cplusplus
}
#endif

#endif /* PROXY_H */
