#ifndef PROXY_LIST_H
#define PROXY_LIST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Single proxy entry with IPv4 + port + optional username/password
 */
typedef struct {
    char ip[64];       /* IPv4 string */
    uint16_t port;     /* numeric port */
    char user[64];     /* proxy username (optional) */
    char pass[64];     /* proxy password (optional) */
} btkg_proxy_t;

/*
 * Proxy list
 */
typedef struct {
    size_t count;
    size_t capacity;
    btkg_proxy_t *proxies;
} btkg_proxy_list_t;

/* initialize list */
void btkg_proxy_list_init(btkg_proxy_list_t *list);

/* free list */
void btkg_proxy_list_free(btkg_proxy_list_t *list);

/*
 * Append a proxy entry manually.
 */
int btkg_proxy_list_append(btkg_proxy_list_t *list,
                           const char *ip, uint16_t port,
                           const char *user, const char *pass);

/*
 * Load proxies from file
 * Format:
 *   ip:port
 *   ip:port:user:pass
 *   ip:port::
 *   ip:port:user:
 */
int btkg_proxy_list_load_from_file(const char *filename,
                                   btkg_proxy_list_t *list);

#ifdef __cplusplus
}
#endif

#endif /* PROXY_LIST_H */
