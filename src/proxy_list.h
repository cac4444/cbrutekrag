#ifndef PROXY_LIST_H
#define PROXY_LIST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* single proxy: IPv4 address string and numeric port */
typedef struct {
    char ip[16];     /* e.g. "192.168.0.1" + NUL */
    uint16_t port;   /* host byte order */
} btkg_proxy_t;

/* list of proxies: count and pointer to array of btkg_proxy_t */
typedef struct {
    size_t count;        /* number of proxies stored */
    btkg_proxy_t *proxies; /* dynamically allocated array (length >= count) */
    size_t capacity;     /* internal capacity (not required but helpful) */
} btkg_proxy_list_t;

/* initialize list (must be called before use) */
void btkg_proxy_list_init(btkg_proxy_list_t *list);

/* free list contents and reset to empty */
void btkg_proxy_list_free(btkg_proxy_list_t *list);

/*
 * Append a single proxy to list.
 * ip_str must be a null-terminated IPv4 string, port is numeric (host order).
 * Returns 0 on success, -1 on invalid input or OOM.
 */
int btkg_proxy_list_append(btkg_proxy_list_t *list, const char *ip_str, uint16_t port);

/*
 * Load proxies from file and append to list.
 * Each non-empty non-comment line must be "IPv4:port" (e.g. 1.2.3.4:1080).
 * Returns number of proxies appended (>=0) on success, or -1 on fatal error (e.g. can't open file).
 */
int btkg_proxy_list_load_from_file(const char *filename, btkg_proxy_list_t *list);

#ifdef __cplusplus
}
#endif

#endif /* PROXY_LIST_H */
