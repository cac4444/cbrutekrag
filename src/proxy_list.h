#ifndef BTKG_PROXY_LIST_H
#define BTKG_PROXY_LIST_H

#include <stdint.h>
#include <stddef.h>

/* Canary value to detect memory corruption */
#define BTKG_PROXY_CANARY 0xDEADBEEFu

/* A single proxy entry (IPv4 only) */
typedef struct {
    char ip[16];        /* dotted-decimal IPv4 */
    uint16_t port;      /* TCP port */
    uint32_t canary;    /* must be BTKG_PROXY_CANARY */
} btkg_proxy_t;

/* Dynamic proxy list container */
typedef struct {
    btkg_proxy_t *proxies; /* dynamically allocated array */
    size_t count;          /* number of valid proxies */
    size_t capacity;       /* allocated capacity */
} btkg_proxy_list_t;

/* API */
void btkg_proxy_list_init(btkg_proxy_list_t *list);
void btkg_proxy_list_free(btkg_proxy_list_t *list);
int  btkg_proxy_list_append(btkg_proxy_list_t *list, const char *ip_str, uint16_t port);
int  btkg_proxy_list_load_from_file(const char *filename, btkg_proxy_list_t *list);

#endif /* BTKG_PROXY_LIST_H */
