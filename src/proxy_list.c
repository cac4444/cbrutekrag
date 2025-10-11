#define _POSIX_C_SOURCE 200809L
#include "proxy_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#ifndef BTKG_PROXY_LIST_INITIAL_CAP
#define BTKG_PROXY_LIST_INITIAL_CAP 16
#endif

void btkg_proxy_list_init(btkg_proxy_list_t *list) {
    if (!list) return;
    list->count = 0;
    list->capacity = BTKG_PROXY_LIST_INITIAL_CAP;
    list->proxies = calloc(list->capacity, sizeof(btkg_proxy_t));
    if (!list->proxies) {
        list->capacity = 0;
    }
}

void btkg_proxy_list_free(btkg_proxy_list_t *list) {
    if (!list) return;
    free(list->proxies);
    list->proxies = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* trim leading/trailing whitespace in-place, return pointer to trimmed start */
static char *trim(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

/* validate IPv4 string and numeric port string; on success, fill ip_out and port_out */
static int parse_ipv4_port(const char *line, char *ip_out /* len >=16 */, uint16_t *port_out) {
    if (!line || !ip_out || !port_out) return 0;
    const char *colon = strchr(line, ':');
    if (!colon) return 0;

    size_t ip_len = (size_t)(colon - line);
    if (ip_len == 0 || ip_len >= 16) return 0;

    char ipbuf[16];
    memcpy(ipbuf, line, ip_len);
    ipbuf[ip_len] = '\0';

    struct in_addr a;
    if (inet_pton(AF_INET, ipbuf, &a) != 1) return 0;

    const char *port_str = colon + 1;
    if (*port_str == '\0') return 0;

    char *endptr = NULL;
    errno = 0;
    long p = strtol(port_str, &endptr, 10);
    if (errno != 0 || endptr == port_str || *endptr != '\0') return 0;
    if (p < 1 || p > 65535) return 0;

    /* success */
    snprintf(ip_out, 16, "%s", ipbuf);  /* safe, always null-terminates */
    *port_out = (uint16_t)p;            /* host order */
    return 1;
}

int btkg_proxy_list_append(btkg_proxy_list_t *list, const char *ip_str, uint16_t port) {
    if (!list || !ip_str) return -1;

    /* basic validation of ip */
    struct in_addr tmp;
    if (inet_pton(AF_INET, ip_str, &tmp) != 1) return -1;
    if (port == 0) return -1;

    if (!list->proxies) {
        list->capacity = BTKG_PROXY_LIST_INITIAL_CAP;
        list->proxies = calloc(list->capacity, sizeof(btkg_proxy_t));
        if (!list->proxies) return -1;
    }

    if (list->count >= list->capacity) {
        size_t newcap = list->capacity ? list->capacity * 2 : BTKG_PROXY_LIST_INITIAL_CAP;
        btkg_proxy_t *tmpproxies = realloc(list->proxies, newcap * sizeof(btkg_proxy_t));
        if (!tmpproxies) return -1;
        list->proxies = tmpproxies;
        list->capacity = newcap;
    }

    /* append */
    btkg_proxy_t *dst = &list->proxies[list->count++];
    strncpy(dst->ip, ip_str, sizeof(dst->ip));
    dst->ip[sizeof(dst->ip) - 1] = '\0';
    dst->port = port;
    return 0;
}

int btkg_proxy_list_load_from_file(const char *filename, btkg_proxy_list_t *list) {
    if (!filename || !list) return -1;

    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    char *line = NULL;
    size_t linelen = 0;
    ssize_t nread;
    int appended = 0;

    while ((nread = getline(&line, &linelen, f)) != -1) {
        if (nread <= 0) continue;
        char *trimmed = trim(line);
        if (trimmed[0] == '\0') continue; /* skip blank */
        if (trimmed[0] == '#') continue;  /* skip comments */

        /* safety: trimmed should be short */
        if (strlen(trimmed) >= 64) continue; /* too long line, skip */

        char ipbuf[16];
        uint16_t port;
        if (!parse_ipv4_port(trimmed, ipbuf, &port)) {
            /* invalid, skip */
            continue;
        }

        if (btkg_proxy_list_append(list, ipbuf, port) == 0) {
            appended++;
        } else {
            /* OOM or fatal: clean up and return -1 */
            free(line);
            fclose(f);
            return -1;
        }
    }

    free(line);
    fclose(f);
    return appended;
}
