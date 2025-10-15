#define _POSIX_C_SOURCE 200809L
#include "proxy_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>

#include "log.h"

#ifndef BTKG_PROXY_LIST_INITIAL_CAP
#define BTKG_PROXY_LIST_INITIAL_CAP 16
#endif

#define IPV4_STR_MAX 16

void btkg_proxy_list_init(btkg_proxy_list_t *list) {
    if (!list) return;
    list->count = 0;
    list->capacity = BTKG_PROXY_LIST_INITIAL_CAP;
    list->proxies = calloc(list->capacity, sizeof(btkg_proxy_t));
    if (list->proxies == NULL) {
        log_error("btkg_proxy_list_init: calloc failed");
        list->capacity = 0;
    } else {
        log_debug("btkg_proxy_list_init: allocated capacity %zu", list->capacity);
    }
}

void btkg_proxy_list_free(btkg_proxy_list_t *list) {
    if (!list) return;
    if (list->proxies) {
        free(list->proxies);
        list->proxies = NULL;
    }
    list->count = 0;
    list->capacity = 0;
    log_debug("btkg_proxy_list_free: freed proxy list");
}

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

static int parse_ipv4_port(const char *line, char *ip_out, size_t ip_out_size, uint16_t *port_out) {
    if (!line || !ip_out || !port_out || ip_out_size < IPV4_STR_MAX) return 0;

    const char *colon = strchr(line, ':');
    if (!colon) {
        log_debug("parse_ipv4_port: no ':' found in '%s'", line);
        return 0;
    }

    size_t ip_len = (size_t)(colon - line);
    if (ip_len == 0 || ip_len >= IPV4_STR_MAX) {
        log_debug("parse_ipv4_port: invalid ip length %zu in '%s'", ip_len, line);
        return 0;
    }

    char ipbuf[IPV4_STR_MAX];
    memcpy(ipbuf, line, ip_len);
    ipbuf[ip_len] = '\0';

    struct in_addr ina;
    if (inet_pton(AF_INET, ipbuf, &ina) != 1) {
        log_debug("parse_ipv4_port: inet_pton failed for ip '%s'", ipbuf);
        return 0;
    }

    const char *port_s = colon + 1;
    if (*port_s == '\0') {
        log_debug("parse_ipv4_port: empty port in '%s'", line);
        return 0;
    }

    char *endptr = NULL;
    errno = 0;
    long p = strtol(port_s, &endptr, 10);
    if (errno != 0 || endptr == port_s || *endptr != '\0') {
        log_debug("parse_ipv4_port: port parse failed for '%s' (errno=%d)", port_s, errno);
        return 0;
    }
    if (p < 1 || p > 65535) {
        log_debug("parse_ipv4_port: port out of range %ld in '%s'", p, line);
        return 0;
    }

    size_t copy_len = (ip_len < ip_out_size - 1) ? ip_len : ip_out_size - 1;
    memcpy(ip_out, ipbuf, copy_len);
    ip_out[copy_len] = '\0';
    *port_out = (uint16_t)p;
    return 1;
}

int btkg_proxy_list_append(btkg_proxy_list_t *list, const char *ip_str, uint16_t port) {
    if (!list || !ip_str) return -1;

    struct in_addr ina;
    if (inet_pton(AF_INET, ip_str, &ina) != 1) {
        log_error("btkg_proxy_list_append: invalid IPv4 '%s'", ip_str);
        return -1;
    }
    if (port == 0) {
        log_error("btkg_proxy_list_append: invalid port 0");
        return -1;
    }

    if (!list->proxies) {
        list->capacity = BTKG_PROXY_LIST_INITIAL_CAP;
        list->proxies = calloc(list->capacity, sizeof(btkg_proxy_t));
        if (!list->proxies) {
            log_error("btkg_proxy_list_append: calloc failed");
            list->capacity = 0;
            return -1;
        }
    }

    if (list->count >= list->capacity) {
        size_t newcap = list->capacity ? list->capacity * 2 : BTKG_PROXY_LIST_INITIAL_CAP;
        btkg_proxy_t *tmp = realloc(list->proxies, newcap * sizeof(btkg_proxy_t));
        if (!tmp) {
            log_error("btkg_proxy_list_append: realloc failed");
            return -1;
        }
        list->proxies = tmp;
        list->capacity = newcap;
        log_debug("btkg_proxy_list_append: increased capacity to %zu", list->capacity);
    }

    btkg_proxy_t *dst = &list->proxies[list->count];
    
    size_t ip_len = strlen(ip_str);
    size_t max_copy = sizeof(dst->ip) - 1;
    size_t copy_len = (ip_len < max_copy) ? ip_len : max_copy;
    
    memcpy(dst->ip, ip_str, copy_len);
    dst->ip[copy_len] = '\0';
    dst->port = port;
    
    list->count++;

    log_info("btkg_proxy_list_append: appended proxy %s:%u (total=%zu)", dst->ip, (unsigned)dst->port, list->count);
    return 0;
}

int btkg_proxy_list_load_from_file(const char *filename, btkg_proxy_list_t *list) {
    if (!filename || !list) return -1;

    log_info("btkg_proxy_list_load_from_file: loading proxies from '%s'", filename);

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_error("btkg_proxy_list_load_from_file: fopen('%s') failed: %s", filename, strerror(errno));
        return -1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    int appended = 0;
    int lineno = 0;

    while ((nread = getline(&line, &len, f)) != -1) {
        lineno++;
        log_debug("line %d: raw read %zd bytes", lineno, nread);

        if (nread > 0) {
            while (nread > 0 && (line[nread-1] == '\n' || line[nread-1] == '\r')) {
                line[nread-1] = '\0';
                nread--;
            }
        }

        char *trimmed = trim(line);
        log_debug("line %d trimmed => '%s'", lineno, trimmed);

        if (trimmed[0] == '\0') {
            log_debug("line %d: skipped (empty)", lineno);
            continue;
        }
        if (trimmed[0] == '#') {
            log_debug("line %d: skipped (comment)", lineno);
            continue;
        }

        char ipbuf[IPV4_STR_MAX];
        uint16_t port;
        if (!parse_ipv4_port(trimmed, ipbuf, sizeof(ipbuf), &port)) {
            log_error("line %d: invalid proxy format or invalid ip/port: '%s' (expected IPv4:port)", lineno, trimmed);
            continue;
        }

        log_debug("line %d: parsed ip='%s' port=%u", lineno, ipbuf, (unsigned)port);

        if (btkg_proxy_list_append(list, ipbuf, port) == 0) {
            appended++;
        } else {
            log_error("line %d: failed to append proxy %s:%u", lineno, ipbuf, (unsigned)port);
            free(line);
            fclose(f);
            return -1;
        }
    }

    free(line);
    fclose(f);

    log_info("btkg_proxy_list_load_from_file: finished, appended %d proxies", appended);
    return appended;
}
