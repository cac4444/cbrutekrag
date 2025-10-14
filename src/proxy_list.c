#define _POSIX_C_SOURCE 200809L
#include "proxy_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>

#include "log.h" /* project logging functions: log_info, log_debug, log_error */

/* Initial capacity for proxy array */
#ifndef BTKG_PROXY_LIST_INITIAL_CAP
#define BTKG_PROXY_LIST_INITIAL_CAP 16
#endif

void btkg_proxy_list_init(btkg_proxy_list_t *list) {
    if (!list) return;
    list->count = 0;
    list->capacity = BTKG_PROXY_LIST_INITIAL_CAP;
    list->items = calloc(list->capacity, sizeof(btkg_proxy_t));
    if (list->items == NULL) {
        log_error("btkg_proxy_list_init: calloc failed");
        list->capacity = 0;
    } else {
        log_debug("btkg_proxy_list_init: allocated capacity %zu", list->capacity);
    }
}

void btkg_proxy_list_free(btkg_proxy_list_t *list) {
    if (!list) return;
    if (list->items) {
        free(list->items);
        list->items = NULL;
    }
    list->count = 0;
    list->capacity = 0;
    log_debug("btkg_proxy_list_free: freed proxy list");
}

/* trim leading/trailing whitespace in-place; return pointer to trimmed start */
static char *trim(char *s) {
    if (!s) return s;
    /* leading */
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    /* trailing */
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

/* Parse "ip:port" for IPv4 only. On success, write ip (len>=16) and port_out and return 1.
 * On failure return 0.
 */
static int parse_ipv4_port(const char *line, char *ip_out /* >=16 */, uint16_t *port_out) {
    if (!line || !ip_out || !port_out) return 0;

    const char *colon = strchr(line, ':');
    if (!colon) {
        log_debug("parse_ipv4_port: no ':' found in '%s'", line);
        return 0;
    }

    size_t ip_len = (size_t)(colon - line);
    if (ip_len == 0 || ip_len >= 16) {
        log_debug("parse_ipv4_port: invalid ip length %zu in '%s'", ip_len, line);
        return 0;
    }

    char ipbuf[16];
    memcpy(ipbuf, line, ip_len);
    ipbuf[ip_len] = '\0';

    /* validate IPv4 address */
    struct in_addr ina;
    if (inet_pton(AF_INET, ipbuf, &ina) != 1) {
        log_debug("parse_ipv4_port: inet_pton failed for ip '%s'", ipbuf);
        return 0;
    }

    /* parse port */
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

    /* success: copy safely */
    snprintf(ip_out, 16, "%s", ipbuf);
    *port_out = (uint16_t)p;
    return 1;
}

int btkg_proxy_list_append(btkg_proxy_list_t *list, const char *ip_str, uint16_t port) {
    if (!list || !ip_str) return -1;

    /* validate ip */
    struct in_addr ina;
    if (inet_pton(AF_INET, ip_str, &ina) != 1) {
        log_error("btkg_proxy_list_append: invalid IPv4 '%s'", ip_str);
        return -1;
    }
    if (port == 0) {
        log_error("btkg_proxy_list_append: invalid port 0");
        return -1;
    }

    if (!list->items) {
        list->capacity = BTKG_PROXY_LIST_INITIAL_CAP;
        list->items = calloc(list->capacity, sizeof(btkg_proxy_t));
        if (!list->items) {
            log_error("btkg_proxy_list_append: calloc failed");
            list->capacity = 0;
            return -1;
        }
    }

    if (list->count >= list->capacity) {
        size_t newcap = list->capacity ? list->capacity * 2 : BTKG_PROXY_LIST_INITIAL_CAP;
        btkg_proxy_t *tmp = realloc(list->items, newcap * sizeof(btkg_proxy_t));
        if (!tmp) {
            log_error("btkg_proxy_list_append: realloc failed");
            return -1;
        }
        list->items = tmp;
        list->capacity = newcap;
        log_debug("btkg_proxy_list_append: increased capacity to %zu", list->capacity);
    }

    btkg_proxy_t *dst = &list->items[list->count++];
    snprintf(dst->ip, sizeof(dst->ip), "%s", ip_str);
    dst->port = port;

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

        /* strip trailing newline(s) */
        if (nread > 0) {
            /* remove CR/LF if present */
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

        char ipbuf[16];
        uint16_t port;
        if (!parse_ipv4_port(trimmed, ipbuf, &port)) {
            log_error("line %d: invalid proxy format or invalid ip/port: '%s' (expected IPv4:port)", lineno, trimmed);
            continue;
        }

        log_debug("line %d: parsed ip='%s' port=%u", lineno, ipbuf, (unsigned)port);

        if (btkg_proxy_list_append(list, ipbuf, port) == 0) {
            appended++;
        } else {
            log_error("line %d: failed to append proxy %s:%u", lineno, ipbuf, (unsigned)port);
            /* do not exit; cleanup and return error */
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
