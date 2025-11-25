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
#define BTKG_PROXY_LIST_INITIAL_CAP 64
#endif

#define IPV4_STR_MAX 64

/* Remove whitespace */
static char* trim(char *s) {
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

void btkg_proxy_list_init(btkg_proxy_list_t *list) {
    if (!list) return;
    list->count = 0;
    list->capacity = BTKG_PROXY_LIST_INITIAL_CAP;
    list->proxies = calloc(list->capacity, sizeof(btkg_proxy_t));
    if (!list->proxies) {
        log_error("proxy_list_init: calloc failed");
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

/* Internal ensure capacity */
static int ensure_capacity(btkg_proxy_list_t *list) {
    if (list->count < list->capacity) return 1;

    size_t newcap = list->capacity * 2;
    btkg_proxy_t *tmp = realloc(list->proxies, newcap * sizeof(btkg_proxy_t));
    if (!tmp) return 0;

    list->proxies = tmp;
    list->capacity = newcap;
    return 1;
}

int btkg_proxy_list_append(btkg_proxy_list_t *list,
                           const char *ip, uint16_t port,
                           const char *user, const char *pass)
{
    if (!list || !ip) return -1;

    /* Validate IPv4 */
    struct in_addr ina;
    if (inet_pton(AF_INET, ip, &ina) != 1) {
        log_error("proxy_list_append: invalid IPv4 '%s'", ip);
        return -1;
    }
    if (port == 0) {
        log_error("proxy_list_append: invalid port 0");
        return -1;
    }

    if (!ensure_capacity(list)) {
        log_error("proxy_list_append: realloc failed");
        return -1;
    }

    btkg_proxy_t *px = &list->proxies[list->count];

    snprintf(px->ip, sizeof(px->ip), "%s", ip);
    px->port = port;

    if (user)
        snprintf(px->user, sizeof(px->user), "%s", user);
    else
        px->user[0] = '\0';

    if (pass)
        snprintf(px->pass, sizeof(px->pass), "%s", pass);
    else
        px->pass[0] = '\0';

    list->count++;

    log_info("Loaded proxy %s:%u user='%s'",
             px->ip, (unsigned)px->port,
             px->user[0] ? px->user : "(none)");

    return 0;
}

/*
 * Parse line format:
 *   ip:port
 *   ip:port:user
 *   ip:port:user:pass
 */
static int parse_proxy_line(char *line,
                            char *ip, uint16_t *port,
                            char *user, char *pass)
{
    char *tok[4] = {0};
    int i = 0;

    char *save;
    char *p = strtok_r(line, ":", &save);
    while (p && i < 4) {
        tok[i++] = p;
        p = strtok_r(NULL, ":", &save);
    }

    if (i < 2) return 0;  /* at least ip:port */

    /* IP */
    strncpy(ip, tok[0], IPV4_STR_MAX - 1);
    ip[IPV4_STR_MAX - 1] = 0;

    /* port */
    char *endptr = NULL;
    long pnum = strtol(tok[1], &endptr, 10);
    if (*endptr || pnum < 1 || pnum > 65535) return 0;
    *port = (uint16_t)pnum;

    /* user */
    if (i >= 3 && tok[2])
        snprintf(user, 64, "%s", tok[2]);
    else
        user[0] = '\0';

    /* pass */
    if (i >= 4 && tok[3])
        snprintf(pass, 64, "%s", tok[3]);
    else
        pass[0] = '\0';

    return 1;
}

int btkg_proxy_list_load_from_file(const char *filename,
                                   btkg_proxy_list_t *list)
{
    if (!filename || !list) return -1;

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_error("Cannot open proxy file: %s", filename);
        return -1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    int appended = 0;

    while ((nread = getline(&line, &len, f)) != -1) {
        if (nread == 0) continue;

        /* remove newline */
        while (nread > 0 &&
               (line[nread - 1] == '\n' || line[nread - 1] == '\r')) {
            line[--nread] = 0;
        }

        char *t = trim(line);
        if (!*t || *t == '#') continue;

        char ip[IPV4_STR_MAX]; 
        uint16_t port;
        char user[64], pass[64];

        if (!parse_proxy_line(t, ip, &port, user, pass)) {
            log_error("Invalid proxy format: %s", t);
            continue;
        }

        if (btkg_proxy_list_append(list, ip, port, user, pass) == 0)
            appended++;
    }

    free(line);
    fclose(f);

    log_info("proxy_list: loaded %d proxies", appended);
    return appended;
}
