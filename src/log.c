/*
Copyright (c) 2014-2018 Jorge Matricali

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdarg.h> /* va_list, va_start, va_end */
#include <stdio.h> /* fprintf, vfprintf, stderr */
#include <string.h> /* strlen, malloc */
#include <time.h> /* time_t, time, tm, localtime, strftime */

#include "cbrutekrag.h" /* CBRUTEKRAG_VERBOSE_MODE */
#include "log.h"
#include "str.h" /* btkg_str_replace_placeholder */

extern int g_verbose;
extern char *g_output_format;

#define TIMESTAMP_BUFFER_SIZE 20

static inline const char *get_current_timestamp(void)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	static char buffer[TIMESTAMP_BUFFER_SIZE];

	buffer[strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", tm)] =
		'\0';

	return buffer;
}

void print_output(int level, const char *file, int line, const char *head,
		  const char *tail, FILE *stream, const char *format, ...)
{
	if (level == LOG_DEBUG && !(g_verbose & CBRUTEKRAG_VERBOSE_MODE)) {
		return;
	}

	va_list arg;

	fprintf(stream, "\033[2K\r%s[%s] ", head, get_current_timestamp());

#ifndef DEBUG
	if (level == LOG_DEBUG)
#endif
		fprintf(stream, "%s:%d ", file, line);

	va_start(arg, format);
	vfprintf(stream, format, arg);
	va_end(arg);
	fprintf(stream, "%s\n", tail);
	fflush(stream);
}

void log_output(FILE *stream, const char *format, ...)
{
	va_list arg;

	fprintf(stream, "%s ", get_current_timestamp());

	va_start(arg, format);
	vfprintf(stream, format, arg);
	va_end(arg);
	fflush(stream);
}

void btkg_log_successfull_login(FILE *stream, const char *hostname, int port,
				const char *username, const char *password)
{
	if (g_output_format == NULL) {
		log_error("g_output_format is NULL");
		return;
	}

	int port_len = snprintf(NULL, 0, "%d", port);
	char strport[port_len + 1]; // +1 for the null terminator

	snprintf(strport, sizeof(strport), "%d", port);

	// Allocation
	size_t output_len = strlen(g_output_format) + 1;
	char *output = malloc(output_len);

	if (output == NULL) {
		log_error("Error allocating memory");
		return;
	}

	snprintf(output, output_len, "%s", g_output_format);

	output = btkg_str_replace_placeholder(output, "%DATETIME%",
					      get_current_timestamp());
	if (output == NULL)
		goto error;

	output = btkg_str_replace_placeholder(output, "%HOSTNAME%", hostname);
	if (output == NULL)
		goto error;

	output = btkg_str_replace_placeholder(output, "%USERNAME%", username);
	if (output == NULL)
		goto error;

	output = btkg_str_replace_placeholder(output, "%PASSWORD%", password);
	if (output == NULL)
		goto error;

	output = btkg_str_replace_placeholder(output, "%PORT%", strport);
	if (output == NULL)
		goto error;

	// Print buffer
	fprintf(stream, "%s", output);
	free(output);

	return;

error:
	log_error("Error replacing placeholders");
	free(output);
}
