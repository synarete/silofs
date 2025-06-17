/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include "configs.h"
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <silofs/version.h>
#include <silofs/logging.h>

#define SILOFS_LOG_LEVEL_DEFAULT (SILOFS_LOG_ERROR)

#define SILOFS_LOG_FLAGS_DEFAULT                                          \
	(SILOFS_LOGF_STDOUT | SILOFS_LOGF_SYSLOG | SILOFS_LOGF_PROGNAME | \
	 SILOFS_LOGF_FILINE)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_log_params *silofs_global_log_params = NULL;

static const char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

void silofs_set_global_log_params(const struct silofs_log_params *logp)
{
	silofs_global_log_params = logp;
}

static const char *log_progname(void)
{
	const struct silofs_log_params *params = silofs_global_log_params;

	return (params && params->progname) ? params->progname :
	                                      program_invocation_short_name;
}

static const char *log_timestamp(char *buf, size_t bsz)
{
	struct tm tm_now;
	const time_t now = time(NULL);
	size_t n;

	localtime_r(&now, &tm_now);
	n = strftime(buf, bsz, "%Y-%m-%d %H:%M:%S", &tm_now);
	return (n == 0) ? "" : buf;
}

static void log_to_stdout(enum silofs_log_flags log_flags, const char *msg,
                          const char *file, int line)
{
	FILE *fp = stdout;

	flockfile(fp);
	if (log_flags & SILOFS_LOGF_TIMESTAMP) {
		char buf[40] = { 0 };

		fprintf(fp, "[%s] ", log_timestamp(buf, sizeof(buf)));
	}
	if (log_flags & SILOFS_LOGF_PROGNAME) {
		fprintf(fp, "%s: ", log_progname());
	}
	if ((file != NULL) && line) {
		fprintf(fp, "[%s:%d] ", file, line);
	}
	fprintf(fp, "%s\n", msg);
	fflush(fp);
	funlockfile(fp);
}

static int syslog_level(enum silofs_log_level log_level)
{
	int sl_level = -1;

	if (log_level <= SILOFS_LOG_CRIT) {
		sl_level = LOG_CRIT;
	} else if (log_level <= SILOFS_LOG_ERROR) {
		sl_level = LOG_ERR;
	} else if (log_level <= SILOFS_LOG_WARN) {
		sl_level = LOG_WARNING;
	} else if (log_level <= SILOFS_LOG_INFO) {
		sl_level = LOG_INFO;
	} else if (log_level <= SILOFS_LOG_DEBUG) {
		sl_level = LOG_DEBUG;
	}
	return sl_level;
}

static void log_to_syslog(enum silofs_log_level log_level, const char *msg,
                          const char *file, int line)
{
	const int level = syslog_level(log_level);

	if (level >= 0) {
		if ((file != NULL) && line) {
			syslog(level, "[%s:%d] %s", file, line, msg);
		} else {
			syslog(level, "%s", msg);
		}
	}
}

static void
log_msg(enum silofs_log_level log_level, enum silofs_log_flags log_flags,
        const char *msg, const char *file, int line)
{
	if (log_flags & SILOFS_LOGF_STDOUT) {
		log_to_stdout(log_flags, msg, file, line);
	}
	if (log_flags & SILOFS_LOGF_SYSLOG) {
		log_to_syslog(log_level, msg, file, line);
	}
}

static enum silofs_log_flags log_ctrl_flags(void)
{
	const struct silofs_log_params *params = silofs_global_log_params;
	const enum silofs_log_flags log_flags =
		(params != NULL) ? params->flags : SILOFS_LOG_FLAGS_DEFAULT;

	return log_flags;
}

static enum silofs_log_flags log_ctrl_flags_by(enum silofs_log_level log_level)
{
	enum silofs_log_flags log_flags = log_ctrl_flags();

	if ((log_level <= SILOFS_LOG_ERROR) &&
	    (log_flags & SILOFS_LOGF_VERBOSE)) {
		log_flags |= SILOFS_LOGF_PROGNAME | SILOFS_LOGF_FILINE;
	}

	return log_flags;
}

static bool log_output_enabled(void)
{
	const enum silofs_log_flags log_mask =
		(SILOFS_LOGF_STDOUT | SILOFS_LOGF_SYSLOG);

	return (log_ctrl_flags() & log_mask) > 0;
}

static bool
log_with_file_line(enum silofs_log_flags log_flags, const char *file, int line)
{
	return (file != NULL) && (line > 0) &&
	       ((log_flags & SILOFS_LOGF_FILINE) > 0);
}

static bool log_level_enabled(enum silofs_log_level log_level)
{
	const struct silofs_log_params *params = silofs_global_log_params;
	const enum silofs_log_level log_level_want =
		(params != NULL) ? params->level : SILOFS_LOG_LEVEL_DEFAULT;

	return (log_level <= log_level_want);
}

static bool log_enabled_with(enum silofs_log_level log_level)
{
	return log_output_enabled() && log_level_enabled(log_level);
}

int silofs_logf(enum silofs_log_level log_level, const char *file, int line,
                const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	const char *filename = NULL;
	const int saved_errno = errno;
	enum silofs_log_flags log_flags;
	int n;

	if (!log_enabled_with(log_level)) {
		return -1;
	}

	log_flags = log_ctrl_flags_by(log_level);
	if (log_with_file_line(log_flags, file, line)) {
		filename = basename_of(file);
	}

	va_start(ap, fmt);
	n = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if (n >= (int)sizeof(msg)) {
		msg[sizeof(msg) - 1] = '\0';
	}

	log_msg(log_level, log_flags, msg, filename, line);

	errno = saved_errno;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool eqs(const char *s, const char *t)
{
	return strcmp(s, t) == 0;
}

static bool icase_eqs(const char *s, const char *t)
{
	return strcasecmp(s, t) == 0;
}

enum silofs_log_level silofs_log_level_by_rfc5424(const char *s)
{
	enum silofs_log_level ll = SILOFS_LOG_ERROR; /* default value */

	if (s != NULL) {
		if (eqs(s, "0") || eqs(s, "1") || eqs(s, "2") ||
		    icase_eqs(s, "ALERT") || icase_eqs(s, "CRIT")) {
			ll = SILOFS_LOG_CRIT;
		} else if (eqs(s, "3") || icase_eqs(s, "ERROR")) {
			ll = SILOFS_LOG_ERROR;
		} else if (eqs(s, "4") || eqs(s, "5") ||
		           icase_eqs(s, "WARN") || icase_eqs(s, "NOTICE")) {
			ll = SILOFS_LOG_WARN;
		} else if (eqs(s, "6") || icase_eqs(s, "INFO")) {
			ll = SILOFS_LOG_INFO;
		} else if (eqs(s, "7") || icase_eqs(s, "DEBUG")) {
			ll = SILOFS_LOG_DEBUG;
		}
	}
	return ll;
}

static void make_version_banner(char *s, unsigned int n, int start)
{
	const char *tag = start ? "============" : "------------";

	snprintf(s, n, "%s %s", silofs_version.string, tag);
}

void silofs_log_meta_banner(const char *name, int start)
{
	char buf[128] = "";

	make_version_banner(buf, sizeof(buf) - 1, start);
	silofs_log_info("%s %s", name, buf);
}
