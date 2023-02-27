/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/configs.h>
#include <silofs/version.h>
#include <silofs/logging.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>


#define SILOFS_LOG_DEFAULT \
	(SILOFS_LOG_ERROR | SILOFS_LOG_CRIT | SILOFS_LOG_STDOUT)

#define SILOFS_LOG_CONTROL \
	(SILOFS_LOG_STDOUT | SILOFS_LOG_SYSLOG | SILOFS_LOG_FILINE)

static const int *silofs_g_logmaskp = NULL;

static int log_mask_now(void)
{
	const int *log_mask = silofs_g_logmaskp;

	return (log_mask != NULL) ? *log_mask : SILOFS_LOG_DEFAULT;
}

void silofs_set_logmaskp(const int *log_maskp)
{
	silofs_g_logmaskp = log_maskp;
}

static void log_to_stdout(const char *msg, const char *file, int line)
{
	FILE *fp = stdout;
	const char *prog = program_invocation_short_name;

	flockfile(fp);
	if (file && line) {
		fprintf(fp, "%s: [%s:%d] \t%s\n", prog, file, line, msg);
	} else {
		fprintf(fp, "%s: %s\n", prog, msg);
	}
	funlockfile(fp);
}

static int syslog_level(int log_mask)
{
	int sl_level;

	if (log_mask & SILOFS_LOG_CRIT) {
		sl_level = LOG_CRIT;
	} else if (log_mask & SILOFS_LOG_ERROR) {
		sl_level = LOG_ERR;
	} else if (log_mask & SILOFS_LOG_WARN) {
		sl_level = LOG_WARNING;
	} else if (log_mask & SILOFS_LOG_INFO) {
		sl_level = LOG_INFO;
	} else if (log_mask & SILOFS_LOG_DEBUG) {
		sl_level = LOG_DEBUG;
	} else {
		sl_level = 0;
	}
	return sl_level;
}

static void log_to_syslog(int log_mask, const char *msg,
                          const char *file, int line)
{
	const int level = syslog_level(log_mask);

	if (file && line) {
		syslog(level, "[%s:%d] \t%s", file, line, msg);
	} else {
		syslog(level, "%s", msg);
	}
}

static void log_msg(int log_mask, const char *msg, const char *file, int line)
{
	if (log_mask & SILOFS_LOG_STDOUT) {
		log_to_stdout(msg, file, line);
	}
	if (log_mask & SILOFS_LOG_SYSLOG) {
		log_to_syslog(log_mask, msg, file, line);
	}
}

static const char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

void silofs_logf(int flags, const char *file, int line, const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	size_t len;
	int saved_errno;
	int log_mask;
	int ctl_mask;

	log_mask = log_mask_now();
	ctl_mask = SILOFS_LOG_FILINE;
	if ((log_mask & ctl_mask) && file && line) {
		file = basename_of(file);
	} else {
		file = NULL;
		line = 0;
	}

	if (flags & log_mask) {
		saved_errno = errno;
		va_start(ap, fmt);
		len = (size_t)vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);
		if (len >= sizeof(msg)) {
			len = sizeof(msg) - 1;
		}
		msg[len] = '\0';

		ctl_mask = SILOFS_LOG_CONTROL;
		log_msg(flags | (log_mask & ctl_mask), msg, file, line);
		errno = saved_errno;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_log_mask_by_str(int *log_maskp, const char *mode)
{
	const char *modstr = (mode != NULL) ? mode : "0";

	if (!strcmp(modstr, "0")) {
		*log_maskp &= ~SILOFS_LOG_DEBUG;
		*log_maskp &= ~SILOFS_LOG_INFO;
		*log_maskp &= ~SILOFS_LOG_FILINE;
	} else if (!strcmp(modstr, "1")) {
		*log_maskp |= SILOFS_LOG_INFO;
	} else if (!strcmp(modstr, "2")) {
		*log_maskp |= SILOFS_LOG_INFO;
		*log_maskp |= SILOFS_LOG_DEBUG;
	} else if (!strcmp(modstr, "3")) {
		*log_maskp |= SILOFS_LOG_DEBUG;
		*log_maskp |= SILOFS_LOG_INFO;
		*log_maskp |= SILOFS_LOG_FILINE;
	}
}

void silofs_log_meta_banner(const char *name, int start)
{
	const char *tag = start ? "++++++++" : "--------";
	const char *vers = silofs_version.string;

	silofs_log_info("%s %s %s", name, vers, tag);
}

