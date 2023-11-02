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
#ifndef SILOFS_LOGGING_H_
#define SILOFS_LOGGING_H_

/* log-levels (rfc-5424) */
enum silofs_log_level {
	SILOFS_LOG_CRIT  = 2,
	SILOFS_LOG_ERROR = 3,
	SILOFS_LOG_WARN  = 4,
	SILOFS_LOG_INFO  = 6,
	SILOFS_LOG_DEBUG = 7,
};

/* logging control flags */
enum silofs_log_flags {
	SILOFS_LOGF_STDOUT = 0x01,
	SILOFS_LOGF_SYSLOG = 0x02,
	SILOFS_LOGF_FILINE = 0x04,
};

struct silofs_log_params {
	enum silofs_log_level   level;
	enum silofs_log_flags   flags;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define silofs_log_debug(fmt, ...) \
	silofs_logf(SILOFS_LOG_DEBUG, __FILE__, __LINE__, fmt, __VA_ARGS__)

#define silofs_log_info(fmt, ...) \
	silofs_logf(SILOFS_LOG_INFO, __FILE__, __LINE__, fmt, __VA_ARGS__)

#define silofs_log_warn(fmt, ...) \
	silofs_logf(SILOFS_LOG_WARN, __FILE__, __LINE__, fmt, __VA_ARGS__)

#define silofs_log_error(fmt, ...) \
	silofs_logf(SILOFS_LOG_ERROR, __FILE__, __LINE__, fmt, __VA_ARGS__)

#define silofs_log_crit(fmt, ...) \
	silofs_logf(SILOFS_LOG_CRIT, __FILE__, __LINE__, fmt, __VA_ARGS__)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


void silofs_set_global_log_params(const struct silofs_log_params *logp);

int silofs_logf(enum silofs_log_level log_level,
                const char *file, int line, const char *fmt, ...);


void silofs_log_params_by_str(struct silofs_log_params *logp, const char *str);

void silofs_log_meta_banner(const char *name, int start);

void silofs_make_version_banner(char *s, unsigned int n, int start);

#endif /* SILOFS_LOGGING_H_ */
