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


enum SILOFS_LOG_LEVEL {
	SILOFS_LOG_DEBUG  = 0x0001,
	SILOFS_LOG_INFO   = 0x0002,
	SILOFS_LOG_WARN   = 0x0004,
	SILOFS_LOG_ERROR  = 0x0008,
	SILOFS_LOG_CRIT   = 0x0010,
	SILOFS_LOG_STDOUT = 0x1000,
	SILOFS_LOG_SYSLOG = 0x2000,
	SILOFS_LOG_FILINE = 0x4000,
};

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


void silofs_set_logmaskp(const int *log_maskp);

void silofs_logf(int flags, const char *file, int line, const char *fmt, ...);


void silofs_log_mask_by_str(int *log_maskp, const char *mode);

void silofs_log_meta_banner(const char *name, int start);

#endif /* SILOFS_LOGGING_H_ */
