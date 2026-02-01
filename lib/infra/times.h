/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#ifndef SILOFS_TIMES_H_
#define SILOFS_TIMES_H_

#include <time.h>

int silofs_init_times(void);

void silofs_uptime(struct timespec *out_ts);

int silofs_localtime_now(struct tm *res);

time_t silofs_time_real_now(void);

time_t silofs_time_mono_now(void);

void silofs_clock_real_now(struct timespec *ts);

void silofs_clock_mono_now(struct timespec *ts);

void silofs_ts_omit(struct timespec *ts);

void silofs_ts_copy(struct timespec *dst, const struct timespec *src);

int silofs_ts_gettime(struct timespec *ts, int realtime);

void silofs_ts_diff(const struct timespec *start,
                    const struct timespec *finish, struct timespec *dif);

int silofs_suspend_ts(const struct timespec *ts);

int silofs_suspend_secs(time_t secs);

int silofs_suspend_usecs(useconds_t usecs);

#endif /* SILOFS_TIMES_H_ */
