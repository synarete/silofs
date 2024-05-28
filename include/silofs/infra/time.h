/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_TIME_H_
#define SILOFS_TIME_H_

#include <time.h>

time_t silofs_time_now(void);

time_t silofs_time_now_monotonic(void);

void silofs_rclock_now(struct timespec *ts);

void silofs_mclock_now(struct timespec *ts);

void silofs_mclock_dur(const struct timespec *start, struct timespec *dur);

void silofs_mclock_dif(const struct timespec *start,
                       const struct timespec *finish, struct timespec *dif);

void silofs_ts_copy(struct timespec *dst, const struct timespec *src);

int silofs_ts_gettime(struct timespec *ts, int realtime);

int silofs_suspend_ts(const struct timespec *ts);

int silofs_suspend_secs(time_t secs);

#endif /* SILOFS_TIME_H_ */
