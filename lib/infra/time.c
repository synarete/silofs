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
#include <silofs/syscall.h>
#include <silofs/panic.h>
#include <silofs/time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

static void do_clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	int err;

	err = silofs_sys_clock_gettime(clock_id, tp);
	if (err) {
		silofs_panic("clock_gettime failure: clock_id=%ld err=%d",
		             (long)clock_id, err);
	}
}

void silofs_rclock_now(struct timespec *ts)
{
	do_clock_gettime(CLOCK_REALTIME, ts);
}

void silofs_mclock_now(struct timespec *ts)
{
	do_clock_gettime(CLOCK_MONOTONIC, ts);
}

static void timespec_dif(const struct timespec *beg,
                         const struct timespec *end, struct timespec *dif)
{
	dif->tv_sec = end->tv_sec - beg->tv_sec;
	if (end->tv_nsec >= beg->tv_nsec) {
		dif->tv_nsec = end->tv_nsec - beg->tv_nsec;
	} else {
		dif->tv_sec -= 1;
		dif->tv_nsec = beg->tv_nsec - end->tv_nsec;
	}
}

void silofs_mclock_dur(const struct timespec *start, struct timespec *dur)
{
	struct timespec now;

	silofs_mclock_now(&now);
	timespec_dif(start, &now, dur);
}

time_t silofs_time_now(void)
{
	return time(NULL);
}

time_t silofs_time_now_monotonic(void)
{
	struct timespec ts;

	silofs_mclock_now(&ts);
	return ts.tv_sec;
}

void silofs_ts_copy(struct timespec *dst, const struct timespec *src)
{
	dst->tv_sec = src->tv_sec;
	dst->tv_nsec = src->tv_nsec;
}

int silofs_ts_gettime(struct timespec *ts, int realtime)
{
	int err = 0;

	if (realtime) {
		err = silofs_sys_clock_gettime(CLOCK_REALTIME, ts);
	} else {
		ts->tv_sec = silofs_time_now();
		ts->tv_nsec = 0;
	}
	return err;
}
