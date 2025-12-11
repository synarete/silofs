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
#define _GNU_SOURCE 1
#include "configs.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <silofs/syscall.h>
#include <silofs/panic.h>
#include "times.h"

static struct timespec silofs_start_ts_mono;

static void do_clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	int err;

	err = silofs_sys_clock_gettime(clock_id, tp);
	if (err) {
		silofs_panic("clock_gettime failure: clock_id=%ld err=%d",
		             (long)clock_id, err);
	}
}

void silofs_clock_real_now(struct timespec *ts)
{
	do_clock_gettime(CLOCK_REALTIME, ts);
}

void silofs_clock_mono_now(struct timespec *ts)
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

time_t silofs_time_real_now(void)
{
	return time(nullptr);
}

time_t silofs_time_mono_now(void)
{
	struct timespec ts;

	silofs_clock_mono_now(&ts);
	return ts.tv_sec;
}

void silofs_ts_omit(struct timespec *ts)
{
	ts->tv_sec  = UTIME_OMIT;
	ts->tv_nsec = UTIME_OMIT;
}

void silofs_ts_copy(struct timespec *dst, const struct timespec *src)
{
	dst->tv_sec  = src->tv_sec;
	dst->tv_nsec = src->tv_nsec;
}

int silofs_ts_gettime(struct timespec *ts, int realtime)
{
	int err = 0;

	if (realtime) {
		err = silofs_sys_clock_gettime(CLOCK_REALTIME, ts);
	} else {
		err = silofs_sys_clock_gettime(CLOCK_MONOTONIC, ts);
	}
	return err;
}

void silofs_ts_diff(const struct timespec *start,
                    const struct timespec *finish, struct timespec *out_dif)
{
	timespec_dif(start, finish, out_dif);
}

static int silofs_nanosleep(const struct timespec *req, struct timespec *rem)
{
	int err;

	if (req->tv_sec || req->tv_nsec) {
		err = nanosleep(req, rem);
	} else {
		rem->tv_sec  = 0;
		rem->tv_nsec = 0;
		err          = 0;
	}
	return err ? -errno : 0;
}

int silofs_suspend_nsecs(time_t nsecs)
{
	const struct timespec ts = { .tv_sec = nsecs, .tv_nsec = 0 };

	return (nsecs > 0) ? silofs_suspend_ts(&ts) : 0;
}

int silofs_suspend_ts(const struct timespec *ts)
{
	struct timespec req = { .tv_sec = ts->tv_sec, .tv_nsec = ts->tv_nsec };
	struct timespec rem = { .tv_sec = 0, .tv_nsec = 0 };
	int             err;

	err = silofs_nanosleep(&req, &rem);
	while ((err == -EINTR) && (rem.tv_sec || rem.tv_nsec)) {
		req.tv_sec  = rem.tv_sec;
		req.tv_nsec = rem.tv_nsec;
		rem.tv_sec  = 0;
		rem.tv_nsec = 0;
		err         = silofs_nanosleep(&req, &rem);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_times(void)
{
	struct tm res = { .tm_zone = nullptr };
	int       err;

	tzset();
	err = silofs_localtime_now(&res);
	if (err) {
		return err;
	}
	silofs_clock_mono_now(&silofs_start_ts_mono);
	return 0;
}

void silofs_uptime(struct timespec *out_ts)
{
	struct timespec ts_now;

	silofs_clock_mono_now(&ts_now);
	silofs_ts_diff(&silofs_start_ts_mono, &ts_now, out_ts);
}

int silofs_localtime_now(struct tm *res)
{
	const time_t     now = silofs_time_real_now();
	const struct tm *ptm = nullptr;

	errno = 0;
	ptm   = localtime_r(&now, res);
	return (ptm == res) ? 0 : -errno;
}
