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
#define _GNU_SOURCE 1
#include <silofs/configs.h>
#include <silofs/syscall.h>
#include <silofs/infra/panic.h>
#include <silofs/infra/time.h>
#include <sys/stat.h>
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
	silofs_mclock_dif(start, &now, dur);
}

void silofs_mclock_dif(const struct timespec *start,
		       const struct timespec *finish, struct timespec *dif)
{
	timespec_dif(start, finish, dif);
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

void silofs_ts_omit(struct timespec *ts)
{
	ts->tv_sec = UTIME_OMIT;
	ts->tv_nsec = UTIME_OMIT;
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

static int silofs_nanosleep(const struct timespec *req, struct timespec *rem)
{
	int err;

	if (req->tv_sec || req->tv_nsec) {
		err = nanosleep(req, rem);
	} else {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
		err = 0;
	}
	return err ? -errno : 0;
}

int silofs_suspend_secs(time_t secs)
{
	struct timespec ts = { .tv_sec = secs, .tv_nsec = 0 };

	return silofs_suspend_ts(&ts);
}

int silofs_suspend_ts(const struct timespec *ts)
{
	struct timespec req = { .tv_sec = ts->tv_sec, .tv_nsec = ts->tv_nsec };
	struct timespec rem = { .tv_sec = 0, .tv_nsec = 0 };
	int err;

	err = silofs_nanosleep(&req, &rem);
	while ((err == -EINTR) && (rem.tv_sec || rem.tv_nsec)) {
		req.tv_sec = rem.tv_sec;
		req.tv_nsec = rem.tv_nsec;
		rem.tv_sec = 0;
		rem.tv_nsec = 0;
		err = silofs_nanosleep(&req, &rem);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_time(void)
{
	struct tm res = { .tm_zone = NULL };

	tzset();
	return silofs_localtime_now(&res);
}

int silofs_localtime_now(struct tm *res)
{
	const time_t now = silofs_time_now();
	const struct tm *ptm = NULL;

	errno = 0;
	ptm = localtime_r(&now, res);
	return (ptm == res) ? 0 : -errno;
}
