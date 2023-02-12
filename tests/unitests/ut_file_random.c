/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include "unitests.h"


struct ut_ioparams {
	loff_t offset;
	size_t length;
	size_t nskip;
	size_t count;
};

#define MKPARAMS(o_, l_, s_, c_) \
	{ .offset = (o_), .length = (l_), .nskip = (s_), .count = (c_) }


static struct ut_dvec **new_dvecs(struct ut_env *ute,
                                  const struct ut_ioparams *params)
{
	loff_t off;
	struct ut_dvec **list;
	const size_t step = params->length + params->nskip;

	list = ut_zerobuf(ute, params->count * sizeof(struct ut_dvec *));
	for (size_t i = 0; i < params->count; ++i) {
		off = params->offset + (loff_t)(i * step);
		list[i] = ut_new_dvec(ute, off, params->length);
	}
	return list;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static unsigned long *random_indices(struct ut_env *ute, size_t cnt)
{
	return (unsigned long *)ut_randseq(ute, cnt, 0);
}

static void ut_file_random_io_(struct ut_env *ute, ino_t ino,
                               const struct ut_ioparams *params)
{
	size_t *idx = NULL;
	struct ut_dvec *dvec = NULL;
	struct ut_dvec **dvecs = NULL;
	const size_t cnt = params->count;

	dvecs = new_dvecs(ute, params);
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_write_dvec(ute, ino, dvec);
	}
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_read_dvec(ute, ino, dvec);
	}
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_read_dvec(ute, ino, dvec);
	}
	dvecs = new_dvecs(ute, params);
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_write_dvec(ute, ino, dvec);
	}
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_read_dvec(ute, ino, dvec);
	}
}

static void ut_file_random_io2_(struct ut_env *ute, ino_t ino,
                                const struct ut_ioparams *params)
{
	size_t *idx = NULL;
	struct ut_dvec *dvec = NULL;
	struct ut_dvec **dvecs = NULL;
	const size_t cnt = params->count;

	dvecs = new_dvecs(ute, params);
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_write_dvec(ute, ino, dvec);
	}
	ut_sync_drop(ute);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_read_dvec(ute, ino, dvec);
	}
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_read_dvec(ute, ino, dvec);
	}
	dvecs = new_dvecs(ute, params);
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_write_dvec(ute, ino, dvec);
	}
	ut_sync_drop(ute);
	idx = random_indices(ute, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dvec = dvecs[idx[i]];
		ut_read_dvec(ute, ino, dvec);
	}
}

static void ut_file_random_(struct ut_env *ute,
                            const struct ut_ioparams *params)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_file_random_io_(ute, ino, params);
	ut_file_random_io2_(ute, ino, params);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_random_arr_(struct ut_env *ute,
                                const struct ut_ioparams *arr, size_t nelems)
{
	for (size_t i = 0; i < nelems; ++i) {
		ut_file_random_(ute, &arr[i]);
		ut_freeall(ute);
	}
}

#define ut_file_random_arr(ctx_, arr_) \
	ut_file_random_arr_(ctx_, arr_, UT_ARRAY_SIZE(arr_))


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_random_simple(struct ut_env *ute)
{
	const struct ut_ioparams params[] = {
		MKPARAMS(0, UT_UMEGA, 0, 10),
		MKPARAMS(UT_GIGA, UT_UMEGA, 0, 20),
	};

	ut_file_random_arr(ute, params);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_random_aligned(struct ut_env *ute)
{
	const struct ut_ioparams params[] = {
		MKPARAMS(0, UT_BK_SIZE, 0, 4),
		MKPARAMS(0, UT_UMEGA, 0, 4),
		MKPARAMS(UT_BK_SIZE, UT_BK_SIZE, UT_BK_SIZE, 16),
		MKPARAMS(UT_BK_SIZE, UT_UMEGA, UT_BK_SIZE, 16),
		MKPARAMS(UT_MEGA, UT_BK_SIZE, UT_BK_SIZE, 16),
		MKPARAMS(UT_MEGA, UT_BK_SIZE, UT_UMEGA, 32),
		MKPARAMS(UT_MEGA, UT_UMEGA, UT_BK_SIZE, 16),
		MKPARAMS(UT_MEGA, UT_UMEGA, UT_UMEGA, 32),
		MKPARAMS(UT_MEGA - UT_BK_SIZE, UT_BK_SIZE, UT_GIGA, 64),
		MKPARAMS(UT_MEGA - UT_BK_SIZE, UT_UMEGA / 2, UT_GIGA, 64),
		MKPARAMS(UT_MEGA - UT_BK_SIZE, UT_UMEGA / 2, 0, 8),
		MKPARAMS(UT_GIGA, UT_UMEGA, 0, 8),
		MKPARAMS(UT_GIGA - UT_BK_SIZE, UT_UMEGA / 2, 0, 16),
		MKPARAMS(UT_TERA - UT_BK_SIZE, UT_BK_SIZE, UT_BK_SIZE, 64),
		MKPARAMS(UT_TERA - UT_BK_SIZE, UT_UMEGA / 2, 0, 64),
		MKPARAMS(UT_FSIZE_MAX - UT_MEGA, UT_BK_SIZE, 0, 16),
		MKPARAMS(UT_FSIZE_MAX - UT_GIGA, UT_UMEGA, UT_UMEGA, 8),
		MKPARAMS(UT_FSIZE_MAX - (16 * UT_MEGA), UT_UMEGA / 2, 0, 16)
	};

	ut_file_random_arr(ute, params);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_random_unaligned(struct ut_env *ute)
{
	const struct ut_ioparams params[] = {
		MKPARAMS(79, UT_BK_SIZE + 7, 1, 7),
		MKPARAMS(79, UT_UMEGA / 7, 1, 7),
		MKPARAMS(7907, UT_BK_SIZE + 17, 0, 17),
		MKPARAMS(7907, UT_UMEGA / 17, 0, 17),
		MKPARAMS(UT_MEGA / 77773, UT_BK_SIZE + 77773, 1, 773),
		MKPARAMS(UT_MEGA / 77773, UT_UMEGA / 7, 1, 73),
		MKPARAMS(UT_GIGA / 19777, UT_BK_SIZE + 19777, 173, 37),
		MKPARAMS(UT_GIGA / 19, UT_UMEGA / 601, 601, 601),
		MKPARAMS(UT_TERA / 77003, UT_BK_SIZE + 99971, 0, 661),
		MKPARAMS(UT_TERA / 77003, UT_UMEGA / 101, 0, 101),
		MKPARAMS(UT_FSIZE_MAX / 100003, UT_BK_SIZE + 100003, 0, 13),
		MKPARAMS(UT_FSIZE_MAX / 100003, UT_UMEGA / 307, 307, 307),
		MKPARAMS(UT_FSIZE_MAX / 3, UT_UMEGA / 11, 11111, 11),
	};

	ut_file_random_arr(ute, params);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_random_random(struct ut_env *ute)
{
	uint64_t rand = 0;
	struct ut_ioparams params;

	for (size_t i = 0; i < 10; i++) {
		ut_randfill(ute, &rand, sizeof(rand));
		params.offset = (loff_t)(rand % UT_FSIZE_MAX) / 13;
		params.length = (rand % UT_UMEGA) + UT_BK_SIZE;
		params.nskip = (rand % UT_UGIGA) / 11;
		params.count = (rand % 16) + 1;
		ut_file_random_(ute, &params);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_file_random_simple),
	UT_DEFTEST(ut_file_random_aligned),
	UT_DEFTEST(ut_file_random_unaligned),
	UT_DEFTEST(ut_file_random_random),
};

const struct ut_testdefs ut_tdefs_file_random = UT_MKTESTS(ut_local_tests);
