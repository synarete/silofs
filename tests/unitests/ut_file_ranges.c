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

#define MKRANGE(pos_, cnt_) { .off = (pos_), .len = (cnt_) }
#define MKRANGES(a_) { .arr = (a_), .cnt = UT_ARRAY_SIZE(a_) }


struct ut_dvecs {
	struct ut_dvec *dvec[64];
	size_t count;
};

static struct ut_dvecs *new_dvecs(struct ut_env *ute)
{
	struct ut_dvecs *dvecs;

	dvecs = ut_zalloc(ute, sizeof(*dvecs));
	dvecs->count = 0;
	return dvecs;
}

static void assign(struct ut_env *ute, struct ut_dvecs *dvecs,
                   const struct ut_ranges *rngs)
{
	loff_t off;
	size_t len;
	struct ut_dvec *dvec;

	for (size_t i = 0; i < rngs->cnt; ++i) {
		off = rngs->arr[i].off;
		len = rngs->arr[i].len;
		dvec = ut_new_dvec(ute, off, len);
		dvecs->dvec[dvecs->count++] = dvec;
	}
}

static void swap(struct ut_dvec **pa, struct ut_dvec **pb)
{
	struct ut_dvec *c = *pa;

	*pa = *pb;
	*pb = c;
}

static struct ut_dvecs *
simple(struct ut_env *ute, const struct ut_ranges *ranges)
{
	struct ut_dvecs *drefs = new_dvecs(ute);

	assign(ute, drefs, ranges);
	return drefs;
}

static struct ut_dvecs *
reverse(struct ut_env *ute, const struct ut_ranges *ranges)
{
	struct ut_dvecs *dvecs = simple(ute, ranges);

	for (size_t i = 0; i < dvecs->count / 2; ++i) {
		swap(&dvecs->dvec[i], &dvecs->dvec[dvecs->count - i - 1]);
	}
	return dvecs;
}

static struct ut_dvecs *
zigzag(struct ut_env *ute, const struct ut_ranges *ranges)
{
	struct ut_dvecs *dvecs = simple(ute, ranges);

	for (size_t i = 0; i < dvecs->count - 1; i += 2) {
		swap(&dvecs->dvec[i], &dvecs->dvec[i + 1]);
	}
	return dvecs;
}

static struct ut_dvecs *
rzigzag(struct ut_env *ute, const struct ut_ranges *ranges)
{
	struct ut_dvecs *dvecs = reverse(ute, ranges);

	for (size_t i = 0; i < dvecs->count - 1; i += 2) {
		swap(&dvecs->dvec[i], &dvecs->dvec[i + 1]);
	}
	return dvecs;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
static void ut_write_read_n(struct ut_env *ute,
                            const struct ut_dvecs *dvecs, ino_t ino)
{
	void *buf;
	loff_t off;
	size_t len;
	const struct ut_dvec *dvec;

	for (size_t i = 0; i < dvecs->count; ++i) {
		dvec = dvecs->dvec[i];
		len = dvec->len;
		off = dvec->off;
		ut_write_ok(ute, ino, dvec->dat, len, off);
	}

	for (size_t j = 0; j < dvecs->count; ++j) {
		dvec = dvecs->dvec[j];
		len = dvec->len;
		off = dvec->off;
		buf = ut_randbuf(ute, len);
		ut_read_ok(ute, ino, buf, len, off);
		ut_expect_eqm(buf, dvec->dat, len);
	}
}


static void ut_rdwr_file1(struct ut_env *ute,
                          const struct ut_dvecs *drefs)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read_n(ute, drefs, ino);
	ut_release_ok(ute, ino);
	ut_unlink_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_rdwr_file2(struct ut_env *ute,
                          const struct ut_dvecs *drefs1,
                          const struct ut_dvecs *drefs2)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read_n(ute, drefs1, ino);
	ut_write_read_n(ute, drefs2, ino);
	ut_release_ok(ute, ino);
	ut_unlink_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_range s_ut_ranges1[] = {
	MKRANGE(1, 1),
	MKRANGE(3, 4),
	MKRANGE(8, 16),
	MKRANGE(29, 31),
	MKRANGE(127, 111),
};

static const struct ut_range s_ut_ranges2[] = {
	MKRANGE(UT_BK_SIZE, UT_BK_SIZE),
	MKRANGE(UT_MEGA, UT_BK_SIZE),
	MKRANGE(UT_GIGA, UT_BK_SIZE),
	MKRANGE(UT_TERA, UT_BK_SIZE)
};

static const struct ut_range s_ut_ranges3[] = {
	MKRANGE(UT_BK_SIZE - 1, UT_BK_SIZE + 3),
	MKRANGE(UT_MEGA - 1, UT_BK_SIZE + 3),
	MKRANGE(UT_GIGA - 1, UT_BK_SIZE + 3),
	MKRANGE(UT_TERA - 1, UT_BK_SIZE + 3)
};

static const struct ut_range s_ut_ranges4[] = {
	MKRANGE(UT_BK_SIZE, UT_UMEGA),
	MKRANGE(3 * UT_MEGA - 3, UT_UMEGA / 3),
	MKRANGE(5 * UT_MEGA + 5, UT_UMEGA / 5),
	MKRANGE(7 * UT_MEGA - 7, UT_UMEGA / 7),
	MKRANGE(11 * UT_MEGA + 11, UT_UMEGA / 11),
	MKRANGE(13 * UT_MEGA - 13, UT_UMEGA / 13),
};

static const struct ut_range s_ut_ranges5[] = {
	MKRANGE(1, 11),
	MKRANGE(23 * UT_BK_SIZE, 2 * UT_BK_SIZE),
	MKRANGE(31 * UT_MEGA - 3, 3 * UT_BK_SIZE),
	MKRANGE(677 * UT_MEGA - 3, 3 * UT_BK_SIZE),
	MKRANGE(47 * UT_GIGA - 4, 4 * UT_BK_SIZE),
	MKRANGE(977 * UT_GIGA - 4, 4 * UT_BK_SIZE),
	MKRANGE(5 * UT_TERA - 5, 5 * UT_BK_SIZE),
};

static const struct ut_range s_ut_ranges6[] = {
	MKRANGE((UT_MEGA / 23) - 23, UT_UMEGA),
	MKRANGE(23 * UT_MEGA + 23, UT_UMEGA),
	MKRANGE(113 * UT_GIGA - 113, UT_UMEGA),
	MKRANGE(223 * UT_GIGA + 223, UT_UMEGA),
};

static const struct ut_ranges s_ranges_defs[] = {
	MKRANGES(s_ut_ranges1),
	MKRANGES(s_ut_ranges2),
	MKRANGES(s_ut_ranges3),
	MKRANGES(s_ut_ranges4),
	MKRANGES(s_ut_ranges5),
	MKRANGES(s_ut_ranges6),
};


static void ut_file_ranges_(struct ut_env *ute,
                            const struct ut_ranges *ranges)
{
	ut_rdwr_file1(ute, simple(ute, ranges));
	ut_rdwr_file1(ute, reverse(ute, ranges));
	ut_rdwr_file1(ute, zigzag(ute, ranges));
	ut_rdwr_file1(ute, rzigzag(ute, ranges));
}

static void ut_file_ranges(struct ut_env *ute)
{
	const struct ut_ranges *ranges;

	for (size_t i = 0; i < UT_ARRAY_SIZE(s_ranges_defs); ++i) {
		ranges = &s_ranges_defs[i];
		ut_file_ranges_(ute, ranges);
	}
}

static void ut_file_xranges_(struct ut_env *ute,
                             const struct ut_ranges *r1,
                             const struct ut_ranges *r2)
{
	ut_rdwr_file2(ute, simple(ute, r1), simple(ute, r2));
	ut_rdwr_file2(ute, reverse(ute, r1), reverse(ute, r2));
	ut_rdwr_file2(ute, zigzag(ute, r1), zigzag(ute, r2));
	ut_rdwr_file2(ute, rzigzag(ute, r1), rzigzag(ute, r2));
	ut_rdwr_file2(ute, reverse(ute, r1), zigzag(ute, r2));
	ut_rdwr_file2(ute, rzigzag(ute, r1), simple(ute, r2));
}

static void ut_file_xranges(struct ut_env *ute)
{
	const struct ut_ranges *r1;
	const struct ut_ranges *r2;

	for (size_t j = 0; j < UT_ARRAY_SIZE(s_ranges_defs) - 1; ++j) {
		r1 = &s_ranges_defs[j];
		r2 = &s_ranges_defs[j + 1];
		ut_file_xranges_(ute, r1, r2);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_ranges),
	UT_DEFTEST(ut_file_xranges),
};

const struct ut_testdefs ut_tdefs_file_ranges = UT_MKTESTS(ut_local_tests);
