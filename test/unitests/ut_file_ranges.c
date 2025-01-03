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
#include "unitests.h"

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
static void
ut_write_read_n(struct ut_env *ute, const struct ut_dvecs *dvecs, ino_t ino)
{
	const struct ut_dvec *dvec = NULL;
	void *buf = NULL;
	loff_t off = -1;
	size_t len = 0;

	for (size_t i = 0; i < dvecs->count; ++i) {
		dvec = dvecs->dvec[i];
		len = dvec->len;
		off = dvec->off;
		ut_write(ute, ino, dvec->dat, len, off);
	}

	for (size_t j = 0; j < dvecs->count; ++j) {
		dvec = dvecs->dvec[j];
		len = dvec->len;
		off = dvec->off;
		buf = ut_randbuf(ute, len);
		ut_read(ute, ino, buf, len, off);
		ut_expect_eqm(buf, dvec->dat, len);
	}
}

static void ut_rdwr_file1(struct ut_env *ute, const struct ut_dvecs *drefs)
{
	const char *name = UT_NAME;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read_n(ute, drefs, ino);
	ut_release(ute, ino);
	ut_unlink(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_rdwr_file2(struct ut_env *ute, const struct ut_dvecs *drefs1,
                          const struct ut_dvecs *drefs2)
{
	const char *name = UT_NAME;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read_n(ute, drefs1, ino);
	ut_write_read_n(ute, drefs2, ino);
	ut_release(ute, ino);
	ut_unlink(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_range s_ut_ranges1[] = {
	UT_MKRANGE1(1, 1),   UT_MKRANGE1(3, 4),     UT_MKRANGE1(8, 16),
	UT_MKRANGE1(29, 31), UT_MKRANGE1(127, 111),
};

static const struct ut_range s_ut_ranges2[] = {
	UT_MKRANGE1(UT_BK_SIZE, UT_BK_SIZE), UT_MKRANGE1(UT_1M, UT_BK_SIZE),
	UT_MKRANGE1(UT_1G, UT_BK_SIZE), UT_MKRANGE1(UT_1T, UT_BK_SIZE)
};

static const struct ut_range s_ut_ranges3[] = {
	UT_MKRANGE1(UT_BK_SIZE - 1, UT_BK_SIZE + 3),
	UT_MKRANGE1(UT_1M - 1, UT_BK_SIZE + 3),
	UT_MKRANGE1(UT_1G - 1, UT_BK_SIZE + 3),
	UT_MKRANGE1(UT_1T - 1, UT_BK_SIZE + 3)
};

static const struct ut_range s_ut_ranges4[] = {
	UT_MKRANGE1(UT_BK_SIZE, UT_1M),
	UT_MKRANGE1(3 * UT_1M - 3, UT_1M / 3),
	UT_MKRANGE1(5 * UT_1M + 5, UT_1M / 5),
	UT_MKRANGE1(7 * UT_1M - 7, UT_1M / 7),
	UT_MKRANGE1(11 * UT_1M + 11, UT_1M / 11),
	UT_MKRANGE1(13 * UT_1M - 13, UT_1M / 13),
};

static const struct ut_range s_ut_ranges5[] = {
	UT_MKRANGE1(1, 11),
	UT_MKRANGE1(23 * UT_BK_SIZE, 2 * UT_BK_SIZE),
	UT_MKRANGE1(31 * UT_1M - 3, 3 * UT_BK_SIZE),
	UT_MKRANGE1(677 * UT_1M - 3, 3 * UT_BK_SIZE),
	UT_MKRANGE1(47 * UT_1G - 4, 4 * UT_BK_SIZE),
	UT_MKRANGE1(977 * UT_1G - 4, 4 * UT_BK_SIZE),
	UT_MKRANGE1(5 * UT_1T - 5, 5 * UT_BK_SIZE),
};

static const struct ut_range s_ut_ranges6[] = {
	UT_MKRANGE1((UT_1M / 23) - 23, UT_1M),
	UT_MKRANGE1(23 * UT_1M + 23, UT_1M),
	UT_MKRANGE1(113 * UT_1G - 113, UT_1M),
	UT_MKRANGE1(223 * UT_1G + 223, UT_1M),
};

static const struct ut_ranges s_ranges_defs[] = {
	UT_MKRANGE1S(s_ut_ranges1), UT_MKRANGE1S(s_ut_ranges2),
	UT_MKRANGE1S(s_ut_ranges3), UT_MKRANGE1S(s_ut_ranges4),
	UT_MKRANGE1S(s_ut_ranges5), UT_MKRANGE1S(s_ut_ranges6),
};

static void ut_file_ranges_(struct ut_env *ute, const struct ut_ranges *ranges)
{
	ut_rdwr_file1(ute, simple(ute, ranges));
	ut_relax_mem(ute);
	ut_rdwr_file1(ute, reverse(ute, ranges));
	ut_relax_mem(ute);
	ut_rdwr_file1(ute, zigzag(ute, ranges));
	ut_relax_mem(ute);
	ut_rdwr_file1(ute, rzigzag(ute, ranges));
	ut_relax_mem(ute);
}

static void ut_file_ranges(struct ut_env *ute)
{
	for (size_t i = 0; i < UT_ARRAY_SIZE(s_ranges_defs); ++i) {
		ut_file_ranges_(ute, &s_ranges_defs[i]);
	}
}

static void ut_file_xranges_(struct ut_env *ute, const struct ut_ranges *r1,
                             const struct ut_ranges *r2)
{
	ut_rdwr_file2(ute, simple(ute, r1), simple(ute, r2));
	ut_relax_mem(ute);
	ut_rdwr_file2(ute, reverse(ute, r1), reverse(ute, r2));
	ut_relax_mem(ute);
	ut_rdwr_file2(ute, zigzag(ute, r1), zigzag(ute, r2));
	ut_relax_mem(ute);
	ut_rdwr_file2(ute, rzigzag(ute, r1), rzigzag(ute, r2));
	ut_relax_mem(ute);
	ut_rdwr_file2(ute, reverse(ute, r1), zigzag(ute, r2));
	ut_relax_mem(ute);
	ut_rdwr_file2(ute, rzigzag(ute, r1), simple(ute, r2));
	ut_relax_mem(ute);
}

static void ut_file_xranges(struct ut_env *ute)
{
	const struct ut_ranges *r1 = NULL;
	const struct ut_ranges *r2 = NULL;

	for (size_t j = 0; j < UT_ARRAY_SIZE(s_ranges_defs) - 1; ++j) {
		r1 = &s_ranges_defs[j];
		r2 = &s_ranges_defs[j + 1];
		ut_file_xranges_(ute, r1, r2);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST2(ut_file_ranges),
	UT_DEFTEST2(ut_file_xranges),
};

const struct ut_testdefs ut_tdefs_file_ranges = UT_MKTESTS(ut_local_tests);
