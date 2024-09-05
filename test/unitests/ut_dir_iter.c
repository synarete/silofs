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
#include "unitests.h"

struct ut_readdir_ctx *ut_new_readdir_ctx(struct ut_env *ute)
{
	struct ut_readdir_ctx *readdir_ctx;

	readdir_ctx = ut_zerobuf(ute, sizeof(*readdir_ctx));
	return readdir_ctx;
}


static const struct ut_dirent_info *
ut_find_not_dot(const struct ut_dirent_info *deis, size_t n, size_t start_pos)
{
	size_t pos = start_pos;
	const struct ut_dirent_info *dei = NULL;

	for (size_t i = 0; i < n; ++i) {
		if (pos >= n) {
			pos = 0;
		}
		dei = deis + pos;
		if (ut_not_dot_or_dotdot(dei->de.d_name)) {
			break;
		}
		++pos;
		dei = NULL;
	}
	ut_expect_not_null(dei);
	return dei;
}

static const struct ut_dirent_info *
ut_find_first_not_dot(const struct ut_dirent_info *dei, size_t n)
{
	return ut_find_not_dot(dei, n, 0);
}

static const struct ut_dirent_info *
ut_find_any_not_dot(const struct ut_dirent_info *dei, size_t n)
{
	return ut_find_not_dot(dei, n, n / 2);
}

static void ut_expect_name_exists(const struct ut_dirent_info *dei,
                                  size_t n, const char *name)
{
	bool name_exists = false;

	while ((n-- > 0) && !name_exists) {
		name_exists = (strcmp(dei->de.d_name, name) == 0);
		++dei;
	}
	ut_expect(name_exists);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_open_release(struct ut_env *ute)
{
	struct stat st = { .st_size = 0 };
	const char *name = UT_NAME;
	const ino_t parent = UT_ROOT_INO;
	ino_t ino;

	ut_mkdir(ute, parent, name, &st);
	ut_lookup(ute, parent, name, &st);
	ino = st.st_ino;
	ut_opendir(ute, ino);
	ut_releasedir(ute, ino);
	ut_rmdir(ute, parent, name);
	ut_opendir_err(ute, ino, -ENOENT);
	ut_releasedir_err(ute, ino, -ENOENT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_verify_iter_simple(struct ut_env *ute, const char *pre,
                                  const struct ut_readdir_ctx *rd_ctx)
{
	const char *name = NULL;
	const struct ut_dirent_info *dei = rd_ctx->dei;

	ut_expect_ge(rd_ctx->nde, 2);
	ut_expect_eqs(dei[0].de.d_name, ".");
	ut_expect_eqs(dei[1].de.d_name, "..");

	for (size_t i = 0; i < rd_ctx->nde - 2; ++i) {
		name = ut_make_name(ute, pre, i);
		ut_expect_name_exists(dei, rd_ctx->nde, name);
	}
}

static void ut_dir_iter_simple(struct ut_env *ute)
{
	ino_t dino;
	struct stat st;
	const char *name = NULL;
	const char *dname = UT_NAME;
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);
	const size_t count = UT_ARRAY_SIZE(rd_ctx->dei) - 2;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir(ute, dino);
	for (size_t i = 0; i < count; ++i) {
		ut_readdir(ute, dino, 0, rd_ctx);
		ut_expect_eq(rd_ctx->nde, i + 2);

		name = ut_make_name(ute, dname, i);
		ut_mkdir(ute, dino, name, &st);
		ut_readdir(ute, dino, 0, rd_ctx);
		ut_expect_eq(rd_ctx->nde, i + 3);

		ut_fsyncdir(ute, dino);
		ut_verify_iter_simple(ute, dname, rd_ctx);
	}
	for (size_t j = count; j > 0; --j) {
		name = ut_make_name(ute, dname, j - 1);
		ut_rmdir(ute, dino, name);
		ut_readdir(ute, dino, 0, rd_ctx);
		ut_verify_iter_simple(ute, dname, rd_ctx);
	}
	ut_releasedir(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_iter_names_(struct ut_env *ute,
                               const char *names[], size_t nnames)
{
	ino_t ino;
	ino_t dino;
	loff_t doff = 0;
	size_t dcnt = 0;
	const char *name = NULL;
	const char *dname = UT_NAME;
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir(ute, dino);
	for (size_t i = 0; i < nnames; ++i) {
		ut_create_only(ute, dino, names[i], &ino);
	}
	ut_readdir(ute, dino, doff, rd_ctx);
	while (rd_ctx->nde > 0) {
		for (size_t i = 0; i < rd_ctx->nde; ++i) {
			name = rd_ctx->dei[i].de.d_name;
			doff = rd_ctx->dei[i].de.d_off;
			if (ut_dot_or_dotdot(name)) {
				continue;
			}
			ut_unlink_file(ute, dino, name);
			if (++dcnt >= 5) {
				break;
			}
		}
		ut_readdir(ute, dino, doff, rd_ctx);
		dcnt = 0;
	}
	for (size_t i = nnames; i > 0; --i) {
		ut_create_only(ute, dino, names[i - 1], &ino);
	}
	ut_readdir(ute, dino, 0, rd_ctx);
	for (size_t i = 0; i < rd_ctx->nde; ++i) {
		name = rd_ctx->dei[i].de.d_name;
		if (!ut_dot_or_dotdot(name)) {
			ut_unlink_file(ute, dino, name);
		}
	}
	ut_releasedir(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_iter_fixed_names(struct ut_env *ute)
{
	const char *dig_names[] = {
		"1",
		"22",
		"333",
		"4444",
		"55555"
		"666666"
		"7777777"
		"88888888"
		"999999999"
	};
	const char *abc_names[] = {
		"a",
		"bb",
		"ccc",
		"dddd",
		"eeeee",
		"ffffff",
		"ggggggg",
		"hhhhhhhh",
		"iiiiiiiii",
		"jjjjjjjjjj",
		"kkkkkkkkkkk",
		"llllllllllll",
		"mmmmmmmmmmmmm",
		"nnnnnnnnnnnnnn",
		"ooooooooooooooo",
		"pppppppppppppppp",
		"qqqqqqqqqqqqqqqqq",
		"rrrrrrrrrrrrrrrrrr",
		"sssssssssssssssssss",
		"tttttttttttttttttttt",
		"uuuuuuuuuuuuuuuuuuuuu",
		"vvvvvvvvvvvvvvvvvvvvvv",
		"wwwwwwwwwwwwwwwwwwwwwww",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		"yyyyyyyyyyyyyyyyyyyyyyyyy",
		"zzzzzzzzzzzzzzzzzzzzzzzzzz",
	};

	ut_dir_iter_names_(ute, dig_names, UT_ARRAY_SIZE(dig_names));
	ut_dir_iter_names_(ute, abc_names, UT_ARRAY_SIZE(abc_names));
}

static void ut_dir_iter_rand_names_(struct ut_env *ute, size_t name_len)
{
	const char *names[40];
	char *name_i;
	const size_t nnames = UT_ARRAY_SIZE(names);

	for (size_t i = 0; i < nnames; ++i) {
		name_i = ut_randstr(ute, name_len);
		name_i[0] = (char)('A' + ((int)i % 23));
		names[i] = name_i;
	}
	ut_dir_iter_names_(ute, names, nnames);
}

static void ut_dir_iter_rand_names(struct ut_env *ute)
{
	const size_t name_len[] = { 10, 50, UT_NAME_MAX };

	for (size_t i = 0; i < UT_ARRAY_SIZE(name_len); ++i) {
		ut_dir_iter_rand_names_(ute, name_len[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_iter_links_(struct ut_env *ute, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	const char *lname = NULL;
	const char *fname = UT_NAME;
	const char *dname = UT_NAME;
	const char *dname2 = "AAA";
	const struct ut_dirent_info *dei = NULL;
	struct ut_readdir_ctx *rd_ctx = NULL;
	loff_t doff = -1;
	ino_t dino = 0;
	ino_t dino2 = 0;
	ino_t ino = 0;

	/* TODO: Use comp wrappers */
	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir(ute, dino);
	ut_mkdir_at_root(ute, dname2, &dino2);
	ut_opendir(ute, dino2);
	ut_create_only(ute, dino2, fname, &ino);
	rd_ctx = ut_new_readdir_ctx(ute);
	for (size_t i = 0; i < cnt; ++i) {
		lname = ut_make_name(ute, dname, i);
		ut_link(ute, ino, dino, lname, &st);
		ut_expect_eq(ino, st.st_ino);
		ut_expect_eq(i + 2, st.st_nlink);
		ut_fsyncdir(ute, dino);
	}
	doff = 0;
	for (size_t i = 0; i < cnt; ++i) {
		ut_readdir(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);
		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_lookup(ute, dino, dei->de.d_name, &st);
		ut_expect_eq(ino, st.st_ino);
		doff = dei->de.d_off + 1;
	}
	doff = 0;
	for (size_t i = 0; i < cnt; ++i) {
		ut_readdir(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);
		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_unlink(ute, dino, dei->de.d_name);
		ut_lookup_noent(ute, dino, dei->de.d_name);
		doff = dei->de.d_off;
	}
	ut_unlink(ute, dino2, fname);
	ut_releasedir(ute, dino2);
	ut_releasedir(ute, dino);
	ut_rmdir_at_root(ute, dname2);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_iter_links(struct ut_env *ute)
{
	const size_t cnt[] = { 10, 100, 1000, 10000 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(cnt); ++i) {
		ut_dir_iter_links_(ute, cnt[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_iter_unlink_(struct ut_env *ute, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);
	const struct ut_dirent_info *dei = NULL;
	const char *fname = NULL;
	const char *dname = UT_NAME;
	loff_t doff = 0;
	size_t nde = 0;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir(ute, dino);
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, dname, i);
		ut_create_only(ute, dino, fname, &ino);
	}
	for (size_t i = 0; i < cnt; ++i) {
		ut_readdir(ute, dino, doff, rd_ctx);
		nde = rd_ctx->nde;
		ut_expect_gt(nde, 0);

		dei = ut_find_any_not_dot(rd_ctx->dei, nde);
		ut_lookup(ute, dino, dei->de.d_name, &st);
		ut_unlink(ute, dino, dei->de.d_name);

		dei = ut_find_first_not_dot(rd_ctx->dei, nde);
		doff = dei->de.d_off;
	}
	ut_releasedir(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_iter_unlink(struct ut_env *ute)
{
	const size_t cnt[] = { 100, 10000 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(cnt); ++i) {
		ut_dir_iter_unlink_(ute, cnt[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_iter_plus_(struct ut_env *ute, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);
	const struct ut_dirent_info *dei = NULL;
	const char *name = NULL;
	const char *dname = UT_NAME;
	loff_t doff = 0;
	ino_t dino = 0;
	ino_t ino = 0;
	uint8_t x = 1;

	/* TODO: Use comp wrappers */
	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir(ute, dino);
	for (size_t i = 0; i < cnt; ++i) {
		name = ut_make_name(ute, dname, i);
		ut_create_file(ute, dino, name, &ino);
		ut_write_read(ute, ino, &x, 1, (loff_t)i);
		ut_release_file(ute, ino);
	}
	doff = 0;
	for (size_t i = 0; i < cnt; ++i) {
		ut_readdirplus(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);

		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_lookup(ute, dino, dei->de.d_name, &st);
		ut_expect_gt(dei->attr.st_size, 0);
		ut_expect_eq(dei->attr.st_size, st.st_size);
		ut_expect_eq(dei->attr.st_mode, st.st_mode);
		doff = dei->de.d_off + 1;
	}
	doff = 0;
	for (size_t i = 0; i < cnt; ++i) {
		ut_readdirplus(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);

		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_unlink(ute, dino, dei->de.d_name);
		doff = dei->de.d_off;
	}
	ut_releasedir(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_iter_plus(struct ut_env *ute)
{
	const size_t cnt[] = { 10, 100, 1000 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(cnt); ++i) {
		ut_dir_iter_plus_(ute, cnt[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_dir_open_release),
	UT_DEFTEST1(ut_dir_iter_simple),
	UT_DEFTEST(ut_dir_iter_fixed_names),
	UT_DEFTEST(ut_dir_iter_rand_names),
	UT_DEFTEST(ut_dir_iter_links),
	UT_DEFTEST(ut_dir_iter_unlink),
	UT_DEFTEST(ut_dir_iter_plus),
};

const struct ut_testdefs ut_tdefs_dir_iter = UT_MKTESTS(ut_local_tests);
