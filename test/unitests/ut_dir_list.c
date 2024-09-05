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
#include <limits.h>
#include <dirent.h>

struct ut_direlem {
	struct ut_direlem *next;
	struct ut_dirent_info dei;
	mode_t mode;
	int pad;
};

struct ut_dirlist {
	struct ut_env *ute;
	ino_t dino;
	size_t count;
	struct ut_direlem *list;
};


static struct ut_direlem *
new_direlem(struct ut_env *ute, const struct ut_dirent_info *dei)
{
	struct ut_direlem *de = ut_zerobuf(ute, sizeof(*de));

	memcpy(&de->dei, dei, sizeof(de->dei));
	de->mode = DTTOIF((mode_t)dei->de.d_type);
	return de;
}

static struct ut_dirlist *
new_dirlist(struct ut_env *ute, ino_t dino)
{
	struct ut_dirlist *dl = ut_zerobuf(ute, sizeof(*dl));

	dl->ute = ute;
	dl->dino = dino;
	dl->count = 0;
	dl->list = NULL;
	return dl;
}

static void push_direlem(struct ut_dirlist *dl,
                         struct ut_direlem *de)
{
	de->next = dl->list;
	dl->list = de;
	dl->count++;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct ut_dirlist *
dir_list(struct ut_env *ute, ino_t dino, size_t expected_nents)
{
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);
	struct ut_dirlist *dl = new_dirlist(ute, dino);
	const size_t ndents_max = UT_ARRAY_SIZE(rd_ctx->dei);
	const struct ut_dirent_info *dei = NULL;
	size_t ndents = 1;
	size_t dots = 0;
	loff_t doff = 0;
	int partial = 0;

	ut_opendir(ute, dino);
	while (ndents > 0) {
		ut_readdir(ute, dino, doff, rd_ctx);
		ndents = rd_ctx->nde;
		ut_expect_le(ndents, ndents_max);

		if (ndents && (ndents < ndents_max)) {
			ut_expect_eq(partial, 0);
			partial++;
		}
		for (size_t i = 0; i < ndents; ++i) {
			dei = &rd_ctx->dei[i];
			if (!ut_dot_or_dotdot(dei->de.d_name)) {
				ut_expect_lt(dl->count, expected_nents);
				push_direlem(dl, new_direlem(ute, dei));
			} else {
				ut_expect_lt(dots, 2);
				dots++;
			}
			doff = dei->de.d_off + 1;
		}
	}
	if (expected_nents < UINT_MAX) {
		ut_expect_eq(dl->count, expected_nents);
	}
	ut_releasedir(ute, dino);
	return dl;
}

static struct ut_dirlist *dir_list_all(struct ut_env *ute, ino_t dino)
{
	return dir_list(ute, dino, UINT_MAX);
}

static struct ut_dirlist *dir_list_some(struct ut_env *ute, ino_t dino,
                                        loff_t off, size_t max_nents)
{
	bool keep_iter = true;
	loff_t doff = off;
	const struct ut_dirent_info *dei;
	struct ut_dirlist *dl = new_dirlist(ute, dino);
	struct ut_readdir_ctx *rd_ctx =
	        ut_new_readdir_ctx(ute);

	ut_opendir(ute, dino);
	while (keep_iter) {
		ut_readdir(ute, dino, doff, rd_ctx);
		for (size_t i = 0; i < rd_ctx->nde; ++i) {
			dei = &rd_ctx->dei[i];
			if (!ut_dot_or_dotdot(dei->de.d_name)) {
				push_direlem(dl, new_direlem(ute, dei));
				if (dl->count == max_nents) {
					keep_iter = false;
				}
			}
			doff = dei->de.d_off + 1;
		}
		if (!rd_ctx->nde) {
			keep_iter = false;
		}
	}
	ut_releasedir(ute, dino);
	return dl;
}

static void dir_unlink_all(struct ut_dirlist *dl)
{
	size_t count = 0;
	const char *name;
	const struct ut_direlem *de;

	for (de = dl->list; de != NULL; de = de->next) {
		ut_expect_lt(count, dl->count);
		name = de->dei.de.d_name;
		if (S_ISDIR(de->mode)) {
			ut_rmdir(dl->ute, dl->dino, name);
		} else if (S_ISLNK(de->mode)) {
			ut_remove_link(dl->ute, dl->dino, name);
		} else {
			ut_unlink(dl->ute, dl->dino, name);
		}
		count += 1;
	}
	ut_expect_eq(count, dl->count);
	dl->count = 0;
	dl->list = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_create_nfiles(struct ut_env *ute, ino_t dino,
                             const char *dname, size_t count)
{
	const char *name = NULL;
	ino_t ino = 0;

	for (size_t i = 0; i < count; ++i) {
		name = ut_make_name(ute, dname, i);
		ut_create_only(ute, dino, name, &ino);
	}
}

static void ut_create_ninodes(struct ut_env *ute, ino_t dino,
                              const char *dname, size_t count)
{
	char s[256] = "";
	struct stat st;
	const char *name = NULL;
	ino_t ino;

	for (size_t i = 0; i < count; ++i) {
		name = ut_make_name(ute, dname, i);
		if ((i % 3) == 0) {
			ut_mkdir2(ute, dino, name, &ino);
		} else if ((i % 5) == 0) {
			snprintf(s, sizeof(s) - 1, "%s_%lu", dname, i);
			ut_symlink(ute, dino, name, s, &ino);
		} else {
			ut_create_only(ute, dino, name, &ino);
		}
	}
	ut_getattr(ute, dino, &st);
	ut_expect_ge(st.st_size, count);
}


static void ut_dir_list_simple_(struct ut_env *ute, size_t cnt)
{
	struct ut_dirlist *dl = NULL;
	const char *name = UT_NAME;
	ino_t dino;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_nfiles(ute, dino, name, cnt);
	dl = dir_list(ute, dino, cnt);
	dir_unlink_all(dl);
	ut_create_ninodes(ute, dino, name, cnt);
	dl = dir_list(ute, dino, cnt);
	dir_unlink_all(dl);
	ut_rmdir_at_root(ute, name);
}

static void ut_dir_list_simple(struct ut_env *ute)
{
	const size_t cnt[] = { 10, 100, 1000 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(cnt); ++i) {
		ut_dir_list_simple_(ute, cnt[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_list_repeated_(struct ut_env *ute,
                                  size_t count, size_t niter)
{
	struct ut_dirlist *dl;
	const char *prefix = NULL;
	const char *name = UT_NAME;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	while (niter-- > 0) {
		prefix = ut_randstr(ute, 31);
		ut_create_nfiles(ute, dino, prefix, count);
		dl = dir_list(ute, dino, count);
		dir_unlink_all(dl);

		prefix = ut_randstr(ute, 127);
		ut_create_ninodes(ute, dino, prefix, count / 2);
		dl = dir_list(ute, dino, count / 2);
		dir_unlink_all(dl);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_dir_list_repeated(struct ut_env *ute)
{
	const size_t count[] = { 10, 100, 1000, 10000 };
	const size_t nelems = UT_ARRAY_SIZE(count);

	for (size_t i = 0; i < nelems; ++i) {
		ut_dir_list_repeated_(ute, count[i], nelems - i + 1);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void create_nfiles_sparse(struct ut_env *ute, ino_t dino,
                                 const char *prefix, size_t count)
{
	const char *name = NULL;
	ino_t ino = 0;

	for (size_t i = 0; i < (2 * count); ++i) {
		name = ut_make_name(ute, prefix, i);
		ut_create_only(ute, dino, name, &ino);
	}
	for (size_t j = 1; j < (2 * count); j += 2) {
		name = ut_make_name(ute, prefix, j);
		ut_unlink(ute, dino, name);
	}
}

static void ut_dir_list_sparse_(struct ut_env *ute, size_t count)
{
	ino_t dino;
	loff_t doff = (loff_t)count;
	const char *dname = UT_NAME;
	struct ut_dirlist *dl = NULL;

	ut_mkdir_at_root(ute, dname, &dino);
	create_nfiles_sparse(ute, dino, ut_randstr(ute, 71), count);
	dl = dir_list_some(ute, dino, (2 * doff) / 3, count);
	dir_unlink_all(dl);
	dl = dir_list_some(ute, dino, doff / 3, count);
	dir_unlink_all(dl);
	create_nfiles_sparse(ute, dino, ut_randstr(ute, 127), count / 2);
	dl = dir_list_some(ute, dino, doff / 3, count);
	dir_unlink_all(dl);
	dl = dir_list_all(ute, dino);
	dir_unlink_all(dl);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_list_sparse(struct ut_env *ute)
{
	const size_t cnt[] = { 10, 100, 1000 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(cnt); ++i) {
		ut_dir_list_sparse_(ute, cnt[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_dir_list_simple),
	UT_DEFTEST(ut_dir_list_repeated),
	UT_DEFTEST(ut_dir_list_sparse),
};

const struct ut_testdefs ut_tdefs_dir_list = UT_MKTESTS(ut_local_tests);
