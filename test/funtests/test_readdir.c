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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct ft_getdents_ctx {
	char buf[FT_1M / 4];
	struct dirent64 dents[1024];
	size_t ndents;
};

static struct ft_getdents_ctx *
ft_new_getdents_ctx(struct ft_env *fte)
{
	struct ft_getdents_ctx *gd_ctx;

	gd_ctx = ft_new_buf_zeros(fte, sizeof(*gd_ctx));
	return gd_ctx;
}

static void ft_verify_getdents_ctx(struct ft_env *fte,
                                   struct ft_getdents_ctx *gd_ctx)
{
	loff_t off_curr;
	loff_t off_prev = -1;
	const struct dirent64 *dent;

	for (size_t i = 0; i < gd_ctx->ndents; ++i) {
		dent = &gd_ctx->dents[i];
		off_curr = dent->d_off;
		if (off_curr == -1) {
			ft_expect_eq(i + 1, gd_ctx->ndents);
		} else {
			ft_expect_gt(off_curr, off_prev);
		}
		off_prev = dent->d_off;
	}
	silofs_unused(fte);
}

static void ft_getdents2(int fd, struct ft_getdents_ctx *gd_ctx)
{
	size_t ndents = 0;
	const size_t ndents_max = FT_ARRAY_SIZE(gd_ctx->dents);

	ft_getdents(fd, gd_ctx->buf, sizeof(gd_ctx->buf),
	            gd_ctx->dents, ndents_max, &ndents);
	ft_expect_le(ndents, ndents_max);
	gd_ctx->ndents = ndents;
}

static void ft_getdents_from(struct ft_env *fte, int fd, loff_t off,
                             struct ft_getdents_ctx *gd_ctx)
{
	loff_t pos = -1;

	ft_llseek(fd, off, SEEK_SET, &pos);
	ft_expect_eq(off, pos);
	ft_getdents2(fd, gd_ctx);
	ft_verify_getdents_ctx(fte, gd_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects Linux getdents(2) to read all dir-entries.
 */
static void test_readdir_basic_(struct ft_env *fte, size_t lim)
{
	struct stat st = { .st_size = -1 };
	struct dirent64 dent = { .d_ino = 0 };
	const char *path1 = NULL;
	const char *path0 = ft_new_path_unique(fte);
	loff_t pos = -1;
	loff_t off = 0;
	size_t cnt = 0;
	size_t itr = 0;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path0, 0755);
	ft_open(path0, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < lim; ++i) {
		path1 = ft_new_pathf(fte, path0, "%08x", i);
		ft_creat(path1, 0600, &fd);
		ft_close(fd);
		ft_fstat(dfd, &st);
		ft_expect_ge(st.st_size, i + 1);
	}
	while (cnt < lim) {
		itr += 1;
		ft_expect_lt(itr, 10 * lim);

		ft_llseek(dfd, off, SEEK_SET, &pos);
		ft_expect_eq(off, pos);
		ft_getdent(dfd, &dent);
		off = dent.d_off;
		if (ft_dirent_isxdot(&dent)) {
			continue;
		}
		ft_expect_true(ft_dirent_isreg(&dent));
		cnt++;
	}
	for (size_t j = 0; j < lim; ++j) {
		ft_fstat(dfd, &st);
		ft_expect_ge(st.st_size, lim - j);
		path1 = ft_new_pathf(fte, path0, "%08x", j);
		ft_stat(path1, &st);
		ft_unlink(path1);
		ft_stat_noent(path1);
	}
	ft_close(dfd);
	ft_rmdir(path0);
}

static void test_readdir_basic(struct ft_env *fte)
{
	const size_t lim[] = { 1, 2, 4, 32, 128 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(lim); ++i) {
		test_readdir_basic_(fte, lim[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects getdents(2) to read all dir-entries while unlinking.
 */
static void test_readdir_unlink_(struct ft_env *fte, size_t lim)
{
	struct stat st = { .st_size = -1 };
	struct dirent64 dent = { .d_ino = 0 };
	const char *path1 = NULL;
	const char *path0 = ft_new_path_unique(fte);
	loff_t pos = -1;
	loff_t off = 0;
	size_t cnt = 0;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_open(path0, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < lim; ++i) {
		path1 = ft_new_path_under(fte, path0);
		ft_creat(path1, 0600, &fd);
		ft_close(fd);
		ft_fstat(dfd, &st);
		ft_expect_ge(st.st_size, i + 1);
	}
	while (cnt < lim) {
		ft_expect_lt(cnt, (2 * lim));

		ft_llseek(dfd, off, SEEK_SET, &pos);
		ft_expect_eq(off, pos);
		ft_getdent(dfd, &dent);
		if (!strlen(dent.d_name)) {
			break;
		}
		if (ft_dirent_isxdot(&dent)) {
			off = dent.d_off;
			continue;
		}
		ft_expect_true(ft_dirent_isreg(&dent));
		ft_expect_false(ft_dirent_isdir(&dent));

		path1 = ft_new_path_nested(fte, path0, dent.d_name);
		ft_stat(path1, &st);
		ft_unlink(path1);
		ft_stat_noent(path1);
		off = 2;
		cnt++;
	}
	ft_close(dfd);
	ft_rmdir(path0);
}

static void test_readdir_unlink(struct ft_env *fte)
{
	const size_t lim[] = { 4, 16, 128 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(lim); ++i) {
		test_readdir_unlink_(fte, lim[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects Linux getdents(2) to read all dir-entries of large dir. Read single
 * dentry at a time.
 */
static const char *
make_iname(struct ft_env *fte, const char *path, const char *pref, size_t idx)
{
	return ft_new_pathf(fte, path, "%s-%08lx", pref, idx);
}

static void test_readdir_getdents_(struct ft_env *fte, size_t lim)
{
	char buf[1024];
	struct dirent64 dents[8];
	struct stat st = { .st_size = -1 };
	const size_t bsz = sizeof(buf);
	const size_t ndents = FT_ARRAY_SIZE(dents);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = NULL;
	const char *prefix = ft_new_name_unique(fte);
	const struct dirent64 *dent = NULL;
	loff_t pos = -1;
	loff_t off = 0;
	size_t nde = 0;
	size_t cnt = 0;
	int cmp = 0;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path0, 0755);
	ft_open(path0, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < lim; ++i) {
		path1 = make_iname(fte, path0, prefix, i);
		ft_creat(path1, 0600, &fd);
		ft_close(fd);
		ft_fstat(dfd, &st);
		ft_expect_ge(st.st_size, i + 1);
	}
	while (cnt < lim) {
		ft_llseek(dfd, off, SEEK_SET, &pos);
		ft_expect_eq(off, pos);

		ft_getdents(dfd, buf, bsz, dents, ndents, &nde);
		for (size_t j = 0; j < nde; ++j) {
			dent = &dents[j];
			off = dent->d_off;
			if (ft_dirent_isxdot(dent)) {
				continue;
			}
			ft_expect_true(ft_dirent_isreg(dent));
			cmp = strncmp(dent->d_name, prefix, strlen(prefix));
			ft_expect_eq(cmp, 0);
			cnt++;
		}
	}
	for (size_t k = 0; k < lim; ++k) {
		path1 = make_iname(fte, path0, prefix, k);
		ft_stat(path1, &st);
		ft_unlink(path1);
		ft_stat_noent(path1);
		ft_fstat(dfd, &st);
		ft_expect_ge(st.st_size, lim - (k + 1));
	}
	ft_close(dfd);
	ft_rmdir(path0);
}

static void test_readdir_getdents(struct ft_env *fte)
{
	const size_t lim[] = { 2, 32, 256, 8192, 32768 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(lim); ++i) {
		test_readdir_getdents_(fte, lim[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests getdents(2) system call with multiple dir-entries at a time.
 */
static void test_readdir_counted_(struct ft_env *fte, size_t lim)
{
	struct ft_getdents_ctx *gd_ctx = ft_new_getdents_ctx(fte);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = NULL;
	const char *name = NULL;
	const struct dirent64 *dent = NULL;
	loff_t off = 0;
	size_t cnt = 0;
	int dfd = -1;

	ft_mkdir(path0, 0700);
	for (size_t diri = 0; diri < lim; ++diri) {
		path1 = ft_new_pathf(fte, path0, "%04lx", diri);
		ft_mkdir(path1, 0700);
	}
	ft_open(path0, O_DIRECTORY | O_RDONLY, 0, &dfd);
	while (cnt < lim) {
		ft_getdents_from(fte, dfd, off, gd_ctx);
		ft_expect_gt(gd_ctx->ndents, 0);
		for (size_t i = 0; i < gd_ctx->ndents; ++i) {
			dent = &gd_ctx->dents[i];
			off = dent->d_off;
			ft_expect_true(ft_dirent_isdir(dent));
			if (ft_dirent_isxdot(dent)) {
				continue;
			}
			cnt++;
		}
	}
	cnt = 0;
	while (cnt < lim) {
		ft_getdents_from(fte, dfd, 0, gd_ctx);
		ft_expect_gt(gd_ctx->ndents, 0);
		for (size_t j = 0; j < gd_ctx->ndents; ++j) {
			dent = &gd_ctx->dents[j];
			ft_expect_true(ft_dirent_isdir(dent));
			if (ft_dirent_isxdot(dent)) {
				continue;
			}
			name = dent->d_name;
			path1 = ft_new_path_nested(fte, path0, name);
			ft_rmdir(path1);
			cnt++;
		}
	}
	ft_close(dfd);
	ft_rmdir(path0);
}

static void test_readdir_counted(struct ft_env *fte)
{
	const size_t lim[] = {
		10,
		100,
		silofs_min(SILOFS_LINK_MAX - 2, 100000)
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(lim); ++i) {
		test_readdir_counted_(fte, lim[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_readdir_unlinkat_(struct ft_env *fte, size_t lim)
{
	struct stat st = { .st_size = -1 };
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	const char *fname = ft_new_name_unique(fte);
	struct ft_getdents_ctx *gd_ctx = ft_new_getdents_ctx(fte);
	const struct dirent64 *dent = NULL;
	const char *name = NULL;
	loff_t doff = 0;
	size_t cnt = 0;
	size_t itr = 0;
	int dfd1 = -1;
	int dfd2 = -1;
	int fd = -1;

	ft_mkdir(path1, 0700);
	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	ft_mkdir(path2, 0700);
	ft_open(path2, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	ft_openat(dfd2, fname, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < lim; ++i) {
		name = ft_make_ulong_name(fte, i + 1);
		ft_linkat(dfd2, fname, dfd1, name, 0);
		ft_fstat(dfd1, &st);
		ft_expect_ge(st.st_size, i + 1);
	}
	for (size_t i = 0; i < lim; ++i) {
		name = ft_make_ulong_name(fte, i + 1);
		ft_linkat_err(dfd2, fname, dfd1, name, 0, -EEXIST);
	}
	while (cnt < lim) {
		ft_fstat(dfd1, &st);
		ft_expect_gt(st.st_size, 0);
		doff = st.st_size / 2;
		ft_getdents_from(fte, dfd1, doff, gd_ctx);
		if (gd_ctx->ndents == 0) {
			ft_getdents_from(fte, dfd1, 2, gd_ctx);
			ft_expect_gt(gd_ctx->ndents, 0);
		}
		for (size_t j = 0; j < gd_ctx->ndents; ++j) {
			dent = &gd_ctx->dents[j];
			if (ft_dirent_isxdot(dent)) {
				continue;
			}
			ft_expect_true(ft_dirent_isreg(dent));
			ft_unlinkat(dfd1, dent->d_name, 0);
			cnt++;
		}
		ft_expect_lt(itr, lim);
		itr++;
	}
	ft_close(fd);
	ft_close(dfd1);
	ft_rmdir(path1);
	ft_unlinkat(dfd2, fname, 0);
	ft_close(dfd2);
	ft_rmdir(path2);
}

static void test_readdir_unlinkat(struct ft_env *fte)
{
	const size_t lim[] = { 8, 64, 512, 8192, SILOFS_LINK_MAX - 1 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(lim); ++i) {
		test_readdir_unlinkat_(fte, lim[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects Linux getdents(2) to work on directory without X_OK permission, but
 * do not allow stat(2).
 */
static void test_readdir_nox_(struct ft_env *fte, size_t cnt)
{
	struct ft_getdents_ctx *gd_ctx = ft_new_getdents_ctx(fte);
	const char *path = ft_new_path_unique(fte);
	const struct dirent64 *dent = NULL;
	const char *name = NULL;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		name = ft_make_ulong_name(fte, i + 1);
		ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
		ft_close(fd);
	}
	ft_close(dfd);
	ft_chmod(path, 0600);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_getdents2(dfd, gd_ctx);
	ft_expect_gt(gd_ctx->ndents, 2);
	ft_expect_le(gd_ctx->ndents, cnt + 2);
	for (size_t i = 0; i < gd_ctx->ndents; ++i) {
		dent = &gd_ctx->dents[i];
		if (ft_dirent_isxdot(dent)) {
			continue;
		}
		ft_fstatat_err(dfd, dent->d_name, 0, -EACCES);
	}
	ft_close(dfd);
	ft_chmod(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		name = ft_make_ulong_name(fte, i + 1);
		ft_unlinkat(dfd, name, 0);
	}
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_readdir_nox(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_readdir_nox_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects Linux getdents(2) to iterate on all entries from various directory
 * stream positions, while unlinking entries.
 */
static void
test_readdir_unlink_names_arr_(struct ft_env *fte,
                               const char *names[], size_t cnt)
{
	struct ft_getdents_ctx *gd_ctx = ft_new_getdents_ctx(fte);
	const char *path = ft_new_path_unique(fte);
	const struct dirent64 *dent = NULL;
	loff_t doff = 0;
	size_t dcnt = 0;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		ft_openat(dfd, names[i], O_CREAT | O_RDWR, 0600, &fd);
		ft_close(fd);
	}
	while (doff >= 0) {
		dcnt = 0;
		ft_getdents_from(fte, dfd, doff, gd_ctx);
		for (size_t i = 0; i < gd_ctx->ndents; ++i) {
			dent = &gd_ctx->dents[i];
			doff = dent->d_off;
			if (ft_dirent_isxdot(dent)) {
				continue;
			}
			ft_unlinkat(dfd, dent->d_name, 0);
			if (++dcnt >= 5) {
				break;
			}
		}
	}
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_readdir_unlink_names_(struct ft_env *fte, size_t nlen)
{
	const char *names[256];
	char *name_i = NULL;
	const size_t cnt = FT_ARRAY_SIZE(names);

	for (size_t i = 0; i < cnt; ++i) {
		name_i = ft_make_rand_name(fte, nlen);
		name_i[0] = (char)('A' + ((int)i % 23));
		names[i] = name_i;
	}
	test_readdir_unlink_names_arr_(fte, names, cnt);
}

static void test_readdir_unlink_names(struct ft_env *fte)
{
	const size_t nlen[] = { SILOFS_NAME_MAX / 5, SILOFS_NAME_MAX };

	for (size_t i = 0; i < FT_ARRAY_SIZE(nlen); ++i) {
		test_readdir_unlink_names_(fte, nlen[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_readdir_basic),
	FT_DEFTEST(test_readdir_unlink),
	FT_DEFTEST(test_readdir_getdents),
	FT_DEFTEST(test_readdir_counted),
	FT_DEFTEST(test_readdir_unlinkat),
	FT_DEFTEST(test_readdir_nox),
	FT_DEFTEST(test_readdir_unlink_names),
};

const struct ft_tests ft_test_readdir = FT_DEFTESTS(ft_local_tests);
