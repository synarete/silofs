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

static void ut_rename_within_same_dir(struct ut_env *ute)
{
	ino_t ino = 0;
	ino_t dino = 0;
	struct stat st = { .st_size = -1 };
	const char *dname = UT_NAME;
	const char *newname = NULL;
	const size_t name_max = UT_NAME_MAX;
	const char *name = ut_randstr(ute, name_max);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < name_max; ++i) {
		newname = ut_randstr(ute, i + 1);
		ut_rename_move(ute, dino, name, dino, newname);

		ut_getattr(ute, ino, &st);
		ut_expect_eq(st.st_nlink, 1);

		name = newname;
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_rename_toggle_between_dirs(struct ut_env *ute)
{
	ino_t ino = 0;
	ino_t dino1 = 0;
	ino_t dino2 = 0;
	ino_t src_dino = 0;
	ino_t dst_dino = 0;
	const char *dname = UT_NAME;
	const char *name = ut_randstr(ute, UT_NAME_MAX);
	const char *newname = NULL;
	struct stat st = { .st_ino = 0 };

	ut_mkdir_at_root(ute, dname, &dino1);
	ut_mkdir2(ute, dino1, dname, &dino2);
	ut_create_file(ute, dino2, name, &ino);
	for (size_t i = 0; i < UT_NAME_MAX; ++i) {
		newname = ut_randstr(ute, i + 1);
		src_dino = (i & 1) ? dino1 : dino2;
		dst_dino = (i & 1) ? dino2 : dino1;
		ut_rename_move(ute, src_dino, name, dst_dino, newname);
		ut_getattr(ute, ino, &st);
		ut_expect_eq(st.st_nlink, 1);

		name = newname;
	}
	ut_remove_file(ute, dst_dino, name, ino);
	ut_rmdir(ute, dino1, dname);
	ut_rmdir_at_root(ute, dname);
}

static void ut_rename_replace_without_data(struct ut_env *ute)
{
	ino_t ino1 = 0;
	ino_t ino2 = 0;
	ino_t dino1 = 0;
	ino_t dino2 = 0;
	ino_t base_dino = 0;
	const size_t name_max = UT_NAME_MAX;
	const char *base_dname = UT_NAME;
	const char *dname1 = ut_randstr(ute, name_max);
	const char *dname2 = ut_randstr(ute, name_max);
	const char *name1 = NULL;
	const char *name2 = NULL;
	struct stat st = { .st_size = -1 };

	ut_mkdir_at_root(ute, base_dname, &base_dino);
	ut_mkdir2(ute, base_dino, dname1, &dino1);
	ut_mkdir2(ute, base_dino, dname2, &dino2);
	for (size_t i = 0; i < name_max; ++i) {
		name1 = ut_randstr(ute, i + 1);
		name2 = ut_randstr(ute, name_max - i);
		ut_create_only(ute, dino1, name1, &ino1);
		ut_create_only(ute, dino2, name2, &ino2);
		ut_drop_caches_fully(ute);
		ut_rename_replace(ute, dino1, name1, dino2, name2);
		ut_getattr(ute, ino1, &st);
		ut_expect_eq(st.st_nlink, 1);
		ut_drop_caches_fully(ute);
		ut_unlink(ute, dino2, name2);
	}
	ut_rmdir(ute, base_dino, dname1);
	ut_rmdir(ute, base_dino, dname2);
	ut_rmdir_at_root(ute, base_dname);
}

static void ut_rename_replace_with_data(struct ut_env *ute)
{
	loff_t off = -1;
	size_t bsz = 0;
	ino_t ino1 = 0;
	ino_t ino2 = 0;
	ino_t dino1 = 0;
	ino_t dino2 = 0;
	ino_t base_dino = 0;
	char *name1 = NULL;
	char *name2 = NULL;
	char *dname1 = NULL;
	char *dname2 = NULL;
	void *buf1 = NULL;
	void *buf2 = NULL;
	const char *base_dname = UT_NAME;
	const size_t name_max = UT_NAME_MAX;

	dname1 = ut_randstr(ute, name_max);
	dname2 = ut_randstr(ute, name_max);
	ut_mkdir_at_root(ute, base_dname, &base_dino);
	ut_mkdir2(ute, base_dino, dname1, &dino1);
	ut_mkdir2(ute, base_dino, dname2, &dino2);

	bsz = UT_BK_SIZE;
	for (size_t i = 0; i < name_max; ++i) {
		off = (loff_t)((i * bsz) + i);
		buf1 = ut_randbuf(ute, bsz);
		buf2 = ut_randbuf(ute, bsz);
		name1 = ut_randstr(ute, i + 1);
		name2 = ut_randstr(ute, name_max - i);

		ut_create_file(ute, dino1, name1, &ino1);
		ut_create_file(ute, dino2, name2, &ino2);
		ut_write_read(ute, ino1, buf1, bsz, off);
		ut_write_read(ute, ino2, buf2, bsz, off);
		ut_release_file(ute, ino2);
		ut_rename_replace(ute, dino1, name1, dino2, name2);
		ut_read(ute, ino1, buf1, bsz, off);
		ut_release_file(ute, ino1);
		ut_unlink(ute, dino2, name2);
	}
	ut_rmdir(ute, base_dino, dname1);
	ut_rmdir(ute, base_dino, dname2);
	ut_rmdir_at_root(ute, base_dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_rename_move_multi_(struct ut_env *ute, size_t cnt)
{
	ino_t ino = 0;
	ino_t dino1 = 0;
	ino_t dino2 = 0;
	ino_t base_dino = 0;
	const char *base_dname = UT_NAME;
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char *dname1 = ut_randstr(ute, UT_NAME_MAX);
	const char *dname2 = ut_randstr(ute, UT_NAME_MAX);
	const ino_t root_ino = UT_ROOT_INO;

	ut_getattr_dirsize(ute, root_ino, 0);
	ut_mkdir2(ute, root_ino, base_dname, &base_dino);
	ut_mkdir2(ute, base_dino, dname1, &dino1);
	ut_mkdir2(ute, base_dino, dname2, &dino2);

	ut_getattr_dirsize(ute, base_dino, 2);
	ut_lookup_dir(ute, base_dino, dname1, dino1);
	ut_lookup_dir(ute, base_dino, dname2, dino2);

	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, "s", i);
		ut_create_only(ute, dino1, name1, &ino);
		ut_getattr_dirsize(ute, dino1, (loff_t)i + 1);
		ut_lookup_file(ute, dino1, name1, ino);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, "s", i);
		name2 = ut_make_name(ute, "t", i);
		ut_rename_move(ute, dino1, name1, dino2, name2);
		ut_getattr_dirsize(ute, dino2, (loff_t)i + 1);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name2 = ut_make_name(ute, "t", i);
		ut_unlink(ute, dino2, name2);
	}

	ut_rmdir(ute, base_dino, dname1);
	ut_rmdir(ute, base_dino, dname2);
	ut_getattr_dirsize(ute, base_dino, 0);
	ut_rmdir(ute, root_ino, base_dname);
	ut_getattr_dirsize(ute, root_ino, 0);
}

static void ut_rename_move_multi(struct ut_env *ute)
{
	ut_rename_move_multi_(ute, 100);
	ut_rename_move_multi_(ute, 2000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_rename_onto_link_(struct ut_env *ute, size_t niter, size_t cnt)
{
	ino_t ino = 0;
	ino_t dino = 0;
	struct stat st = { .st_size = -1 };
	const char *tname = UT_NAME;
	const char *prefix = "dummy";
	const char *name = NULL;

	ut_mkdir_at_root(ute, tname, &dino);
	for (size_t i = 0; i < niter; ++i) {
		name = ut_make_name(ute, prefix, i);
		ut_create_only(ute, dino, name, &ino);

		ut_create_only(ute, dino, tname, &ino);
		for (size_t j = 0; j < cnt; ++j) {
			name = ut_make_name(ute, tname, j);
			ut_link(ute, ino, dino, name, &st);
		}
		for (size_t j = 0; j < cnt; ++j) {
			name = ut_make_name(ute, tname, j);
			ut_rename_replace(ute, dino, tname, dino, name);
			ut_rename_move(ute, dino, name, dino, tname);
		}
		ut_unlink(ute, dino, tname);
	}
	for (size_t i = 0; i < niter; ++i) {
		name = ut_make_name(ute, prefix, i);
		ut_unlink(ute, dino, name);
	}
	ut_rmdir_at_root(ute, tname);
}

static void ut_rename_onto_link(struct ut_env *ute)
{
	ut_rename_onto_link_(ute, 10, 10);
	ut_rename_onto_link_(ute, 3, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_rename_exchange_aux_(struct ut_env *ute, ino_t dino1,
				    ino_t dino2, size_t cnt)
{
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char *prefix = UT_NAME;
	ino_t ino1 = 0;
	ino_t ino2 = 0;

	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, prefix, i + 1);
		name2 = ut_make_name(ute, prefix, i + cnt + 1);
		ut_create_only(ute, dino1, name1, &ino1);
		ut_symlink(ute, dino2, name2, name1, &ino2);
		ut_rename_exchange(ute, dino1, name1, dino2, name2);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, prefix, i + 1);
		name2 = ut_make_name(ute, prefix, i + cnt + 1);
		ut_rename_exchange(ute, dino1, name1, dino2, name2);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, prefix, i + 1);
		name2 = ut_make_name(ute, prefix, i + cnt + 1);
		ut_unlink(ute, dino1, name1);
		ut_unlink(ute, dino2, name2);
	}
}

static void ut_rename_exchange_(struct ut_env *ute, size_t cnt)
{
	const char *dname1 = "dir1";
	const char *dname2 = "dir2";
	ino_t dino1 = 0;
	ino_t dino2 = 0;

	ut_mkdir_at_root(ute, dname1, &dino1);
	ut_mkdir_at_root(ute, dname2, &dino2);
	ut_rename_exchange_aux_(ute, dino1, dino2, cnt);
	ut_rmdir_at_root(ute, dname1);
	ut_rmdir_at_root(ute, dname2);
}

static void ut_rename_exchange_simple(struct ut_env *ute)
{
	ut_rename_exchange_(ute, 10);
	ut_rename_exchange_(ute, 1000);
}

static void ut_rename_exchange_same_(struct ut_env *ute, size_t cnt)
{
	const char *dname = UT_NAME;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_rename_exchange_aux_(ute, dino, dino, cnt);
	ut_rmdir_at_root(ute, dname);
}

static void ut_rename_exchange_same(struct ut_env *ute)
{
	const size_t cnt[] = { 1, 10, 1000 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(cnt); ++i) {
		ut_rename_exchange_same_(ute, cnt[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_rename_override_(struct ut_env *ute, size_t cnt,
				loff_t off_base, size_t bsz)
{
	void *buf1 = ut_randbuf(ute, bsz);
	void *buf2 = ut_randbuf(ute, bsz);
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char *dname1 = ut_make_name(ute, UT_NAME, 1);
	const char *dname2 = ut_make_name(ute, UT_NAME, 2);
	ino_t dino1 = 0;
	ino_t dino2 = 0;
	ino_t ino1 = 0;
	ino_t ino2 = 0;

	ut_mkdir_at_root(ute, dname1, &dino1);
	ut_mkdir_at_root(ute, dname2, &dino2);
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, dname1, i);
		ut_create_file(ute, dino1, name1, &ino1);
		ut_write(ute, ino1, buf1, bsz, off_base + (loff_t)i);
		ut_release_file(ute, ino1);
		name2 = ut_make_name(ute, dname2, i);
		ut_create_file(ute, dino2, name2, &ino2);
		ut_write(ute, ino2, buf2, bsz, off_base + (loff_t)(i + 1));
		ut_release_file(ute, ino2);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, dname1, i);
		name2 = ut_make_name(ute, dname2, i);
		ut_rename_replace(ute, dino1, name1, dino2, name2);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name2 = ut_make_name(ute, dname2, i);
		ut_lookup_ino(ute, dino2, name2, &ino2);
		ut_open_rdonly(ute, ino2);
		ut_read_verify(ute, ino2, buf1, bsz, off_base + (loff_t)i);
		ut_release_file(ute, ino2);
		ut_unlink_file(ute, dino2, name2);
	}
	ut_rmdir_at_root(ute, dname1);
	ut_rmdir_at_root(ute, dname2);
}

static void ut_rename_override(struct ut_env *ute)
{
	ut_rename_override_(ute, 1000, 0, UT_1K);
	ut_relax_mem(ute);
	ut_rename_override_(ute, 100, UT_1T, UT_1M);
	ut_relax_mem(ute);
	ut_rename_override_(ute, 10, 11, UT_1K + 11);
	ut_relax_mem(ute);
	ut_rename_override_(ute, 100, UT_64K - 1, UT_64K + 11);
	ut_relax_mem(ute);
	ut_rename_override_(ute, 1000, UT_1G - 11, UT_1K + 1111);
	ut_relax_mem(ute);
	ut_rename_override_(ute, 10, UT_1T - 111, UT_1M + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_ino_to_str(struct ut_env *ute, ino_t ino, char *s, size_t n)
{
	snprintf(s, n - 1, "user.ino=%ld", (long)ino);
	ut_unused(ute);
}

static void ut_setxattr_ino(struct ut_env *ute, ino_t ino)
{
	char str[64] = "";
	struct ut_keyval kv = {
		.name = str,
		.value = &ino,
		.size = sizeof(ino),
	};

	ut_ino_to_str(ute, ino, str, sizeof(str));
	ut_setxattr_create(ute, ino, &kv);
}

static void ut_getxattr_ino(struct ut_env *ute, ino_t ino)
{
	char str[64] = "";
	struct ut_keyval kv = {
		.name = str,
		.value = &ino,
		.size = sizeof(ino),
	};

	ut_ino_to_str(ute, ino, str, sizeof(str));
	ut_getxattr_value(ute, ino, &kv);
}

static void ut_rename_with_xattr_(struct ut_env *ute, size_t cnt,
				  loff_t off_base, size_t bsz)
{
	void *buf1 = ut_randbuf(ute, bsz);
	void *buf2 = ut_randbuf(ute, bsz);
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char *name3 = NULL;
	const char *dname = ut_make_name(ute, UT_NAME, 0);
	ino_t dino = 0;
	ino_t ino1 = 0;
	ino_t ino2 = 0;

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, dname, i);
		name2 = ut_make_name(ute, dname, i + cnt);
		ut_create_file(ute, dino, name1, &ino1);
		ut_create_file(ute, dino, name2, &ino2);
		ut_write(ute, ino1, buf1, bsz, off_base + (loff_t)i);
		ut_write(ute, ino2, buf2, bsz, off_base + (loff_t)(i + 1));
		ut_setxattr_ino(ute, ino1);
		ut_setxattr_ino(ute, ino2);
		ut_release_file(ute, ino1);
		ut_release_file(ute, ino2);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ut_make_name(ute, dname, i);
		name2 = ut_make_name(ute, dname, i + cnt);
		name3 = ut_make_name(ute, dname, i + (2 * cnt));
		ut_lookup_ino(ute, dino, name1, &ino1);
		ut_lookup_ino(ute, dino, name2, &ino2);
		ut_getxattr_ino(ute, ino1);
		ut_getxattr_ino(ute, ino2);
		ut_rename_replace(ute, dino, name1, dino, name2);
		ut_rename_move(ute, dino, name2, dino, name3);
		ut_lookup_ino(ute, dino, name3, &ino1);
		ut_getxattr_ino(ute, ino1);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name3 = ut_make_name(ute, dname, i + (2 * cnt));
		ut_lookup_ino(ute, dino, name3, &ino1);
		ut_open_rdonly(ute, ino1);
		ut_read_verify(ute, ino1, buf1, bsz, off_base + (loff_t)i);
		ut_getxattr_ino(ute, ino1);
		ut_release_file(ute, ino1);
		ut_unlink_file(ute, dino, name3);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_rename_with_xattr(struct ut_env *ute)
{
	ut_rename_with_xattr_(ute, 10, 11, UT_1K + 11);
	ut_relax_mem(ute);
	ut_rename_with_xattr_(ute, 100, UT_64K - 1, UT_64K + 11);
	ut_relax_mem(ute);
	ut_rename_with_xattr_(ute, 1000, UT_1G - 11, UT_1K + 1111);
	ut_relax_mem(ute);
	ut_rename_with_xattr_(ute, 100, UT_1T - 111, UT_64K + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_rename_within_same_dir),
	UT_DEFTEST(ut_rename_toggle_between_dirs),
	UT_DEFTEST(ut_rename_replace_without_data),
	UT_DEFTEST(ut_rename_replace_with_data),
	UT_DEFTEST(ut_rename_move_multi),
	UT_DEFTEST(ut_rename_onto_link),
	UT_DEFTEST(ut_rename_exchange_simple),
	UT_DEFTEST(ut_rename_exchange_same),
	UT_DEFTEST(ut_rename_override),
	UT_DEFTEST(ut_rename_with_xattr),
};

const struct ut_testdefs ut_tdefs_rename = UT_MKTESTS(ut_local_tests);
