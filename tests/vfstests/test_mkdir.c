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
#include "vfstests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to create nested directories structure and allow rmdir(3p)
 * only to apply on last. Expects all other non-empty directories to return
 * -ENOTEMPTY upon rmdir(3p).
 */
static void test_rmdir_notempty(struct vt_env *vte,
                                char const **pathi, size_t count)
{
	for (size_t i = 0; i < count; ++i) {
		vt_rmdir_err(pathi[i], -ENOTEMPTY);
	}
	for (size_t j = count; j > 0; --j) {
		vt_rmdir_err(pathi[j - 1], -ENOTEMPTY);
	}
	silofs_unused(vte);
}

static void test_mkdir_rmdir(struct vt_env *vte)
{
	const char *pathi[32];
	const size_t nelems = VT_ARRAY_SIZE(pathi);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = path0;

	vt_mkdir(path0, 0700);
	for (size_t i = 0; i < nelems; ++i) {
		path1 = vt_new_pathf(vte, path1, "D%d", (int)i);
		vt_mkdir(path1, 0700);
		pathi[i] = path1;
	}
	for (size_t j = nelems; j > 0; --j) {
		test_rmdir_notempty(vte, pathi, j - 1);
		path1 = pathi[j - 1];
		vt_rmdir(path1);
	}
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to create a directory with a mode modified by the process'
 * umask.
 */
static void test_mkdir_umask(struct vt_env *vte)
{
	mode_t umsk;
	const mode_t ifmt = S_IFMT;
	struct stat st[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);

	umsk  = umask(0020);
	vt_mkdir(path0, 0755);
	vt_stat(path0, &st[0]);
	vt_expect_dir(st[0].st_mode);

	vt_mkdir(path1, 0755);
	vt_stat(path1, &st[1]);
	vt_expect_dir(st[1].st_mode);
	vt_expect_eq((st[1].st_mode & ~ifmt), 0755);
	vt_rmdir(path1);

	vt_mkdir(path1, 0153);
	vt_stat(path1, &st[1]);
	vt_expect_dir(st[1].st_mode);
	vt_expect_eq((st[1].st_mode & ~ifmt), 0153);
	vt_rmdir(path1);

	umask(077);
	vt_mkdir(path1, 0151);
	vt_stat(path1, &st[1]);
	vt_expect_dir(st[1].st_mode);
	vt_expect_eq((st[1].st_mode & ~ifmt), 0100);
	vt_rmdir(path1);

	umask(070);
	vt_mkdir(path1, 0345);
	vt_stat(path1, &st[1]);
	vt_expect_dir(st[1].st_mode);
	vt_expect_eq((st[1].st_mode & ~ifmt), 0305);
	vt_rmdir(path1);

	umask(0501);
	vt_mkdir(path1, 0345);
	vt_stat(path1, &st[1]);
	vt_expect_dir(st[1].st_mode);
	vt_expect_eq((st[1].st_mode & ~ifmt), 0244);

	vt_rmdir(path1);
	vt_rmdir(path0);
	vt_stat_noent(path0);
	vt_stat_noent(path1);
	umask(umsk);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to create a nested directory when parent directory is
 * writable or not.
 */
static void test_mkdir_chmod(struct vt_env *vte)
{
	struct stat st;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path1);

	vt_mkdir(path0, 0700);
	vt_stat(path0, &st);
	vt_expect_true(st.st_mode & S_IWUSR);
	vt_expect_true(st.st_mode & S_IXUSR);
	vt_mkdir(path1, st.st_mode);
	vt_stat(path1, &st);
	vt_expect_true(st.st_mode & S_IWUSR);
	vt_expect_true(st.st_mode & S_IXUSR);
	vt_chmod(path1, st.st_mode & ~((mode_t)S_IRUSR));
	vt_stat(path1, &st);
	vt_expect_false(st.st_mode & S_IRUSR);
	vt_mkdir(path2, st.st_mode);
	vt_stat(path2, &st);
	vt_expect_true(st.st_mode & S_IWUSR);
	vt_expect_true(st.st_mode & S_IXUSR);
	vt_expect_false(st.st_mode & S_IRUSR);
	vt_chmod(path2, st.st_mode & ~((mode_t)S_IXUSR));
	vt_stat(path2, &st);
	vt_expect_true(st.st_mode & S_IWUSR);
	vt_expect_false(st.st_mode & S_IXUSR);
	vt_rmdir(path2);
	vt_stat(path1, &st);
	vt_expect_true(st.st_mode & S_IWUSR);
	vt_chmod(path1, st.st_mode & ~((mode_t)S_IWUSR));
	vt_mkdir_err(path2, 0700, -EACCES);
	vt_rmdir(path1);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to return ELOOP if too many symbolic links were
 * encountered in translating of the pathname.
 */
static void test_mkdir_loop(struct vt_env *vte)
{
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_under(vte, path0);
	const char *path3 = vt_new_path_under(vte, path1);

	vt_symlink(path0, path1);
	vt_symlink(path1, path0);
	vt_mkdir_err(path2, 0755, -ELOOP);
	vt_mkdir_err(path3, 0750, -ELOOP);
	vt_unlink(path0);
	vt_unlink(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* TODO: rename test and move me from here */

/*
 * Verify creation & removal of many-many dir-entries.
 */
static void test_mkdir_many_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	int dfd = -1;
	struct stat st;
	const char *name = NULL;
	const char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0755);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);

	for (size_t i = 0; i < cnt; ++i) {
		name = vt_make_ulong_name(vte, i);
		vt_openat(dfd, name, O_CREAT | O_RDWR, 0644, &fd);
		vt_close(fd);
	}
	for (size_t j = 0; j < cnt; ++j) {
		name = vt_make_ulong_name(vte, j);
		vt_fstatat(dfd, name, &st, 0);
		vt_unlinkat(dfd, name, 0);
	}
	vt_stat(path, &st);
	vt_expect_eq(st.st_nlink, 2);
	vt_close(dfd);
	vt_rmdir(path);
}

static void test_mkdir_many(struct vt_env *vte)
{
	test_mkdir_many_(vte, 1000);
}

static void test_mkdir_many_more(struct vt_env *vte)
{
	test_mkdir_many_(vte, 30000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Create and remove deeply-nested directories structure
 */
static void test_mkdir_nested(struct vt_env *vte)
{
	char *pathi[64];
	char *path0 = vt_new_path_unique(vte);
	char *path1 = path0;

	vt_mkdir(path0, 0700);
	for (size_t i = 0; i < VT_ARRAY_SIZE(pathi); ++i) {
		path1 = vt_new_pathf(vte, path1, "D%d", (int)i);
		vt_mkdir(path1, 0700);
		pathi[i] = path1;
	}
	for (size_t i = VT_ARRAY_SIZE(pathi); i > 0; --i) {
		path1 = pathi[i - 1];
		vt_rmdir(path1);
	}
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Create recursively directory tree structure
 */
static const char *makename(struct vt_env *vte,
                            const char *prefix, size_t depth, size_t id)
{
	return vt_strfmt(vte, "%s%03x-%03x",
	                 prefix, (int)depth, (int)id);
}

static void test_walktree_recursive(struct vt_env *vte,
                                    const char *base)
{
	int fd = -1;
	loff_t pos = -1;
	loff_t off = 0;
	const char *path = NULL;
	struct dirent64 dent = { .d_ino = 0 };

	vt_open(base, O_DIRECTORY | O_RDONLY, 0, &fd);
	while (1) {
		vt_llseek(fd, off, SEEK_SET, &pos);
		vt_getdent(fd, &dent);
		off = dent.d_off;
		if (off <= 0) {
			break;
		}
		if (!strcmp(dent.d_name, ".") || !strcmp(dent.d_name, "..")) {
			continue;
		}
		if (dent.d_type == DT_DIR) {
			continue;
		}
		path = vt_new_path_nested(vte, base, dent.d_name);
		test_walktree_recursive(vte, path);
	}
	vt_close(fd);
}


static void test_mktree_recursive(struct vt_env *vte,
                                  const char *parent,
                                  size_t id, size_t nchilds,
                                  size_t depth, size_t depth_max)
{
	int fd = -1;
	const char *path = NULL;
	const char *name = NULL;

	if (depth < depth_max) {
		name = makename(vte, "d", depth, id);
		path = vt_new_path_nested(vte, parent, name);
		vt_mkdir(path, 0700);
		for (size_t i = 0; i < nchilds; ++i) {
			test_mktree_recursive(vte, path, i + 1, nchilds,
			                      depth + 1, depth_max);
		}
	} else {
		name = makename(vte, "f", depth, id);
		path = vt_new_path_nested(vte, parent, name);
		vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
		vt_close(fd);
	}
}

static void test_rmtree_recursive(struct vt_env *vte,
                                  const char *parent,
                                  size_t id, size_t nchilds,
                                  size_t depth, size_t depth_max)
{
	const char *path = NULL;
	const char *name = NULL;

	if (depth < depth_max) {
		name = makename(vte, "d", depth, id);
		path = vt_new_path_nested(vte, parent, name);
		for (size_t i = 0; i < nchilds; ++i) {
			test_rmtree_recursive(vte, path, i + 1, nchilds,
			                      depth + 1, depth_max);
		}
		vt_rmdir(path);
	} else {
		name = makename(vte, "f", depth, id);
		path = vt_new_path_nested(vte, parent, name);
		vt_unlink(path);
	}
}

static void test_mkdir_tree_(struct vt_env *vte,
                             size_t nchilds, size_t depth_max)
{
	const char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0700);
	for (size_t i = 0; i < nchilds; ++i) {
		test_mktree_recursive(vte, path, i + 1,
		                      nchilds, 1, depth_max);
	}
	test_walktree_recursive(vte, path);
	for (size_t j = 0; j < nchilds; ++j) {
		test_rmtree_recursive(vte, path, j + 1,
		                      nchilds, 1, depth_max);
	}
	vt_rmdir(path);
}

static void test_mkdir_tree_wide(struct vt_env *vte)
{
	test_mkdir_tree_(vte, 32, 2);
}

static void test_mkdir_tree_deep(struct vt_env *vte)
{
	test_mkdir_tree_(vte, 2, 8);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful rmdir(3p) to update the last data modification and last
 * file status change time-stamps of the parent directory
 */
static void test_rmdir_mctime(struct vt_env *vte)
{
	struct stat st[2];
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_under(vte, path1);

	vt_mkdir(path1, 0700);
	vt_mkdir(path2, 0700);
	vt_stat(path1, &st[0]);
	vt_expect_dir(st[0].st_mode);
	vt_suspends(vte, 2);
	vt_rmdir(path2);
	vt_stat_err(path2, -ENOENT);
	vt_stat(path1, &st[1]);
	vt_expect_mtime_gt(&st[0], &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);
	vt_rmdir(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful rmdir(3p) on empty directory while still referenced by
 * open file-descriptor.
 */
static void test_rmdir_openat(struct vt_env *vte)
{
	int dfd1 = -1;
	int dfd2 = -1;
	struct stat st;
	const char *name = vt_new_name_unique(vte);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_nested(vte, path1, name);

	vt_mkdir(path1, 0700);
	vt_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	vt_mkdirat(dfd1, name, 0700);
	vt_openat(dfd1, name, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	vt_fstat(dfd1, &st);
	vt_expect_dir(st.st_mode);
	vt_fstat(dfd2, &st);
	vt_expect_dir(st.st_mode);
	vt_expect_eq(st.st_nlink, 2);
	vt_rmdir(path2);
	vt_fstat(dfd2, &st);
	vt_expect_dir(st.st_mode);
	vt_expect_le(st.st_nlink, 1); /* TODO: why not eq 1 ? */
	vt_rmdir(path1);
	vt_close(dfd1);
	vt_close(dfd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to preserve S_ISGID of parent directory
 */
static void test_mkdir_setgid(struct vt_env *vte)
{
	struct stat st;
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_under(vte, path1);
	const char *path3 = vt_new_path_under(vte, path2);

	vt_mkdir(path1, 0700);
	vt_stat(path1, &st);
	vt_expect_eq(st.st_mode & S_ISGID, 0);
	vt_mkdir(path2, 0700);
	vt_stat(path2, &st);
	vt_expect_eq(st.st_mode & S_ISGID, 0);
	vt_chmod(path2, st.st_mode | S_ISGID);
	vt_stat(path2, &st);
	vt_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	vt_mkdir(path3, 0700);
	vt_stat(path3, &st);
	vt_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	vt_rmdir(path3);
	vt_rmdir(path2);
	vt_rmdir(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdirat(2) to work with nested dirs/files
 */
static void test_mkdirat_nested(struct vt_env *vte)
{
	int dfd = -1;
	const char *nested1 = "nested1";
	const char *nested2 = "nested1/nested2";
	const char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_mkdirat(dfd, nested1, 0755);
	vt_mkdirat(dfd, nested2, 0755);
	vt_unlinkat(dfd, nested2, AT_REMOVEDIR);
	vt_mknodat(dfd, nested2, 0755, 0);
	vt_unlinkat(dfd, nested2, 0);
	vt_unlinkat(dfd, nested1, AT_REMOVEDIR);
	vt_close(dfd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_mkdir_rmdir),
	VT_DEFTEST(test_mkdir_umask),
	VT_DEFTEST(test_mkdir_chmod),
	VT_DEFTEST(test_mkdir_loop),
	VT_DEFTEST(test_mkdir_nested),
	VT_DEFTEST(test_mkdir_many),
	VT_DEFTEST(test_mkdir_many_more),
	VT_DEFTEST(test_mkdir_tree_wide),
	VT_DEFTEST(test_mkdir_tree_deep),
	VT_DEFTEST(test_rmdir_mctime),
	VT_DEFTEST(test_rmdir_openat),
	VT_DEFTEST(test_mkdir_setgid),
	VT_DEFTEST(test_mkdirat_nested),
};

const struct vt_tests vt_test_mkdir = VT_DEFTESTS(vt_local_tests);
