/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include "fftests.h"
#include <signal.h>
#include <error.h>
#include <time.h>


#define FT_METATEST(t_) (&(t_))

static const struct ft_tests *const ft_testsbl[]  = {
	FT_METATEST(ft_test_access),
	FT_METATEST(ft_test_stat),
	FT_METATEST(ft_test_statvfs),
	FT_METATEST(ft_test_utimes),
	FT_METATEST(ft_test_mkdir),
	FT_METATEST(ft_test_readdir),
	FT_METATEST(ft_test_create),
	FT_METATEST(ft_test_open),
	FT_METATEST(ft_test_link),
	FT_METATEST(ft_test_unlink),
	FT_METATEST(ft_test_chmod),
	FT_METATEST(ft_test_symlink),
	FT_METATEST(ft_test_mkfifo),
	FT_METATEST(ft_test_fsync),
	FT_METATEST(ft_test_rename),
	FT_METATEST(ft_test_xattr),
	FT_METATEST(ft_test_write),
	FT_METATEST(ft_test_lseek),
	FT_METATEST(ft_test_fiemap),
	FT_METATEST(ft_test_truncate),
	FT_METATEST(ft_test_namespace),
	FT_METATEST(ft_test_rw_basic),
	FT_METATEST(ft_test_boundaries),
	FT_METATEST(ft_test_stat_io),
	FT_METATEST(ft_test_rw_sequencial),
	FT_METATEST(ft_test_rw_sparse),
	FT_METATEST(ft_test_rw_random),
	FT_METATEST(ft_test_rw_large),
	FT_METATEST(ft_test_rw_osync),
	FT_METATEST(ft_test_unlinked_file),
	FT_METATEST(ft_test_truncate_io),
	FT_METATEST(ft_test_fallocate),
	FT_METATEST(ft_test_copy_file_range),
	FT_METATEST(ft_test_tmpfile),
	FT_METATEST(ft_test_mmap),
	FT_METATEST(ft_test_mmap_mt),
	FT_METATEST(ft_test_xstress_mt),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void statvfs_of(const struct ft_env *fte, struct statvfs *stvfs)
{
	ft_statvfs(fte->params.workdir, stvfs);
}

static void ft_list_test(struct ft_env *fte, const struct ft_tdef *tdef)
{
	fte->currtest = tdef;
	fprintf(stdout, "%-40s\n", fte->currtest->name);
	fflush(stdout);
}

static void ft_start_test(struct ft_env *fte, const struct ft_tdef *tdef)
{
	fte->currtest = tdef;
	fte->nbytes_alloc = 0;
	silofs_log_info("  %-40s =>", fte->currtest->name);
	silofs_mclock_now(&fte->ts_start);
	statvfs_of(fte, &fte->stvfs);
}

static void ft_finish_test(struct ft_env *fte)
{
	struct timespec dur;

	silofs_mclock_dur(&fte->ts_start, &dur);
	silofs_log_info("  %-40s OK (%ld.%03lds)", fte->currtest->name,
	                dur.tv_sec, dur.tv_nsec / 1000000L);
	umask(fte->umsk);
	fte->currtest = NULL;
	ft_freeall(fte);
}

static void verify_consistent_statvfs(const struct statvfs *stv_beg,
                                      const struct statvfs *stv_end)
{
	fsblkcnt_t bfree_dif;

	ft_expect_lt(stv_end->f_bfree, stv_end->f_blocks);
	ft_expect_lt(stv_end->f_bavail, stv_end->f_blocks);
	ft_expect_lt(stv_end->f_ffree, stv_end->f_files);
	ft_expect_lt(stv_end->f_favail, stv_end->f_files);

	ft_expect_eq(stv_beg->f_namemax, stv_end->f_namemax);
	ft_expect_eq(stv_beg->f_flag, stv_end->f_flag);
	ft_expect_eq(stv_beg->f_bsize, stv_end->f_bsize);
	ft_expect_eq(stv_beg->f_frsize, stv_end->f_frsize);
	ft_expect_eq(stv_beg->f_files, stv_end->f_files);
	ft_expect_eq(stv_beg->f_ffree, stv_end->f_ffree);
	ft_expect_eq(stv_beg->f_favail, stv_end->f_favail);
	ft_expect_eq(stv_beg->f_blocks, stv_end->f_blocks);
	ft_expect_ge(stv_beg->f_bfree, stv_end->f_bfree);
	ft_expect_ge(stv_beg->f_bavail, stv_end->f_bavail);

	bfree_dif = stv_beg->f_bfree - stv_end->f_bfree;
	ft_expect_lt(bfree_dif, 4096);
}

static bool ft_without_statvfs(const struct ft_env *fte)
{
	return (fte->params.testsmask & FT_F_NOSTAVFS) == FT_F_NOSTAVFS;
}

static void ft_verify_fsstat(const struct ft_env *fte)
{
	struct statvfs stvfs_end;

	if (!ft_without_statvfs(fte)) {
		sleep(1); /* TODO: race in FUSE? */
		statvfs_of(fte, &stvfs_end);
		verify_consistent_statvfs(&fte->stvfs, &stvfs_end);
	}
}

static void ft_exec_test(struct ft_env *fte, const struct ft_tdef *tdef)
{
	ft_start_test(fte, tdef);
	tdef->hook(fte);
	ft_verify_fsstat(fte);
	ft_finish_test(fte);
}

static bool ft_may_exec(const struct ft_env *fte, const struct ft_tdef *tdef)
{
	if (!tdef->flags) {
		return false;
	}
	if ((tdef->flags & FT_F_STAVFS) && ft_without_statvfs(fte)) {
		return false;
	}
	if (!(fte->params.testsmask & tdef->flags)) {
		return false;
	}
	return true;
}

static bool ignore(const struct ft_tdef *tdef)
{
	return (tdef->flags & FT_F_IGNORE) > 0;
}

static bool wanted(const struct ft_tdef *tdef, const char *wantname)
{
	return (wantname == NULL) || (strstr(tdef->name, wantname) != NULL);
}

static void ft_runtests(struct ft_env *fte)
{
	const struct ft_tdef *tdef;
	const struct ft_tests *tests = &fte->tests;
	const struct ft_params *params = &fte->params;
	const char *wantname = params->testname;

	for (size_t i = 0; i < tests->len; ++i) {
		tdef = &tests->arr[i];
		if (!ignore(tdef) && wanted(tdef, wantname)) {
			if (params->listtests) {
				ft_list_test(fte, tdef);
			} else if (ft_may_exec(fte, tdef)) {
				ft_exec_test(fte, tdef);
			}
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void copy_testdef(struct ft_tdef *dst,
                         const struct ft_tdef *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static void swap_testdef(struct ft_tdef *td1, struct ft_tdef *td2)
{
	struct ft_tdef tmp;

	copy_testdef(&tmp, td1);
	copy_testdef(td1, td2);
	copy_testdef(td2, &tmp);
}

static void *safe_malloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		error(EXIT_FAILURE, errno, "malloc failed: size=%lu", size);
		abort(); /* makes gcc '-fanalyzer' happy */
	}
	return ptr;
}

static struct ft_tdef *alloc_tests_arr(void)
{
	size_t asz;
	size_t cnt = 0;
	struct ft_tdef *arr;
	const size_t nelems = FT_ARRAY_SIZE(ft_testsbl);

	for (size_t i = 0; i < nelems; ++i) {
		cnt += ft_testsbl[i]->len;
	}
	asz = cnt * sizeof(*arr);
	arr = (struct ft_tdef *)safe_malloc(asz);
	memset(arr, 0, asz);

	return arr;
}

static void random_shuffle_tests(struct ft_env *fte)
{
	size_t pos1;
	size_t pos2;
	uint64_t rand;
	struct ft_tests *tests = &fte->tests;
	struct ft_tdef *tests_arr = silofs_unconst(tests->arr);

	for (size_t i = 0; i < tests->len; ++i) {
		rand = (uint64_t)ft_lrand(fte);
		pos1 = (rand ^ i) % tests->len;
		pos2 = (rand >> 32) % tests->len;
		swap_testdef(&tests_arr[pos1], &tests_arr[pos2]);
	}
}

static void ft_clone_tests(struct ft_env *fte)
{
	size_t len = 0;
	struct ft_tdef *arr = alloc_tests_arr();
	const struct ft_tdef *tdef = NULL;
	const size_t nelems = FT_ARRAY_SIZE(ft_testsbl);

	for (size_t i = 0; i < nelems; ++i) {
		for (size_t j = 0; j < ft_testsbl[i]->len; ++j) {
			tdef = &ft_testsbl[i]->arr[j];
			copy_testdef(&arr[len++], tdef);
		}
	}
	fte->tests.arr = arr;
	fte->tests.len = len;
	if (fte->params.testsmask & FT_F_RANDOM) {
		random_shuffle_tests(fte);
	}
}

static void ft_free_tests(struct ft_env *fte)
{
	void *arr = silofs_unconst(fte->tests.arr);

	free(arr);
	fte->tests.arr = NULL;
	fte->tests.len = 0;
}

void fte_exec(struct ft_env *fte)
{
	for (int i = 0; i < fte->params.repeatn; ++i) {
		ft_clone_tests(fte);
		ft_runtests(fte);
		ft_free_tests(fte);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void ft_exec_with_ranges_(struct ft_env *fte,
                          void (*fn)(struct ft_env *, loff_t, size_t),
                          const struct ft_range *range, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

