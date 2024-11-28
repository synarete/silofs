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
#include <error.h>
#include <ctype.h>
#include <limits.h>

#define UT_DEFTGRP(t_)                  \
	{                               \
		.tests = &(t_),         \
		.name = SILOFS_STR(t_), \
	}

static struct ut_tgroup const g_ut_tgroups[] = {
	/* infra */
	UT_DEFTGRP(ut_tdefs_strings),
	UT_DEFTGRP(ut_tdefs_avl),
	UT_DEFTGRP(ut_tdefs_base64),
	UT_DEFTGRP(ut_tdefs_qalloc),
	/* namespace */
	UT_DEFTGRP(ut_tdefs_super),
	UT_DEFTGRP(ut_tdefs_statfs),
	UT_DEFTGRP(ut_tdefs_ioctl),
	UT_DEFTGRP(ut_tdefs_dir),
	UT_DEFTGRP(ut_tdefs_dir_iter),
	UT_DEFTGRP(ut_tdefs_dir_list),
	UT_DEFTGRP(ut_tdefs_namei),
	UT_DEFTGRP(ut_tdefs_rename),
	/* symlink & xattr */
	UT_DEFTGRP(ut_tdefs_symlink),
	UT_DEFTGRP(ut_tdefs_xattr),
	/* file */
	UT_DEFTGRP(ut_tdefs_file_basic),
	UT_DEFTGRP(ut_tdefs_file_stat),
	UT_DEFTGRP(ut_tdefs_file_rwiter),
	UT_DEFTGRP(ut_tdefs_file_ranges),
	UT_DEFTGRP(ut_tdefs_file_records),
	UT_DEFTGRP(ut_tdefs_file_random),
	UT_DEFTGRP(ut_tdefs_file_edges),
	UT_DEFTGRP(ut_tdefs_file_truncate),
	UT_DEFTGRP(ut_tdefs_file_fallocate),
	UT_DEFTGRP(ut_tdefs_file_lseek),
	UT_DEFTGRP(ut_tdefs_file_fiemap),
	UT_DEFTGRP(ut_tdefs_file_copy_range),
	UT_DEFTGRP(ut_tdefs_file_mthreads),
	/* fs (pre snapshot)*/
	UT_DEFTGRP(ut_tdefs_inspect),
	UT_DEFTGRP(ut_tdefs_reload),
	UT_DEFTGRP(ut_tdefs_fillfs),
	UT_DEFTGRP(ut_tdefs_archive),
	/* snapshot */
	UT_DEFTGRP(ut_tdefs_snap_basic),
	UT_DEFTGRP(ut_tdefs_snap_io),
	/* re-run (post snapshot) */
	UT_DEFTGRP(ut_tdefs_archive),
	UT_DEFTGRP(ut_tdefs_file_stat),
	UT_DEFTGRP(ut_tdefs_dir_iter),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *ut_malloc_safe(size_t size)
{
	void *ptr = NULL;
	int err;

	err = posix_memalign(&ptr, 64, size);
	if (err || (ptr == NULL)) {
		error(EXIT_FAILURE, err, "malloc failed: size=%lu", size);
		abort(); /* makes gcc '-fanalyzer' happy */
	}
	return ptr;
}

static void ut_free_safe(void *ptr, size_t size)
{
	if (ptr != NULL) {
		memset(ptr, 0xFF, ut_min(size, 64));
		free(ptr);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ute_init(struct ut_env *ute, struct ut_args *args)
{
	memset(ute, 0, sizeof(*ute));
	ute->args = args;
	ute->malloc_list = NULL;
	ute->nbytes_alloc = 0;
	ute->unique_opid = 1;
	ute->ftype = SILOFS_FILE_TYPE1;
	ute->run_level = ut_globals.run_level;
	silofs_prandgen_init(&ute->prng);
	silofs_mutex_init(&ute->mutex);
}

static void ute_cleanup(struct ut_env *ute)
{
	if (ute->fsenv != NULL) {
		silofs_del_fsenv(ute->fsenv);
		ute->fsenv = NULL;
	}
}

static void ute_fini(struct ut_env *ute)
{
	ut_freeall(ute);
	ute_cleanup(ute);
	silofs_mutex_fini(&ute->mutex);
	memset(ute, 0xFF, sizeof(*ute));
}

static void ute_lock(struct ut_env *ute)
{
	silofs_mutex_lock(&ute->mutex);
}

static void ute_unlock(struct ut_env *ute)
{
	silofs_mutex_unlock(&ute->mutex);
}

static void ute_setup_random_passwd(struct ut_env *ute)
{
	struct silofs_fs_args *fs_args = &ute->args->fs_args;
	struct silofs_password *pp = &ute->passwd;

	pp->passlen = sizeof(pp->pass) - 1;
	silofs_prandgen_ascii(&ute->prng, (char *)pp->pass, pp->passlen);
	fs_args->bref.passwd = (const char *)(pp->pass);
}

static void ute_setup(struct ut_env *ute)
{
	int err;

	err = silofs_new_fsenv(&ute->args->fs_args, &ute->fsenv);
	silofs_assert_ok(err);
}

static struct ut_env *ute_new(struct ut_args *args)
{
	struct ut_env *ute;

	ute = (struct ut_env *)ut_malloc_safe(sizeof(*ute));
	ute_init(ute, args);
	return ute;
}

static void ute_del(struct ut_env *ute)
{
	ute_fini(ute);
	ut_free_safe(ute, sizeof(*ute));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_track_test(struct ut_env *ute, const struct ut_testdef *td,
			  bool pre_execute)
{
	struct timespec dur;

	if (pre_execute) {
		printf("  %-40s", td->name);
		silofs_mclock_now(&ute->ts_start);
	} else {
		silofs_mclock_dur(&ute->ts_start, &dur);
		printf("OK (%ld.%03lds)\n", dur.tv_sec,
		       dur.tv_nsec / 1000000L);
	}
	fflush(stdout);
}

static void ut_check_valid_statvfs(const struct statvfs *stv)
{
	ut_expect_le(stv->f_bfree, stv->f_blocks);
	ut_expect_le(stv->f_bavail, stv->f_blocks);
	ut_expect_le(stv->f_ffree, stv->f_files);
	ut_expect_le(stv->f_favail, stv->f_files);
}

static void
ut_check_statvfs(const struct statvfs *stv1, const struct statvfs *stv2)
{
	ut_check_valid_statvfs(stv1);
	ut_check_valid_statvfs(stv2);
	ut_expect_statvfs(stv1, stv2);
}

static void ut_check_valid_spacecounts(const struct silofs_spacegauges *spc)
{
	ut_expect_ge(spc->nsuper, 1);
	ut_expect_ge(spc->nspnode, 4);
	ut_expect_ge(spc->nspleaf, 4);
	ut_expect_ge(spc->ninode, 1);
	ut_expect_ge(spc->nxanode, 0);
	ut_expect_ge(spc->nxanode, 0);
	ut_expect_ge(spc->ndtnode, 0);
	ut_expect_ge(spc->nsymval, 0);
	ut_expect_ge(spc->nftnode, 0);
	ut_expect_ge(spc->ndata1k, 0);
	ut_expect_ge(spc->ndata4k, 0);
	ut_expect_ge(spc->ndatabk, 0);
}

static void ut_expect_spacestats(const struct silofs_spacestats *spst1,
				 const struct silofs_spacestats *spst2)
{
	ut_expect_le(spst1->lsegs.nsuper, spst2->lsegs.nsuper);
	ut_expect_le(spst1->lsegs.nspnode, spst2->lsegs.nspnode);
	ut_expect_le(spst1->lsegs.nspleaf, spst2->lsegs.nspleaf);
	ut_expect_le(spst1->lsegs.ninode, spst2->lsegs.ninode);
	ut_expect_le(spst1->lsegs.nxanode, spst2->lsegs.nxanode);
	ut_expect_le(spst1->lsegs.ndtnode, spst2->lsegs.ndtnode);
	ut_expect_le(spst1->lsegs.nsymval, spst2->lsegs.nsymval);
	ut_expect_le(spst1->lsegs.nftnode, spst2->lsegs.nftnode);
	ut_expect_le(spst1->lsegs.ndata1k, spst2->lsegs.ndata1k);
	ut_expect_le(spst1->lsegs.ndata4k, spst2->lsegs.ndata4k);
	ut_expect_le(spst1->lsegs.ndatabk, spst2->lsegs.ndatabk);

	ut_expect_le(spst1->bks.nsuper, spst2->bks.nsuper);
	ut_expect_le(spst1->bks.nspnode, spst2->bks.nspnode);
	ut_expect_le(spst1->bks.nspleaf, spst2->bks.nspleaf);
	ut_expect_le(spst1->bks.ninode, spst2->bks.ninode);
	ut_expect_le(spst1->bks.nxanode, spst2->bks.nxanode);
	ut_expect_le(spst1->bks.ndtnode, spst2->bks.ndtnode);
	ut_expect_le(spst1->bks.nsymval, spst2->bks.nsymval);
	ut_expect_le(spst1->bks.nftnode, spst2->bks.nftnode);
	ut_expect_le(spst1->bks.ndata1k, spst2->bks.ndata1k);
	ut_expect_le(spst1->bks.ndata4k, spst2->bks.ndata4k);
	ut_expect_le(spst1->bks.ndatabk, spst2->bks.ndatabk);

	ut_expect_le(spst1->objs.nsuper, spst2->objs.nsuper);
	ut_expect_le(spst1->objs.nspnode, spst2->objs.nspnode);
	ut_expect_le(spst1->objs.nspleaf, spst2->objs.nspleaf);
	ut_expect_eq(spst1->objs.ninode, spst2->objs.ninode);
	ut_expect_eq(spst1->objs.nxanode, spst2->objs.nxanode);
	ut_expect_eq(spst1->objs.ndtnode, spst2->objs.ndtnode);
	ut_expect_eq(spst1->objs.nsymval, spst2->objs.nsymval);
	ut_expect_eq(spst1->objs.nftnode, spst2->objs.nftnode);
	ut_expect_eq(spst1->objs.ndata1k, spst2->objs.ndata1k);
	ut_expect_eq(spst1->objs.ndata4k, spst2->objs.ndata4k);
	ut_expect_eq(spst1->objs.ndatabk, spst2->objs.ndatabk);
}

static void ut_check_spacestats(const struct silofs_spacestats *spst1,
				const struct silofs_spacestats *spst2)
{
	ut_expect_le(spst1->btime, spst2->btime);
	ut_expect_le(spst1->ctime, spst2->ctime);
	ut_expect_eq(spst1->capacity, spst2->capacity);
	ut_expect_eq(spst1->vspacesize, spst2->vspacesize);
	ut_check_valid_spacecounts(&spst1->lsegs);
	ut_check_valid_spacecounts(&spst1->bks);
	ut_check_valid_spacecounts(&spst1->objs);
	ut_check_valid_spacecounts(&spst2->lsegs);
	ut_check_valid_spacecounts(&spst2->bks);
	ut_check_valid_spacecounts(&spst2->objs);
	ut_expect_spacestats(spst1, spst2);
}

static size_t ualloc_nbytes_now(const struct ut_env *ute)
{
	struct silofs_cachestats st;

	silofs_stat_fs(ute->fsenv, &st);
	return st.nalloc_bytes;
}

static void ut_probe_stats(struct ut_env *ute, bool pre_execute)
{
	size_t ualloc_now;
	size_t ualloc_dif;

	if (pre_execute) {
		ut_statfs_rootd(ute, &ute->stvfs[0]);
		ut_statsp_rootd(ute, &ute->spst[0]);
		ut_drop_caches_fully(ute);
		ute->ualloc_start = ualloc_nbytes_now(ute);
	} else {
		ut_statfs_rootd(ute, &ute->stvfs[1]);
		ut_statsp_rootd(ute, &ute->spst[1]);
		ut_check_statvfs(&ute->stvfs[0], &ute->stvfs[1]);
		ut_check_spacestats(&ute->spst[0], &ute->spst[1]);

		ut_drop_caches_fully(ute);
		ualloc_now = ualloc_nbytes_now(ute);
		ut_expect_ge(ualloc_now, ute->ualloc_start);
		ualloc_dif = ualloc_now - ute->ualloc_start;
		ut_expect_le(ualloc_dif, 2 * UT_BK_SIZE);
	}
}

static void ut_do_run_test(struct ut_env *ute, const struct ut_testdef *td)
{
	ut_probe_stats(ute, true);
	td->hook(ute);
	ut_probe_stats(ute, false);
}

static void ut_run_test1(struct ut_env *ute, const struct ut_testdef *td)
{
	ut_track_test(ute, td, true);
	ut_do_run_test(ute, td);
	ut_track_test(ute, td, false);
}

static void ut_run_test2(struct ut_env *ute, const struct ut_testdef *td)
{
	ut_track_test(ute, td, true);
	ute->ftype = SILOFS_FILE_TYPE1;
	ut_do_run_test(ute, td);
	ute->ftype = SILOFS_FILE_TYPE2;
	ut_do_run_test(ute, td);
	ute->ftype = SILOFS_FILE_TYPE1;
	ut_track_test(ute, td, false);
}

static void ut_run_test(struct ut_env *ute, const struct ut_testdef *td)
{
	const int run_level = ute->run_level;
	const bool quick = (td->flags & UT_F_QUICK) > 0;
	const bool with_ftype2 = (td->flags & UT_F_FTYPE2) > 0;

	if ((run_level >= 2) || (quick && run_level)) {
		if (with_ftype2) {
			ut_run_test2(ute, td);
		} else {
			ut_run_test1(ute, td);
		}
	}
}

static void ut_post_test(struct ut_env *ute)
{
	struct silofs_task task;
	int err;

	ut_setup_task(ute, &task);
	err = silofs_fs_maintain(&task, SILOFS_F_NOW);
	ut_release_task(ute, &task);
	silofs_assert_ok(err);
}

static void ut_run_tests_group(struct ut_env *ute, const struct ut_tgroup *tg)
{
	const struct ut_testdef *td = NULL;

	for (size_t i = 0; i < tg->tests->len; ++i) {
		td = &tg->tests->arr[i];
		ut_run_test(ute, td);
		ut_freeall(ute);
		ut_post_test(ute);
	}
}

static void ut_exec_tests(struct ut_env *ute)
{
	for (size_t i = 0; i < UT_ARRAY_SIZE(g_ut_tgroups); ++i) {
		ut_run_tests_group(ute, &g_ut_tgroups[i]);
	}
}

static void ut_prep_tests(struct ut_env *ute)
{
	ut_format_repo(ute);
	ut_format_fs(ute);
	ut_close_fs(ute);
	ut_close_repo(ute);
	ut_open_repo(ute);
	ut_open_fs(ute);
}

static void ut_done_tests(struct ut_env *ute)
{
	ut_close_fs(ute);
	ut_close_repo(ute);
}

static void ut_execute_tests_cycle(struct ut_args *args)
{
	struct ut_env *ute;

	ute = ute_new(args);
	ute_setup_random_passwd(ute);
	ute_setup(ute);
	ut_prep_tests(ute);
	ut_exec_tests(ute);
	ut_done_tests(ute);
	ut_freeall(ute);
	ute_cleanup(ute);
	ute_del(ute);
}

static void ut_print_tests_info(const struct ut_args *args, int start)
{
	char buf[128] = "";

	silofs_make_version_banner(buf, sizeof(buf) - 1, start);
	printf("  %s %s \n", args->program, buf);
}

static struct silofs_uids *ut_new_uids(void)
{
	struct silofs_uids *uids;

	uids = ut_malloc_safe(2 * sizeof(*uids));
	uids[0].host_uid = 0;
	uids[0].fs_uid = 100000;
	uids[1].host_uid = getuid();
	uids[1].fs_uid = 100001;
	return uids;
}

static void ut_del_uids(struct silofs_uids *uids)
{
	ut_free_safe(uids, 2 * sizeof(*uids));
}

static struct silofs_gids *ut_new_gids(void)
{
	struct silofs_gids *gids;

	gids = ut_malloc_safe(2 * sizeof(*gids));
	gids[0].host_gid = 0;
	gids[0].fs_gid = 200000;
	gids[1].host_gid = getgid();
	gids[1].fs_gid = 200001;
	return gids;
}

static void ut_del_gids(struct silofs_gids *gids)
{
	ut_free_safe(gids, 2 * sizeof(*gids));
}

static void ut_init_args(struct ut_args *args)
{
	memset(args, 0, sizeof(*args));
	silofs_bootref_init(&args->fs_args.bref);
	args->fs_args.bref.repodir = ut_globals.test_dir_repo;
	args->fs_args.bref.name = "unitests";
	args->fs_args.mntdir = "/";
	args->fs_args.ids.users.uids = ut_new_uids();
	args->fs_args.ids.users.nuids = 2;
	args->fs_args.ids.groups.gids = ut_new_gids();
	args->fs_args.ids.groups.ngids = 2;
	args->fs_args.uid = getuid();
	args->fs_args.gid = getgid();
	args->fs_args.pid = getpid();
	args->fs_args.umask = 0002;
	args->fs_args.capacity = SILOFS_CAPACITY_SIZE_MIN;
	args->fs_args.memwant = UT_1G;
	args->fs_args.cflags.pedantic = ut_globals.pedantic;
	args->fs_args.cflags.asyncwr = ut_globals.asyncwr;
	args->fs_args.cflags.stdalloc = ut_globals.stdalloc;
	args->program = ut_globals.program;
}

static void ut_fini_args(struct ut_args *args)
{
	ut_del_uids(args->fs_args.ids.users.uids);
	ut_del_gids(args->fs_args.ids.groups.gids);
	memset(args, 0, sizeof(*args));
}

void ut_execute_tests(void)
{
	struct ut_args args;

	ut_init_args(&args);
	ut_print_tests_info(&args, 1);
	ut_execute_tests_cycle(&args);
	ut_print_tests_info(&args, 0);
	ut_fini_args(&args);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct ut_malloc_chunk *
ut_do_malloc_chunk(struct ut_env *ute, size_t nbytes)
{
	struct ut_malloc_chunk *mchunk;

	mchunk = (struct ut_malloc_chunk *)ut_malloc_safe(sizeof(*mchunk));
	mchunk->data = ut_malloc_safe(nbytes);
	mchunk->size = nbytes;
	mchunk->next = ute->malloc_list;
	ute->malloc_list = mchunk;
	ute->nbytes_alloc += nbytes + sizeof(*mchunk);
	return mchunk;
}

static struct ut_malloc_chunk *
ut_malloc_chunk(struct ut_env *ute, size_t nbytes)
{
	struct ut_malloc_chunk *mchunk;

	ute_lock(ute);
	mchunk = ut_do_malloc_chunk(ute, nbytes);
	ute_unlock(ute);
	return mchunk;
}

static void ut_do_free(struct ut_env *ute, struct ut_malloc_chunk *mchunk)
{
	silofs_assert_ge(ute->nbytes_alloc, mchunk->size + sizeof(*mchunk));

	ut_free_safe(mchunk->data, mchunk->size);
	ute->nbytes_alloc -= mchunk->size;
	ut_free_safe(mchunk, sizeof(*mchunk));
	ute->nbytes_alloc -= sizeof(*mchunk);
}

void *ut_malloc(struct ut_env *ute, size_t nbytes)
{
	struct ut_malloc_chunk *mchunk;

	mchunk = ut_malloc_chunk(ute, nbytes);
	return mchunk->data;
}

void *ut_zalloc(struct ut_env *ute, size_t nbytes)
{
	void *ptr;

	ptr = ut_malloc(ute, nbytes);
	memset(ptr, 0, nbytes);

	return ptr;
}

char *ut_strdup(struct ut_env *ute, const char *str)
{
	return ut_strndup(ute, str, strlen(str));
}

char *ut_strndup(struct ut_env *ute, const char *str, size_t len)
{
	char *str2;

	str2 = ut_zalloc(ute, len + 1);
	memcpy(str2, str, len);

	return str2;
}

static void ut_do_freeall(struct ut_env *ute)
{
	struct ut_malloc_chunk *mnext = NULL;
	struct ut_malloc_chunk *mchunk = NULL;

	mchunk = ute->malloc_list;
	while (mchunk != NULL) {
		mnext = mchunk->next;
		ut_do_free(ute, mchunk);
		mchunk = mnext;
	}
	silofs_assert_eq(ute->nbytes_alloc, 0);

	ute->nbytes_alloc = 0;
	ute->malloc_list = NULL;
}

void ut_freeall(struct ut_env *ute)
{
	ute_lock(ute);
	ut_do_freeall(ute);
	ute_unlock(ute);
}

void ut_relax_mem(struct ut_env *ute)
{
	ut_freeall(ute);
}

const char *ut_make_name(struct ut_env *ute, const char *pre, size_t idx)
{
	const char *name;

	if (pre && strlen(pre)) {
		name = ut_strfmt(ute, "%s%lu", pre, idx + 1);
	} else {
		name = ut_strfmt(ute, "%lu", idx + 1);
	}
	return name;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void *ut_zerobuf(struct ut_env *ute, size_t bsz)
{
	return ut_zalloc(ute, bsz);
}

void ut_randfill(struct ut_env *ute, void *buf, size_t bsz)
{
	ute_lock(ute);
	silofs_prandgen_take(&ute->prng, buf, bsz);
	ute_unlock(ute);
}

void *ut_randbuf(struct ut_env *ute, size_t bsz)
{
	uint8_t *buf = NULL;

	if (bsz > 0) {
		buf = ut_malloc(ute, bsz);
		ut_randfill(ute, buf, bsz);
	}
	return buf;
}

static void swap(long *arr, size_t p1, size_t p2)
{
	long tmp = arr[p1];

	arr[p1] = arr[p2];
	arr[p2] = tmp;
}

long *ut_randseq(struct ut_env *ute, size_t len, long base)
{
	long *arr;
	size_t *pos;

	arr = ut_zerobuf(ute, len * sizeof(*arr));
	pos = ut_randbuf(ute, len * sizeof(*pos));
	if ((arr != NULL) && (pos != NULL)) { /* make gcc-analyzer happy */
		for (size_t i = 0; i < len; ++i) {
			arr[i] = base++;
		}
		for (size_t i = 0; i < len; ++i) {
			swap(arr, i, pos[i] % len);
		}
	}
	return arr;
}

static void ut_force_alnum(char *str, size_t len)
{
	const char *alt = "_0123456789abcdefghijklmnopqrstuvwxyz";
	const size_t alt_len = strlen(alt);
	size_t idx;
	int ch;

	for (size_t i = 0; i < len; ++i) {
		ch = (int)(str[i]);
		if (!isalnum(ch)) {
			idx = (size_t)abs(ch);
			str[i] = alt[idx % alt_len];
		}
	}
}

char *ut_randstr(struct ut_env *ute, size_t len)
{
	char *str;

	str = ut_randbuf(ute, len + 1);
	if (str != NULL) { /* make gcc-analyzer happy */
		ut_force_alnum(str, len);
		str[len] = '\0';
	}
	return str;
}

char *ut_strfmt(struct ut_env *ute, const char *fmt, ...)
{
	char tmp[1024] = "";
	va_list ap;
	int nb = 0;

	va_start(ap, fmt);
	nb = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	ut_expect_lt(nb, sizeof(tmp));

	return ut_strdup(ute, tmp);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct ut_dvec *ut_new_dvec(struct ut_env *ute, loff_t off, size_t len)
{
	size_t size;
	struct ut_dvec *dvec;

	size = (sizeof(*dvec) + len - sizeof(dvec->dat)) | 0x7;
	dvec = ut_zerobuf(ute, size);
	dvec->off = off;
	dvec->len = len;
	ut_randfill(ute, dvec->dat, len);
	return dvec;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void swap_long(long *a, long *b)
{
	const long c = *a;

	*a = *b;
	*b = c;
}

/*
 * Pseudo-random shuffle
 * See: http://benpfaff.org/writings/clc/shuffle.html
 */
static uint64_t ute_next_prandom(struct ut_env *ute)
{
	uint64_t rnd;

	ute_lock(ute);
	silofs_prandgen_take_u64(&ute->prng, &rnd);
	ute_unlock(ute);
	return rnd;
}

void ut_prandom_shuffle(struct ut_env *ute, long *arr, size_t len)
{
	size_t j;
	uint64_t rnd = 0;

	if (len > 1) {
		for (size_t i = 0; i < len - 1; i++) {
			if ((i % 17) == 0) {
				rnd = ute_next_prandom(ute);
			} else {
				rnd = rnd >> 1;
			}
			j = i + (rnd / (ULONG_MAX / (len - i) + 1));
			swap_long(arr + i, arr + j);
		}
	}
}
static void create_seq(long *arr, size_t len, long base)
{
	for (size_t i = 0; i < len; ++i) {
		arr[i] = base++;
	}
}

/* Generates sequence of integers [base..base+n) and then random shuffle */
void ut_prandom_seq(struct ut_env *ute, long *arr, size_t len, long base)
{
	create_seq(arr, len, base);
	ut_prandom_shuffle(ute, arr, len);
}

void ut_reverse_inplace(long *arr, size_t len)
{
	for (size_t i = 0; i < len / 2; i++) {
		swap_long(arr + i, arr + (len - i - 1));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ut_equal_strings(const char *s1, const char *s2)
{
	return (strcmp(s1, s2) == 0);
}

bool ut_dot_or_dotdot(const char *s)
{
	return ut_equal_strings(s, ".") || ut_equal_strings(s, "..");
}

bool ut_not_dot_or_dotdot(const char *s)
{
	return !ut_dot_or_dotdot(s);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void ut_exec_with_ranges_(struct ut_env *ute,
			  void (*fn)(struct ut_env *, loff_t, size_t),
			  const struct ut_range *range, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}
