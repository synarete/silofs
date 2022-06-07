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
#include <error.h>

#define UT_DEFTGRP(t_) \
	{ .tests = &(t_), .name = SILOFS_STR(t_) }

static struct ut_tgroup const g_ut_tgroups[] = {
	UT_DEFTGRP(ut_tdefs_strings),
	UT_DEFTGRP(ut_tdefs_avl),
	UT_DEFTGRP(ut_tdefs_base64),
	UT_DEFTGRP(ut_tdefs_qalloc),
	UT_DEFTGRP(ut_tdefs_super),
	UT_DEFTGRP(ut_tdefs_ioctl),
	UT_DEFTGRP(ut_tdefs_dir),
	UT_DEFTGRP(ut_tdefs_dir_iter),
	UT_DEFTGRP(ut_tdefs_dir_list),
	UT_DEFTGRP(ut_tdefs_namei),
	UT_DEFTGRP(ut_tdefs_rename),
	UT_DEFTGRP(ut_tdefs_symlink),
	UT_DEFTGRP(ut_tdefs_xattr),
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
	UT_DEFTGRP(ut_tdefs_reload),
	UT_DEFTGRP(ut_tdefs_fillfs),
	UT_DEFTGRP(ut_tdefs_snap_basic),
	UT_DEFTGRP(ut_tdefs_snap_io),
	UT_DEFTGRP(ut_tdefs_pack),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *ut_malloc_safe(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		error(EXIT_FAILURE, errno, "malloc failed: size=%lu", size);
		abort(); /* makes gcc '-fanalyzer' happy */
	}
	return ptr;
}

static void ut_free_safe(void *ptr, size_t size)
{
	if (ptr != NULL) {
		memset(ptr, 0xFF, size);
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
	silofs_prandgen_init(&ute->prng);
}

static void ute_cleanup(struct ut_env *ute)
{
	if (ute->fs_env != NULL) {
		silofs_fse_term(ute->fs_env);
		silofs_fse_del(ute->fs_env);
		ute->fs_env = NULL;
	}
}

static void ute_fini(struct ut_env *ute)
{
	ut_freeall(ute);
	ute_cleanup(ute);
	memset(ute, 0xFF, sizeof(*ute));
}

static void ute_setup_random_passwd(struct ut_env *ute)
{
	struct silofs_fs_args *fs_args = &ute->args->fs_args;
	struct silofs_passphrase *pp = &ute->passph;

	pp->passlen = sizeof(pp->pass) - 1;
	silofs_prandgen_ascii(&ute->prng, (char *)pp->pass, pp->passlen);
	fs_args->passwd = (const char *)(pp->pass);
}

static void ute_setup(struct ut_env *ute)
{
	int err;

	err = silofs_fse_new(&ute->args->fs_args, &ute->fs_env);
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

static void ut_track_test(struct ut_env *ute,
                          const struct ut_testdef *td, bool pre_execute)
{
	struct timespec dur;

	if (pre_execute) {
		printf("  %-40s", td->name);
		silofs_mclock_now(&ute->ts_start);
	} else {
		silofs_mclock_dur(&ute->ts_start, &dur);
		printf("OK (%ld.%03lds)\n",
		       dur.tv_sec, dur.tv_nsec / 1000000L);
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

static void ut_check_statvfs(const struct statvfs *stv1,
                             const struct statvfs *stv2)
{
	ut_check_valid_statvfs(stv1);
	ut_check_valid_statvfs(stv2);
	ut_expect_statvfs(stv1, stv2);
}

static size_t ualloc_nbytes_now(const struct ut_env *ute)
{
	struct silofs_fs_stats st;

	silofs_fse_stats(ute->fs_env, &st);
	return st.nalloc_bytes;
}

static void ut_probe_stats(struct ut_env *ute, bool pre_execute)
{
	struct statvfs stvfs_now;
	const size_t bk_sz = UT_BK_SIZE;
	size_t ualloc_now;

	if (pre_execute) {
		ut_statfs_rootd(ute, &ute->stvfs_start);
		ut_drop_caches_fully(ute);
		ute->ualloc_start = ualloc_nbytes_now(ute);
	} else {
		ut_statfs_rootd(ute, &stvfs_now);
		ut_check_statvfs(&ute->stvfs_start, &stvfs_now);
		ut_drop_caches_fully(ute);
		ualloc_now = ualloc_nbytes_now(ute);
		/* XXX ut_expect_eq(ute->ualloc_start, ualloc_now); */
		ut_expect_ge(ute->ualloc_start + (2 * bk_sz), ualloc_now);
	}
}

static void ut_run_test(struct ut_env *ute, const struct ut_testdef *td)
{
	td->hook(ute);
}

static void ut_post_test(struct ut_env *ute)
{
	const struct silofs_fs_ctx *fs_ctx = ut_fs_ctx_of(ute);
	int err;

	err = silofs_fs_timedout(fs_ctx, SILOFS_F_NOW);
	silofs_assert_ok(err);
}

static void ut_run_tests_group(struct ut_env *ute, const struct ut_tgroup *tg)
{
	const struct ut_testdef *td = NULL;

	for (size_t i = 0; i < tg->tests->len; ++i) {
		td = &tg->tests->arr[i];
		ut_track_test(ute, td, true);
		ut_probe_stats(ute, true);
		ut_run_test(ute, td);
		ut_probe_stats(ute, false);
		ut_track_test(ute, td, false);
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

static void ut_format_filesystem(struct ut_env *ute)
{
	struct silofs_bootsec bsec = { .flags = 0 };
	int err;

	err = silofs_fse_format_fs(ute->fs_env, &bsec);
	silofs_assert_ok(err);

	ut_save_bsec_ok(ute, &bsec);
}

static void ut_prep_tests(struct ut_env *ute)
{
	struct silofs_bootsec bsec = { .flags = 0 };
	struct silofs_fs_env *fse = ute->fs_env;
	int err;

	err = silofs_fse_format_repos(fse);
	silofs_assert_ok(err);

	err = silofs_fse_term(fse);
	silofs_assert_ok(err);

	ut_format_filesystem(ute);

	err = silofs_fse_term(fse);
	silofs_assert_ok(err);

	ut_load_bsec_ok(ute, &bsec);

	err = silofs_fse_reopen(fse, &bsec);
	silofs_assert_ok(err);

	err = silofs_fse_reload(fse, &bsec);
	silofs_assert_ok(err);
}

static void ut_done_tests(struct ut_env *ute)
{
	int err;

	err = silofs_fse_term(ute->fs_env);
	silofs_assert_ok(err);
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

static void ut_print_tests_start(const struct ut_args *args)
{
	printf("  %s %s kcopy=%d concp=%d\n", args->program, args->version,
	       (int)args->fs_args.kcopy, (int)args->fs_args.concp);
}

void ut_execute_tests(void)
{
	struct ut_args args = {
		.fs_args = {
			.uid = getuid(),
			.gid = getgid(),
			.pid = getpid(),
			.umask = 0002,
			.main_repodir = ut_globals.test_dir_main,
			.cold_repodir = ut_globals.test_dir_cold,
			.main_name = "unitests",
			.cold_name = "unitests2",
			.mntdir = "/",
			.capacity = SILOFS_CAPACITY_SIZE_MIN,
			.memwant = UT_GIGA,
			.pedantic = false, /* TODO: make me a knob (true) */
		},
		.program = ut_globals.program,
		.version = ut_globals.version
	};

	for (int test_itr = 0; test_itr < 4; ++test_itr) {
		args.fs_args.kcopy = ((test_itr & 1) == 1);
		args.fs_args.concp = ((test_itr & 2) == 2);
		ut_print_tests_start(&args);
		ut_execute_tests_cycle(&args);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/


static size_t aligned_size(size_t sz, size_t a)
{
	return ((sz + a - 1) / a) * a;
}

static size_t malloc_total_size(size_t nbytes)
{
	size_t total_size;
	struct ut_malloc_chunk *mchunk = NULL;
	const size_t mchunk_size = sizeof(*mchunk);
	const size_t data_size = sizeof(mchunk->data);

	total_size = mchunk_size;
	if (nbytes > data_size) {
		total_size += aligned_size(nbytes - data_size, mchunk_size);
	}
	return total_size;
}

static struct ut_malloc_chunk *
ut_malloc_chunk(struct ut_env *ute, size_t nbytes)
{
	size_t total_size;
	struct ut_malloc_chunk *mchunk;

	total_size = malloc_total_size(nbytes);
	mchunk = (struct ut_malloc_chunk *)ut_malloc_safe(total_size);
	mchunk->size = total_size;
	mchunk->next = ute->malloc_list;
	ute->malloc_list = mchunk;
	ute->nbytes_alloc += total_size;

	return mchunk;
}

static void ut_free(struct ut_env *ute,
                    struct ut_malloc_chunk *mchunk)
{
	silofs_assert_ge(ute->nbytes_alloc, mchunk->size);

	ute->nbytes_alloc -= mchunk->size;
	memset(mchunk, 0xFC, mchunk->size);
	free(mchunk);
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

char *ut_strndup(struct ut_env *ute, const char *str,
                 size_t len)
{
	char *str2;

	str2 = ut_zalloc(ute, len + 1);
	memcpy(str2, str, len);

	return str2;
}

void ut_freeall(struct ut_env *ute)
{
	struct ut_malloc_chunk *mnext;
	struct ut_malloc_chunk *mchunk = ute->malloc_list;

	while (mchunk != NULL) {
		mnext = mchunk->next;
		ut_free(ute, mchunk);
		mchunk = mnext;
	}
	silofs_assert_eq(ute->nbytes_alloc, 0);

	ute->nbytes_alloc = 0;
	ute->malloc_list = NULL;
}

const char *ut_make_name(struct ut_env *ute, const char *pre, size_t idx)
{
	const char *name;

	if (pre && strlen(pre)) {
		name = ut_strfmt(ute, "%s-%lx", pre, idx + 1);
	} else {
		name = ut_strfmt(ute, "%lx", idx + 1);
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
	silofs_prandgen_take(&ute->prng, buf, bsz);
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
	int nb;
	size_t bsz = 255;
	char *buf;
	va_list ap;

	va_start(ap, fmt);
	nb = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if ((size_t)nb > bsz) {
		bsz = (size_t)nb;
	}

	va_start(ap, fmt);
	buf = ut_zerobuf(ute, bsz + 1);
	nb = vsnprintf(buf, bsz, fmt, ap);
	va_end(ap);

	silofs_unused(nb);
	return buf;
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

	silofs_prandgen_take_u64(&ute->prng, &rnd);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint64_t ut_fnv1a(const void *buf, size_t len, uint64_t seed)
{
	return silofs_hash_fnv1a(buf, len, seed);
}
