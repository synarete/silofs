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
#include <sys/wait.h>
#include <error.h>
#include <stdarg.h>
#include <ctype.h>

#define MCHUNK_MAGIC 0x3A4BE8C1

struct ft_mchunk {
	struct ft_mchunk *next;
	uint8_t      *data;
	size_t        size;
	unsigned long magic;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void fte_init(struct ft_env *fte, const struct ft_params *params)
{
	memset(fte, 0, sizeof(*fte));
	memcpy(&fte->params, params, sizeof(fte->params));
	silofs_prandgen_init(&fte->prng);
	silofs_mutex_init(&fte->mutex);
	fte->currtest = NULL;
	fte->start = time(NULL);
	fte->seqn = 0;
	fte->nbytes_alloc = 0;
	fte->malloc_list = NULL;
	fte->pid = getpid();
	fte->uid = geteuid();
	fte->gid = getegid();
	fte->umsk = umask(0);
	umask(fte->umsk);
}

void fte_fini(struct ft_env *fte)
{
	ft_freeall(fte);
	silofs_mutex_fini(&fte->mutex);
	memset(fte, 0, sizeof(*fte));
}

static void fte_lock(struct ft_env *fte)
{
	silofs_mutex_lock(&fte->mutex);
}

static void fte_unlock(struct ft_env *fte)
{
	silofs_mutex_unlock(&fte->mutex);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *malloc_ok(size_t nbytes)
{
	void *mem;

	mem = malloc(nbytes);
	if (mem == NULL) {
		error(1, errno, "malloc failure: nbytes=%lu", nbytes);
		abort(); /* make clang-scan happy */
	}
	return mem;
}

static struct ft_mchunk *ft_malloc_chunk(struct ft_env *fte, size_t nbytes)
{
	struct ft_mchunk *mchunk = NULL;

	mchunk = (struct ft_mchunk *)malloc_ok(sizeof(*mchunk));
	mchunk->data = malloc_ok(nbytes);
	mchunk->size = nbytes + sizeof(*mchunk);
	mchunk->next = fte->malloc_list;
	mchunk->magic  = MCHUNK_MAGIC;

	fte->malloc_list = mchunk;
	fte->nbytes_alloc += mchunk->size;

	return mchunk;
}

static void ft_free_mchunk(struct ft_env *fte, struct ft_mchunk *mchunk)
{
	void *data = mchunk->data;

	silofs_assert_not_null(data);
	silofs_assert(fte->nbytes_alloc >= mchunk->size);
	silofs_assert_eq(mchunk->magic, MCHUNK_MAGIC);

	fte->nbytes_alloc -= mchunk->size;
	free(mchunk->data);
	silofs_memffff(mchunk, sizeof(*mchunk));
	free(mchunk);
}

static void *ft_do_malloc(struct ft_env *fte, size_t sz)
{
	struct ft_mchunk *mchunk;

	mchunk = ft_malloc_chunk(fte, sz);
	return mchunk->data;
}

static void *ft_do_zalloc(struct ft_env *fte, size_t sz)
{
	void *ptr;

	ptr = ft_do_malloc(fte, sz);
	memset(ptr, 0, sz);

	return ptr;
}

static char *ft_do_strdup(struct ft_env *fte, const char *str)
{
	char *str2;
	const size_t len = strlen(str);

	str2 = ft_do_malloc(fte, len + 1);
	memcpy(str2, str, len);
	str2[len] = '\0';

	return str2;
}

char *ft_strdup(struct ft_env *fte, const char *str)
{
	char *dup;

	fte_lock(fte);
	dup = ft_do_strdup(fte, str);
	fte_unlock(fte);
	return dup;
}

static char *ft_do_strcat(struct ft_env *fte,
                          const char *str1, const char *str2)
{
	char *str;
	const size_t len1 = strlen(str1);
	const size_t len2 = strlen(str2);

	str = ft_do_malloc(fte, len1 + len2 + 1);
	memcpy(str, str1, len1);
	memcpy(str + len1, str2, len2);
	str[len1 + len2] = '\0';

	return str;
}

char *ft_strcat(struct ft_env *fte, const char *str1, const char *str2)
{
	char *str;

	fte_lock(fte);
	str = ft_do_strcat(fte, str1, str2);
	fte_unlock(fte);
	return str;
}

static void ft_do_freeall(struct ft_env *fte)
{
	struct ft_mchunk *mnext = NULL;
	struct ft_mchunk *mchunk = fte->malloc_list;

	while (mchunk != NULL) {
		mnext = mchunk->next;
		ft_free_mchunk(fte, mchunk);
		mchunk = mnext;
	}
	silofs_assert_eq(fte->nbytes_alloc, 0);

	fte->nbytes_alloc = 0;
	fte->malloc_list = NULL;
}

void ft_freeall(struct ft_env *fte)
{
	fte_lock(fte);
	ft_do_freeall(fte);
	fte_unlock(fte);
}

void ft_relax_mem(struct ft_env *fte)
{
	ft_freeall(fte);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ft_do_fill_random(struct ft_env *fte, void *buf, size_t bsz)
{
	silofs_prandgen_take(&fte->prng, buf, bsz);
}

void ft_suspend(const struct ft_env *fte, int sec, int part)
{
	struct timespec rem = { 0, 0 };
	struct timespec req = { sec, (long)part * 1000000LL };
	int err;

	err = nanosleep(&req, &rem);
	while (err && (errno == EINTR)) {
		memcpy(&req, &rem, sizeof(req));
		err = nanosleep(&req, &rem);
	}
	(void)fte;
}

void ft_suspends(const struct ft_env *fte, int sec)
{
	ft_suspend(fte, sec, 0);
}

void ft_suspend1(const struct ft_env *fte)
{
	ft_suspends(fte, 1);
}

static char *ft_do_joinpath(struct ft_env *fte, const char *s1, const char *s2)
{
	char *path;
	const size_t len1 = strlen(s1);
	const size_t len2 = strlen(s2);
	const size_t msz = len1 + len2 + 2;

	path = (char *)ft_do_malloc(fte, msz);
	strncpy(path, s1, len1 + 1);
	path[len1] = '/';
	strncpy(path + len1 + 1, s2, len2 + 1);
	path[len1 + 1 + len2] = '\0';
	return path;
}

char *ft_new_path_nested(struct ft_env *fte,
                         const char *base, const char *name)
{
	char *ret;

	fte_lock(fte);
	ret = ft_do_joinpath(fte, base, name);
	fte_unlock(fte);
	return ret;
}

char *ft_new_path_name(struct ft_env *fte, const char *name)
{
	const char *workdir = fte->params.testdir;

	return ft_new_path_nested(fte, workdir, name);
}

char *ft_new_path_unique(struct ft_env *fte)
{
	const char *name = ft_new_name_unique(fte);

	return ft_new_path_name(fte, name);
}

char *ft_new_path_under(struct ft_env *fte, const char *base)
{
	const char *name = ft_new_name_unique(fte);

	return ft_new_path_nested(fte, base, name);
}

char *ft_new_namef(struct ft_env *fte, const char *fmt, ...)
{
	va_list ap;
	char name[NAME_MAX + 1] = "";

	va_start(ap, fmt);
	vsnprintf(name, sizeof(name) - 1, fmt, ap);
	va_end(ap);
	return ft_strdup(fte, name);
}

char *ft_new_pathf(struct ft_env *fte, const char *p, const char *fmt, ...)
{
	va_list ap;
	char buf[PATH_MAX / 2] = "";

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	return ft_new_path_nested(fte, p, buf);
}

void *ft_new_buf_zeros(struct ft_env *fte, size_t bsz)
{
	void *ret;

	fte_lock(fte);
	ret = ft_do_zalloc(fte, bsz);
	fte_unlock(fte);
	return ret;
}

void *ft_new_buf_rands(struct ft_env *fte, size_t bsz)
{
	void *buf;

	if (bsz == 0) {
		return NULL;
	}
	fte_lock(fte);
	buf = ft_do_malloc(fte, bsz);
	ft_do_fill_random(fte, buf, bsz);
	fte_unlock(fte);
	return buf;
}

long ft_lrand(struct ft_env *fte)
{
	long r = 0;

	fte_lock(fte);
	ft_do_fill_random(fte, &r, sizeof(r));
	fte_unlock(fte);
	return r;
}

/* Generates ordered sequence of integers [base..base+n) */
static void make_seq(long *arr, size_t n, long base)
{
	for (size_t i = 0; i < n; ++i) {
		arr[i] = base++;
	}
}

static long *ft_new_seq(struct ft_env *fte, size_t cnt, long base)
{
	long *arr = ft_new_buf_zeros(fte, cnt * sizeof(*arr));

	make_seq(arr, cnt, base);
	return arr;
}

/* Generates sequence of integers [base..base+n) and then random shuffle */
static void swap(long *arr, size_t i, size_t j)
{
	long tmp = arr[i];

	arr[i] = arr[j];
	arr[j] = tmp;
}

long *ft_new_buf_randseq(struct ft_env *fte, size_t cnt, long base)
{
	long *arr = NULL;
	size_t *pos;

	arr = ft_new_seq(fte, cnt, base);
	pos = ft_new_buf_rands(fte, cnt * sizeof(*pos));
	if (pos != NULL) { /* make gcc-analyzer happy */
		for (size_t j = 0; j < cnt; ++j) {
			swap(arr, j, pos[j] % cnt);
		}
	}
	return arr;
}

static void fill_buf_nums(long base, void *buf, size_t bsz)
{
	uint8_t *rem;
	uint8_t *end;
	int64_t *ubuf = buf;
	const size_t cnt = bsz / sizeof(*ubuf);

	for (size_t i = 0; i < cnt; ++i) {
		ubuf[i] = base + (long)i;
	}
	rem = (uint8_t *)buf + (cnt * sizeof(*ubuf));
	end = (uint8_t *)buf + bsz;
	while (rem < end) {
		*rem++ = 0;
	}
}

void *ft_new_buf_nums(struct ft_env *fte, long base, size_t bsz)
{
	void *buf;

	buf = ft_new_buf_zeros(fte, bsz);
	fill_buf_nums(base, buf, bsz);
	return buf;
}

char *ft_strfmt(struct ft_env *fte, const char *fmt, ...)
{
	char str[2000] = "";
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);

	ft_expect_lt(len, sizeof(str));
	return ft_strdup(fte, str);
}

char *ft_make_ulong_name(struct ft_env *fte, unsigned long key)
{
	return ft_strfmt(fte, "%08lx", key);
}


static void ft_force_alnum(char *str, size_t len)
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

char *ft_make_rand_name(struct ft_env *fte, size_t name_len)
{
	char *str;

	str = ft_new_buf_rands(fte, name_len + 1);
	ft_force_alnum(str, name_len);
	str[name_len] = '\0';
	return str;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t ft_next_seqn(struct ft_env *fte)
{
	uint64_t ret;

	fte_lock(fte);
	ret = ++fte->seqn;
	fte_unlock(fte);
	return ret;
}

const char *ft_curr_test_name(const struct ft_env *fte)
{
	return fte->currtest->name;
}

char *ft_make_xname_unique(struct ft_env *fte, size_t nlen,
                           char *buf, size_t bsz)
{
	const uint32_t seq = (uint32_t)ft_next_seqn(fte);
	const uint32_t rnd = (uint32_t)ft_lrand(fte);
	const uint32_t val = seq ^ rnd ^ (uint32_t)fte->pid;
	ssize_t len;

	if ((bsz > 0) && (nlen < bsz)) {
		len = snprintf(buf, bsz, "%s_%08x",
		               ft_curr_test_name(fte), val);
		if ((size_t)len < bsz) {
			memset(buf + len, 'x', bsz - (size_t)len);
		}
		buf[nlen] = '\0';
	}
	return buf;
}

char *ft_new_name_unique(struct ft_env *fte)
{
	const uint32_t seq = (uint32_t)ft_next_seqn(fte);
	const uint32_t rnd = (uint32_t)ft_lrand(fte);
	const uint32_t val = seq ^ rnd ^ (uint32_t)fte->pid;

	return ft_strfmt(fte, "%s_%08x", ft_curr_test_name(fte), val);
}

long ft_timespec_diff(const struct timespec *ts1, const struct timespec *ts2)
{
	const long n = 1000000000L;
	const long d_sec = ts2->tv_sec - ts1->tv_sec;
	const long d_nsec = ts2->tv_nsec - ts1->tv_nsec;

	return (d_sec * n) + d_nsec;
}

long ft_xtimestamp_diff(const struct statx_timestamp *ts1,
                        const struct statx_timestamp *ts2)
{
	const long n = 1000000000L;
	const long d_sec = ts2->tv_sec - ts1->tv_sec;
	const long d_nsec = ts2->tv_nsec - ts1->tv_nsec;

	return (d_sec * n) + d_nsec;
}

size_t ft_page_size(void)
{
	return (size_t)silofs_sc_page_size();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int ft_dirent_isdot(const struct dirent64 *dent)
{
	return (strcmp(".", dent->d_name) == 0);
}

int ft_dirent_isdotdot(const struct dirent64 *dent)
{
	return (strcmp("..", dent->d_name) == 0);
}

int ft_dirent_isxdot(const struct dirent64 *dent)
{
	return ft_dirent_isdot(dent) || ft_dirent_isdotdot(dent);
}

mode_t ft_dirent_gettype(const struct dirent64 *dent)
{
	const mode_t d_type = (mode_t)dent->d_type;

	return DTTOIF(d_type);
}

int ft_dirent_isdir(const struct dirent64 *dent)
{
	const mode_t mode = ft_dirent_gettype(dent);

	return S_ISDIR(mode);
}

int ft_dirent_isreg(const struct dirent64 *dent)
{
	const mode_t mode = ft_dirent_gettype(dent);

	return S_ISREG(mode);
}

