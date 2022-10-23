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
#include <sys/wait.h>
#include <error.h>
#include <stdarg.h>
#include <ctype.h>

#define MCHUNK_MAGIC 0x3AABE871

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

static struct vt_mchunk *malloc_chunk(struct vt_env *vte, size_t nbytes)
{
	struct vt_mchunk *mchunk = NULL;

	mchunk = (struct vt_mchunk *)malloc_ok(sizeof(*mchunk));
	mchunk->data = malloc_ok(nbytes);
	mchunk->size = nbytes + sizeof(*mchunk);
	mchunk->next = vte->malloc_list;
	mchunk->magic  = MCHUNK_MAGIC;

	vte->malloc_list = mchunk;
	vte->nbytes_alloc += mchunk->size;

	return mchunk;
}

static void free_mchunk(struct vt_env *vte, struct vt_mchunk *mchunk)
{
	void *data = mchunk->data;

	silofs_assert_not_null(data);
	silofs_assert(vte->nbytes_alloc >= mchunk->size);
	silofs_assert_eq(mchunk->magic, MCHUNK_MAGIC);

	vte->nbytes_alloc -= mchunk->size;
	free(mchunk->data);
	silofs_memffff(mchunk, sizeof(*mchunk));
	free(mchunk);
}

static void *do_malloc(struct vt_env *vte, size_t sz)
{
	struct vt_mchunk *mchunk;

	mchunk = malloc_chunk(vte, sz);
	return mchunk->data;
}

static void *do_zalloc(struct vt_env *vte, size_t sz)
{
	void *ptr;

	ptr = do_malloc(vte, sz);
	memset(ptr, 0, sz);

	return ptr;
}

char *vt_strdup(struct vt_env *vte, const char *str)
{
	char *str2;
	const size_t len = strlen(str);

	str2 = do_malloc(vte, len + 1);
	memcpy(str2, str, len);
	str2[len] = '\0';

	return str2;
}

char *vt_strcat(struct vt_env *vte, const char *str1, const char *str2)
{
	char *str;
	const size_t len1 = strlen(str1);
	const size_t len2 = strlen(str2);

	str = do_malloc(vte, len1 + len2 + 1);
	memcpy(str, str1, len1);
	memcpy(str + len1, str2, len2);
	str[len1 + len2] = '\0';

	return str;
}

void vt_freeall(struct vt_env *vte)
{
	struct vt_mchunk *mnext = NULL;
	struct vt_mchunk *mchunk = vte->malloc_list;

	while (mchunk != NULL) {
		mnext = mchunk->next;
		free_mchunk(vte, mchunk);
		mchunk = mnext;
	}
	silofs_assert_eq(vte->nbytes_alloc, 0);

	vte->nbytes_alloc = 0;
	vte->malloc_list = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void vte_init(struct vt_env *vte, const struct vt_params *params)
{
	memset(vte, 0, sizeof(*vte));
	memcpy(&vte->params, params, sizeof(vte->params));
	silofs_prandgen_init(&vte->prng);
	vte->currtest = NULL;
	vte->start = time(NULL);
	vte->seqn = 0;
	vte->nbytes_alloc = 0;
	vte->malloc_list = NULL;
	vte->pid = getpid();
	vte->uid = geteuid();
	vte->gid = getegid();
	vte->umsk = umask(0);
	umask(vte->umsk);
}

void vte_fini(struct vt_env *vte)
{
	vt_freeall(vte);
	memset(vte, 0, sizeof(*vte));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vte_fill_random(struct vt_env *vte, void *buf, size_t bsz)
{
	silofs_prandgen_take(&vte->prng, buf, bsz);
}

void vt_suspend(const struct vt_env *vte, int sec,
                int part)
{
	int err;
	struct timespec rem = { 0, 0 };
	struct timespec req = { sec, (long)part * 1000000LL };

	err = nanosleep(&req, &rem);
	while (err && (errno == EINTR)) {
		memcpy(&req, &rem, sizeof(req));
		err = nanosleep(&req, &rem);
	}
	(void)vte;
}

void vt_suspends(const struct vt_env *vte, int sec)
{
	vt_suspend(vte, sec, 0);
}

static char *joinpath(struct vt_env *vte, const char *s1,
                      const char *s2)
{
	char *path;
	const size_t len1 = strlen(s1);
	const size_t len2 = strlen(s2);
	const size_t msz = len1 + len2 + 2;

	path = (char *)do_malloc(vte, msz);
	strncpy(path, s1, len1 + 1);
	path[len1] = '/';
	strncpy(path + len1 + 1, s2, len2 + 1);
	path[len1 + 1 + len2] = '\0';
	return path;
}

char *vt_new_path_nested(struct vt_env *vte,
                         const char *base, const char *name)
{
	return joinpath(vte, base, name);
}

char *vt_new_path_name(struct vt_env *vte, const char *name)
{
	const char *workdir = vte->params.workdir;

	return vt_new_path_nested(vte, workdir, name);
}

char *vt_new_path_unique(struct vt_env *vte)
{
	const char *name = vt_new_name_unique(vte);

	return vt_new_path_name(vte, name);
}

char *vt_new_path_under(struct vt_env *vte, const char *base)
{
	const char *name = vt_new_name_unique(vte);

	return vt_new_path_nested(vte, base, name);
}

char *vt_new_pathf(struct vt_env *vte, const char *p, const char *fmt, ...)
{
	va_list ap;
	char buf[PATH_MAX / 2] = "";

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	return vt_new_path_nested(vte, p, buf);
}

void *vt_new_buf_zeros(struct vt_env *vte, size_t bsz)
{
	return do_zalloc(vte, bsz);
}

void *vt_new_buf_rands(struct vt_env *vte, size_t bsz)
{
	void *buf = NULL;

	if (bsz > 0) {
		buf = do_malloc(vte, bsz);
		vte_fill_random(vte, buf, bsz);
	}
	return buf;
}

long vt_lrand(struct vt_env *vte)
{
	long r = 0;

	vte_fill_random(vte, &r, sizeof(r));
	return r;
}

/* Generates ordered sequence of integers [base..base+n) */
static void vt_create_seq(long *arr, size_t n, long base)
{
	for (size_t i = 0; i < n; ++i) {
		arr[i] = base++;
	}
}

static long *vt_new_seq(struct vt_env *vte, size_t cnt, long base)
{
	long *arr = vt_new_buf_zeros(vte, cnt * sizeof(*arr));

	vt_create_seq(arr, cnt, base);
	return arr;
}

/* Generates sequence of integers [base..base+n) and then random shuffle */
static void swap(long *arr, size_t i, size_t j)
{
	long tmp = arr[i];

	arr[i] = arr[j];
	arr[j] = tmp;
}

long *vt_new_buf_randseq(struct vt_env *vte, size_t cnt, long base)
{
	long *arr = NULL;
	size_t *pos;

	arr = vt_new_seq(vte, cnt, base);
	pos = vt_new_buf_rands(vte, cnt * sizeof(*pos));
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

void *vt_new_buf_nums(struct vt_env *vte, long base, size_t bsz)
{
	void *buf;

	buf = vt_new_buf_zeros(vte, bsz);
	fill_buf_nums(base, buf, bsz);
	return buf;
}

char *vt_strfmt(struct vt_env *vte, const char *fmt, ...)
{
	char str[2000] = "";
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);

	vt_expect_lt(len, sizeof(str));
	return vt_strdup(vte, str);
}

char *vt_make_ulong_name(struct vt_env *vte, unsigned long key)
{
	return vt_strfmt(vte, "%08lx", key);
}


static void vt_force_alnum(char *str, size_t len)
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

char *vt_make_rand_name(struct vt_env *vte, size_t name_len)
{
	char *str;

	str = vt_new_buf_rands(vte, name_len + 1);
	vt_force_alnum(str, name_len);
	str[name_len] = '\0';
	return str;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

char *vt_make_xname_unique(struct vt_env *vte, size_t nlen,
                           char *buf, size_t bsz)
{
	const uint32_t seq = (uint32_t)(++vte->seqn);
	const uint32_t rnd = (uint32_t)vt_lrand(vte);
	const uint32_t val = seq ^ rnd ^ (uint32_t)vte->pid;
	ssize_t len;

	if ((bsz > 0) && (nlen < bsz)) {
		len = snprintf(buf, bsz, "%s_%08x", vte->currtest->name, val);
		if ((size_t)len < bsz) {
			memset(buf + len, 'x', bsz - (size_t)len);
		}
		buf[nlen] = '\0';
	}
	return buf;
}

char *vt_new_name_unique(struct vt_env *vte)
{
	const uint32_t seq = (uint32_t)(++vte->seqn);
	const uint32_t rnd = (uint32_t)vt_lrand(vte);
	const uint32_t val = seq ^ rnd ^ (uint32_t)vte->pid;

	return vt_strfmt(vte, "%s_%08x", vte->currtest->name, val);
}

long vt_timespec_diff(const struct timespec *ts1, const struct timespec *ts2)
{
	const long n = 1000000000L;
	const long d_sec = ts2->tv_sec - ts1->tv_sec;
	const long d_nsec = ts2->tv_nsec - ts1->tv_nsec;

	return (d_sec * n) + d_nsec;
}

long vt_xtimestamp_diff(const struct statx_timestamp *ts1,
                        const struct statx_timestamp *ts2)
{
	const long n = 1000000000L;
	const long d_sec = ts2->tv_sec - ts1->tv_sec;
	const long d_nsec = ts2->tv_nsec - ts1->tv_nsec;

	return (d_sec * n) + d_nsec;
}

size_t vt_page_size(void)
{
	return (size_t)sysconf(_SC_PAGE_SIZE);
}
