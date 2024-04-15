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

#define MAGIC   0xDEADBEEF

struct ut_mrecord {
	long    magic;
	struct silofs_qalloc *qal;
	struct silofs_list_head link;
	void  *mem;
	size_t len;
	size_t dat_len;
	char   dat[8];
};

static void mrecord_setup(struct ut_mrecord *mr, void *mem, size_t len)
{
	SILOFS_STATICASSERT_EQ(sizeof(*mr), 64);

	ut_expect_ge(len, sizeof(*mr));
	silofs_list_head_init(&mr->link);
	mr->magic = MAGIC;
	mr->mem = mem;
	mr->len = len;
	mr->dat_len = len - offsetof(struct ut_mrecord, dat);
}

static struct ut_mrecord *mrecord_of(void *mem, size_t len)
{
	struct ut_mrecord *mr = mem;

	mrecord_setup(mr, mem, len);
	return mr;
}

static void mrecord_check(const struct ut_mrecord *mr)
{
	ut_expect_eq(mr->magic, MAGIC);
	ut_expect_ge(mr->len, sizeof(*mr));
	ut_expect_not_null(mr->mem);
}

static struct ut_mrecord *
link_to_mrecord(const struct silofs_list_head *link)
{
	const struct ut_mrecord *mr =
	        ut_container_of2(link, struct ut_mrecord, link);

	mrecord_check(mr);
	return silofs_unconst(mr);
}

static struct ut_mrecord *
mrecord_new(struct silofs_qalloc *qal, size_t msz)
{
	struct silofs_iovec iov = {
		.iov_base = NULL,
		.iov_fd = -1
	};
	struct ut_mrecord *mr = NULL;
	void *mem = NULL;
	int err = 0;

	mem = silofs_qalloc_malloc(qal, msz, 0);
	ut_expect_not_null(mem);

	err = silofs_qalloc_mcheck(qal, mem, msz);
	ut_expect_ok(err);

	err = silofs_qalloc_resolve(qal, mem, msz, &iov);
	ut_expect_ok(err);
	ut_expect_eq(mem, iov.iov_base);

	mr = mrecord_of(mem, msz);
	mr->qal = qal;

	return mr;
}

static void mrecord_del(struct ut_mrecord *mr)
{
	int err;
	struct silofs_qalloc *qal = mr->qal;

	mrecord_check(mr);
	err = silofs_qalloc_mcheck(qal, mr->mem, mr->len);
	ut_expect_ok(err);
	silofs_qalloc_free(qal, mr->mem, mr->len, 0);
}

static void link_mrecord_del(struct silofs_list_head *link)
{
	struct ut_mrecord *mr;

	mr = link_to_mrecord(link);
	silofs_list_head_remove(link);
	mrecord_del(mr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_qalloc *
ut_new_qalloc(struct ut_env *ute, size_t sz)
{
	struct silofs_qalloc *qal = NULL;
	enum silofs_qallocf qaf;
	int err;

	qal = ut_zalloc(ute, sizeof(*qal));
	qaf = SILOFS_QALLOCF_NOFAIL | SILOFS_QALLOCF_DEMASK;
	err = silofs_qalloc_init(qal, sz, qaf);
	ut_expect_ok(err);
	return qal;
}

static void ut_del_qalloc(struct silofs_qalloc *qal)
{
	int err;

	err = silofs_qalloc_fini(qal);
	ut_expect_ok(err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_qalloc_simple(struct ut_env *ute)
{
	struct silofs_qalloc *qal = NULL;
	uint32_t *ptr;
	uint32_t len;

	qal = ut_new_qalloc(ute, 8 * UT_1M);
	for (uint32_t n = 8; n <= UT_1M; n *= 2) {
		len = n;
		ptr = silofs_qalloc_malloc(qal, len, 0);
		ut_expect_not_null(ptr);
		silofs_qalloc_free(qal, ptr, len, 0);
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_qalloc_simple3(struct ut_env *ute)
{
	struct silofs_qalloc *qal = NULL;
	uint32_t *ptr1;
	uint32_t *ptr2;
	uint32_t *ptr3;
	uint32_t len;

	qal = ut_new_qalloc(ute, 8 * UT_1M);
	for (uint32_t n = 8; n <= UT_1M; n *= 2) {
		len = n;
		ptr1 = silofs_qalloc_malloc(qal, len, 0);
		ut_expect_not_null(ptr1);
		*ptr1 = len;

		len = n - 1;
		ptr2 = silofs_qalloc_malloc(qal, len, 0);
		ut_expect_not_null(ptr2);
		*ptr2 = len;

		len = n + 1;
		ptr3 = silofs_qalloc_malloc(qal, len, 0);
		ut_expect_not_null(ptr3);
		*ptr3 = len;

		len = n;
		silofs_assert_eq(*ptr1, len);
		silofs_qalloc_free(qal, ptr1, len, 0);

		len = n - 1;
		silofs_assert_eq(*ptr2, len);
		silofs_qalloc_free(qal, ptr2, len, 0);

		len = n + 1;
		silofs_assert_eq(*ptr3, len);
		silofs_qalloc_free(qal, ptr3, len, 0);
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_del_mrecords(struct ut_env *ute, struct silofs_list_head *lst)
{
	struct ut_mrecord *mr = NULL;
	struct silofs_list_head *lnk = NULL;
	int cnt = 0;

	lnk = (cnt++ & 1) ? lst->next : lst->prev;
	while (lnk != lst) {
		silofs_list_head_remove(lnk);
		mr = link_to_mrecord(lnk);
		mrecord_del(mr);
		lnk = (cnt++ & 1) ? lst->next : lst->prev;
	}
	ut_unused(ute);
}

static void ut_qalloc_nbks_simple(struct ut_env *ute)
{
	struct silofs_list_head lst;
	struct silofs_qalloc *qal;
	struct ut_mrecord *mr = NULL;
	const size_t sizes[] = {
		UT_64K - 1,
		UT_64K,
		UT_64K + 1,
		2 * UT_64K,
		8 * UT_64K - 1
	};

	silofs_list_init(&lst);
	qal = ut_new_qalloc(ute, 32 * UT_1M);
	for (size_t i = 0; i < UT_ARRAY_SIZE(sizes); ++i) {
		mr = mrecord_new(qal, sizes[i]);
		memset(mr->dat, (int)i, mr->dat_len);
		silofs_list_push_back(&lst, &mr->link);
	}

	ut_del_mrecords(ute, &lst);
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t align_up(size_t nn, size_t align)
{
	return ((nn + align - 1) / align) * align;
}

static void ut_qalloc_free_nbks(struct ut_env *ute)
{
	struct silofs_alloc_stat alst;
	struct silofs_list_head lst;
	struct silofs_qalloc *qal = NULL;
	struct ut_mrecord *mr = NULL;
	const size_t bk_size =  UT_BK_SIZE;
	size_t total = 0;
	size_t msz = 0;
	size_t rem = 0;

	silofs_list_init(&lst);
	qal = ut_new_qalloc(ute, 32 * UT_1M);
	silofs_qalloc_stat(qal, &alst);
	while (total < alst.nbytes_max) {
		rem = alst.nbytes_max - total;
		msz = sizeof(*mr) + (bk_size / 2) + (total % 10000);
		msz = silofs_clamp(msz, (bk_size / 2) + 1, rem);

		mr = mrecord_new(qal, msz);
		silofs_list_push_back(&lst, &mr->link);

		total += align_up(msz, bk_size);
		silofs_qalloc_stat(qal, &alst);
	}

	ut_del_mrecords(ute, &lst);
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_qalloc_small_elems(struct ut_env *ute)
{
	struct silofs_list_head lst;
	struct silofs_qalloc *qal = NULL;
	struct ut_mrecord *mr = NULL;
	const size_t small_sz = UT_64K;
	size_t val = 0;
	size_t msz = 0;

	silofs_list_init(&lst);
	qal = ut_new_qalloc(ute, 256 * UT_1M);
	for (size_t i = 0; i < 10000; ++i) {
		val = (small_sz + i) % (small_sz / 2);
		msz = silofs_clamp(val, sizeof(*mr), (small_sz / 2));
		mr = mrecord_new(qal, msz);
		memset(mr->dat, (int)i, mr->dat_len);
		silofs_list_push_back(&lst, &mr->link);

		if ((i % 7) == 1) {
			link_mrecord_del(lst.next);
		}
	}
	ut_del_mrecords(ute, &lst);
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_qalloc_mixed(struct ut_env *ute)
{
	size_t msz = 0;
	size_t val = 0;
	size_t val2 = 0;
	size_t val_max = 100000;
	struct silofs_qalloc *qal = NULL;
	const size_t bk_size = UT_BK_SIZE;
	struct ut_mrecord *mr = NULL;
	struct silofs_list_head lst;

	silofs_list_init(&lst);
	qal = ut_new_qalloc(ute, 256 * UT_1M);
	for (val = 0; val < val_max; val += 100) {
		msz = silofs_clamp(val, sizeof(*mr), 11 * bk_size);
		mr = mrecord_new(qal, msz);
		silofs_list_push_back(&lst, &mr->link);

		if ((val % 11) == 1) {
			link_mrecord_del(lst.next);
		}

		val2 = (val_max - val) / 2;
		msz = silofs_clamp(val2, sizeof(*mr), 11 * bk_size);
		mr = mrecord_new(qal, msz);
		silofs_list_push_back(&lst, &mr->link);
	}

	ut_del_mrecords(ute, &lst);
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define NALLOC_SMALL 128

static size_t small_alloc_size(size_t i)
{
	return (i * 17) + 1;
}

static void ut_qalloc_small_sizes(struct ut_env *ute)
{
	void *ptr[NALLOC_SMALL];
	long idx_arr[NALLOC_SMALL];
	struct silofs_qalloc *qal = NULL;
	void *mem = NULL;
	size_t idx = 0;
	size_t msz = 0;

	qal = ut_new_qalloc(ute, 32 * UT_1M);
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		msz = small_alloc_size(i);
		mem = silofs_qalloc_malloc(qal, msz, 0);
		ut_expect_not_null(mem);
		memset(mem, (int)i, msz);
		ptr[i] = mem;
	}
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		msz = small_alloc_size(i);
		mem = ptr[i];
		silofs_qalloc_free(qal, mem, msz, 0);
		ptr[i] = NULL;
	}

	ut_prandom_seq(ute, idx_arr, UT_ARRAY_SIZE(idx_arr), 0);
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		idx = (size_t)idx_arr[i];
		msz = small_alloc_size(idx);
		mem = silofs_qalloc_malloc(qal, msz, 0);
		ut_expect_not_null(mem);
		memset(mem, (int)i, msz);
		ptr[idx] = mem;
	}
	ut_prandom_seq(ute, idx_arr, UT_ARRAY_SIZE(idx_arr), 0);
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		idx = (size_t)idx_arr[i];
		msz = small_alloc_size(idx);
		mem = ptr[idx];
		silofs_qalloc_free(qal, mem, msz, 0);
		ptr[idx] = NULL;
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct iovec *random_iovecs(struct ut_env *ute,
                                   size_t cnt, size_t len_min, size_t len_max)
{
	struct iovec *iov = NULL;
	const size_t msz = sizeof(*iov) * cnt;
	const size_t len_dif = len_max - len_min;

	iov = ut_malloc(ute, msz);
	ut_randfill(ute, iov, msz);

	for (size_t i = 0; i < cnt; ++i) {
		iov[i].iov_len = (iov[i].iov_len % len_dif) + len_min;
		iov[i].iov_base = NULL;
	}
	return iov;
}

static void ut_qalloc_random_(struct ut_env *ute, size_t cnt)
{
	struct silofs_qalloc *qal = NULL;
	struct iovec *iov = NULL;
	const size_t pg_size = SILOFS_PAGE_SIZE_MIN;
	void *mem = NULL;
	size_t msz = 0;
	int err = 0;

	qal = ut_new_qalloc(ute, cnt * 2 * pg_size);
	iov = random_iovecs(ute, cnt, 1, 2 * pg_size);
	for (size_t i = 0; i < cnt; ++i) {
		msz = iov[i].iov_len;
		mem = silofs_qalloc_malloc(qal, msz, 0);
		ut_expect_not_null(mem);
		memset(mem, (int)i, msz);
		err = silofs_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		iov[i].iov_base = mem;
	}
	for (size_t i = 0; i < cnt; i += 3) {
		msz = iov[i].iov_len;
		mem = iov[i].iov_base;
		err = silofs_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		silofs_qalloc_free(qal, mem, msz, 0);
		iov[i].iov_base = NULL;
	}
	for (size_t i = 1; i < cnt; i += 3) {
		msz = iov[i].iov_len;
		mem = iov[i].iov_base;
		err = silofs_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		silofs_qalloc_free(qal, mem, msz, 0);
		iov[i].iov_len = 0;
		iov[i].iov_base = NULL;
	}
	for (size_t i = 0; i < cnt; i += 3) {
		msz = iov[i].iov_len;
		mem = silofs_qalloc_malloc(qal, msz, 0);
		ut_expect_ok(err);
		ut_expect_not_null(mem);
		iov[i].iov_base = mem;
	}
	for (size_t i = 0; i < cnt; i++) {
		msz = iov[i].iov_len;
		mem = iov[i].iov_base;
		err = silofs_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		silofs_qalloc_free(qal, mem, msz, 0);
		iov[i].iov_len = 0;
		iov[i].iov_base = NULL;
	}
	ut_del_qalloc(qal);
}

static void ut_qalloc_random(struct ut_env *ute)
{
	ut_qalloc_random_(ute, 1024);
	ut_qalloc_random_(ute, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_qalloc_simple),
	UT_DEFTEST1(ut_qalloc_simple3),
	UT_DEFTEST1(ut_qalloc_nbks_simple),
	UT_DEFTEST(ut_qalloc_free_nbks),
	UT_DEFTEST(ut_qalloc_small_elems),
	UT_DEFTEST(ut_qalloc_mixed),
	UT_DEFTEST(ut_qalloc_small_sizes),
	UT_DEFTEST(ut_qalloc_random),
};

const struct ut_testdefs ut_tdefs_qalloc = UT_MKTESTS(ut_local_tests);

