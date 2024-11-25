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

struct ft_mmap_mt_ctx {
	struct silofs_thread th;
	struct ft_env *fte;
	uint8_t *addr;
	size_t size;
	size_t sgsz;
	size_t indx;
	int fd;
};

static void
ft_mmtc_exec_thread(struct ft_mmap_mt_ctx *mmtc, silofs_execute_fn exec)
{
	int err;

	err = silofs_thread_create(&mmtc->th, exec, mmtc, NULL);
	ft_expect_ok(err);
}

static void ft_mmtc_join_thread(struct ft_mmap_mt_ctx *mmtc)
{
	int err;

	err = silofs_thread_join(&mmtc->th);
	ft_expect_ok(err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_mmap_mt_seq_at_(struct ft_env *fte, const struct ft_mmap_mt_ctx *mmtc)
{
	const size_t indx = mmtc->indx;
	const size_t nsegs = mmtc->size / mmtc->sgsz;
	const size_t bsz = mmtc->sgsz;
	uint8_t *buf = ft_new_buf_zeros(fte, bsz);
	const uint8_t *src = NULL;
	uint8_t *dst = NULL;
	uint8_t dat = (uint8_t)('A' + (int)indx);
	size_t seg;
	loff_t pos;

	memset(buf, dat, bsz);
	for (size_t i = 0; i < nsegs; ++i) {
		seg = (i + indx) % nsegs;
		pos = (loff_t)(seg * mmtc->sgsz);
		dst = mmtc->addr + pos;
		ft_memcpy(dst, buf, bsz - indx);
	}
	for (size_t i = 0; i < nsegs; ++i) {
		seg = (i + indx + 1) % nsegs;
		pos = (loff_t)(seg * mmtc->sgsz);
		src = mmtc->addr + pos;
		ft_memcpy(buf, src, bsz - indx);
		dat = buf[0];
		ft_expect_ne(dat, 0);
	}
}

static int start_test_mmap_mt_seq(struct silofs_thread *th)
{
	const struct ft_mmap_mt_ctx *mmtc = th->arg;

	test_mmap_mt_seq_at_(mmtc->fte, mmtc);
	return 0;
}

static void
test_mmap_mt_seq_(struct ft_env *fte, loff_t off, size_t msz, size_t sgsz)
{
	struct ft_mmap_mt_ctx mmt_ctx[16];
	const char *path = ft_new_path_unique(fte);
	void *addr = NULL;
	int fd = -1;

	memset(mmt_ctx, 0, sizeof(mmt_ctx));
	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_ftruncate(fd, off + (long)msz);
	ft_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	for (size_t i = 0; i < FT_ARRAY_SIZE(mmt_ctx); ++i) {
		mmt_ctx[i].fte = fte;
		mmt_ctx[i].addr = addr;
		mmt_ctx[i].size = msz;
		mmt_ctx[i].sgsz = sgsz;
		mmt_ctx[i].indx = i;
		mmt_ctx[i].fd = fd;
		ft_mmtc_exec_thread(&mmt_ctx[i], start_test_mmap_mt_seq);
	}
	for (size_t i = 0; i < FT_ARRAY_SIZE(mmt_ctx); ++i) {
		ft_mmtc_join_thread(&mmt_ctx[i]);
	}
	ft_munmap(addr, msz);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_mt_seq(struct ft_env *fte)
{
	test_mmap_mt_seq_(fte, 0, FT_1G, FT_1M);
	ft_relax_mem(fte);
	test_mmap_mt_seq_(fte, FT_1G, FT_1M, FT_4K);
	ft_relax_mem(fte);
	test_mmap_mt_seq_(fte, FT_1T, 4 * FT_1M, FT_1M / 4);
	ft_relax_mem(fte);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_mmap_mt_seq),
};

const struct ft_tests ft_test_mmap_mt = FT_DEFTESTS(ft_local_tests);
