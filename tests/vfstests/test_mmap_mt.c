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

struct vt_mmap_mt_ctx {
	struct silofs_thread th;
	struct vt_env  *vte;
	uint8_t        *addr;
	size_t          size;
	size_t          sgsz;
	size_t          indx;
	int             fd;
};

static void vt_mmtc_exec_thread(struct vt_mmap_mt_ctx *mmtc,
                                silofs_execute_fn exec)
{
	int err;

	err = silofs_thread_create(&mmtc->th, exec, mmtc, NULL);
	vt_expect_ok(err);
}

static void vt_mmtc_join_thread(struct vt_mmap_mt_ctx *mmtc)
{
	int err;

	err = silofs_thread_join(&mmtc->th);
	vt_expect_ok(err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_mmap_mt_seq_at_(struct vt_env *vte, const struct vt_mmap_mt_ctx *mmtc)
{
	const size_t indx = mmtc->indx;
	const size_t nsegs = mmtc->size / mmtc->sgsz;
	const size_t bsz = mmtc->sgsz;
	uint8_t *buf = vt_new_buf_zeros(vte, bsz);
	const uint8_t *src = NULL;
	uint8_t *dst = NULL;
	uint8_t dat = 'A' + (uint8_t)indx;
	size_t seg;
	loff_t pos;

	memset(buf, dat, bsz);
	for (size_t i = 0; i < nsegs; ++i) {
		seg = (i + indx) % nsegs;
		pos = (loff_t)(seg * mmtc->sgsz);
		dst = mmtc->addr + pos;
		memcpy(dst, buf, bsz - indx);
	}
	for (size_t i = 0; i < nsegs; ++i) {
		seg = (i + indx + 1) % nsegs;
		pos = (loff_t)(seg * mmtc->sgsz);
		src = mmtc->addr + pos;
		memcpy(buf, src, bsz - indx);
		dat = buf[0];
		vt_expect_ne(dat, 0);
	}
}

static int start_test_mmap_mt_seq(struct silofs_thread *th)
{
	const struct vt_mmap_mt_ctx *mmtc = th->arg;

	test_mmap_mt_seq_at_(mmtc->vte, mmtc);
	return 0;
}

static void test_mmap_mt_seq_(struct vt_env *vte, loff_t off,
                              size_t msz, size_t sgsz)
{
	struct vt_mmap_mt_ctx mmt_ctx[16];
	const char *path = vt_new_path_unique(vte);
	void *addr = NULL;
	int fd = -1;

	memset(mmt_ctx, 0, sizeof(mmt_ctx));
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_ftruncate(fd, off + (long)msz);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	for (size_t i = 0; i < VT_ARRAY_SIZE(mmt_ctx); ++i) {
		mmt_ctx[i].vte = vte;
		mmt_ctx[i].addr = addr;
		mmt_ctx[i].size = msz;
		mmt_ctx[i].sgsz = sgsz;
		mmt_ctx[i].indx = i;
		mmt_ctx[i].fd = fd;
		vt_mmtc_exec_thread(&mmt_ctx[i], start_test_mmap_mt_seq);
	}
	for (size_t i = 0; i < VT_ARRAY_SIZE(mmt_ctx); ++i) {
		vt_mmtc_join_thread(&mmt_ctx[i]);
	}
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_mt_seq(struct vt_env *vte)
{
	test_mmap_mt_seq_(vte, 0, VT_GIGA, VT_MEGA);
	test_mmap_mt_seq_(vte, VT_GIGA, VT_MEGA, VT_4K);
	test_mmap_mt_seq_(vte, VT_TERA, 4 * VT_MEGA, VT_MEGA / 4);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_mmap_mt_seq),
};

const struct vt_tests vt_test_mmap_mt = VT_DEFTESTS(vt_local_tests);

