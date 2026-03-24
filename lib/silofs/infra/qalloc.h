/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#ifndef SILOFS_QALLOC_H_
#define SILOFS_QALLOC_H_

#include <stdlib.h>
#include <stdint.h>

#include <silofs/ccattr.h>
#include <silofs/memalloc.h>
#include <silofs/infra/iovec.h>
#include <silofs/infra/list.h>
#include <silofs/infra/thread.h>

/* quick memory allocator */
enum silofs_qallocf {
	SILOFS_QALLOCF_NONE   = 0x0,
	SILOFS_QALLOCF_DEMASK = 0x1,
	SILOFS_QALLOCF_NOFAIL = 0x2,
};

struct silofs_memfd {
	void  *mem;
	size_t msz;
	int    fd;
};

struct silofs_qpool {
	struct silofs_list_head free_pgs;
	struct silofs_mutex     mutex;
	struct silofs_memfd     data;
	struct silofs_memfd     meta;
	size_t                  npgs_max;
	size_t                  npgs_use;
	uint32_t                unique_id;
	enum silofs_qallocf     flags;
} silofs_attr_aligned64;

struct silofs_slab {
	struct silofs_list_head free_list;
	struct silofs_qpool    *qpool;
	struct silofs_mutex     mutex;
	size_t                  nfree;
	size_t                  nused;
	uint32_t                elemsz;
	int32_t                 sindex;
} silofs_attr_aligned64;

struct silofs_qalloc {
	struct silofs_slab  slabs[12];
	struct silofs_qpool qpool;
	struct silofs_alloc alloc;
	size_t              nbytes_use;
} silofs_attr_aligned64;

/* quick allocator */
int silofs_qalloc_init(struct silofs_qalloc *qal, size_t memsize,
                       enum silofs_qallocf flags);

int silofs_qalloc_fini(struct silofs_qalloc *qal);

void *silofs_qalloc_malloc(struct silofs_qalloc *qal, size_t nb, int fl);

void silofs_qalloc_free(struct silofs_qalloc *qal, void *p, size_t nb, int fl);

void silofs_qalloc_stat(const struct silofs_qalloc *qal,
                        struct silofs_alloc_stat   *out_stat);

int silofs_qalloc_resolve(const struct silofs_qalloc *qal, void *ptr,
                          size_t len, struct silofs_iovec *iov);

int silofs_qalloc_mcheck(const struct silofs_qalloc *qal, const void *ptr,
                         size_t nbytes);

#endif /* SILOFS_QALLOC_H_ */
