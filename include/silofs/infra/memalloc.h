/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_MEMALLOC_H_
#define SILOFS_MEMALLOC_H_

#include <stdlib.h>
#include <stdint.h>

struct silofs_iovec;

/* allocation flags */
enum silofs_allocf {
	SILOFS_ALLOCF_NONE     = 0x00,
	SILOFS_ALLOCF_BZERO    = 0x01,
	SILOFS_ALLOCF_TRYPUNCH = 0x02,
	SILOFS_ALLOCF_NOPUNCH  = 0x04,
};

/* allocator stats */
struct silofs_alloc_stat {
	size_t nbytes_max;
	size_t nbytes_use;
	size_t nbytes_ext;
};

/* allocator interface */
struct silofs_alloc {
	void *(*malloc_fn)(struct silofs_alloc *alloc, size_t size, int flags);
	void (*free_fn)(struct silofs_alloc *alloc, void *ptr, size_t size,
	                int flags);
	void (*stat_fn)(const struct silofs_alloc *alloc,
	                struct silofs_alloc_stat  *out_stat);
};

/* default allocator interface (C malloc/free) */
extern struct silofs_alloc *silofs_default_alloc;

/* allocator via standard C malloc/free */
struct silofs_stdalloc {
	struct silofs_alloc alloc;
	unsigned long       nbytes_max;
	unsigned long       nbytes_use;
};

int silofs_stdalloc_init(struct silofs_stdalloc *sal, size_t memsize);

int silofs_stdalloc_fini(struct silofs_stdalloc *sal);

/* memory allocation convenience wrappers */
void *silofs_memalloc(struct silofs_alloc *alloc, size_t n, int flags);

void silofs_memfree(struct silofs_alloc *alloc, void *p, size_t n, int flags);

void silofs_memstat(const struct silofs_alloc *alloc,
                    struct silofs_alloc_stat  *out_stat);

/* extra memory utilities */
void silofs_memzero(void *s, size_t n);

void silofs_memffff(void *s, size_t n);

int silofs_zmalloc(size_t sz, void **out_mem);

void silofs_zfree(void *mem, size_t sz);

int silofs_memlimits(uint64_t *out_phy, uint64_t *out_as);

#endif /* SILOFS_MEMALLOC_H_ */
