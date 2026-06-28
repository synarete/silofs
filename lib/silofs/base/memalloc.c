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
#include <silofs/configs.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <silofs/ccattr.h>
#include <silofs/consts.h>
#include <silofs/macros.h>
#include <silofs/syscall.h>
#include <silofs/memalloc.h>
#include <silofs/panic.h>
#include <silofs/base/utility.h>
#include <silofs/base/atomic.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_memzero(void *s, size_t n)
{
	silofs_assert_not_null(s);
	silofs_assert_lt(n, SILOFS_GIGA);

	memset(s, 0, n);
}

void silofs_memffff(void *s, size_t n)
{
	silofs_assert_not_null(s);
	silofs_assert_lt(n, SILOFS_GIGA);

	memset(s, 0xff, n);
}

static size_t alignment_of(size_t sz)
{
	const size_t al_min = 64;
	const size_t al_max = 65536;
	size_t al;

	if (sz <= al_min) {
		al = al_min;
	} else if (sz >= al_max) {
		al = al_max;
	} else {
		al = (size_t)(UINT64_C(1) << (64 - silofs_clz_u64(sz - 1)));
	}
	return al;
}

static int cstd_memalign(size_t sz, void **out_mem)
{
	const size_t align_size = alignment_of(sz);

	errno = 0;
	if (silofs_unlikely(sz == 0)) {
		*out_mem = nullptr;
	} else if ((sz % align_size) == 0) {
		*out_mem = aligned_alloc(align_size, sz);
	} else {
		*out_mem = malloc(sz);
	}
	if (silofs_unlikely(*out_mem == nullptr)) {
		return errno ? -abs(errno) : -ENOMEM;
	}
	return 0;
}

static void cstd_memfree(void *mem, size_t sz)
{
	if ((mem != nullptr) && (sz > 0)) {
		/*
		 * TODO-0064: use 'free_aligned_sized' (glibc >= 2.43)
		 *
		 * Start using C23 sized allocations.
		 */
		free(mem);
	}
}

static void do_memzero(void *p, size_t n)
{
	if ((p != nullptr) && (n > 0)) {
		silofs_memzero(p, n);
	}
}

int silofs_zmalloc(size_t sz, void **out_mem)
{
	int err;

	*out_mem = nullptr;
	err      = cstd_memalign(sz, out_mem);
	if (err) {
		return err;
	}
	do_memzero(*out_mem, sz);
	return 0;
}

void silofs_zfree(void *mem, size_t sz)
{
	do_memzero(mem, sz);
	cstd_memfree(mem, sz);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_stdalloc *
alloc_to_stdalloc(const struct silofs_alloc *alloc)
{
	const struct silofs_stdalloc *stdal;

	stdal = silofs_container_of(alloc, struct silofs_stdalloc, alloc);
	return silofs_unconst(stdal);
}

static void *
stdalloc_malloc(struct silofs_stdalloc *stdal, size_t n, int flags)
{
	void *ptr = nullptr;
	int err;

	err = cstd_memalign(n, &ptr);
	if (err) {
		return nullptr;
	}
	silofs_atomic_sqc_addul(&stdal->nbytes_use, n);
	silofs_unused(flags);
	return ptr;
}

static void
stdalloc_free(struct silofs_stdalloc *stdal, void *ptr, size_t n, int flags)
{
	silofs_unused(flags);
	if ((ptr != nullptr) && (n > 0)) {
		cstd_memfree(ptr, n);
		silofs_atomic_sqc_subul(&stdal->nbytes_use, n);
	}
}

static void stdalloc_stat(struct silofs_stdalloc *stdal,
                          struct silofs_alloc_stat *out_stat)
{
	silofs_memzero(out_stat, sizeof(*out_stat));
	out_stat->nbytes_max = silofs_atomic_sqc_getul(&stdal->nbytes_max);
	out_stat->nbytes_use = silofs_atomic_sqc_getul(&stdal->nbytes_use);
}

static void *stdal_malloc(struct silofs_alloc *alloc, size_t n, int flags)
{
	return stdalloc_malloc(alloc_to_stdalloc(alloc), n, flags);
}

static void
stdal_free(struct silofs_alloc *alloc, void *ptr, size_t n, int flags)
{
	stdalloc_free(alloc_to_stdalloc(alloc), ptr, n, flags);
}

static void stdal_stat(const struct silofs_alloc *alloc,
                       struct silofs_alloc_stat *out_stat)
{
	stdalloc_stat(alloc_to_stdalloc(alloc), out_stat);
}

int silofs_stdalloc_init(struct silofs_stdalloc *sal, size_t memsize)
{
	silofs_memzero(sal, sizeof(*sal));
	sal->alloc.malloc_fn = stdal_malloc;
	sal->alloc.free_fn   = stdal_free;
	sal->alloc.stat_fn   = stdal_stat;
	sal->nbytes_max      = memsize;
	return 0;
}

int silofs_stdalloc_fini(struct silofs_stdalloc *sal)
{
	silofs_memzero(sal, sizeof(*sal));
	return 0;
}

static struct silofs_stdalloc g_stdalloc = {
	.alloc.malloc_fn = stdal_malloc,
	.alloc.free_fn   = stdal_free,
	.alloc.stat_fn   = stdal_stat,
	.nbytes_max      = UINT32_MAX,
};

struct silofs_alloc *silofs_default_alloc = &g_stdalloc.alloc;

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void post_malloc(void *ptr, size_t size, int flags)
{
	if ((ptr != nullptr) && (flags & SILOFS_ALLOCF_BZERO)) {
		silofs_memzero(ptr, size);
	}
}

static void pre_free(void *ptr, size_t size, int flags)
{
	if ((ptr != nullptr) && (flags & SILOFS_ALLOCF_BZERO)) {
		silofs_memzero(ptr, size);
	}
}

void *silofs_memalloc(struct silofs_alloc *alloc, size_t n, int flags)
{
	void *ptr = nullptr;

	if (silofs_likely(alloc->malloc_fn && n)) {
		ptr = alloc->malloc_fn(alloc, n, flags);
		post_malloc(ptr, n, flags);
	}
	return ptr;
}

void silofs_memfree(struct silofs_alloc *alloc, void *ptr, size_t n, int flags)
{
	if (silofs_likely((ptr != nullptr) && n && alloc->free_fn)) {
		pre_free(ptr, n, flags);
		alloc->free_fn(alloc, ptr, n, flags);
	}
}

void *
silofs_memdup(struct silofs_alloc *alloc, const void *ptr, size_t n, int flags)
{
	void *dup;

	dup = silofs_memalloc(alloc, n, flags);
	if (dup != nullptr) {
		memcpy(dup, ptr, n);
	}
	return dup;
}

void silofs_memstat(const struct silofs_alloc *alloc,
                    struct silofs_alloc_stat *out_stat)
{
	silofs_memzero(out_stat, sizeof(*out_stat));
	if (alloc->stat_fn != nullptr) {
		alloc->stat_fn(alloc, out_stat);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int getmemlimit(uint64_t *out_lim)
{
	struct rlimit rlim = { .rlim_cur = 0 };
	int err;

	err      = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	*out_lim = err ? 0 : rlim.rlim_cur;
	return err;
}

static uint64_t calcmemsize(void)
{
	const uint64_t page_size  = (uint64_t)silofs_sc_page_size();
	const uint64_t phys_pages = (uint64_t)silofs_sc_phys_pages();

	return page_size * phys_pages;
}

int silofs_memlimits(uint64_t *out_phy, uint64_t *out_as)
{
	*out_phy = calcmemsize();
	return getmemlimit(out_as);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void burnstack_recursively(int depth, int nbytes)
{
	char buf[1024];
	const int32_t cnt = silofs_min_i32((int)sizeof(buf), nbytes);

	if ((cnt > 0) && (depth >= 0) && (depth < 64)) {
		memset(buf, 0xF4 ^ depth, (size_t)cnt);
		burnstack_recursively(depth + 1, nbytes - cnt);
	}
}

void silofs_burnstack(void)
{
	burnstack_recursively(0, 4096);
}
