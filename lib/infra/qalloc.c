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
#include <silofs/configs.h>
#include <silofs/consts.h>
#include <silofs/syscall.h>
#include <silofs/macros.h>
#include <silofs/errors.h>
#include <silofs/list.h>
#include <silofs/utility.h>
#include <silofs/iovec.h>
#include <silofs/panic.h>
#include <silofs/logging.h>
#include <silofs/random.h>
#include <silofs/thread.h>
#include <silofs/atomic.h>
#include <silofs/qalloc.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#define QALLOC_MALLOC_SIZE_MAX  (64 * SILOFS_UMEGA)
#define QALLOC_PAGE_SIZE        (4 * SILOFS_KILO)

#define MPAGE_SIZE              QALLOC_PAGE_SIZE
#define MPAGE_NSEGS             (MPAGE_SIZE / MSLAB_SEG_SIZE)
#define MPAGES_LARGE_CHUNK      (16)

#define MSLAB_SEG_SIZE          (32)
#define MSLAB_SIZE_MIN          MSLAB_SEG_SIZE
#define MSLAB_SIZE_MAX          (MPAGE_SIZE / 2)

#define MSLAB_INDEX_NONE        (0)

#define QALLOC_NSLABS           (MSLAB_SIZE_MAX / MSLAB_SIZE_MIN)

#define STATICASSERT_EQ(a_, b_) \
	SILOFS_STATICASSERT_EQ(a_, b_)

#define STATICASSERT_SIZEOF(t_, s_) \
	SILOFS_STATICASSERT_EQ(sizeof(t_), s_)

#define STATICASSERT_SIZEOF_GE(t_, s_) \
	SILOFS_STATICASSERT_GE(sizeof(t_), s_)

#define STATICASSERT_SIZEOF_LE(t_, s_) \
	SILOFS_STATICASSERT_LE(sizeof(t_), s_)


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* TODO: Use AVL instead of linked-list for free-chunks? */

struct silofs_slab_seg {
	struct silofs_list_head link;
	uint8_t pad[16];
} silofs_aligned32;


union silofs_page {
	struct silofs_slab_seg seg[MPAGE_NSEGS];
	uint8_t data[MPAGE_SIZE];
} silofs_packed_aligned64;


struct silofs_page_info {
	struct silofs_list_head  lh;
	struct silofs_page_info *prev;
	union silofs_page       *pg;
	uint64_t        pg_index;
	uint64_t        pg_count; /* num pages free/used */
	uint16_t        pg_free;
	uint16_t        pg_reserved;
	int32_t         slab_index;
	int32_t         slab_nused;
	int32_t         slab_nelems;
} __attribute__((__aligned__(SILOFS_CACHELINE_SIZE_DFL)));


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void static_assert_alloc_sizes(void)
{
	const struct silofs_qalloc *qal = NULL;

	STATICASSERT_SIZEOF(struct silofs_slab_seg, MSLAB_SEG_SIZE);
	STATICASSERT_SIZEOF(union silofs_page, MPAGE_SIZE);
	STATICASSERT_SIZEOF(struct silofs_page_info, 64);
	STATICASSERT_SIZEOF_LE(struct silofs_slab_seg,
	                       SILOFS_CACHELINE_SIZE_MAX);
	STATICASSERT_SIZEOF_GE(struct silofs_page_info,
	                       SILOFS_CACHELINE_SIZE_DFL);
	STATICASSERT_EQ(SILOFS_ARRAY_SIZE(qal->slabs), QALLOC_NSLABS);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nbytes_to_npgs(size_t nbytes)
{
	return (nbytes + MPAGE_SIZE - 1) / MPAGE_SIZE;
}

static ssize_t npgs_to_nbytes(size_t npgs)
{
	return (ssize_t)(npgs * MPAGE_SIZE);
}

static bool isslabsize(size_t size)
{
	return ((size > 0) && (size <= MSLAB_SIZE_MAX));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void apply_allocf(void *ptr, size_t size, int flags)
{
	if (silofs_likely(ptr != NULL)) {
		if (flags & SILOFS_ALLOCF_BZERO) {
			memset(ptr, 0, size);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_qalloc *alloc_to_qalloc(const struct silofs_alloc *alloc)
{
	const struct silofs_qalloc *qal;

	qal = silofs_container_of2(alloc, struct silofs_qalloc, alloc);
	return silofs_unconst(qal);
}

static void *qal_malloc(struct silofs_alloc *aif, size_t nbytes, int flags)
{
	struct silofs_qalloc *qal = alloc_to_qalloc(aif);

	return silofs_qalloc_malloc(qal, nbytes, flags);
}

static void qal_free(struct silofs_alloc *aif,
                     void *ptr, size_t nbytes, int flags)
{
	struct silofs_qalloc *qal = alloc_to_qalloc(aif);

	silofs_qalloc_free(qal, ptr, nbytes, flags);
}

static void qal_stat(const struct silofs_alloc *alloc,
                     struct silofs_alloc_stat *out_stat)
{
	const struct silofs_qalloc *qal = alloc_to_qalloc(alloc);

	silofs_qalloc_stat(qal, out_stat);
}

static int qal_resolve(const struct silofs_alloc *alloc,
                       void *ptr, size_t len, struct silofs_iovec *iov)
{
	const struct silofs_qalloc *qal = alloc_to_qalloc(alloc);

	return silofs_qalloc_resolve(qal, ptr, len, iov);
}

void *silofs_allocate(struct silofs_alloc *alloc, size_t size, int flags)
{
	void *ptr = NULL;

	if (silofs_likely(alloc->malloc_fn != NULL) && size) {
		ptr = alloc->malloc_fn(alloc, size, flags);
	}
	return ptr;
}

void silofs_deallocate(struct silofs_alloc *alloc,
                       void *ptr, size_t size, int flags)
{
	if (silofs_likely((ptr != NULL) && size && (alloc->free_fn != NULL))) {
		alloc->free_fn(alloc, ptr, size, flags);
	}
}

void silofs_allocstat(const struct silofs_alloc *alloc,
                      struct silofs_alloc_stat *out_stat)
{
	if (alloc->stat_fn != NULL) {
		alloc->stat_fn(alloc, out_stat);
	} else {
		memset(out_stat, 0, sizeof(*out_stat));
	}
}

int silofs_allocresolve(const struct silofs_alloc *alloc, void *ptr,
                        size_t len, struct silofs_iovec *iov)
{
	int ret = -ENOTSUP;

	if (alloc->resolve_fn != NULL) {
		ret = alloc->resolve_fn(alloc, ptr, len, iov);
	} else {
		memset(iov, 0, sizeof(*iov));
		iov->iov_fd = -1;
	}
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int memfd_setup(struct silofs_memfd *memfd,
                       const char *name, size_t size)
{
	void *mem = NULL;
	const int prot = PROT_READ | PROT_WRITE;
	const int flags = MAP_SHARED;
	int fd = -1;
	int err;

	err = silofs_sys_memfd_create(name, 0, &fd);
	if (err) {
		return err;
	}
	err = silofs_sys_ftruncate(fd, (loff_t)size);
	if (err) {
		silofs_sys_close(fd);
		return err;
	}
	err = silofs_sys_mmap(NULL, size, prot, flags, fd, 0, &mem);
	if (err) {
		silofs_sys_close(fd);
		return err;
	}
	memfd->fd = fd;
	memfd->mem = mem;
	memfd->msz = size;
	return 0;
}

static int memfd_close(struct silofs_memfd *memfd)
{
	int err;

	if (!memfd->msz) {
		return 0;
	}
	err = silofs_sys_munmap(memfd->mem, memfd->msz);
	if (err) {
		return err;
	}
	err = silofs_sys_close(memfd->fd);
	if (err) {
		return err;
	}
	memfd->mem = NULL;
	memfd->msz = 0;
	memfd->fd = -1;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_page_info *
pgi_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_page_info *pgi =
	        silofs_container_of2(lh, struct silofs_page_info, lh);

	return silofs_unconst(pgi);
}

static void pgi_update(struct silofs_page_info *pgi,
                       struct silofs_page_info *prev, size_t count)
{
	pgi->prev = prev;
	pgi->pg_count = count;
	pgi->pg_free = 1;
}

static void pgi_mute(struct silofs_page_info *pgi)
{
	pgi_update(pgi, NULL, 0);
}

static void pgi_init(struct silofs_page_info *pgi,
                     union silofs_page *pg, size_t pg_index)
{
	silofs_list_head_init(&pgi->lh);
	pgi_mute(pgi);
	pgi->pg = pg;
	pgi->pg_index = pg_index;
	pgi->slab_nused = 0;
	pgi->slab_index = MSLAB_INDEX_NONE;
}

static void pgi_push_head(struct silofs_page_info *pgi,
                          struct silofs_list_head *ls)
{
	silofs_list_push_front(ls, &pgi->lh);
}

static void pgi_push_tail(struct silofs_page_info *pgi,
                          struct silofs_list_head *ls)
{
	silofs_list_push_back(ls, &pgi->lh);
}

static void pgi_unlink(struct silofs_page_info *pgi)
{
	silofs_list_head_remove(&pgi->lh);
}

static void pgi_unlink_mute(struct silofs_page_info *pgi)
{
	pgi_unlink(pgi);
	pgi_mute(pgi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
calc_mem_sizes(size_t npgs, size_t *out_data_msz, size_t *out_meta_msz)
{
	const size_t npgs_max = UINT_MAX; /* TODO: proper upper limit */
	int ret = -EINVAL;

	if ((npgs > 0) && (npgs <= npgs_max)) {
		*out_data_msz = npgs * sizeof(union silofs_page);
		*out_meta_msz = npgs * sizeof(struct silofs_page_info);
		ret = 0;
	}
	return ret;
}

static void *pgal_page_at(const struct silofs_pgal *pgal, size_t idx)
{
	union silofs_page *pg_arr = pgal->data.mem;

	return pg_arr + idx;
}

static struct silofs_page_info *
pgal_page_info_at(const struct silofs_pgal *pgal, size_t idx)
{
	struct silofs_page_info *pgi_arr = pgal->meta.mem;

	silofs_assert_lt(idx, pgal->npgs_max);

	return pgi_arr + idx;
}

static struct silofs_page_info *
pgal_next(const struct silofs_pgal *pgal,
          const struct silofs_page_info *pgi, size_t npgs)
{
	const size_t idx_next = pgi->pg_index + npgs;
	struct silofs_page_info *pgi_next = NULL;

	if (idx_next < pgal->npgs_max) {
		pgi_next = pgal_page_info_at(pgal, idx_next);
	}
	return pgi_next;
}

static int pgal_init_memfds(struct silofs_pgal *pgal, size_t npgs)
{
	char name[256] = "";
	const pid_t pid = getpid();
	size_t data_msz;
	size_t meta_msz;
	uint32_t id;
	int err;

	silofs_getentropy(&id, sizeof(id));
	err = calc_mem_sizes(npgs, &data_msz, &meta_msz);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "silofs-data-%d-%08x", pid, id);
	err = memfd_setup(&pgal->data, name, data_msz);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "silofs-meta-%d-%08x", pid, id);
	err = memfd_setup(&pgal->meta, name, meta_msz);
	if (err) {
		memfd_close(&pgal->data);
		return err;
	}
	pgal->npgs_max = npgs;
	return 0;
}

static void pgal_update(const struct silofs_pgal *pgal,
                        struct silofs_page_info *pgi, size_t npgs)
{
	struct silofs_page_info *pgi_next;

	pgi_next = pgal_next(pgal, pgi, npgs);
	if (pgi_next != NULL) {
		pgi_next->prev = pgi;
	}
}

static void pgal_add_free(struct silofs_pgal *pgal,
                          struct silofs_page_info *pgi,
                          struct silofs_page_info *prev, size_t npgs)
{
	struct silofs_list_head *free_list = &pgal->free_pgs;

	pgi_update(pgi, prev, npgs);
	pgal_update(pgal, pgi, npgs);
	if (npgs >= MPAGES_LARGE_CHUNK) {
		pgi_push_head(pgi, free_list);
	} else {
		pgi_push_tail(pgi, free_list);
	}
}

static void pgal_init_page_infos(struct silofs_pgal *pgal)
{
	union silofs_page *pg;
	struct silofs_page_info *pgi;

	for (size_t i = 0; i < pgal->npgs_max; ++i) {
		pg = pgal_page_at(pgal, i);
		pgi = pgal_page_info_at(pgal, i);
		pgi_init(pgi, pg, i);
	}
	pgi = pgal_page_info_at(pgal, 0);
	pgal_add_free(pgal, pgi, NULL, pgal->npgs_max);
}

static int pgal_init_mutex(struct silofs_pgal *pgal)
{
	return silofs_mutex_init(&pgal->mutex);
}

static void pgal_fini_mutex(struct silofs_pgal *pgal)
{
	silofs_mutex_fini(&pgal->mutex);
}

static int pgal_init(struct silofs_pgal *pgal, size_t memsize)
{
	const size_t npgs = memsize / MPAGE_SIZE;
	int err;

	silofs_memzero(pgal, sizeof(*pgal));
	silofs_list_init(&pgal->free_pgs);

	err = pgal_init_mutex(pgal);
	if (err) {
		return err;
	}
	err = pgal_init_memfds(pgal, npgs);
	if (err) {
		pgal_fini_mutex(pgal);
		return err;
	}
	pgal_init_page_infos(pgal);
	return 0;
}

static int pgal_fini(struct silofs_pgal *pgal)
{
	int err1 = 0;
	int err2 = 0;

	pgal_fini_mutex(pgal);
	if (pgal->npgs_max) {
		err1 = memfd_close(&pgal->data);
		err2 = memfd_close(&pgal->meta);
	}
	return err1 ? err1 : err2;
}

static void pgal_lock(struct silofs_pgal *pgal)
{
	silofs_mutex_lock(&pgal->mutex);
}

static void pgal_unlock(struct silofs_pgal *pgal)
{
	silofs_mutex_unlock(&pgal->mutex);
}

static struct silofs_page_info *
pgal_search_free_from_tail(struct silofs_pgal *pgal, size_t npgs)
{
	struct silofs_page_info *pgi;
	struct silofs_list_head *itr;
	struct silofs_list_head *free_list = &pgal->free_pgs;

	itr = free_list->prev;
	while (itr != free_list) {
		pgi = pgi_from_lh(itr);
		if (pgi->pg_count >= npgs) {
			return pgi;
		}
		itr = itr->prev;
	}
	return NULL;
}

static struct silofs_page_info *
pgal_search_free_from_head(struct silofs_pgal *pgal, size_t npgs)
{
	struct silofs_page_info *pgi;
	struct silofs_list_head *itr;
	struct silofs_list_head *free_list = &pgal->free_pgs;

	itr = free_list->next;
	while (itr != free_list) {
		pgi = pgi_from_lh(itr);
		if (pgi->pg_count >= npgs) {
			return pgi;
		}
		itr = itr->next;
	}
	return NULL;
}

static struct silofs_page_info *
pgal_search_free_list(struct silofs_pgal *pgal, size_t npgs)
{
	struct silofs_page_info *pgi = NULL;

	if ((pgal->npgs_use + npgs) <= pgal->npgs_max) {
		if (npgs >= MPAGES_LARGE_CHUNK) {
			pgi = pgal_search_free_from_head(pgal, npgs);
		} else {
			pgi = pgal_search_free_from_tail(pgal, npgs);
		}
	}
	return pgi;
}

static struct silofs_page_info *
pgal_do_alloc_npgs(struct silofs_pgal *pgal, size_t npgs)
{
	struct silofs_page_info *pgi;
	struct silofs_page_info *pgi_next = NULL;

	pgi = pgal_search_free_list(pgal, npgs);
	if (pgi == NULL) {
		return NULL;
	}
	pgi_unlink(pgi);
	pgi->pg_free = 0;
	if (pgi->pg_count > npgs) {
		pgi_next = pgal_next(pgal, pgi, npgs);
		pgal_add_free(pgal, pgi_next, pgi, pgi->pg_count - npgs);
		pgi->pg_count = npgs;
	}
	return pgi;
}

static struct silofs_page_info *
pgal_alloc_npgs(struct silofs_pgal *pgal, size_t npgs)
{
	struct silofs_page_info *pgi;

	pgal_lock(pgal);
	pgi = pgal_do_alloc_npgs(pgal, npgs);
	pgal_unlock(pgal);
	return pgi;
}


static int pgal_do_alloc_multi_pg(struct silofs_pgal *pgal,
                                  size_t nbytes, void **out_ptr)
{
	size_t npgs;
	struct silofs_page_info *pgi;

	npgs = nbytes_to_npgs(nbytes);
	pgi = pgal_do_alloc_npgs(pgal, npgs);
	if (pgi == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_ptr = pgi->pg->data;
	pgal->npgs_use += npgs;
	silofs_assert_ge(pgal->npgs_max, pgal->npgs_use);
	return 0;
}

static int pgal_alloc_multi_pg(struct silofs_pgal *pgal,
                               size_t nbytes, void **out_ptr)
{
	int err;

	pgal_lock(pgal);
	err = pgal_do_alloc_multi_pg(pgal, nbytes, out_ptr);
	pgal_unlock(pgal);
	return err;
}

static loff_t pgal_ptr_to_off(const struct silofs_pgal *pgal, const void *ptr)
{
	return (const char *)ptr - (const char *)pgal->data.mem;
}

static size_t pgal_ptr_to_pgn(const struct silofs_pgal *pgal, const void *ptr)
{
	const loff_t off = pgal_ptr_to_off(pgal, ptr);

	return (size_t)off / MPAGE_SIZE;
}

static bool pgal_isinrange(const struct silofs_pgal *pgal,
                           const void *ptr, size_t nb)
{
	const loff_t off = pgal_ptr_to_off(pgal, ptr);
	const loff_t end = off + (loff_t)nb;

	return (off >= 0) && (end <= (loff_t)pgal->data.msz);
}

static struct silofs_page_info *
pgal_page_info_of(const struct silofs_pgal *pgal, const void *ptr)
{
	const size_t pgn = pgal_ptr_to_pgn(pgal, ptr);

	silofs_assert_lt(pgn, pgal->npgs_max);
	return pgal_page_info_at(pgal, pgn);
}


static struct silofs_slab_seg *
pgal_slab_seg_of(const struct silofs_pgal *pgal, const void *ptr)
{
	struct silofs_slab_seg *seg;
	loff_t off;
	size_t idx;

	seg = pgal->data.mem;
	off = pgal_ptr_to_off(pgal, ptr);
	idx = (size_t)off / sizeof(*seg);

	return &seg[idx];
}

static int pgal_check_by_page(const struct silofs_pgal *pgal,
                              const void *ptr, size_t nbytes)
{
	const struct silofs_page_info *pgi;
	size_t npgs;

	npgs = nbytes_to_npgs(nbytes);
	if (pgal->npgs_use < npgs) {
		return -EINVAL;
	}
	pgi = pgal_page_info_of(pgal, ptr);
	if (pgi == NULL) {
		return -EINVAL;
	}
	if (pgi->pg_count != npgs) {
		return -EINVAL;
	}
	return 0;
}

static void pgal_punch_hole_at(const struct silofs_pgal *pgal,
                               struct silofs_page_info *pgi, size_t npgs)
{
	loff_t off;
	ssize_t len;
	int mode;
	int fd;
	int err;

	off = npgs_to_nbytes(pgi->pg_index);
	len = npgs_to_nbytes(npgs);
	mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	fd = pgal->data.fd;
	err = silofs_sys_fallocate(fd, mode, off, len);
	if (err) {
		silofs_panic("failed to fallocate punch-hole in memory: "
		             "fd=%d off=%ld len=%ld mode=0x%x err=%d",
		             fd, off, len, mode, err);
	}
}

static void
pgal_update_released(const struct silofs_pgal *pgal,
                     struct silofs_page_info *pgi, size_t npgs, int flags)
{
	const size_t npgs_punch_threshold = (SILOFS_UMEGA / MPAGE_SIZE);

	if ((npgs >= npgs_punch_threshold) || (flags & SILOFS_ALLOCF_PUNCH)) {
		pgal_punch_hole_at(pgal, pgi, npgs);
	}
}

static int
pgal_do_free_npgs(struct silofs_pgal *pgal,
                  struct silofs_page_info *pgi, size_t npgs, int flags)
{
	struct silofs_page_info *pgi_next;
	struct silofs_page_info *pgi_prev;

	pgi_next = pgal_next(pgal, pgi, npgs);
	if (pgi_next && pgi_next->pg_free) {
		npgs += pgi_next->pg_count;
		pgi_unlink_mute(pgi_next);
	}
	pgi_prev = pgi->prev;
	if (pgi_prev && pgi_prev->pg_free) {
		npgs += pgi_prev->pg_count;
		pgi_mute(pgi);
		pgi = pgi_prev;
		pgi_prev = pgi_prev->prev;
		pgi_unlink_mute(pgi);
	}

	pgal_update_released(pgal, pgi, npgs, flags);
	pgal_add_free(pgal, pgi, pgi_prev, npgs);
	return 0;
}

static int pgal_free_npgs(struct silofs_pgal *pgal,
                          struct silofs_page_info *pgi, size_t npgs, int flags)
{
	int err;

	pgal_lock(pgal);
	err = pgal_do_free_npgs(pgal, pgi, npgs, flags);
	pgal_unlock(pgal);
	return err;
}

static int pgal_do_free_multi_pg(struct silofs_pgal *pgal,
                                 void *ptr, size_t nbytes, int flags)
{
	struct silofs_page_info *pgi;
	size_t npgs;
	int err;

	err = pgal_check_by_page(pgal, ptr, nbytes);
	if (err) {
		return err;
	}
	npgs = nbytes_to_npgs(nbytes);
	pgi = pgal_page_info_of(pgal, ptr);
	pgal_do_free_npgs(pgal, pgi, npgs, flags);
	pgal->npgs_use -= npgs;
	return 0;
}

static int pgal_free_multi_pg(struct silofs_pgal *pgal,
                              void *ptr, size_t nbytes, int flags)
{
	int err;

	pgal_lock(pgal);
	err = pgal_do_free_multi_pg(pgal, ptr, nbytes, flags);
	pgal_unlock(pgal);
	return err;
}

static void *pgal_base_of(const struct silofs_pgal *pgal,
                          void *ptr, size_t len)
{
	struct silofs_slab_seg *seg = NULL;
	const struct silofs_page_info *pgi = NULL;
	void *base = NULL;

	if (pgal_isinrange(pgal, ptr, len)) {
		if (isslabsize(len)) {
			seg = pgal_slab_seg_of(pgal, ptr);
			if (seg != NULL) {
				base = seg;
			}
		} else {
			pgi = pgal_page_info_of(pgal, ptr);
			if (pgi != NULL) {
				base = pgi->pg;
			}
		}
	}
	return base;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_slab_seg *
link_to_slab_seg(const struct silofs_list_head *link)
{
	const struct silofs_slab_seg *seg =
	        silofs_container_of2(link, struct silofs_slab_seg, link);

	return silofs_unconst(seg);
}

static struct silofs_list_head *slab_seg_to_link(struct silofs_slab_seg *seg)
{
	return &seg->link;
}

static bool slab_issize(size_t size)
{
	return ((size > 0) && (size <= MSLAB_SIZE_MAX));
}

static size_t slab_size_to_sindex(size_t size)
{
	silofs_assert(slab_issize(size));
	silofs_assert_gt(size, 0);

	return ((size - 1) / MSLAB_SEG_SIZE) + 1;
}

static int slab_init(struct silofs_slab *slab, struct silofs_pgal *pgal,
                     unsigned int sindex, unsigned int elemsz)
{
	silofs_list_init(&slab->free_list);
	slab->pgal = pgal;
	slab->nfree = 0;
	slab->nused = 0;
	slab->elemsz = elemsz;
	slab->sindex = sindex;
	return silofs_mutex_init(&slab->mutex);
}

static void slab_fini(struct silofs_slab *slab)
{
	silofs_mutex_fini(&slab->mutex);
	silofs_list_fini(&slab->free_list);
	slab->elemsz = 0;
	slab->nfree = 0;
	slab->nused = 0;
	slab->sindex = UINT_MAX;
	slab->pgal = NULL;
}

static size_t slab_step_nsegs(const struct silofs_slab *slab)
{
	const struct silofs_slab_seg *seg = NULL;

	return SILOFS_DIV_ROUND_UP(slab->elemsz, sizeof(*seg));
}

static void slab_expand(struct silofs_slab *slab, struct silofs_page_info *pgi)
{
	struct silofs_slab_seg *seg;
	union silofs_page *pg = pgi->pg;
	const size_t step = slab_step_nsegs(slab);
	const size_t nsegs = SILOFS_ARRAY_SIZE(pg->seg);

	pgi->slab_index = (int)slab->sindex;
	pgi->slab_nelems = (int)(sizeof(*pg) / slab->elemsz);
	pgi->slab_nused = 0;
	for (size_t i = 0; (i + step) <= nsegs; i += step) {
		seg = &pg->seg[i];
		silofs_list_push_back(&slab->free_list, &seg->link);
		slab->nfree++;
	}
}

static void slab_shrink(struct silofs_slab *slab, struct silofs_page_info *pgi)
{
	struct silofs_slab_seg *seg;
	union silofs_page *pg = pgi->pg;
	const size_t step = slab_step_nsegs(slab);
	const size_t nsegs = SILOFS_ARRAY_SIZE(pg->seg);

	silofs_assert_eq(pgi->slab_index, slab->sindex);
	silofs_assert_eq(pgi->slab_nused, 0);

	for (size_t i = 0; (i + step) <= nsegs; i += step) {
		silofs_assert_gt(slab->nfree, 0);

		seg = &pg->seg[i];
		silofs_list_head_remove(&seg->link);
		slab->nfree--;
	}
	pgi->slab_index = MSLAB_INDEX_NONE;
	pgi->slab_nelems = 0;
}

static struct silofs_slab_seg *slab_alloc(struct silofs_slab *slab)
{
	struct silofs_list_head *lh;
	struct silofs_slab_seg *seg = NULL;

	lh = silofs_list_pop_front(&slab->free_list);
	if (lh == NULL) {
		return NULL;
	}
	silofs_list_head_fini(lh);

	silofs_assert_gt(slab->nfree, 0);
	slab->nfree--;
	slab->nused++;

	seg = link_to_slab_seg(lh);
	return seg;
}

static void slab_free(struct silofs_slab *slab, struct silofs_slab_seg *seg)
{
	struct silofs_list_head *lh;

	lh = slab_seg_to_link(seg);
	silofs_list_push_front(&slab->free_list, lh);
	silofs_assert_gt(slab->nused, 0);
	slab->nused--;
	slab->nfree++;
}

static void slab_lock(struct silofs_slab *slab)
{
	silofs_mutex_lock(&slab->mutex);
}

static void slab_unlock(struct silofs_slab *slab)
{
	silofs_mutex_unlock(&slab->mutex);
}

static int slab_require_space(struct silofs_slab *slab)
{
	struct silofs_page_info *pgi;

	if (slab->nfree > 0) {
		return 0;
	}
	pgi = pgal_alloc_npgs(slab->pgal, 1);
	if (pgi == NULL) {
		return -SILOFS_ENOMEM;
	}
	slab_expand(slab, pgi);
	return 0;
}

static struct silofs_slab_seg *
slab_alloc_and_update(struct silofs_slab *slab)
{
	struct silofs_slab_seg *seg;
	struct silofs_page_info *pgi;

	seg = slab_alloc(slab);
	if (seg == NULL) {
		return NULL;
	}
	pgi = pgal_page_info_of(slab->pgal, seg);

	silofs_assert_lt(pgi->slab_nused, pgi->slab_nelems);
	pgi->slab_nused += 1;
	return seg;
}

static int slab_do_alloc_seg(struct silofs_slab *slab,
                             struct silofs_slab_seg **out_seg)
{
	struct silofs_slab_seg *seg;
	int err;

	err = slab_require_space(slab);
	if (err) {
		return err;
	}
	seg = slab_alloc_and_update(slab);
	if (seg == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_seg = seg;
	return 0;
}

static int slab_alloc_seg(struct silofs_slab *slab,
                          struct silofs_slab_seg **out_seg)
{
	int err;

	slab_lock(slab);
	err = slab_do_alloc_seg(slab, out_seg);
	slab_unlock(slab);
	return err;
}

static void slab_free_and_update(struct silofs_slab *slab,
                                 struct silofs_slab_seg *seg, int flags)
{
	struct silofs_page_info *pgi = pgal_page_info_of(slab->pgal, seg);

	silofs_assert_eq(pgi->slab_index, slab->sindex);

	slab_free(slab, seg);
	silofs_assert_le(pgi->slab_nused, pgi->slab_nelems);
	silofs_assert_gt(pgi->slab_nused, 0);

	pgi->slab_nused -= 1;
	if (!pgi->slab_nused) {
		slab_shrink(slab, pgi);
		pgal_free_npgs(slab->pgal, pgi, 1, flags);
	}
}

static int slab_check_seg(const struct silofs_slab *slab,
                          const struct silofs_slab_seg *seg, size_t nb)
{
	const struct silofs_page_info *pgi;
	const size_t seg_size = MSLAB_SEG_SIZE;

	if (!slab->nused) {
		return -EINVAL;
	}
	if (nb > slab->elemsz) {
		return -EINVAL;
	}
	if ((nb + seg_size) < slab->elemsz) {
		return -EINVAL;
	}
	pgi = pgal_page_info_of(slab->pgal, seg);
	if (pgi->slab_index != ((int)slab->sindex)) {
		return -EINVAL;
	}
	if (pgi->slab_nused == 0) {
		return -EINVAL;
	}
	return 0;
}

static int
slab_do_free_seg(struct silofs_slab *slab,
                 struct silofs_slab_seg *seg, size_t nbytes, int flags)
{
	int err;

	err = slab_check_seg(slab, seg, nbytes);
	if (!err) {
		slab_free_and_update(slab, seg, flags);
	}
	return err;
}

static int slab_free_seg(struct silofs_slab *slab,
                         struct silofs_slab_seg *seg, size_t nbytes, int flags)
{
	int err;

	slab_lock(slab);
	err = slab_do_free_seg(slab, seg, nbytes, flags);
	slab_unlock(slab);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int qalloc_init_pgal(struct silofs_qalloc *qal, size_t memsize)
{
	return pgal_init(&qal->pgal, memsize);
}

static int qalloc_fini_pgal(struct silofs_qalloc *qal)
{
	return pgal_fini(&qal->pgal);
}

static int qalloc_init_slabs(struct silofs_qalloc *qal)
{
	unsigned int sindex;
	unsigned int elemsz;
	size_t init_ok = 0;
	int err;

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(qal->slabs); ++i) {
		sindex = (unsigned int)(i + 1);
		elemsz = sindex * MSLAB_SEG_SIZE;
		err = slab_init(&qal->slabs[i], &qal->pgal, sindex, elemsz);
		if (err) {
			goto out_err;
		}
		init_ok++;
	}
	return 0;
out_err:
	for (size_t i = 0; i < init_ok; ++i) {
		slab_fini(&qal->slabs[i]);
	}
	return err;
}

static void qalloc_fini_slabs(struct silofs_qalloc *qal)
{
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(qal->slabs); ++i) {
		slab_fini(&qal->slabs[i]);
	}
}

static int check_memsize(size_t memsize)
{
	static_assert_alloc_sizes();

	if (memsize < (8 * SILOFS_UMEGA)) {
		return -EINVAL;
	}
	if (memsize > (64 * SILOFS_UGIGA)) {
		return -EINVAL;
	}
	return 0;
}

static void qalloc_init_interface(struct silofs_qalloc *qal)
{
	qal->alloc.malloc_fn = qal_malloc;
	qal->alloc.free_fn = qal_free;
	qal->alloc.stat_fn = qal_stat;
	qal->alloc.resolve_fn = qal_resolve;
}

static void qalloc_fini_interface(struct silofs_qalloc *qal)
{
	qal->alloc.malloc_fn = NULL;
	qal->alloc.free_fn = NULL;
	qal->alloc.stat_fn = NULL;
	qal->alloc.resolve_fn = NULL;
}

static int check_mode(int mode)
{
	return ((mode == SILOFS_QALLOC_NORMAL) ||
	        (mode == SILOFS_QALLOC_PEDANTIC)) ? 0 : -EINVAL;
}

int silofs_qalloc_init(struct silofs_qalloc *qal, size_t memsize, int mode)
{
	int err;

	silofs_memzero(qal, sizeof(*qal));
	qal->nbytes_use = 0;
	qal->mode = 0;

	err = check_mode(mode);
	if (err) {
		return err;
	}
	err = check_memsize(memsize);
	if (err) {
		return err;
	}
	err = qalloc_init_pgal(qal, memsize);
	if (err) {
		return err;
	}
	err = qalloc_init_slabs(qal);
	if (err) {
		qalloc_fini_pgal(qal);
		return err;
	}
	qalloc_init_interface(qal);
	qal->mode = mode;

	return 0;
}

int silofs_qalloc_fini(struct silofs_qalloc *qal)
{
	/* TODO: release all pending memory-elements in slabs */
	qalloc_fini_interface(qal);
	qalloc_fini_slabs(qal);
	return qalloc_fini_pgal(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t qalloc_slab_slot_of(const struct silofs_qalloc *qal, size_t size)
{
	const size_t sindex = slab_size_to_sindex(size);

	silofs_assert_le(sindex, SILOFS_ARRAY_SIZE(qal->slabs));
	silofs_assert_gt(sindex, 0);
	return sindex - 1;
}

static struct silofs_slab *
qalloc_slab_of(const struct silofs_qalloc *qal, size_t nbytes)
{
	const struct silofs_slab *slab = NULL;
	const size_t slot = qalloc_slab_slot_of(qal, nbytes);

	if (slot < SILOFS_ARRAY_SIZE(qal->slabs)) {
		slab = &qal->slabs[slot];
	}
	return silofs_unconst(slab);
}

static int qalloc_alloc_by_slab(struct silofs_qalloc *qal, size_t nbytes,
                                struct silofs_slab_seg **out_seg)
{
	struct silofs_slab *slab;
	int err;

	slab = qalloc_slab_of(qal, nbytes);
	if (silofs_likely(slab != NULL)) {
		err = slab_alloc_seg(slab, out_seg);
	} else {
		err = -SILOFS_ENOMEM;
	}
	return err;
}

static int qalloc_check_alloc(const struct silofs_qalloc *qal, size_t nbytes)
{
	const size_t nbytes_max = QALLOC_MALLOC_SIZE_MAX;

	if (qal->pgal.data.mem == NULL) {
		return -SILOFS_ENOMEM;
	}
	if (nbytes > nbytes_max) {
		return -SILOFS_ENOMEM;
	}
	if (!nbytes) {
		return -EINVAL;
	}
	return 0;
}

static int qalloc_alloc_sub_pg(struct silofs_qalloc *qal,
                               size_t nbytes, void **out_ptr)
{
	struct silofs_slab_seg *seg;
	int err;

	err = qalloc_alloc_by_slab(qal, nbytes, &seg);
	if (err) {
		return err;
	}
	*out_ptr = seg;
	return 0;
}

static int qalloc_alloc_multi_pg(struct silofs_qalloc *qal,
                                 size_t nbytes, void **out_ptr)
{
	return pgal_alloc_multi_pg(&qal->pgal, nbytes, out_ptr);
}

static void qalloc_add_nbytes_use(struct silofs_qalloc *qal, size_t nbytes)
{
	silofs_atomic_addul(&qal->nbytes_use, nbytes);
}

static void qalloc_sub_nbytes_use(struct silofs_qalloc *qal, size_t nbytes)
{
	silofs_assert_ge(qal->nbytes_use, nbytes);
	silofs_atomic_subul(&qal->nbytes_use, nbytes);
}

static size_t qalloc_get_nbytes_use(const struct silofs_qalloc *qal)
{
	return silofs_atomic_getul(&qal->nbytes_use);
}

static void qalloc_apply_flags(const struct silofs_qalloc *qal,
                               void *ptr, size_t size, int flags)
{
	apply_allocf(ptr, size, flags);
	silofs_unused(qal);
}

static int qalloc_malloc(struct silofs_qalloc *qal,
                         size_t nbytes, int flags, void **out_ptr)
{
	int err;

	*out_ptr = NULL;
	err = qalloc_check_alloc(qal, nbytes);
	if (err) {
		return err;
	}
	if (isslabsize(nbytes)) {
		err = qalloc_alloc_sub_pg(qal, nbytes, out_ptr);
	} else {
		err = qalloc_alloc_multi_pg(qal, nbytes, out_ptr);
	}
	if (err) {
		return err;
	}
	qalloc_add_nbytes_use(qal, nbytes);
	qalloc_apply_flags(qal, *out_ptr, nbytes, flags);
	return 0;
}

static void qalloc_require_malloc_ok(const struct silofs_qalloc *qal,
                                     size_t nbytes, int err)
{
	if (err) {
		silofs_log_debug("malloc failed: nbytes=%lu "
		                 "data_msz=%lu err=%d",
		                 nbytes, qal->pgal.data.msz, err);
	}
}

void *silofs_qalloc_malloc(struct silofs_qalloc *qal, size_t nbytes, int flags)
{
	void *ptr = NULL;
	int err;

	err = qalloc_malloc(qal, nbytes, flags, &ptr);
	qalloc_require_malloc_ok(qal, nbytes, err);
	return ptr;
}

static int qalloc_check_free(const struct silofs_qalloc *qal,
                             const void *ptr, size_t nbytes)
{
	if (!qal->mode || (ptr == NULL)) {
		return -EINVAL;
	}
	if (!nbytes || (nbytes > QALLOC_MALLOC_SIZE_MAX)) {
		return -EINVAL;
	}
	if (!pgal_isinrange(&qal->pgal, ptr, nbytes)) {
		return -EINVAL;
	}
	return 0;
}

static int
qalloc_check_slab_seg_of(const struct silofs_qalloc *qal,
                         const struct silofs_slab_seg *seg, size_t nb)
{
	const struct silofs_slab *slab;
	int err = -EINVAL;

	slab = qalloc_slab_of(qal, nb);
	if (slab != NULL) {
		err = slab_check_seg(slab, seg, nb);
	}
	return err;
}

static int
qalloc_free_by_slab(struct silofs_qalloc *qal,
                    struct silofs_slab_seg *seg, size_t nbytes, int flags)
{
	struct silofs_slab *slab;
	int err = -EINVAL;

	slab = qalloc_slab_of(qal, nbytes);
	if (slab != NULL) {
		err = slab_free_seg(slab, seg, nbytes, flags);
	}
	return err;
}

static int qalloc_free_sub_pg(struct silofs_qalloc *qal,
                              void *ptr, size_t nbytes, int flags)
{
	struct silofs_slab_seg *seg;

	seg = pgal_slab_seg_of(&qal->pgal, ptr);
	return qalloc_free_by_slab(qal, seg, nbytes, flags);
}

static int qalloc_free_multi_pg(struct silofs_qalloc *qal,
                                void *ptr, size_t nbytes, int flags)
{
	return pgal_free_multi_pg(&qal->pgal, ptr, nbytes, flags);
}

static void
qalloc_wreck_data(const struct silofs_qalloc *qal, void *ptr, size_t nbytes)
{
	const bool pedantic = (qal->mode & SILOFS_QALLOC_PEDANTIC) > 0;

	if (pedantic && ptr) {
		memset(ptr, 0xF3, silofs_min(512, nbytes));
	}
}

static int qalloc_free(struct silofs_qalloc *qal,
                       void *ptr, size_t nbytes, int flags)
{
	int err;

	if ((ptr == NULL) || (nbytes == 0)) {
		return 0;
	}
	err = qalloc_check_free(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	qalloc_apply_flags(qal, ptr, nbytes, flags);
	qalloc_wreck_data(qal, ptr, nbytes);
	if (isslabsize(nbytes)) {
		err = qalloc_free_sub_pg(qal, ptr, nbytes, flags);
	} else {
		err = qalloc_free_multi_pg(qal, ptr, nbytes, flags);
	}
	if (err) {
		return err;
	}
	qalloc_sub_nbytes_use(qal, nbytes);
	return err;
}

static void qalloc_require_free_ok(const struct silofs_qalloc *qal,
                                   const void *ptr, size_t nbytes, int err)
{
	if (err) {
		silofs_panic("free error: ptr=%p nbytes=%lu data_msz=%lu "
		             "err=%d", ptr, nbytes, qal->pgal.data.msz, err);
	}
}

void silofs_qalloc_free(struct silofs_qalloc *qal,
                        void *ptr, size_t nbytes, int flags)
{
	int err;

	err = qalloc_free(qal, ptr, nbytes, flags);
	qalloc_require_free_ok(qal, ptr, nbytes, err);
}

static int qalloc_check_by_slab(const struct silofs_qalloc *qal,
                                const void *ptr, size_t nbytes)
{
	const struct silofs_slab_seg *seg;
	int err = -EINVAL;

	seg = pgal_slab_seg_of(&qal->pgal, ptr);
	if (seg != NULL) {
		err = qalloc_check_slab_seg_of(qal, seg, nbytes);
	}
	return err;
}

static int qalloc_check_by_pgal(const struct silofs_qalloc *qal,
                                const void *ptr, size_t nbytes)
{
	return pgal_check_by_page(&qal->pgal, ptr, nbytes);
}

int silofs_qalloc_mcheck(const struct silofs_qalloc *qal,
                         const void *ptr, size_t nbytes)
{
	int err;

	if ((ptr == NULL) || (nbytes == 0)) {
		return 0;
	}
	err = qalloc_check_free(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	if (isslabsize(nbytes)) {
		err = qalloc_check_by_slab(qal, ptr, nbytes);
	} else {
		err = qalloc_check_by_pgal(qal, ptr, nbytes);
	}
	return err;
}

/*
 * Do not use qalloc_lock/unlock for qalloc_resolve and qalloc_stat as those
 * operations need to be fast and are executed on the data-path. As such, it is
 * better to avoid the heavy locking involved with alloc/dealloc path.
 */
int silofs_qalloc_resolve(const struct silofs_qalloc *qal,
                          void *ptr, size_t len, struct silofs_iovec *iov)
{
	const void *base;

	base = pgal_base_of(&qal->pgal, ptr, len);
	if (silofs_unlikely(base == NULL)) {
		return -ERANGE;
	}
	if (silofs_unlikely(base > ptr)) {
		return -ERANGE;
	}
	iov->iov_off = pgal_ptr_to_off(&qal->pgal, ptr);
	iov->iov_len = len;
	iov->iov_base = ptr;
	iov->iov_fd = qal->pgal.data.fd;
	iov->iov_ref = NULL;
	return 0;
}

void silofs_qalloc_stat(const struct silofs_qalloc *qal,
                        struct silofs_alloc_stat *out_stat)
{
	silofs_memzero(out_stat, sizeof(*out_stat));
	out_stat->nbytes_max = qal->pgal.data.msz;
	out_stat->nbytes_use = qalloc_get_nbytes_use(qal);
	out_stat->nbytes_ext = qal->pgal.meta.msz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* memory utilities */

void silofs_memzero(void *s, size_t n)
{
	memset(s, 0, n);
}

void silofs_memffff(void *s, size_t n)
{
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
		al = 1 << (64 - silofs_clz64(sz - 1));
	}
	return al;
}

static int cstd_memalign(size_t sz, void **out_mem)
{
	return posix_memalign(out_mem, alignment_of(sz), sz);
}

static void cstd_memfree(void *mem, size_t sz)
{
	if (mem && sz) {
		free(mem);
	}
}

int silofs_zmalloc(size_t sz, void **out_mem)
{
	int err;

	err = cstd_memalign(sz, out_mem);
	if (!err) {
		silofs_memzero(*out_mem, sz);
	}
	return err;
}

void silofs_zfree(void *mem, size_t sz)
{
	silofs_memzero(mem, sz);
	cstd_memfree(mem, sz);
}

static void burnstack_recursively(int depth, int nbytes)
{
	char buf[512];
	const int cnt = silofs_min32((int)sizeof(buf), nbytes);

	if (cnt > 0) {
		memset(buf, 0xF4 ^ depth, (size_t)cnt);
		burnstack_recursively(depth + 1, nbytes - cnt);
	}
}

void silofs_burnstackn(int n)
{
	burnstack_recursively(0, n);
}

void silofs_burnstack(void)
{
	silofs_burnstackn((int)silofs_sc_page_size());
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_calloc *
alloc_to_calloc(const struct silofs_alloc *alloc)
{
	const struct silofs_calloc *cal;

	cal = silofs_container_of2(alloc, struct silofs_calloc, alloc);
	return silofs_unconst(cal);
}

static void calloc_apply_flags(const struct silofs_calloc *cal,
                               void *ptr, size_t size, int flags)
{
	apply_allocf(ptr, size, flags);
	silofs_unused(cal);
}

static void *calloc_malloc(struct silofs_calloc *cal, size_t size, int flags)
{
	void *ptr = NULL;
	int err;

	err = cstd_memalign(size, &ptr);
	if (err) {
		return NULL;
	}
	silofs_atomic_addul(&cal->nbytes_use, size);
	calloc_apply_flags(cal, ptr, size, flags);
	return ptr;
}

static void calloc_free(struct silofs_calloc *cal,
                        void *ptr, size_t size, int flags)
{
	if ((ptr != NULL) && (size > 0)) {
		calloc_apply_flags(cal, ptr, size, flags);
		cstd_memfree(ptr, size);
		silofs_atomic_subul(&cal->nbytes_use, size);
	}
}

static int calloc_resolve(struct silofs_calloc *cal,
                          void *ptr, size_t len, struct silofs_iovec *iov)
{
	memset(iov, 0, sizeof(*iov));
	iov->iov_base = ptr;
	iov->iov_len = len;
	iov->iov_fd = -1;
	silofs_unused(cal);
	return 0;
}

static void calloc_stat(struct silofs_calloc *cal,
                        struct silofs_alloc_stat *out_stat)
{
	silofs_memzero(out_stat, sizeof(*out_stat));
	out_stat->nbytes_max = silofs_atomic_getul(&cal->nbytes_max);
	out_stat->nbytes_use = silofs_atomic_getul(&cal->nbytes_use);
}

static void *cal_malloc(struct silofs_alloc *alloc, size_t size, int flags)
{
	return calloc_malloc(alloc_to_calloc(alloc), size, flags);
}

static void cal_free(struct silofs_alloc *alloc,
                     void *ptr, size_t size, int flags)
{
	calloc_free(alloc_to_calloc(alloc), ptr, size, flags);
}

static void cal_stat(const struct silofs_alloc *alloc,
                     struct silofs_alloc_stat *out_stat)
{
	calloc_stat(alloc_to_calloc(alloc), out_stat);
}

static int cal_resolve(const struct silofs_alloc *alloc, void *ptr,
                       size_t len, struct silofs_iovec *iov)
{
	return calloc_resolve(alloc_to_calloc(alloc), ptr, len, iov);
}

int silofs_calloc_init(struct silofs_calloc *cal, size_t memsize)
{
	silofs_memzero(cal, sizeof(*cal));
	cal->alloc.malloc_fn = cal_malloc;
	cal->alloc.free_fn = cal_free;
	cal->alloc.stat_fn = cal_stat;
	cal->alloc.resolve_fn = cal_resolve;
	cal->nbytes_max = memsize;
	return 0;
}

int silofs_calloc_fini(struct silofs_calloc *cal)
{
	silofs_memzero(cal, sizeof(*cal));
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int getmemlimit(size_t *out_lim)
{
	struct rlimit rlim = { .rlim_cur = 0 };
	int err;

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	*out_lim = err ? 0 : rlim.rlim_cur;
	return err;
}

int silofs_memory_limits(size_t *out_phy, size_t *out_as)
{
	const long page_size = silofs_sc_page_size();
	const long phys_pages = silofs_sc_phys_pages();

	*out_phy = (size_t)(page_size * phys_pages);
	return getmemlimit(out_as);
}
