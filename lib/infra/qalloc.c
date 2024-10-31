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
#include <silofs/configs.h>
#include <silofs/errors.h>
#include <silofs/syscall.h>
#include <silofs/infra.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#define QALLOC_MAGIC            (0xBCC12573666F)
#define QALLOC_MALLOC_SIZE_MAX  (64 * SILOFS_UMEGA)
#define QALLOC_FREE_NPAGES_MANY (16)

#define QALLOC_PAGE_SHIFT       (16)
#define QALLOC_PAGE_SIZE        (1U << QALLOC_PAGE_SHIFT)
#define QALLOC_PAGE_NSEGS       (QALLOC_PAGE_SIZE / QALLOC_SLAB_SEG_SIZE)

#define QALLOC_SLAB_SHIFT_MIN   (4)
#define QALLOC_SLAB_SHIFT_MAX   (QALLOC_PAGE_SHIFT - 1)
#define QALLOC_SLAB_SIZE_MIN    (1U << QALLOC_SLAB_SHIFT_MIN)
#define QALLOC_SLAB_SIZE_MAX    (1U << QALLOC_SLAB_SHIFT_MAX)
#define QALLOC_SLAB_SEG_SIZE    QALLOC_SLAB_SIZE_MIN
#define QALLOC_SLAB_INDEX_NONE  (-1)
#define QALLOC_NSLABS_MAX       (QALLOC_PAGE_SHIFT - QALLOC_SLAB_SHIFT_MIN)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* TODO: Use AVL/RB instead of linked-list for free-chunks? */

struct silofs_slab_seg {
	struct silofs_list_head link;
} silofs_aligned16;


union silofs_qpage {
	struct silofs_slab_seg seg[QALLOC_PAGE_NSEGS];
	uint8_t data[QALLOC_PAGE_SIZE];
} silofs_packed_aligned64;


struct silofs_qpage_info {
	union silofs_qpage       *qpg;
	struct silofs_qpage_info *qpg_prev;
	struct silofs_list_head   qpg_lh;
	uint64_t        qpg_index;
	uint64_t        qpg_count; /* num pages free/used */
	uint8_t         qpg_free;  /* free/alloc state (boolean) */
	uint8_t         qpg_reserved[3];
	int32_t         qpg_slab_index;
	int32_t         qpg_slab_nused;
	int32_t         qpg_slab_nelems;
} __attribute__((__aligned__(SILOFS_CACHELINE_SIZE_DFL)));


/* global qpool's unique id (per process) */
static long g_qpool_id;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void qalloc_staticassert_defs(const struct silofs_qalloc *qal)
{
	STATICASSERT_GE(QALLOC_PAGE_SIZE, SILOFS_PAGE_SIZE_MIN);
	STATICASSERT_LE(QALLOC_PAGE_SIZE, SILOFS_PAGE_SIZE_MAX);
	STATICASSERT_EQ(sizeof(struct silofs_slab_seg), QALLOC_SLAB_SEG_SIZE);
	STATICASSERT_EQ(sizeof(union silofs_qpage), QALLOC_PAGE_SIZE);
	STATICASSERT_EQ(sizeof(struct silofs_qpage_info), 64);
	STATICASSERT_LE(sizeof(struct silofs_slab_seg),
	                SILOFS_CACHELINE_SIZE_MAX);
	STATICASSERT_GE(sizeof(struct silofs_qpage_info),
	                SILOFS_CACHELINE_SIZE_DFL);
	STATICASSERT_EQ(ARRAY_SIZE(qal->slabs), QALLOC_NSLABS_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nbytes_to_npgs(size_t nbytes)
{
	return (nbytes + QALLOC_PAGE_SIZE - 1) / QALLOC_PAGE_SIZE;
}

static ssize_t npgs_to_nbytes(size_t npgs)
{
	return (ssize_t)(npgs * QALLOC_PAGE_SIZE);
}

static bool is_slab_size(size_t size)
{
	return ((size > 0) && (size <= QALLOC_SLAB_SIZE_MAX));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void apply_allocf(void *ptr, size_t size, int flags)
{
	if (likely(ptr != NULL)) {
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

static void *qal_malloc(struct silofs_alloc *alloc, size_t nbytes, int flags)
{
	struct silofs_qalloc *qal = alloc_to_qalloc(alloc);

	return silofs_qalloc_malloc(qal, nbytes, flags);
}

static void qal_free(struct silofs_alloc *alloc,
                     void *ptr, size_t nbytes, int flags)
{
	struct silofs_qalloc *qal = alloc_to_qalloc(alloc);

	silofs_qalloc_free(qal, ptr, nbytes, flags);
}

static void qal_stat(const struct silofs_alloc *alloc,
                     struct silofs_alloc_stat *out_stat)
{
	const struct silofs_qalloc *qal = alloc_to_qalloc(alloc);

	silofs_qalloc_stat(qal, out_stat);
}

void *silofs_memalloc(struct silofs_alloc *alloc, size_t size, int flags)
{
	void *ptr = NULL;

	if (likely(alloc->malloc_fn && size)) {
		ptr = alloc->malloc_fn(alloc, size, flags);
	}
	return ptr;
}

void silofs_memfree(struct silofs_alloc *alloc,
                    void *ptr, size_t size, int flags)
{
	if (likely(ptr && size && alloc->free_fn)) {
		alloc->free_fn(alloc, ptr, size, flags);
	}
}

void silofs_memstat(const struct silofs_alloc *alloc,
                    struct silofs_alloc_stat *out_stat)
{
	if (alloc->stat_fn != NULL) {
		alloc->stat_fn(alloc, out_stat);
	} else {
		memset(out_stat, 0, sizeof(*out_stat));
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int memfd_setup(struct silofs_memfd *memfd,
                       const char *name, size_t size)
{
	void *mem = NULL;
	const int prot = PROT_READ | PROT_WRITE;
	const int flags = MAP_PRIVATE;
	int fd = -1;
	int err;

	err = silofs_sys_memfd_create(name, MFD_CLOEXEC, &fd);
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

static struct silofs_qpage_info *
qpgi_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_qpage_info *qpgi =
	        silofs_container_of2(lh, struct silofs_qpage_info, qpg_lh);

	return silofs_unconst(qpgi);
}

static void qpgi_update(struct silofs_qpage_info *qpgi,
                        struct silofs_qpage_info *qpgi_prev, size_t count)
{
	qpgi->qpg_prev = qpgi_prev;
	qpgi->qpg_count = count;
	qpgi->qpg_free = 1;
}

static void qpgi_mute(struct silofs_qpage_info *qpgi)
{
	qpgi_update(qpgi, NULL, 0);
}

static void qpgi_init(struct silofs_qpage_info *qpgi,
                      union silofs_qpage *qpg, size_t pg_index)
{
	silofs_list_head_init(&qpgi->qpg_lh);
	qpgi_mute(qpgi);
	qpgi->qpg = qpg;
	qpgi->qpg_index = pg_index;
	qpgi->qpg_count = 0;
	qpgi->qpg_slab_nused = 0;
	qpgi->qpg_slab_index = QALLOC_SLAB_INDEX_NONE;
	qpgi->qpg_free = 1;
}

static void qpgi_push_head(struct silofs_qpage_info *qpgi,
                           struct silofs_list_head *ls)
{
	silofs_list_push_front(ls, &qpgi->qpg_lh);
}

static void qpgi_push_tail(struct silofs_qpage_info *qpgi,
                           struct silofs_list_head *ls)
{
	silofs_list_push_back(ls, &qpgi->qpg_lh);
}

static void qpgi_unlink(struct silofs_qpage_info *qpgi)
{
	silofs_list_head_remove(&qpgi->qpg_lh);
}

static void qpgi_unlink_mute(struct silofs_qpage_info *qpgi)
{
	qpgi_unlink(qpgi);
	qpgi_mute(qpgi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool qpool_nofail_mode(const struct silofs_qpool *qpool)
{
	return (qpool->flags & SILOFS_QALLOCF_NOFAIL) > 0;
}

#define qpool_error(qpool_, fmt_, ...) \
	qpool_errorf(qpool_, __FILE__, __LINE__, fmt_, __VA_ARGS__)

static void qpool_errorf(const struct silofs_qpool *qpool,
                         const char *file, int line, const char *fmt, ...)
{
	char msg[256] = "";
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	if (qpool_nofail_mode(qpool)) {
		silofs_panicf(file, line,
		              "qpool error: %s npgs_use=%zu npgs_max=%zu "
		              "memsz=%zu memaddr=%p", msg, qpool->npgs_use,
		              qpool->npgs_max, qpool->data.msz,
		              qpool->data.mem);
	} else {
		silofs_logf(SILOFS_LOG_ERROR, file, line,
		            "qpool error: %s npgs_use=%zu npgs_max=%zu "
		            "memsz=%zu memaddr=%p", msg, qpool->npgs_use,
		            qpool->npgs_max, qpool->data.msz,
		            qpool->data.mem);
	}
}

static int
calc_mem_sizes(size_t npgs, size_t *out_data_msz, size_t *out_meta_msz)
{
	const size_t npgs_max = UINT_MAX; /* TODO: proper upper limit */
	int ret = -SILOFS_EINVAL;

	if ((npgs > 0) && (npgs <= npgs_max)) {
		*out_data_msz = npgs * sizeof(union silofs_qpage);
		*out_meta_msz = npgs * sizeof(struct silofs_qpage_info);
		ret = 0;
	}
	return ret;
}

static void *qpool_page_at(const struct silofs_qpool *qpool, size_t idx)
{
	union silofs_qpage *pg_arr = qpool->data.mem;

	return pg_arr + idx;
}

static struct silofs_qpage_info *
qpool_page_info_at(const struct silofs_qpool *qpool, size_t idx)
{
	struct silofs_qpage_info *qpgi_arr = qpool->meta.mem;

	silofs_assert_lt(idx, qpool->npgs_max);

	return qpgi_arr + idx;
}

static struct silofs_qpage_info *
qpool_next(const struct silofs_qpool *qpool,
           const struct silofs_qpage_info *qpgi, size_t npgs)
{
	const size_t idx_next = qpgi->qpg_index + npgs;
	struct silofs_qpage_info *qpgi_next = NULL;

	if (idx_next < qpool->npgs_max) {
		qpgi_next = qpool_page_info_at(qpool, idx_next);
	}
	return qpgi_next;
}

static void qpool_make_memfd_name(const struct silofs_qpool *qpool,
                                  char *nbuf, size_t nbsz, bool data)
{
	snprintf(nbuf, nbsz, "silofs-%s-%d-%04x",
	         data ? "data" : "meta", getpid(), qpool->unique_id);
}

static int qpool_init_memfds(struct silofs_qpool *qpool, size_t npgs)
{
	char name[256] = "";
	size_t data_msz;
	size_t meta_msz;
	int err;

	err = calc_mem_sizes(npgs, &data_msz, &meta_msz);
	if (err) {
		return err;
	}
	qpool_make_memfd_name(qpool, name, sizeof(name) - 1, true);
	err = memfd_setup(&qpool->data, name, data_msz);
	if (err) {
		return err;
	}
	qpool_make_memfd_name(qpool, name, sizeof(name) - 1, false);
	err = memfd_setup(&qpool->meta, name, meta_msz);
	if (err) {
		memfd_close(&qpool->data);
		return err;
	}
	qpool->npgs_max = npgs;
	return 0;
}

static void qpool_update(const struct silofs_qpool *qpool,
                         struct silofs_qpage_info *qpgi, size_t npgs)
{
	struct silofs_qpage_info *qpgi_next;

	qpgi_next = qpool_next(qpool, qpgi, npgs);
	if (qpgi_next != NULL) {
		qpgi_next->qpg_prev = qpgi;
	}
}

static void qpool_add_free(struct silofs_qpool *qpool,
                           struct silofs_qpage_info *qpgi,
                           struct silofs_qpage_info *qpgi_prev, size_t npgs)
{
	struct silofs_list_head *free_list = &qpool->free_pgs;

	qpgi_update(qpgi, qpgi_prev, npgs);
	qpool_update(qpool, qpgi, npgs);
	if (npgs >= QALLOC_FREE_NPAGES_MANY) {
		qpgi_push_head(qpgi, free_list);
	} else {
		qpgi_push_tail(qpgi, free_list);
	}
}

static void qpool_init_page_infos(struct silofs_qpool *qpool)
{
	union silofs_qpage *qpg;
	struct silofs_qpage_info *qpgi;

	for (size_t i = 0; i < qpool->npgs_max; ++i) {
		qpg = qpool_page_at(qpool, i);
		qpgi = qpool_page_info_at(qpool, i);
		qpgi_init(qpgi, qpg, i);
	}
	qpgi = qpool_page_info_at(qpool, 0);
	qpool_add_free(qpool, qpgi, NULL, qpool->npgs_max);
}

static int qpool_init_mutex(struct silofs_qpool *qpool)
{
	return silofs_mutex_init(&qpool->mutex);
}

static void qpool_fini_mutex(struct silofs_qpool *qpool)
{
	silofs_mutex_fini(&qpool->mutex);
}

static long qpool_next_unique_id(void)
{
	return silofs_atomic_addl(&g_qpool_id, 1);
}

static int qpool_init(struct silofs_qpool *qpool,
                      size_t memsize, enum silofs_qallocf flags)
{
	const size_t npgs = memsize / QALLOC_PAGE_SIZE;
	int err;

	silofs_memzero(qpool, sizeof(*qpool));
	silofs_list_init(&qpool->free_pgs);
	qpool->unique_id = (uint32_t)qpool_next_unique_id();

	err = qpool_init_mutex(qpool);
	if (err) {
		return err;
	}
	err = qpool_init_memfds(qpool, npgs);
	if (err) {
		qpool_fini_mutex(qpool);
		return err;
	}
	qpool_init_page_infos(qpool);
	qpool->flags = flags;
	return 0;
}

static int qpool_fini(struct silofs_qpool *qpool)
{
	int err1 = 0;
	int err2 = 0;

	qpool_fini_mutex(qpool);
	if (qpool->npgs_max) {
		err1 = memfd_close(&qpool->data);
		err2 = memfd_close(&qpool->meta);
	}
	return err1 ? err1 : err2;
}

static void qpool_lock(struct silofs_qpool *qpool)
{
	silofs_mutex_lock(&qpool->mutex);
}

static void qpool_unlock(struct silofs_qpool *qpool)
{
	silofs_mutex_unlock(&qpool->mutex);
}

static struct silofs_qpage_info *
qpool_search_free_from_tail(struct silofs_qpool *qpool, size_t npgs)
{
	struct silofs_qpage_info *qpgi;
	struct silofs_list_head *itr;
	struct silofs_list_head *free_list = &qpool->free_pgs;

	itr = free_list->prev;
	while (itr != free_list) {
		qpgi = qpgi_from_lh(itr);
		if (qpgi->qpg_count >= npgs) {
			return qpgi;
		}
		itr = itr->prev;
	}
	return NULL;
}

static struct silofs_qpage_info *
qpool_search_free_from_head(struct silofs_qpool *qpool, size_t npgs)
{
	struct silofs_qpage_info *qpgi;
	struct silofs_list_head *itr;
	struct silofs_list_head *free_list = &qpool->free_pgs;

	itr = free_list->next;
	while (itr != free_list) {
		qpgi = qpgi_from_lh(itr);
		if (qpgi->qpg_count >= npgs) {
			return qpgi;
		}
		itr = itr->next;
	}
	return NULL;
}

static struct silofs_qpage_info *
qpool_search_free_list(struct silofs_qpool *qpool, size_t npgs)
{
	struct silofs_qpage_info *qpgi = NULL;

	if ((qpool->npgs_use + npgs) <= qpool->npgs_max) {
		if (npgs >= QALLOC_FREE_NPAGES_MANY) {
			qpgi = qpool_search_free_from_head(qpool, npgs);
		} else {
			qpgi = qpool_search_free_from_tail(qpool, npgs);
		}
	}
	return qpgi;
}

static struct silofs_qpage_info *
qpool_do_alloc_npgs(struct silofs_qpool *qpool, size_t npgs)
{
	struct silofs_qpage_info *qpgi;
	struct silofs_qpage_info *qpgi_next = NULL;
	size_t npgs_add = 0;

	qpgi = qpool_search_free_list(qpool, npgs);
	if (qpgi == NULL) {
		return NULL;
	}
	qpgi_unlink(qpgi);
	if (qpgi->qpg_count > npgs) {
		qpgi_next = qpool_next(qpool, qpgi, npgs);
		if (qpgi_next != NULL) {
			npgs_add = qpgi->qpg_count - npgs;
			qpool_add_free(qpool, qpgi_next, qpgi, npgs_add);
		}
		qpgi->qpg_count = npgs;
	}
	qpgi->qpg_free = 0;
	return qpgi;
}

static struct silofs_qpage_info *
qpool_alloc_npgs(struct silofs_qpool *qpool, size_t npgs)
{
	struct silofs_qpage_info *qpgi;

	qpool_lock(qpool);
	qpgi = qpool_do_alloc_npgs(qpool, npgs);
	qpool_unlock(qpool);
	return qpgi;
}


static int qpool_do_alloc_multi_pg(struct silofs_qpool *qpool,
                                   size_t nbytes, void **out_ptr)
{
	size_t npgs;
	struct silofs_qpage_info *qpgi;

	npgs = nbytes_to_npgs(nbytes);
	qpgi = qpool_do_alloc_npgs(qpool, npgs);
	if (qpgi == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_ptr = qpgi->qpg->data;
	qpool->npgs_use += npgs;
	silofs_assert_ge(qpool->npgs_max, qpool->npgs_use);
	return 0;
}

static int qpool_alloc_multi_pg(struct silofs_qpool *qpool,
                                size_t nbytes, void **out_ptr)
{
	int err;

	qpool_lock(qpool);
	err = qpool_do_alloc_multi_pg(qpool, nbytes, out_ptr);
	qpool_unlock(qpool);
	return err;
}

static loff_t
qpool_ptr_to_off(const struct silofs_qpool *qpool, const void *ptr)
{
	return (const char *)ptr - (const char *)qpool->data.mem;
}

static size_t
qpool_ptr_to_pgn(const struct silofs_qpool *qpool, const void *ptr)
{
	const loff_t off = qpool_ptr_to_off(qpool, ptr);

	return (size_t)off / QALLOC_PAGE_SIZE;
}

static bool qpool_isinrange(const struct silofs_qpool *qpool,
                            const void *ptr, size_t nb)
{
	const loff_t off = qpool_ptr_to_off(qpool, ptr);
	const loff_t end = off + (loff_t)nb;

	return (off >= 0) && (end <= (loff_t)qpool->data.msz);
}

static struct silofs_qpage_info *
qpool_page_info_of(const struct silofs_qpool *qpool, const void *ptr)
{
	const size_t pgn = qpool_ptr_to_pgn(qpool, ptr);

	silofs_assert_lt(pgn, qpool->npgs_max);
	return qpool_page_info_at(qpool, pgn);
}


static struct silofs_slab_seg *
qpool_slab_seg_of(const struct silofs_qpool *qpool, const void *ptr)
{
	struct silofs_slab_seg *seg;
	loff_t off;
	size_t idx;

	seg = qpool->data.mem;
	off = qpool_ptr_to_off(qpool, ptr);
	idx = (size_t)off / sizeof(*seg);

	return &seg[idx];
}

static int qpool_check_by_page(const struct silofs_qpool *qpool,
                               const void *ptr, size_t nbytes)
{
	const struct silofs_qpage_info *qpgi = NULL;
	const size_t npgs = nbytes_to_npgs(nbytes);

	if (qpool->npgs_use < npgs) {
		qpool_error(qpool, "more-than-allocated: nbytes=%zu", nbytes);
		return -SILOFS_EQALLOC;
	}
	qpgi = qpool_page_info_of(qpool, ptr);
	if (qpgi == NULL) {
		qpool_error(qpool, "out-of-range: ptr=%p nbytes=%zu",
		            ptr, nbytes);
		return -SILOFS_EQALLOC;
	}
	if (qpgi->qpg_free) {
		qpool_error(qpool, "double-free: ptr=%p nbytes=%zu "
		            "qpg_count=%zu qpg_free=%d", ptr, nbytes,
		            qpgi->qpg_count, (int)qpgi->qpg_free);
	}
	if (qpgi->qpg_count != npgs) {
		qpool_error(qpool, "count-mismatch: ptr=%p nbytes=%zu "
		            "npgs=%zu ptr_pgn=%zu qpg_count=%zu qpg_free=%d",
		            ptr, nbytes, npgs, qpool_ptr_to_pgn(qpool, ptr),
		            qpgi->qpg_count, (int)qpgi->qpg_free);
		return -SILOFS_EQALLOC;
	}
	return 0;
}

static void qpool_punch_hole_at(const struct silofs_qpool *qpool,
                                struct silofs_qpage_info *qpgi, size_t npgs)
{
	loff_t off;
	ssize_t len;
	int mode;
	int fd;
	int err;

	off = npgs_to_nbytes(qpgi->qpg_index);
	len = npgs_to_nbytes(npgs);
	mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	fd = qpool->data.fd;
	err = silofs_sys_fallocate(fd, mode, off, len);
	if (err) {
		silofs_panic("failed to fallocate punch-hole in memory: "
		             "fd=%d off=%ld len=%ld mode=0x%x err=%d",
		             fd, off, len, mode, err);
	}
}

static bool
qpool_update_released(const struct silofs_qpool *qpool,
                      struct silofs_qpage_info *qpgi, size_t npgs, int flags)
{
	size_t npgs_punch_hole_threshold;

	if (flags & SILOFS_ALLOCF_NOPUNCH) {
		/* no-op if explicit request for no-punch */
		return false;
	}

	if (flags & SILOFS_ALLOCF_TRYPUNCH) {
		/* when asked to try-punch, require at least 1M hole size */
		npgs_punch_hole_threshold = 16;
	} else {
		/* by default, require 8M hole size */
		npgs_punch_hole_threshold = 128;
	}
	if (npgs < npgs_punch_hole_threshold) {
		/* avoid redundant syscalls when below threshold */
		return false;
	}

	/* actual memory reclaim to system via fallocate punch-hole */
	qpool_punch_hole_at(qpool, qpgi, npgs);
	return true;
}

static int
qpool_do_free_npgs(struct silofs_qpool *qpool,
                   struct silofs_qpage_info *qpgi, size_t npgs, int flags)
{
	struct silofs_qpage_info *qpgi_next = NULL;
	struct silofs_qpage_info *qpgi_prev = NULL;

	qpgi_next = qpool_next(qpool, qpgi, npgs);
	if ((qpgi_next != NULL) && qpgi_next->qpg_free) {
		npgs += qpgi_next->qpg_count;
		qpgi_unlink_mute(qpgi_next);
	}
	qpgi_prev = qpgi->qpg_prev;
	if ((qpgi_prev != NULL) && qpgi_prev->qpg_free) {
		npgs += qpgi_prev->qpg_count;
		qpgi_mute(qpgi);
		qpgi = qpgi_prev;
		qpgi_prev = qpgi_prev->qpg_prev;
		qpgi_unlink_mute(qpgi);
	}
	qpool_update_released(qpool, qpgi, npgs, flags);
	qpool_add_free(qpool, qpgi, qpgi_prev, npgs);
	return 0;
}

static int qpool_free_npgs(struct silofs_qpool *qpool,
                           struct silofs_qpage_info *qpgi,
                           size_t npgs, int flags)
{
	int err;

	qpool_lock(qpool);
	err = qpool_do_free_npgs(qpool, qpgi, npgs, flags);
	qpool_unlock(qpool);
	return err;
}

static int qpool_do_free_multi_pg(struct silofs_qpool *qpool,
                                  void *ptr, size_t nbytes, int flags)
{
	struct silofs_qpage_info *qpgi;
	size_t npgs;
	int err;

	err = qpool_check_by_page(qpool, ptr, nbytes);
	if (err) {
		return err;
	}
	npgs = nbytes_to_npgs(nbytes);
	qpgi = qpool_page_info_of(qpool, ptr);
	qpool_do_free_npgs(qpool, qpgi, npgs, flags);
	qpool->npgs_use -= npgs;
	return 0;
}

static int qpool_free_multi_pg(struct silofs_qpool *qpool,
                               void *ptr, size_t nbytes, int flags)
{
	int err;

	qpool_lock(qpool);
	err = qpool_do_free_multi_pg(qpool, ptr, nbytes, flags);
	qpool_unlock(qpool);
	return err;
}

static void *qpool_base_of(const struct silofs_qpool *qpool,
                           void *ptr, size_t len)
{
	struct silofs_slab_seg *seg = NULL;
	const struct silofs_qpage_info *qpgi = NULL;
	void *base = NULL;

	if (qpool_isinrange(qpool, ptr, len)) {
		if (is_slab_size(len)) {
			seg = qpool_slab_seg_of(qpool, ptr);
			if (seg != NULL) {
				base = seg;
			}
		} else {
			qpgi = qpool_page_info_of(qpool, ptr);
			if (qpgi != NULL) {
				base = qpgi->qpg;
			}
		}
	}
	return base;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define slab_error(slab_, fmt_, ...) \
	slab_errorf(slab_, __FILE__, __LINE__, fmt_, __VA_ARGS__)

static void slab_errorf(const struct silofs_slab *slab,
                        const char *file, int line, const char *fmt, ...)
{
	char msg[256] = "";
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	if (qpool_nofail_mode(slab->qpool)) {
		silofs_panicf(file, line,
		              "slab error: %s nfree=%zu nused=%zu "
		              "elemsz=%u sindex=%d", msg, slab->nfree,
		              slab->nused, slab->elemsz, slab->sindex);
	} else {
		silofs_logf(SILOFS_LOG_ERROR, file, line,
		            "slab error: %s nfree=%zu nused=%zu "
		            "elemsz=%u sindex=%d", msg, slab->nfree,
		            slab->nused, slab->elemsz, slab->sindex);
	}
}

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
	return ((size > 0) && (size <= QALLOC_SLAB_SIZE_MAX));
}

static size_t slab_size_to_nlz(size_t size)
{
	const size_t shift = QALLOC_SLAB_SHIFT_MIN;

	return silofs_clz_u32(((uint32_t)size - 1) >> shift);
}

static int32_t slab_size_to_sindex(size_t size)
{
	int32_t sindex;
	size_t nlz;

	if (!slab_issize(size)) {
		return QALLOC_SLAB_INDEX_NONE;
	}
	nlz = slab_size_to_nlz(size);
	if (!nlz || (nlz > 32)) {
		return QALLOC_SLAB_INDEX_NONE;
	}
	sindex = 32 - (int32_t)nlz;
	if (sindex >= QALLOC_NSLABS_MAX) {
		return QALLOC_SLAB_INDEX_NONE;
	}
	return sindex;
}

static int slab_init(struct silofs_slab *slab,
                     struct silofs_qpool *qpool,
                     int32_t sindex, uint32_t elemsz)
{
	silofs_list_init(&slab->free_list);
	slab->qpool = qpool;
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
	slab->sindex = QALLOC_SLAB_INDEX_NONE;
	slab->qpool = NULL;
}

static size_t slab_step_nsegs(const struct silofs_slab *slab)
{
	const struct silofs_slab_seg *seg = NULL;

	return SILOFS_DIV_ROUND_UP(slab->elemsz, sizeof(*seg));
}

static void slab_expand(struct silofs_slab *slab,
                        struct silofs_qpage_info *qpgi)
{
	struct silofs_slab_seg *seg;
	union silofs_qpage *qpg = qpgi->qpg;
	const size_t step = slab_step_nsegs(slab);
	const size_t nsegs = ARRAY_SIZE(qpg->seg);

	qpgi->qpg_slab_index = (int)slab->sindex;
	qpgi->qpg_slab_nelems = (int)(sizeof(*qpg) / slab->elemsz);
	qpgi->qpg_slab_nused = 0;
	for (size_t i = 0; (i + step) <= nsegs; i += step) {
		seg = &qpg->seg[i];
		silofs_list_push_back(&slab->free_list, &seg->link);
		slab->nfree++;
	}
}

static void slab_shrink(struct silofs_slab *slab,
                        struct silofs_qpage_info *qpgi)
{
	struct silofs_slab_seg *seg;
	union silofs_qpage *qpg = qpgi->qpg;
	const size_t step = slab_step_nsegs(slab);
	const size_t nsegs = ARRAY_SIZE(qpg->seg);

	silofs_assert_eq(qpgi->qpg_slab_index, slab->sindex);
	silofs_assert_eq(qpgi->qpg_slab_nused, 0);

	for (size_t i = 0; (i + step) <= nsegs; i += step) {
		silofs_assert_gt(slab->nfree, 0);

		seg = &qpg->seg[i];
		silofs_list_head_remove(&seg->link);
		slab->nfree--;
	}
	qpgi->qpg_slab_index = QALLOC_SLAB_INDEX_NONE;
	qpgi->qpg_slab_nelems = 0;
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
	struct silofs_qpage_info *qpgi;

	if (slab->nfree > 0) {
		return 0;
	}
	qpgi = qpool_alloc_npgs(slab->qpool, 1);
	if (qpgi == NULL) {
		return -SILOFS_ENOMEM;
	}
	slab_expand(slab, qpgi);
	return 0;
}

static struct silofs_slab_seg *
slab_alloc_and_update(struct silofs_slab *slab)
{
	struct silofs_slab_seg *seg;
	struct silofs_qpage_info *qpgi;

	seg = slab_alloc(slab);
	if (seg == NULL) {
		return NULL;
	}
	qpgi = qpool_page_info_of(slab->qpool, seg);

	silofs_assert_lt(qpgi->qpg_slab_nused, qpgi->qpg_slab_nelems);
	qpgi->qpg_slab_nused += 1;
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
	struct silofs_qpage_info *qpgi = qpool_page_info_of(slab->qpool, seg);

	silofs_assert_eq(qpgi->qpg_slab_index, slab->sindex);

	slab_free(slab, seg);
	silofs_assert_le(qpgi->qpg_slab_nused, qpgi->qpg_slab_nelems);
	silofs_assert_gt(qpgi->qpg_slab_nused, 0);

	qpgi->qpg_slab_nused -= 1;
	if (!qpgi->qpg_slab_nused) {
		slab_shrink(slab, qpgi);
		qpool_free_npgs(slab->qpool, qpgi, 1, flags);
	}
}

static int slab_check_seg(const struct silofs_slab *slab,
                          const struct silofs_slab_seg *seg, size_t nbytes)
{
	const struct silofs_qpage_info *qpgi = NULL;

	if (!slab->nused) {
		slab_error(slab, "nbytes=%zu", nbytes);
		return -SILOFS_EQALLOC;
	}
	if (nbytes > slab->elemsz) {
		slab_error(slab, "nbytes=%zu", nbytes);
		return -SILOFS_EQALLOC;
	}
	if (nbytes >= (2 * slab->elemsz)) {
		slab_error(slab, "nbytes=%zu", nbytes);
		return -SILOFS_EQALLOC;
	}
	qpgi = qpool_page_info_of(slab->qpool, seg);
	if (qpgi->qpg_slab_index != slab->sindex) {
		slab_error(slab, "qpg_slab_index=%d", qpgi->qpg_slab_index);
		return -SILOFS_EQALLOC;
	}
	if (qpgi->qpg_slab_nused == 0) {
		slab_error(slab, "qpg_slab_index=%d qpg_slab_nused=%d",
		           qpgi->qpg_slab_index, qpgi->qpg_slab_nused);
		return -SILOFS_EQALLOC;
	}
	return 0;
}

static int
slab_do_free_seg(struct silofs_slab *slab,
                 struct silofs_slab_seg *seg, size_t nbytes, int flags)
{
	int err;

	err = slab_check_seg(slab, seg, nbytes);
	if (err) {
		return err;
	}
	slab_free_and_update(slab, seg, flags);
	return 0;
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

static int qalloc_init_qpool(struct silofs_qalloc *qal,
                             size_t memsize, enum silofs_qallocf flags)
{
	return qpool_init(&qal->qpool, memsize, flags);
}

static int qalloc_fini_qpool(struct silofs_qalloc *qal)
{
	return qpool_fini(&qal->qpool);
}

static int qalloc_init_slabs(struct silofs_qalloc *qal)
{
	const int shift_base = QALLOC_SLAB_SHIFT_MIN;
	int32_t sindex;
	uint32_t elemsz;
	size_t init_ok = 0;
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(qal->slabs); ++i) {
		sindex = (int32_t)i;
		elemsz = 1U << (shift_base + sindex);
		err = slab_init(&qal->slabs[i], &qal->qpool, sindex, elemsz);
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
	for (size_t i = 0; i < ARRAY_SIZE(qal->slabs); ++i) {
		slab_fini(&qal->slabs[i]);
	}
}

static int check_memsize(size_t memsize)
{
	if (memsize < (8 * SILOFS_UMEGA)) {
		return -SILOFS_EINVAL;
	}
	if (memsize > (64 * SILOFS_UGIGA)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static void qalloc_init_interface(struct silofs_qalloc *qal)
{
	qal->alloc.malloc_fn = qal_malloc;
	qal->alloc.free_fn = qal_free;
	qal->alloc.stat_fn = qal_stat;
}

static void qalloc_fini_interface(struct silofs_qalloc *qal)
{
	qal->alloc.malloc_fn = NULL;
	qal->alloc.free_fn = NULL;
	qal->alloc.stat_fn = NULL;
}

int silofs_qalloc_init(struct silofs_qalloc *qal,
                       size_t memsize, enum silofs_qallocf flags)
{
	int err;

	qalloc_staticassert_defs(qal);

	silofs_memzero(qal, sizeof(*qal));
	qal->nbytes_use = 0;
	qal->magic = QALLOC_MAGIC;

	err = check_memsize(memsize);
	if (err) {
		return err;
	}
	err = qalloc_init_qpool(qal, memsize, flags);
	if (err) {
		return err;
	}
	err = qalloc_init_slabs(qal);
	if (err) {
		qalloc_fini_qpool(qal);
		return err;
	}
	qalloc_init_interface(qal);
	return 0;
}

int silofs_qalloc_fini(struct silofs_qalloc *qal)
{
	/* TODO: release all pending memory-elements in slabs */
	qalloc_fini_interface(qal);
	qalloc_fini_slabs(qal);
	return qalloc_fini_qpool(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t qalloc_slab_slot_of(const struct silofs_qalloc *qal, size_t size)
{
	const long sindex = slab_size_to_sindex(size);

	silofs_assert_ne(sindex, QALLOC_SLAB_INDEX_NONE);
	qalloc_staticassert_defs(qal);

	return (size_t)sindex;
}

static struct silofs_slab *
qalloc_slab_of(const struct silofs_qalloc *qal, size_t nbytes)
{
	const struct silofs_slab *slab = NULL;
	const size_t slot = qalloc_slab_slot_of(qal, nbytes);

	if (likely(slot < ARRAY_SIZE(qal->slabs))) {
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
	if (likely(slab != NULL)) {
		err = slab_alloc_seg(slab, out_seg);
	} else {
		err = -SILOFS_ENOMEM;
	}
	return err;
}

static int qalloc_check_alloc(const struct silofs_qalloc *qal, size_t nbytes)
{
	const size_t nbytes_max = QALLOC_MALLOC_SIZE_MAX;

	if (qal->qpool.data.mem == NULL) {
		return -SILOFS_ENOMEM;
	}
	if (nbytes > nbytes_max) {
		return -SILOFS_ENOMEM;
	}
	if (!nbytes) {
		return -SILOFS_EINVAL;
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
	return qpool_alloc_multi_pg(&qal->qpool, nbytes, out_ptr);
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
	if (is_slab_size(nbytes)) {
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

static void qalloc_handle_malloc_failure(const struct silofs_qalloc *qal,
                size_t nbytes, int err)
{
	const struct silofs_qpool *qpool = &qal->qpool;

	if (qpool_nofail_mode(qpool)) {
		silofs_log_debug("qalloc malloc failure: nbytes=%zu "
		                 "mem=%p msz=%zu err=%d", nbytes,
		                 qpool->data.mem, qpool->data.msz, err);
	}
}

void *silofs_qalloc_malloc(struct silofs_qalloc *qal, size_t nbytes, int flags)
{
	void *ptr = NULL;
	int err;

	if (nbytes == 0) {
		return NULL; /* OK, no-alloc case */
	}
	err = qalloc_malloc(qal, nbytes, flags, &ptr);
	if (unlikely(err)) {
		qalloc_handle_malloc_failure(qal, nbytes, err);
		return NULL;
	}
	return ptr;
}

static int qalloc_check_free(const struct silofs_qalloc *qal,
                             const void *ptr, size_t nbytes)
{
	const struct silofs_qpool *qpool = &qal->qpool;

	if (!nbytes || (nbytes > QALLOC_MALLOC_SIZE_MAX)) {
		qpool_error(qpool, "nbytes=%zu", nbytes);
		return -SILOFS_EINVAL;
	}
	if (!qpool_isinrange(qpool, ptr, nbytes)) {
		qpool_error(qpool, "not-in-range: ptr=%p nbytes=%zu",
		            ptr, nbytes);
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int
qalloc_check_slab_seg_of(const struct silofs_qalloc *qal,
                         const struct silofs_slab_seg *seg, size_t nbytes)
{
	const struct silofs_slab *slab;
	int ret = -SILOFS_EQALLOC;

	slab = qalloc_slab_of(qal, nbytes);
	if (likely(slab != NULL)) {
		ret = slab_check_seg(slab, seg, nbytes);
	}
	return ret;
}

static int
qalloc_free_by_slab(struct silofs_qalloc *qal,
                    struct silofs_slab_seg *seg, size_t nbytes, int flags)
{
	struct silofs_slab *slab;
	int ret = -SILOFS_EQALLOC;

	slab = qalloc_slab_of(qal, nbytes);
	if (likely(slab != NULL)) {
		ret = slab_free_seg(slab, seg, nbytes, flags);
	}
	return ret;
}

static int qalloc_free_sub_pg(struct silofs_qalloc *qal,
                              void *ptr, size_t nbytes, int flags)
{
	struct silofs_slab_seg *seg;

	seg = qpool_slab_seg_of(&qal->qpool, ptr);
	return qalloc_free_by_slab(qal, seg, nbytes, flags);
}

static int qalloc_free_multi_pg(struct silofs_qalloc *qal,
                                void *ptr, size_t nbytes, int flags)
{
	return qpool_free_multi_pg(&qal->qpool, ptr, nbytes, flags);
}

static bool qalloc_may_demask_on_free(const struct silofs_qalloc *qal)
{
	return (qal->qpool.flags & SILOFS_QALLOCF_DEMASK) > 0;
}

static void qalloc_pre_free(const struct silofs_qalloc *qal,
                            void *ptr, size_t nbytes, int flags)
{
	if (flags) {
		qalloc_apply_flags(qal, ptr, nbytes, flags);
	} else if (qalloc_may_demask_on_free(qal)) {
		memset(ptr, (int)qal->magic, silofs_min(512, nbytes));
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

	qalloc_pre_free(qal, ptr, nbytes, flags);

	if (is_slab_size(nbytes)) {
		err = qalloc_free_sub_pg(qal, ptr, nbytes, flags);
	} else {
		err = qalloc_free_multi_pg(qal, ptr, nbytes, flags);
	}
	if (err) {
		return err;
	}

	qalloc_sub_nbytes_use(qal, nbytes);
	return 0;
}

static void qalloc_handle_free_failure(const struct silofs_qalloc *qal,
                                       const void *ptr, size_t nbytes, int err)
{
	const struct silofs_qpool *qpool = &qal->qpool;

	if (qpool_nofail_mode(&qal->qpool)) {
		silofs_panic("qalloc free failure: ptr=%p nbytes=%zu "
		             "mem=%p msz=%zu err=%d", ptr, nbytes,
		             qpool->data.mem, qpool->data.msz, err);
	} else {
		silofs_log_error("qalloc free failure: ptr=%p nbytes=%zu "
		                 "mem=%p msz=%zu err=%d", ptr, nbytes,
		                 qpool->data.mem, qpool->data.msz, err);
	}
}

void silofs_qalloc_free(struct silofs_qalloc *qal,
                        void *ptr, size_t nbytes, int flags)
{
	int err;

	err = qalloc_free(qal, ptr, nbytes, flags);
	if (unlikely(err)) {
		qalloc_handle_free_failure(qal, ptr, nbytes, err);
	}
}

static int qalloc_check_by_slab(const struct silofs_qalloc *qal,
                                const void *ptr, size_t nbytes)
{
	const struct silofs_slab_seg *seg;
	int ret = -SILOFS_EQALLOC;

	seg = qpool_slab_seg_of(&qal->qpool, ptr);
	if (likely(seg != NULL)) {
		ret = qalloc_check_slab_seg_of(qal, seg, nbytes);
	}
	return ret;
}

static int qalloc_check_by_qpool(const struct silofs_qalloc *qal,
                                 const void *ptr, size_t nbytes)
{
	return qpool_check_by_page(&qal->qpool, ptr, nbytes);
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
	if (is_slab_size(nbytes)) {
		err = qalloc_check_by_slab(qal, ptr, nbytes);
	} else {
		err = qalloc_check_by_qpool(qal, ptr, nbytes);
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

	base = qpool_base_of(&qal->qpool, ptr, len);
	if (unlikely(base == NULL)) {
		return -SILOFS_ERANGE;
	}
	if (unlikely(base > ptr)) {
		return -SILOFS_ERANGE;
	}
	silofs_iovec_reset(iov);
	iov->iov.iov_len = len;
	iov->iov.iov_base = ptr;
	iov->iov_off = qpool_ptr_to_off(&qal->qpool, ptr);
	iov->iov_fd = qal->qpool.data.fd;
	iov->iov_backref = NULL;
	return 0;
}

void silofs_qalloc_stat(const struct silofs_qalloc *qal,
                        struct silofs_alloc_stat *out_stat)
{
	silofs_memzero(out_stat, sizeof(*out_stat));
	out_stat->nbytes_max = qal->qpool.data.msz;
	out_stat->nbytes_use = qalloc_get_nbytes_use(qal);
	out_stat->nbytes_ext = qal->qpool.meta.msz;
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
		al = 1 << (64 - silofs_clz_u64(sz - 1));
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
	if (err) {
		return err;
	}
	silofs_memzero(*out_mem, sz);
	return 0;
}

void silofs_zfree(void *mem, size_t sz)
{
	silofs_memzero(mem, sz);
	cstd_memfree(mem, sz);
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

int silofs_calloc_init(struct silofs_calloc *cal, size_t memsize)
{
	silofs_memzero(cal, sizeof(*cal));
	cal->alloc.malloc_fn = cal_malloc;
	cal->alloc.free_fn = cal_free;
	cal->alloc.stat_fn = cal_stat;
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
