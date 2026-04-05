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
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>

#include <silofs/errors.h>
#include <silofs/syscall.h>
#include <silofs/base.h>
#include <silofs/pv.h>

/*
 * TODO-0035: Define proper upper-bound for cache limit.
 *
 * Have explicit upper-limit to cached lsegs, based on the process' rlimit
 * RLIMIT_NOFILE and memory limits.
 */

static int do_closefd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		log_err("close error: fd=%d err=%d", *pfd, err);
	}
	return err;
}

static int do_opendirat(int dirfd, const char *pathname, int *out_fd)
{
	int err;

	err = silofs_sys_opendirat(dirfd, pathname, out_fd);
	if (err) {
		log_warn("opendirat error: dirfd=%d pathname=%s err=%d", dirfd,
		         pathname, err);
	}
	return err;
}

static int
do_openat(int dfd, const char *pathname, int o_flags, mode_t mode, int *out_fd)
{
	int err;

	err = silofs_sys_openat(dfd, pathname, o_flags, mode, out_fd);
	if (err && (err != -ENOENT)) {
		log_warn("openat error: dfd=%d pathname=%s o_flags=0x%x "
		         "mode=0%o err=%d",
		         dfd, pathname, o_flags, mode, err);
		silofs_assert_ok(err);
	}
	return err;
}

static int do_unlinkat(int dfd, const char *pathname, int flags)
{
	int err;

	err = silofs_sys_unlinkat(dfd, pathname, flags);
	if (err && (err != -ENOENT)) {
		log_warn("unlinkat error: dfd=%d pathname=%s err=%d", dfd,
		         pathname, err);
	}
	return err;
}

static int do_fstat(int fd, struct stat *st)
{
	int err;

	err = silofs_sys_fstat(fd, st);
	if (err && (err != -ENOENT)) {
		log_warn("fstat error: fd=%d err=%d", fd, err);
	}
	return err;
}

static int do_fsync(int fd)
{
	int err;

	err = silofs_sys_fsync(fd);
	if (err && (err != -ENOSYS)) {
		log_warn("fsync error: fd=%d err=%d", fd, err);
	}
	return err;
}

static int do_pwriten(int fd, const void *buf, size_t cnt, off_t off)
{
	int err;

	err = silofs_sys_pwriten(fd, buf, cnt, off);
	if (err) {
		log_warn("pwriten error: fd=%d cnt=%lu off=%ld err=%d", fd,
		         cnt, off, err);
	}
	return err;
}

static int do_pwritevn(int fd, const struct iovec *iov, size_t cnt, off_t off)
{
	int err;

	err = silofs_sys_pwritevn(fd, iov, (int)cnt, off);
	if (err) {
		log_warn("pwritevn error: fd=%d cnt=%lu off=%ld err=%d", fd,
		         cnt, off, err);
	}
	return err;
}

static int do_preadn(int fd, void *buf, size_t cnt, off_t off)
{
	int err;

	err = silofs_sys_preadn(fd, buf, cnt, off);
	if (err) {
		log_warn("preadn error: fd=%d cnt=%lu off=%ld err=%d", fd, cnt,
		         off, err);
	}
	return err;
}

static int do_ftruncate(int fd, off_t len)
{
	int err;

	err = silofs_sys_ftruncate(fd, len);
	if (err) {
		log_warn("ftruncate error: fd=%d len=%ld err=%d", fd, len,
		         err);
	}
	return err;
}

static int do_sync_file_range(int fd, off_t off, off_t nbytes, unsigned flags)
{
	int err;

	err = silofs_sys_sync_file_range(fd, off, nbytes, flags);
	if (err && (err != -ENOSYS)) {
		log_warn("sync_file_range error: fd=%d off=%ld nbytes=%ld "
		         "flags=%x err=%d",
		         fd, off, nbytes, flags, err);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_blobfile {
	struct silofs_list_head bf_htb_lh;
	struct silofs_list_head bf_lru_lh;
	struct silofs_blobidx bf_blobidx;
	int bf_fd;
	bool bf_mapped;
};

static struct silofs_blobfile *bf_unconst(const struct silofs_blobfile *p)
{
	union {
		const struct silofs_blobfile *p;
		struct silofs_blobfile *q;
	} u = { .p = p };

	return u.q;
}

static struct silofs_blobfile *
bf_from_htb_link(const struct silofs_list_head *lh)
{
	const struct silofs_blobfile *bf = nullptr;

	if (lh != nullptr) {
		bf = container_of2(lh, struct silofs_blobfile, bf_htb_lh);
	}
	return bf_unconst(bf);
}

static struct silofs_blobfile *
bf_from_lru_link(const struct silofs_list_head *lh)
{
	const struct silofs_blobfile *bf = nullptr;

	if (lh != nullptr) {
		bf = container_of2(lh, struct silofs_blobfile, bf_lru_lh);
	}
	return bf_unconst(bf);
}

static void
bf_name(const struct silofs_blobfile *bf, struct silofs_strbuf *out_name)
{
	silofs_blobidx_to_str(&bf->bf_blobidx, out_name->str,
	                      sizeof(out_name->str));
}

static int bf_open(struct silofs_blobfile *bf, int dfd)
{
	struct silofs_strbuf name;

	bf_name(bf, &name);
	return do_openat(dfd, name.str, O_RDWR, 0, &bf->bf_fd);
}

static int bf_create(struct silofs_blobfile *bf, int dfd)
{
	struct silofs_strbuf name;

	bf_name(bf, &name);
	return do_openat(dfd, name.str, O_CREAT | O_EXCL | O_RDWR, 0600,
	                 &bf->bf_fd);
}

static int bf_unlink(const struct silofs_blobfile *bf, int dfd)
{
	struct silofs_strbuf name;

	bf_name(bf, &name);
	return do_unlinkat(dfd, name.str, 0);
}

static bool bf_isopen(const struct silofs_blobfile *bf)
{
	return (bf->bf_fd >= 0);
}

static void bf_close(struct silofs_blobfile *bf)
{
	if (bf_isopen(bf)) {
		do_closefd(&bf->bf_fd);
	}
}

static bool bf_has_blobidx(const struct silofs_blobfile *bf,
                           const struct silofs_blobidx *blobidx)
{
	return silofs_blobidx_isequal(&bf->bf_blobidx, blobidx);
}

static int bf_stat(const struct silofs_blobfile *bf, struct stat *out_st)
{
	mode_t mode;
	int err;

	err = do_fstat(bf->bf_fd, out_st);
	if (err) {
		return err;
	}
	mode = out_st->st_mode;
	if (S_ISDIR(mode)) {
		return -SILOFS_EISDIR;
	}
	if (!S_ISREG(mode)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

static int bf_sync(const struct silofs_blobfile *bf)
{
	return do_fsync(bf->bf_fd);
}

static int bf_write(const struct silofs_blobfile *bf, off_t pos,
                    const void *buf, size_t len)
{
	return do_pwriten(bf->bf_fd, buf, len, pos);
}

static int bf_writev(const struct silofs_blobfile *bf, off_t pos,
                     const struct iovec *iov, size_t cnt)
{
	return do_pwritevn(bf->bf_fd, iov, cnt, pos);
}

static int
bf_read(const struct silofs_blobfile *bf, off_t pos, void *buf, size_t len)
{
	return do_preadn(bf->bf_fd, buf, len, pos);
}

static int bf_truncate(const struct silofs_blobfile *bf, off_t pos)
{
	return do_ftruncate(bf->bf_fd, pos);
}

static int bf_punch(const struct silofs_blobfile *bf)
{
	struct stat st = { .st_size = -1 };
	int err;

	err = bf_stat(bf, &st);
	if (err) {
		goto out;
	}
	if (!st.st_blocks || !st.st_size) {
		goto out; /* ok */
	}
	err = bf_truncate(bf, 0);
	if (err) {
		goto out;
	}
	err = bf_truncate(bf, st.st_size);
	if (err) {
		goto out;
	}
out:
	return err;
}

static int
bf_sync_range(const struct silofs_blobfile *bf, off_t off, size_t len)
{
	int err;

	err = do_sync_file_range(bf->bf_fd, off, (off_t)len,
	                         SYNC_FILE_RANGE_WAIT_BEFORE |
	                                 SYNC_FILE_RANGE_WRITE |
	                                 SYNC_FILE_RANGE_WAIT_AFTER);
	if (err && (err != -ENOSYS)) {
		return err;
	}
	return 0;
}

static int bf_expand(const struct silofs_blobfile *bf, off_t off)
{
	struct stat st;
	int err;

	err = bf_stat(bf, &st);
	if (!err && (off > st.st_size)) {
		err = bf_truncate(bf, off);
	}
	return err;
}

static int bf_stat_offset(const struct silofs_blobfile *bf, off_t off)
{
	struct stat st;
	int err;

	err = bf_stat(bf, &st);
	if (!err && (off > st.st_size)) {
		err = -SILOFS_ERANGE;
	}
	return err;
}

static void
bf_init(struct silofs_blobfile *bf, const struct silofs_blobidx *blobidx)
{
	silofs_list_head_init(&bf->bf_htb_lh);
	silofs_list_head_init(&bf->bf_lru_lh);
	silofs_blobidx_assign(&bf->bf_blobidx, blobidx);
	bf->bf_fd     = -1;
	bf->bf_mapped = false;
}

static void bf_fini(struct silofs_blobfile *bf)
{
	silofs_assert(!bf->bf_mapped);

	bf_close(bf);
	silofs_list_head_fini(&bf->bf_lru_lh);
	silofs_list_head_fini(&bf->bf_htb_lh);
}

static struct silofs_blobfile *
bf_new(const struct silofs_blobidx *blobidx, struct silofs_alloc *alloc)
{
	struct silofs_blobfile *bf;

	bf = silofs_memalloc(alloc, sizeof(*bf), 0);
	if (bf != nullptr) {
		bf_init(bf, blobidx);
	}
	return bf;
}

static void bf_del(struct silofs_blobfile *bf, struct silofs_alloc *alloc)
{
	bf_fini(bf);
	silofs_memfree(alloc, bf, sizeof(*bf), 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int lhq_init(struct silofs_dstor_hq *lhq, struct silofs_alloc *alloc)
{
	const size_t nelems = 1024;

	silofs_listq_init(&lhq->dsq_lru);
	lhq->dsq_htb_nelems = 0;
	lhq->dsq_htb        = silofs_new_lh_array(alloc, nelems);
	if (lhq->dsq_htb == nullptr) {
		return -SILOFS_ENOMEM;
	}
	lhq->dsq_htb_nelems = nelems;
	return 0;
}

static void lhq_fini(struct silofs_dstor_hq *lhq, struct silofs_alloc *alloc)
{
	silofs_listq_fini(&lhq->dsq_lru);
	silofs_del_lh_array(lhq->dsq_htb, lhq->dsq_htb_nelems, alloc);
	lhq->dsq_htb        = nullptr;
	lhq->dsq_htb_nelems = 0;
}

static uint64_t lhq_hash_of(const struct silofs_blobidx *blobidx)
{
	return silofs_xxh64(blobidx->idx.hash, sizeof(blobidx->idx.hash), 0);
}

static size_t lhq_htb_slot_of(const struct silofs_dstor_hq *lhq,
                              const struct silofs_blobidx *blobidx)
{
	return lhq_hash_of(blobidx) % lhq->dsq_htb_nelems;
}

static const struct silofs_list_head *
lhq_htb_list_of(const struct silofs_dstor_hq *lhq,
                const struct silofs_blobidx *blobidx)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobidx);

	return &lhq->dsq_htb[slot];
}

static struct silofs_list_head *
lhq_htb_list_of2(struct silofs_dstor_hq *lhq,
                 const struct silofs_blobidx *blobidx)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobidx);

	return &lhq->dsq_htb[slot];
}

static void
lhq_insert_htb(struct silofs_dstor_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_list_head *lst = lhq_htb_list_of2(lhq, &bf->bf_blobidx);

	list_push_front(lst, &bf->bf_htb_lh);
}

static void
lhq_insert_lru(struct silofs_dstor_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_push_front(&lhq->dsq_lru, &bf->bf_lru_lh);
}

static void lhq_insert(struct silofs_dstor_hq *lhq, struct silofs_blobfile *bf)
{
	if (!bf->bf_mapped) {
		lhq_insert_htb(lhq, bf);
		lhq_insert_lru(lhq, bf);
		bf->bf_mapped = true;
	}
}

static size_t lhq_get_lru_size(const struct silofs_dstor_hq *lhq)
{
	return silofs_listq_size(&lhq->dsq_lru);
}

static void
lhq_promote_lru(struct silofs_dstor_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_listq *lru    = &lhq->dsq_lru;
	struct silofs_list_head *lh = &bf->bf_lru_lh;

	silofs_assert_gt(lru->sz, 0);
	if (silofs_listq_front(lru) != lh) {
		silofs_listq_remove(lru, lh);
		silofs_listq_push_front(lru, lh);
	}
}

static struct silofs_blobfile *
lhq_get_lru_head(const struct silofs_dstor_hq *lhq)
{
	const struct silofs_listq *lru = &lhq->dsq_lru;

	return bf_from_lru_link(silofs_listq_front(lru));
}

static struct silofs_blobfile *
lhq_get_lru_next(const struct silofs_dstor_hq *lhq,
                 const struct silofs_blobfile *bf)
{
	const struct silofs_listq *lru = &lhq->dsq_lru;
	struct silofs_blobfile *nxt    = nullptr;

	if (bf == nullptr) {
		nxt = lhq_get_lru_head(lhq);
	} else {
		nxt = bf_from_lru_link(silofs_listq_next(lru, &bf->bf_lru_lh));
	}
	return nxt;
}

static struct silofs_blobfile *
lhq_get_lru_tail(const struct silofs_dstor_hq *lhq)
{
	const struct silofs_listq *lru = &lhq->dsq_lru;

	return bf_from_lru_link(silofs_listq_back(lru));
}

static struct silofs_blobfile *
lhq_lookup_htb(const struct silofs_dstor_hq *lhq,
               const struct silofs_blobidx *blobidx)
{
	const struct silofs_list_head *lst = nullptr;
	const struct silofs_list_head *itr = nullptr;
	const struct silofs_blobfile *bf   = nullptr;

	lst = lhq_htb_list_of(lhq, blobidx);
	itr = lst->next;
	while ((itr != lst) && (itr != nullptr)) {
		bf = bf_from_htb_link(itr);
		if (bf_has_blobidx(bf, blobidx)) {
			return bf_unconst(bf);
		}
		itr = itr->next;
	}
	return nullptr;
}

static struct silofs_blobfile *
lhq_lookup(struct silofs_dstor_hq *lhq, const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf = nullptr;

	if (!lhq_get_lru_size(lhq)) {
		goto out;
	}
	bf = lhq_lookup_htb(lhq, blobidx);
	if (bf == nullptr) {
		goto out;
	}
	lhq_promote_lru(lhq, bf);
out:
	return bf;
}

static void
lhq_remove_htb(struct silofs_dstor_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_assert_gt(lhq->dsq_lru.sz, 0);

	silofs_list_head_remove(&bf->bf_htb_lh);
}

static void
lhq_remove_lru(struct silofs_dstor_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_remove(&lhq->dsq_lru, &bf->bf_lru_lh);
}

static void lhq_remove(struct silofs_dstor_hq *lhq, struct silofs_blobfile *bf)
{
	if (bf->bf_mapped) {
		lhq_remove_htb(lhq, bf);
		lhq_remove_lru(lhq, bf);
		bf->bf_mapped = false;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blobfile *
dstor_lookup_cached_bf(struct silofs_dstor *dstor,
                       const struct silofs_blobidx *blobidx)
{
	return lhq_lookup(&dstor->ds_hq, blobidx);
}

static void
dstor_insert_cached_bf(struct silofs_dstor *dstor, struct silofs_blobfile *bf)
{
	lhq_insert(&dstor->ds_hq, bf);
}

static void
dstor_remove_cached_bf(struct silofs_dstor *dstor, struct silofs_blobfile *bf)
{
	lhq_remove(&dstor->ds_hq, bf);
}

static struct silofs_blobfile *
dstor_new_bf(struct silofs_dstor *dstor, const struct silofs_blobidx *blobidx)
{
	return bf_new(blobidx, dstor->ds_alloc);
}

static void
dstor_del_bf(struct silofs_dstor *dstor, struct silofs_blobfile *bf)
{
	bf_close(bf);
	bf_del(bf, dstor->ds_alloc);
}

static void
dstor_forget_cached_bf(struct silofs_dstor *dstor, struct silofs_blobfile *bf)
{
	dstor_remove_cached_bf(dstor, bf);
	dstor_del_bf(dstor, bf);
}

static void dstor_drop_cached(struct silofs_dstor *dstor)
{
	struct silofs_blobfile *bf;

	bf = lhq_get_lru_tail(&dstor->ds_hq);
	while (bf != nullptr) {
		bf_sync(bf);
		dstor_forget_cached_bf(dstor, bf);
		bf = lhq_get_lru_tail(&dstor->ds_hq);
	}
}

static int dstor_sync_cached(const struct silofs_dstor *dstor)
{
	struct silofs_blobfile *bf;
	int err = 0;

	bf = lhq_get_lru_head(&dstor->ds_hq);
	while (bf != nullptr) {
		err = bf_sync(bf);
		if (err) {
			break;
		}
		bf = lhq_get_lru_next(&dstor->ds_hq, bf);
	}
	return err;
}

static bool dstor_has_overpop_cache(const struct silofs_dstor *dstor)
{
	const size_t cache_lim = 64;

	return (dstor->ds_hq.dsq_lru.sz > cache_lim);
}

static struct silofs_blobfile *dstor_get_overpop_bf(struct silofs_dstor *dstor)
{
	struct silofs_blobfile *bf = nullptr;

	if (dstor_has_overpop_cache(dstor)) {
		bf = lhq_get_lru_tail(&dstor->ds_hq);
	}
	return bf;
}

static void dstor_relax_cache(struct silofs_dstor *dstor)
{
	struct silofs_blobfile *bf;

	bf = dstor_get_overpop_bf(dstor);
	while (bf != nullptr) {
		dstor_forget_cached_bf(dstor, bf);
		bf = dstor_get_overpop_bf(dstor);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dstor_close(struct silofs_dstor *dstor)
{
	do_closefd(&dstor->ds_dfd);
}

int silofs_dstor_init(struct silofs_dstor *dstor, struct silofs_alloc *alloc)
{
	int err;

	dstor->ds_alloc = alloc;
	dstor->ds_dfd   = -1;

	err = silofs_mdigest_init(&dstor->ds_md);
	if (err) {
		return err;
	}
	err = lhq_init(&dstor->ds_hq, dstor->ds_alloc);
	if (err) {
		silofs_mdigest_fini(&dstor->ds_md);
		return err;
	}
	return 0;
}

void silofs_dstor_fini(struct silofs_dstor *dstor)
{
	dstor_drop_cached(dstor);
	dstor_close(dstor);
	lhq_fini(&dstor->ds_hq, dstor->ds_alloc);
	silofs_mdigest_fini(&dstor->ds_md);
	dstor->ds_alloc = nullptr;
}

static bool dstor_isopen(const struct silofs_dstor *dstor)
{
	return dstor->ds_dfd >= 0;
}

static void blobs_pathname(struct silofs_strbuf *sbuf)
{
	const char *dots = SILOFS_REPO_DOTS_DIRNAME;
	const char *subd = SILOFS_REPO_BLOBS_DIRNAME;

	silofs_strbuf_sprintf(sbuf, "%s/%s", dots, subd);
}

static int dstor_open(struct silofs_dstor *dstor, int root_dfd)
{
	struct silofs_strbuf sbuf;

	blobs_pathname(&sbuf);
	return do_opendirat(root_dfd, sbuf.str, &dstor->ds_dfd);
}

int silofs_dstor_open(struct silofs_dstor *dstor, int root_dfd)
{
	if (dstor_isopen(dstor)) {
		return -SILOFS_EALREADY;
	}
	return dstor_open(dstor, root_dfd);
}

void silofs_dstor_close(struct silofs_dstor *dstor)
{
	dstor_drop_cached(dstor);
	if (dstor_isopen(dstor)) {
		dstor_close(dstor);
	}
}

void silofs_dstor_relax(struct silofs_dstor *dstor)
{
	if (dstor_isopen(dstor)) {
		dstor_relax_cache(dstor);
	}
}

void silofs_dstor_drop(struct silofs_dstor *dstor)
{
	if (dstor_isopen(dstor)) {
		dstor_drop_cached(dstor);
	}
}

int silofs_dstor_sync(const struct silofs_dstor *dstor)
{
	int ret = 0;

	if (dstor_isopen(dstor)) {
		ret = dstor_sync_cached(dstor);
	}
	return ret;
}

static int dstor_spawn_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobidx *blobidx,
                            struct silofs_blobfile **out_bf)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	bf = dstor_lookup_cached_bf(dstor, blobidx);
	if (bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	bf = dstor_new_bf(dstor, blobidx);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_create(bf, dstor->ds_dfd);
	if (err) {
		dstor_del_bf(dstor, bf);
		return err;
	}
	*out_bf = bf;
	return 0;
}

static int dstor_spawn_and_cache_bf(struct silofs_dstor *dstor,
                                    const struct silofs_blobidx *blobidx,
                                    struct silofs_blobfile **out_bf)
{
	int err;

	dstor_relax_cache(dstor);
	err = dstor_spawn_blob(dstor, blobidx, out_bf);
	if (err) {
		return err;
	}
	dstor_insert_cached_bf(dstor, *out_bf);
	return 0;
}

static int dstor_stage_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobidx *blobidx,
                            struct silofs_blobfile **out_bf)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	bf = dstor_new_bf(dstor, blobidx);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_open(bf, dstor->ds_dfd);
	if (err) {
		dstor_del_bf(dstor, bf);
		return err;
	}
	*out_bf = bf;
	return err;
}

static int dstor_stage_and_cache_bf(struct silofs_dstor *dstor,
                                    const struct silofs_blobidx *blobidx,
                                    struct silofs_blobfile **out_bf)
{
	int err;

	dstor_relax_cache(dstor);
	err = dstor_stage_blob(dstor, blobidx, out_bf);
	if (err) {
		return err;
	}
	dstor_insert_cached_bf(dstor, *out_bf);
	return 0;
}

static int dstor_require_cached_bf(struct silofs_dstor *dstor,
                                   const struct silofs_blobidx *blobidx,
                                   struct silofs_blobfile **out_bf)
{
	int err = 0;

	*out_bf = dstor_lookup_cached_bf(dstor, blobidx);
	if (*out_bf == nullptr) {
		err = dstor_stage_and_cache_bf(dstor, blobidx, out_bf);
	}
	return err;
}

static void dstor_require_no_cached_bf(struct silofs_dstor *dstor,
                                       const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf = nullptr;

	bf = dstor_lookup_cached_bf(dstor, blobidx);
	if (bf != nullptr) {
		dstor_remove_cached_bf(dstor, bf);
	}
}

static void dstor_blobidx_of(struct silofs_dstor *dstor,
                             const struct silofs_blobid *blobid,
                             struct silofs_blobidx *out_blobidx)
{
	silofs_blobidx_derive(out_blobidx, &dstor->ds_md, blobid);
}

int silofs_dstor_spawn_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;
	struct silofs_blobfile *bf = nullptr;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	bf = dstor_lookup_cached_bf(dstor, &blobidx);
	if (bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	return dstor_spawn_and_cache_bf(dstor, &blobidx, &bf);
}

static int dstor_remove_blob(struct silofs_dstor *dstor,
                             const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf = nullptr;
	int err                    = 0;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_unlink(bf, dstor->ds_dfd);
	if (err) {
		return err;
	}
	dstor_forget_cached_bf(dstor, bf);
	return 0;
}

int silofs_dstor_remove_blob(struct silofs_dstor *dstor,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_remove_blob(dstor, &blobidx);
}

static int
dstor_stat_blob(struct silofs_dstor *dstor,
                const struct silofs_blobidx *blobidx, struct stat *out_st)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_stat(bf, out_st);
	if (err) {
		return err;
	}
	return 0;
}

static int dstor_sense_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobidx *blobidx)
{
	struct stat st;

	return dstor_stat_blob(dstor, blobidx, &st);
}

int silofs_dstor_stat_blob(struct silofs_dstor *dstor,
                           const struct silofs_blobid *blobid,
                           struct stat *out_st)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_stat_blob(dstor, &blobidx, out_st);
}

int silofs_dstor_stage_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_sense_blob(dstor, &blobidx);
}

static int dstor_require_blob(struct silofs_dstor *dstor,
                              const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_sense_blob(dstor, blobidx);
	if (!err) {
		return 0; /* OK */
	}
	if (err != -ENOENT) {
		dstor_require_no_cached_bf(dstor, blobidx);
		return err; /* I/O error */
	}
	return dstor_spawn_and_cache_bf(dstor, blobidx, &bf);
}

int silofs_dstor_require_blob(struct silofs_dstor *dstor,
                              const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_require_blob(dstor, &blobidx);
}

static int dstor_require_bpos(struct silofs_dstor *dstor,
                              const struct silofs_blobidx *blobidx, off_t pos)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_blob(dstor, blobidx);
	if (err) {
		return err;
	}
	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_expand(bf, pos);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_require_blob_at(struct silofs_dstor *dstor,
                                 const struct silofs_blobid *blobid, off_t pos)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_require_bpos(dstor, &blobidx, pos);
}

static int dstor_access_bpos(struct silofs_dstor *dstor,
                             const struct silofs_blobidx *blobidx, off_t pos)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_stat_offset(bf, pos);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_access_blob_at(struct silofs_dstor *dstor,
                                const struct silofs_blobid *blobid, off_t pos)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_access_bpos(dstor, &blobidx, pos);
}

static int dstor_flush_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_sync(bf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_flush_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_flush_blob(dstor, &blobidx);
}

static int dstor_punch_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_punch(bf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_punch_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_punch_blob(dstor, &blobidx);
}

static int dstor_read_blob(struct silofs_dstor *dstor,
                           const struct silofs_blobidx *blobidx, off_t pos,
                           void *buf, size_t len)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_read(bf, pos, buf, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_read_blob_at(struct silofs_dstor *dstor,
                              const struct silofs_blobid *blobid, off_t pos,
                              void *buf, size_t len)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_read_blob(dstor, &blobidx, pos, buf, len);
}

static int dstor_write_blob(struct silofs_dstor *dstor,
                            const struct silofs_blobidx *blobidx, off_t pos,
                            const void *buf, size_t len)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_write(bf, pos, buf, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_write_blob_at(struct silofs_dstor *dstor,
                               const struct silofs_blobid *blobid, off_t pos,
                               const void *buf, size_t len)
{
	struct silofs_blobidx blobidx;

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_write_blob(dstor, &blobidx, pos, buf, len);
}

static int dstor_writev_blob(struct silofs_dstor *dstor,
                             const struct silofs_blobidx *blobidx, off_t pos,
                             const struct iovec *iov, size_t cnt, bool sync)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = dstor_require_cached_bf(dstor, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_writev(bf, pos, iov, cnt);
	if (err) {
		return err;
	}
	return sync ? bf_sync_range(bf, pos, silofs_iov_length(iov, cnt)) : 0;
}

int silofs_dstor_writev_blob_at(struct silofs_dstor *dstor,
                                const struct silofs_blobid *blobid, off_t pos,
                                const struct iovec *iov, size_t cnt)
{
	struct silofs_blobidx blobidx;
	bool sync = false; /* TODO: revisit */

	dstor_blobidx_of(dstor, blobid, &blobidx);
	return dstor_writev_blob(dstor, &blobidx, pos, iov, cnt, sync);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_stat_mbr(struct silofs_dstor *dstor,
                          const struct silofs_mbref *mbref,
                          struct stat *out_st)
{
	return dstor_stat_blob(dstor, &mbref->bx, out_st);
}

int silofs_dstor_save_mbr(struct silofs_dstor *dstor,
                          const struct silofs_mbref *mbref, const void *buf,
                          size_t len)
{
	int err;

	err = dstor_require_blob(dstor, &mbref->bx);
	if (err) {
		return err;
	}
	err = dstor_write_blob(dstor, &mbref->bx, 0, buf, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_load_mbr(struct silofs_dstor *dstor,
                          const struct silofs_mbref *mbref, void *buf,
                          size_t len)
{
	int err;

	err = dstor_sense_blob(dstor, &mbref->bx);
	if (err) {
		return err;
	}
	err = dstor_read_blob(dstor, &mbref->bx, 0, buf, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_dstor_unref_mbr(struct silofs_dstor *dstor,
                           const struct silofs_mbref *mbref)
{
	int err;

	err = dstor_sense_blob(dstor, &mbref->bx);
	if (err) {
		return err;
	}
	err = dstor_remove_blob(dstor, &mbref->bx);
	if (err) {
		return err;
	}
	return 0;
}
