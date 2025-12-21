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
#include <silofs/configs.h>
#include <silofs/errors.h>
#include <silofs/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include "infra.h"
#include "bstore.h"

/*
 * TODO-0035: Define proper upper-bound.
 *
 * Have explicit upper-limit to cached lsegs, based on the process' rlimit
 * RLIMIT_NOFILE and memory limits.
 */
enum {
	SILOFS_LACOS_CACHE_LIM = 64,
};

static int do_closefd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		log_warn("close error: fd=%d err=%d", *pfd, err);
	}
	return err;
}

static int do_opendir(const char *path, int *out_fd)
{
	int err;

	err = silofs_sys_opendir(path, out_fd);
	if (err) {
		log_warn("opendir failed: %s err=%d", path, err);
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
	struct silofs_blobidx   bf_blobidx;
	int                     bf_fd;
	bool                    bf_mapped;
};

static struct silofs_blobfile *bf_unconst(const struct silofs_blobfile *p)
{
	union {
		const struct silofs_blobfile *p;
		struct silofs_blobfile       *q;
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
	silofs_blobidx_tostr(&bf->bf_blobidx, out_name);
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
                           const struct silofs_blobidx  *blobidx)
{
	return silofs_blobidx_isequal(&bf->bf_blobidx, blobidx);
}

static int bf_stat(const struct silofs_blobfile *bf, struct stat *out_st)
{
	mode_t mode;
	int    err;

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
	int         err;

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
	int         err;

	err = bf_stat(bf, &st);
	if (!err && (off > st.st_size)) {
		err = bf_truncate(bf, off);
	}
	return err;
}

static int bf_stat_offset(const struct silofs_blobfile *bf, off_t off)
{
	struct stat st;
	int         err;

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

static int lhq_init(struct silofs_bstore_hq *lhq, struct silofs_alloc *alloc)
{
	const size_t nelems = 1024;

	silofs_listq_init(&lhq->vbq_lru);
	lhq->vbq_htb_nelems = 0;
	lhq->vbq_htb        = silofs_lista_new(alloc, nelems);
	if (lhq->vbq_htb == nullptr) {
		return -SILOFS_ENOMEM;
	}
	lhq->vbq_htb_nelems = nelems;
	return 0;
}

static void lhq_fini(struct silofs_bstore_hq *lhq, struct silofs_alloc *alloc)
{
	silofs_listq_fini(&lhq->vbq_lru);
	silofs_lista_del(lhq->vbq_htb, lhq->vbq_htb_nelems, alloc);
	lhq->vbq_htb        = nullptr;
	lhq->vbq_htb_nelems = 0;
}

static uint64_t lhq_hash_of(const struct silofs_blobidx *blobidx)
{
	return silofs_xxh64(blobidx->idx.hash, sizeof(blobidx->idx.hash), 0);
}

static size_t lhq_htb_slot_of(const struct silofs_bstore_hq *lhq,
                              const struct silofs_blobidx   *blobidx)
{
	return lhq_hash_of(blobidx) % lhq->vbq_htb_nelems;
}

static const struct silofs_list_head *
lhq_htb_list_of(const struct silofs_bstore_hq *lhq,
                const struct silofs_blobidx   *blobidx)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobidx);

	return &lhq->vbq_htb[slot];
}

static struct silofs_list_head *
lhq_htb_list_of2(struct silofs_bstore_hq     *lhq,
                 const struct silofs_blobidx *blobidx)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobidx);

	return &lhq->vbq_htb[slot];
}

static void
lhq_insert_htb(struct silofs_bstore_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_list_head *lst = lhq_htb_list_of2(lhq, &bf->bf_blobidx);

	list_push_front(lst, &bf->bf_htb_lh);
}

static void
lhq_insert_lru(struct silofs_bstore_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_push_front(&lhq->vbq_lru, &bf->bf_lru_lh);
}

static void
lhq_insert(struct silofs_bstore_hq *lhq, struct silofs_blobfile *bf)
{
	if (!bf->bf_mapped) {
		lhq_insert_htb(lhq, bf);
		lhq_insert_lru(lhq, bf);
		bf->bf_mapped = true;
	}
}

static size_t lhq_get_lru_size(const struct silofs_bstore_hq *lhq)
{
	return silofs_listq_size(&lhq->vbq_lru);
}

static void
lhq_promote_lru(struct silofs_bstore_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_listq     *lru = &lhq->vbq_lru;
	struct silofs_list_head *lh  = &bf->bf_lru_lh;

	silofs_assert_gt(lru->sz, 0);
	if (silofs_listq_front(lru) != lh) {
		silofs_listq_remove(lru, lh);
		silofs_listq_push_front(lru, lh);
	}
}

static struct silofs_blobfile *
lhq_get_lru_head(const struct silofs_bstore_hq *lhq)
{
	const struct silofs_listq *lru = &lhq->vbq_lru;

	return bf_from_lru_link(silofs_listq_front(lru));
}

static struct silofs_blobfile *
lhq_get_lru_next(const struct silofs_bstore_hq *lhq,
                 const struct silofs_blobfile  *bf)
{
	const struct silofs_listq *lru = &lhq->vbq_lru;
	struct silofs_blobfile    *nxt = nullptr;

	if (bf == nullptr) {
		nxt = lhq_get_lru_head(lhq);
	} else {
		nxt = bf_from_lru_link(silofs_listq_next(lru, &bf->bf_lru_lh));
	}
	return nxt;
}

static struct silofs_blobfile *
lhq_get_lru_tail(const struct silofs_bstore_hq *lhq)
{
	const struct silofs_listq *lru = &lhq->vbq_lru;

	return bf_from_lru_link(silofs_listq_back(lru));
}

static struct silofs_blobfile *
lhq_lookup_htb(const struct silofs_bstore_hq *lhq,
               const struct silofs_blobidx   *blobidx)
{
	const struct silofs_list_head *lst = nullptr;
	const struct silofs_list_head *itr = nullptr;
	const struct silofs_blobfile  *bf  = nullptr;

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
lhq_lookup(struct silofs_bstore_hq *lhq, const struct silofs_blobidx *blobidx)
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
lhq_remove_htb(struct silofs_bstore_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_assert_gt(lhq->vbq_lru.sz, 0);

	silofs_list_head_remove(&bf->bf_htb_lh);
}

static void
lhq_remove_lru(struct silofs_bstore_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_remove(&lhq->vbq_lru, &bf->bf_lru_lh);
}

static void
lhq_remove(struct silofs_bstore_hq *lhq, struct silofs_blobfile *bf)
{
	if (bf->bf_mapped) {
		lhq_remove_htb(lhq, bf);
		lhq_remove_lru(lhq, bf);
		bf->bf_mapped = false;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blobfile *
bstore_lookup_cached_bf(struct silofs_bstore        *bstore,
                        const struct silofs_blobidx *blobidx)
{
	return lhq_lookup(&bstore->bstore_hq, blobidx);
}

static void bstore_insert_cached_bf(struct silofs_bstore   *bstore,
                                    struct silofs_blobfile *bf)
{
	lhq_insert(&bstore->bstore_hq, bf);
}

static void bstore_remove_cached_bf(struct silofs_bstore   *bstore,
                                    struct silofs_blobfile *bf)
{
	lhq_remove(&bstore->bstore_hq, bf);
}

static struct silofs_blobfile *
bstore_new_bf(struct silofs_bstore        *bstore,
              const struct silofs_blobidx *blobidx)
{
	return bf_new(blobidx, bstore->bstore_alloc);
}

static void
bstore_del_bf(struct silofs_bstore *bstore, struct silofs_blobfile *bf)
{
	bf_close(bf);
	bf_del(bf, bstore->bstore_alloc);
}

static void bstore_forget_cached_bf(struct silofs_bstore   *bstore,
                                    struct silofs_blobfile *bf)
{
	bstore_remove_cached_bf(bstore, bf);
	bstore_del_bf(bstore, bf);
}

static void bstore_drop_cached(struct silofs_bstore *bstore)
{
	struct silofs_blobfile *bf;

	bf = lhq_get_lru_tail(&bstore->bstore_hq);
	while (bf != nullptr) {
		bf_sync(bf);
		bstore_forget_cached_bf(bstore, bf);
		bf = lhq_get_lru_tail(&bstore->bstore_hq);
	}
}

static int bstore_sync_cached(const struct silofs_bstore *bstore)
{
	struct silofs_blobfile *bf;
	int                     err = 0;

	bf = lhq_get_lru_head(&bstore->bstore_hq);
	while (bf != nullptr) {
		err = bf_sync(bf);
		if (err) {
			break;
		}
		bf = lhq_get_lru_next(&bstore->bstore_hq, bf);
	}
	return err;
}

static bool bstore_has_overpop_cache(const struct silofs_bstore *bstore)
{
	return (bstore->bstore_hq.vbq_lru.sz > SILOFS_LACOS_CACHE_LIM);
}

static struct silofs_blobfile *
bstore_get_overpop_bf(struct silofs_bstore *bstore)
{
	struct silofs_blobfile *bf = nullptr;

	if (bstore_has_overpop_cache(bstore)) {
		bf = lhq_get_lru_tail(&bstore->bstore_hq);
	}
	return bf;
}

static void bstore_relax_cache(struct silofs_bstore *bstore)
{
	struct silofs_blobfile *bf;

	bf = bstore_get_overpop_bf(bstore);
	while (bf != nullptr) {
		bstore_forget_cached_bf(bstore, bf);
		bf = bstore_get_overpop_bf(bstore);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bstore_close(struct silofs_bstore *bstore)
{
	do_closefd(&bstore->bstore_dfd);
}

int silofs_bstore_init(struct silofs_bstore *bstore,
                       struct silofs_alloc  *alloc)
{
	int err;

	bstore->bstore_alloc = alloc;
	bstore->bstore_dfd   = -1;

	err = silofs_mdigest_init(&bstore->bstore_md);
	if (err) {
		return err;
	}
	err = lhq_init(&bstore->bstore_hq, bstore->bstore_alloc);
	if (err) {
		silofs_mdigest_fini(&bstore->bstore_md);
		return err;
	}
	return 0;
}

void silofs_bstore_fini(struct silofs_bstore *bstore)
{
	bstore_drop_cached(bstore);
	bstore_close(bstore);
	lhq_fini(&bstore->bstore_hq, bstore->bstore_alloc);
	silofs_mdigest_fini(&bstore->bstore_md);
	bstore->bstore_alloc = nullptr;
}

static bool bstore_isopen(const struct silofs_bstore *bstore)
{
	return bstore->bstore_dfd >= 0;
}

static void blobs_pathname(struct silofs_strbuf *sbuf)
{
	const char *dots = SILOFS_REPO_DOTS_DIRNAME;
	const char *subd = SILOFS_REPO_BLOBS_DIRNAME;

	silofs_strbuf_sprintf(sbuf, "%s/%s", dots, subd);
}

static int
bstore_open(struct silofs_bstore *bstore, const struct silofs_strview *repodir)
{
	struct silofs_strbuf sbuf;
	int                  root_dfd = -1;
	int                  err;

	err = do_opendir(repodir->str, &root_dfd);
	if (err) {
		goto out;
	}
	blobs_pathname(&sbuf);
	err = do_opendirat(root_dfd, sbuf.str, &bstore->bstore_dfd);
	if (err) {
		goto out;
	}
out:
	do_closefd(&root_dfd);
	return err;
}

int silofs_bstore_open(struct silofs_bstore        *bstore,
                       const struct silofs_strview *repodir)
{
	int ret = -SILOFS_EALREADY;

	if (!bstore_isopen(bstore)) {
		ret = bstore_open(bstore, repodir);
	}
	return ret;
}

void silofs_bstore_close(struct silofs_bstore *bstore)
{
	bstore_drop_cached(bstore);
	if (bstore_isopen(bstore)) {
		bstore_close(bstore);
	}
}

void silofs_bstore_relax(struct silofs_bstore *bstore)
{
	if (bstore_isopen(bstore)) {
		bstore_relax_cache(bstore);
	}
}

void silofs_bstore_drop(struct silofs_bstore *bstore)
{
	if (bstore_isopen(bstore)) {
		bstore_drop_cached(bstore);
	}
}

int silofs_bstore_sync(const struct silofs_bstore *bstore)
{
	int ret = 0;

	if (bstore_isopen(bstore)) {
		ret = bstore_sync_cached(bstore);
	}
	return ret;
}

static int bstore_spawn_blob(struct silofs_bstore        *bstore,
                             const struct silofs_blobidx *blobidx,
                             struct silofs_blobfile     **out_bf)
{
	struct silofs_blobfile *bf = nullptr;
	int                     err;

	bf = bstore_lookup_cached_bf(bstore, blobidx);
	if (bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	bf = bstore_new_bf(bstore, blobidx);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_create(bf, bstore->bstore_dfd);
	if (err) {
		bstore_del_bf(bstore, bf);
		return err;
	}
	*out_bf = bf;
	return 0;
}

static int bstore_spawn_blob2(struct silofs_bstore        *bstore,
                              const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf = nullptr;

	return bstore_spawn_blob(bstore, blobidx, &bf);
}

static int bstore_spawn_and_cache_bf(struct silofs_bstore        *bstore,
                                     const struct silofs_blobidx *blobidx,
                                     struct silofs_blobfile     **out_bf)
{
	int err;

	*out_bf = bstore_lookup_cached_bf(bstore, blobidx);
	if (*out_bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	bstore_relax_cache(bstore);

	err = bstore_spawn_blob(bstore, blobidx, out_bf);
	if (err) {
		return err;
	}
	bstore_insert_cached_bf(bstore, *out_bf);
	return 0;
}

static int bstore_stage_blob(struct silofs_bstore        *bstore,
                             const struct silofs_blobidx *blobidx,
                             struct silofs_blobfile     **out_bf)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	bf = bstore_new_bf(bstore, blobidx);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_open(bf, bstore->bstore_dfd);
	if (err) {
		bstore_del_bf(bstore, bf);
		return err;
	}
	*out_bf = bf;
	return err;
}

static int bstore_stage_and_cache_bf(struct silofs_bstore        *bstore,
                                     const struct silofs_blobidx *blobidx,
                                     struct silofs_blobfile     **out_bf)
{
	int err;

	*out_bf = bstore_lookup_cached_bf(bstore, blobidx);
	if (*out_bf != nullptr) {
		return 0; /* cache hit */
	}
	bstore_relax_cache(bstore);

	err = bstore_stage_blob(bstore, blobidx, out_bf);
	if (err) {
		return err;
	}
	bstore_insert_cached_bf(bstore, *out_bf);
	return 0;
}

static void bstore_blobidx_of(struct silofs_bstore       *bstore,
                              const struct silofs_blobid *blobid,
                              struct silofs_blobidx      *out_blobidx)
{
	silofs_blobidx_derive(out_blobidx, &bstore->bstore_md, blobid);
}

int silofs_bstore_spawn_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobidx   blobidx;
	struct silofs_blobfile *bf = nullptr;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_spawn_and_cache_bf(bstore, &blobidx, &bf);
}

static int bstore_remove_blob(struct silofs_bstore        *bstore,
                              const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_unlink(bf, bstore->bstore_dfd);
	if (err) {
		return err;
	}
	bstore_forget_cached_bf(bstore, bf);
	return 0;
}

int silofs_bstore_remove_blob(struct silofs_bstore       *bstore,
                              const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_remove_blob(bstore, &blobidx);
}

static int
bstore_stat_blob(struct silofs_bstore        *bstore,
                 const struct silofs_blobidx *blobidx, struct stat *out_st)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_stat(bf, out_st);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_stat_blob(struct silofs_bstore       *bstore,
                            const struct silofs_blobid *blobid,
                            struct stat                *out_st)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_stat_blob(bstore, &blobidx, out_st);
}

int silofs_bstore_stage_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;
	struct stat           st;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_stat_blob(bstore, &blobidx, &st);
}

static int bstore_require_blob(struct silofs_bstore        *bstore,
                               const struct silofs_blobidx *blobidx)
{
	struct stat st;
	int         err;

	err = bstore_stat_blob(bstore, blobidx, &st);
	if (err && (err == -ENOENT)) {
		err = bstore_spawn_blob2(bstore, blobidx);
	}
	return err;
}

int silofs_bstore_require_blob(struct silofs_bstore       *bstore,
                               const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_require_blob(bstore, &blobidx);
}

static int bstore_require_bpos(struct silofs_bstore        *bstore,
                               const struct silofs_blobidx *blobidx, off_t pos)
{
	struct silofs_blobfile *bf = nullptr;
	int                     err;

	err = bstore_require_blob(bstore, blobidx);
	if (err) {
		return err;
	}
	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_expand(bf, pos);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_require_blob_at(struct silofs_bstore       *bstore,
                                  const struct silofs_blobid *blobid,
                                  off_t                       pos)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_require_bpos(bstore, &blobidx, pos);
}

static int bstore_access_bpos(struct silofs_bstore        *bstore,
                              const struct silofs_blobidx *blobidx, off_t pos)
{
	struct silofs_blobfile *bf = nullptr;
	int                     err;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_stat_offset(bf, pos);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_access_blob_at(struct silofs_bstore       *bstore,
                                 const struct silofs_blobid *blobid, off_t pos)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_access_bpos(bstore, &blobidx, pos);
}

static int bstore_flush_blob(struct silofs_bstore        *bstore,
                             const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_sync(bf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_flush_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_flush_blob(bstore, &blobidx);
}

static int bstore_punch_blob(struct silofs_bstore        *bstore,
                             const struct silofs_blobidx *blobidx)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_punch(bf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_punch_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_punch_blob(bstore, &blobidx);
}

static int bstore_read_blob(struct silofs_bstore        *bstore,
                            const struct silofs_blobidx *blobidx, off_t pos,
                            void *buf, size_t len)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_read(bf, pos, buf, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_read_blob_at(struct silofs_bstore       *bstore,
                               const struct silofs_blobid *blobid, off_t pos,
                               void *buf, size_t len)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_read_blob(bstore, &blobidx, pos, buf, len);
}

static int bstore_write_blob(struct silofs_bstore        *bstore,
                             const struct silofs_blobidx *blobidx, off_t pos,
                             const void *buf, size_t len)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_write(bf, pos, buf, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_write_blob_at(struct silofs_bstore       *bstore,
                                const struct silofs_blobid *blobid, off_t pos,
                                const void *buf, size_t len)
{
	struct silofs_blobidx blobidx;

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_write_blob(bstore, &blobidx, pos, buf, len);
}

static int bstore_writev_blob(struct silofs_bstore        *bstore,
                              const struct silofs_blobidx *blobidx, off_t pos,
                              const struct iovec *iov, size_t cnt, bool sync)
{
	struct silofs_blobfile *bf  = nullptr;
	int                     err = 0;

	err = bstore_stage_and_cache_bf(bstore, blobidx, &bf);
	if (err) {
		return err;
	}
	err = bf_writev(bf, pos, iov, cnt);
	if (err) {
		return err;
	}
	return sync ? bf_sync_range(bf, pos, silofs_iov_length(iov, cnt)) : 0;
}

int silofs_bstore_writev_blob_at(struct silofs_bstore       *bstore,
                                 const struct silofs_blobid *blobid, off_t pos,
                                 const struct iovec *iov, size_t cnt)
{
	struct silofs_blobidx blobidx;
	bool                  sync = false; /* TODO: revisit */

	bstore_blobidx_of(bstore, blobid, &blobidx);
	return bstore_writev_blob(bstore, &blobidx, pos, iov, cnt, sync);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_save_mbref(struct silofs_bstore      *bstore,
                             const struct silofs_mbref *mbref, const void *buf,
                             size_t len)
{
	return bstore_write_blob(bstore, &mbref->bx, 0, buf, len);
}

int silofs_bstore_load_mbref(struct silofs_bstore      *bstore,
                             const struct silofs_mbref *mbref, void *buf,
                             size_t len)
{
	return bstore_read_blob(bstore, &mbref->bx, 0, buf, len);
}
