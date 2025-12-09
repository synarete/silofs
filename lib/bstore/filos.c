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
#include "configs.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <silofs/errors.h>
#include <silofs/syscall.h>
#include "infra.h"
#include "filos.h"

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
	struct silofs_blobid bf_blobid;
	struct silofs_strbuf bf_blobid_name;
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

static const char *bf_name(const struct silofs_blobfile *bf)
{
	return bf->bf_blobid_name.str;
}

static int bf_open(struct silofs_blobfile *bf, int dfd)
{
	return do_openat(dfd, bf_name(bf), O_RDWR, 0, &bf->bf_fd);
}

static int bf_create(struct silofs_blobfile *bf, int dfd)
{
	const int o_flags = O_CREAT | O_EXCL | O_RDWR;

	return do_openat(dfd, bf_name(bf), o_flags, 0600, &bf->bf_fd);
}

static int bf_unlink(const struct silofs_blobfile *bf, int dfd)
{
	return do_unlinkat(dfd, bf_name(bf), 0);
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

static bool bf_has_blobid(const struct silofs_blobfile *bf,
                          const struct silofs_blobid *bid)
{
	return silofs_blobid_isequal(&bf->bf_blobid, bid);
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
                    const struct silofs_rovec *rov)
{
	return do_pwriten(bf->bf_fd, rov->rov_base, rov->rov_len, pos);
}

static int bf_writev(const struct silofs_blobfile *bf, off_t pos,
                     const struct iovec *iov, size_t cnt)
{
	return do_pwritevn(bf->bf_fd, iov, cnt, pos);
}

static int bf_read(const struct silofs_blobfile *bf, off_t pos,
                   const struct silofs_rwvec *rwv)
{
	return do_preadn(bf->bf_fd, rwv->rwv_base, rwv->rwv_len, pos);
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

static void
bf_init(struct silofs_blobfile *bf, const struct silofs_blobid *blobid,
        const struct silofs_strview *name)
{
	silofs_list_head_init(&bf->bf_htb_lh);
	silofs_list_head_init(&bf->bf_lru_lh);
	silofs_blobid_copyto(blobid, &bf->bf_blobid);
	silofs_strbuf_setup(&bf->bf_blobid_name, name);
	bf->bf_fd = -1;
	bf->bf_mapped = false;
}

static void bf_fini(struct silofs_blobfile *bf)
{
	silofs_assert(!bf->bf_mapped);

	bf_close(bf);
	silofs_blobid_reset(&bf->bf_blobid);
	silofs_list_head_fini(&bf->bf_lru_lh);
	silofs_list_head_fini(&bf->bf_htb_lh);
}

static struct silofs_blobfile *
bf_new(const struct silofs_blobid *blobid, const struct silofs_strview *name,
       struct silofs_alloc *alloc)
{
	struct silofs_blobfile *bf;

	bf = silofs_memalloc(alloc, sizeof(*bf), 0);
	if (bf != nullptr) {
		bf_init(bf, blobid, name);
	}
	return bf;
}

static void bf_del(struct silofs_blobfile *bf, struct silofs_alloc *alloc)
{
	bf_fini(bf);
	silofs_memfree(alloc, bf, sizeof(*bf), 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int lhq_init(struct silofs_filos_hq *lhq, struct silofs_alloc *alloc)
{
	const size_t nelems = 1024;

	silofs_listq_init(&lhq->lhq_lru);
	lhq->lhq_htb_nelems = 0;
	lhq->lhq_htb = silofs_lista_new(alloc, nelems);
	if (lhq->lhq_htb == nullptr) {
		return -SILOFS_ENOMEM;
	}
	lhq->lhq_htb_nelems = nelems;
	return 0;
}

static void lhq_fini(struct silofs_filos_hq *lhq, struct silofs_alloc *alloc)
{
	silofs_listq_fini(&lhq->lhq_lru);
	silofs_lista_del(lhq->lhq_htb, lhq->lhq_htb_nelems, alloc);
	lhq->lhq_htb = nullptr;
	lhq->lhq_htb_nelems = 0;
}

static size_t lhq_htb_slot_of(const struct silofs_filos_hq *lhq,
                              const struct silofs_blobid *blobid)
{
	const uint64_t hash = silofs_blobid_hash64(blobid, 0);

	return hash % lhq->lhq_htb_nelems;
}

static const struct silofs_list_head *
lhq_htb_list_of(const struct silofs_filos_hq *lhq,
                const struct silofs_blobid *blobid)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobid);

	return &lhq->lhq_htb[slot];
}

static struct silofs_list_head *
lhq_htb_list_of2(struct silofs_filos_hq *lhq,
                 const struct silofs_blobid *blobid)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobid);

	return &lhq->lhq_htb[slot];
}

static void
lhq_insert_htb(struct silofs_filos_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_list_head *lst = lhq_htb_list_of2(lhq, &bf->bf_blobid);

	list_push_front(lst, &bf->bf_htb_lh);
}

static void
lhq_insert_lru(struct silofs_filos_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_push_front(&lhq->lhq_lru, &bf->bf_lru_lh);
}

static void lhq_insert(struct silofs_filos_hq *lhq, struct silofs_blobfile *bf)
{
	if (!bf->bf_mapped) {
		lhq_insert_htb(lhq, bf);
		lhq_insert_lru(lhq, bf);
		bf->bf_mapped = true;
	}
}

static size_t lhq_get_lru_size(const struct silofs_filos_hq *lhq)
{
	return silofs_listq_size(&lhq->lhq_lru);
}

static void
lhq_promote_lru(struct silofs_filos_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_listq *lru = &lhq->lhq_lru;
	struct silofs_list_head *lh = &bf->bf_lru_lh;

	silofs_assert_gt(lru->sz, 0);
	if (silofs_listq_front(lru) != lh) {
		silofs_listq_remove(lru, lh);
		silofs_listq_push_front(lru, lh);
	}
}

static struct silofs_blobfile *
lhq_get_lru_head(const struct silofs_filos_hq *lhq)
{
	const struct silofs_listq *lru = &lhq->lhq_lru;

	return bf_from_lru_link(silofs_listq_front(lru));
}

static struct silofs_blobfile *
lhq_get_lru_next(const struct silofs_filos_hq *lhq,
                 const struct silofs_blobfile *bf)
{
	const struct silofs_listq *lru = &lhq->lhq_lru;
	struct silofs_blobfile *nxt = nullptr;

	if (bf == nullptr) {
		nxt = lhq_get_lru_head(lhq);
	} else {
		nxt = bf_from_lru_link(silofs_listq_next(lru, &bf->bf_lru_lh));
	}
	return nxt;
}

static struct silofs_blobfile *
lhq_get_lru_tail(const struct silofs_filos_hq *lhq)
{
	const struct silofs_listq *lru = &lhq->lhq_lru;

	return bf_from_lru_link(silofs_listq_back(lru));
}

static struct silofs_blobfile *
lhq_lookup_htb(const struct silofs_filos_hq *lhq,
               const struct silofs_blobid *blobid)
{
	const struct silofs_list_head *lst = nullptr;
	const struct silofs_list_head *itr = nullptr;
	const struct silofs_blobfile *bf = nullptr;

	lst = lhq_htb_list_of(lhq, blobid);
	itr = lst->next;
	while ((itr != lst) && (itr != nullptr)) {
		bf = bf_from_htb_link(itr);
		if (bf_has_blobid(bf, blobid)) {
			return bf_unconst(bf);
		}
		itr = itr->next;
	}
	return nullptr;
}

static struct silofs_blobfile *
lhq_lookup(struct silofs_filos_hq *lhq, const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;

	if (!lhq_get_lru_size(lhq)) {
		goto out;
	}
	bf = lhq_lookup_htb(lhq, blobid);
	if (bf == nullptr) {
		goto out;
	}
	lhq_promote_lru(lhq, bf);
out:
	return bf;
}

static void
lhq_remove_htb(struct silofs_filos_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_assert_gt(lhq->lhq_lru.sz, 0);

	silofs_list_head_remove(&bf->bf_htb_lh);
}

static void
lhq_remove_lru(struct silofs_filos_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_remove(&lhq->lhq_lru, &bf->bf_lru_lh);
}

static void lhq_remove(struct silofs_filos_hq *lhq, struct silofs_blobfile *bf)
{
	if (bf->bf_mapped) {
		lhq_remove_htb(lhq, bf);
		lhq_remove_lru(lhq, bf);
		bf->bf_mapped = false;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blobfile *
filos_lookup_cached_bf(struct silofs_filos *filos,
                       const struct silofs_blobid *blobid)
{
	return lhq_lookup(&filos->los_hq, blobid);
}

static void
filos_insert_cached_bf(struct silofs_filos *filos, struct silofs_blobfile *bf)
{
	lhq_insert(&filos->los_hq, bf);
}

static void
filos_remove_cached_bf(struct silofs_filos *filos, struct silofs_blobfile *bf)
{
	lhq_remove(&filos->los_hq, bf);
}

static void filos_name_of(const struct silofs_filos *filos,
                          const struct silofs_blobid *blobid,
                          struct silofs_strbuf *out_name)
{
	struct silofs_hash256 hash;
	const struct silofs_mdigest *md = &filos->los_md;

	silofs_sha3_256_of(md, blobid->id, sizeof(blobid->id), &hash);
	silofs_hash256_to_name(&hash, out_name);
}

static struct silofs_blobfile *
filos_new_bf(struct silofs_filos *filos, const struct silofs_blobid *blobid)
{
	struct silofs_strbuf name;
	struct silofs_strview sv;

	filos_name_of(filos, blobid, &name);
	silofs_strview_init(&sv, name.str);
	return bf_new(blobid, &sv, filos->los_alloc);
}

static void
filos_del_bf(struct silofs_filos *filos, struct silofs_blobfile *bf)
{
	bf_close(bf);
	bf_del(bf, filos->los_alloc);
}

static void
filos_forget_cached_bf(struct silofs_filos *filos, struct silofs_blobfile *bf)
{
	filos_remove_cached_bf(filos, bf);
	filos_del_bf(filos, bf);
}

static void filos_drop_cached(struct silofs_filos *filos)
{
	struct silofs_blobfile *bf;

	bf = lhq_get_lru_tail(&filos->los_hq);
	while (bf != nullptr) {
		bf_sync(bf);
		filos_forget_cached_bf(filos, bf);
		bf = lhq_get_lru_tail(&filos->los_hq);
	}
}

static int filos_sync_cached(const struct silofs_filos *filos)
{
	struct silofs_blobfile *bf;
	int err = 0;

	bf = lhq_get_lru_head(&filos->los_hq);
	while (bf != nullptr) {
		err = bf_sync(bf);
		if (err) {
			break;
		}
		bf = lhq_get_lru_next(&filos->los_hq, bf);
	}
	return err;
}

static bool filos_has_overpop_cache(const struct silofs_filos *filos)
{
	return (filos->los_hq.lhq_lru.sz > SILOFS_LACOS_CACHE_LIM);
}

static struct silofs_blobfile *filos_get_overpop_bf(struct silofs_filos *filos)
{
	struct silofs_blobfile *bf = nullptr;

	if (filos_has_overpop_cache(filos)) {
		bf = lhq_get_lru_tail(&filos->los_hq);
	}
	return bf;
}

static void filos_relax_cache(struct silofs_filos *filos)
{
	struct silofs_blobfile *bf;

	bf = filos_get_overpop_bf(filos);
	while (bf != nullptr) {
		filos_forget_cached_bf(filos, bf);
		bf = filos_get_overpop_bf(filos);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void filos_close(struct silofs_filos *filos)
{
	do_closefd(&filos->los_dfd);
}

int silofs_filos_init(struct silofs_filos *filos, struct silofs_alloc *alloc)
{
	int err;

	filos->los_alloc = alloc;
	filos->los_dfd = -1;
	err = silofs_mdigest_init(&filos->los_md);
	if (err) {
		return err;
	}
	err = lhq_init(&filos->los_hq, filos->los_alloc);
	if (err) {
		silofs_mdigest_fini(&filos->los_md);
		return err;
	}
	return 0;
}

void silofs_filos_fini(struct silofs_filos *filos)
{
	filos_drop_cached(filos);
	filos_close(filos);
	lhq_fini(&filos->los_hq, filos->los_alloc);
	silofs_mdigest_fini(&filos->los_md);
	filos->los_alloc = nullptr;
}

static bool filos_isopen(const struct silofs_filos *filos)
{
	return filos->los_dfd >= 0;
}

static void blobs_pathname(struct silofs_strbuf *sbuf)
{
	const char *dots = SILOFS_REPO_DOTS_DIRNAME;
	const char *subd = SILOFS_REPO_BLOBS_DIRNAME;

	silofs_strbuf_sprintf(sbuf, "%s/%s", dots, subd);
}

static int
filos_open(struct silofs_filos *filos, const struct silofs_strview *repodir)
{
	struct silofs_strbuf sbuf;
	int root_dfd = -1;
	int err;

	err = do_opendir(repodir->str, &root_dfd);
	if (err) {
		goto out;
	}
	blobs_pathname(&sbuf);
	err = do_opendirat(root_dfd, sbuf.str, &filos->los_dfd);
	if (err) {
		goto out;
	}
out:
	do_closefd(&root_dfd);
	return err;
}

int silofs_filos_open(struct silofs_filos *filos,
                      const struct silofs_strview *repodir)
{
	int ret = -SILOFS_EALREADY;

	if (!filos_isopen(filos)) {
		ret = filos_open(filos, repodir);
	}
	return ret;
}

void silofs_filos_close(struct silofs_filos *filos)
{
	filos_drop_cached(filos);
	if (filos_isopen(filos)) {
		filos_close(filos);
	}
}

void silofs_filos_relax(struct silofs_filos *filos)
{
	if (filos_isopen(filos)) {
		filos_relax_cache(filos);
	}
}

void silofs_filos_drop(struct silofs_filos *filos)
{
	if (filos_isopen(filos)) {
		filos_drop_cached(filos);
	}
}

int silofs_filos_sync(const struct silofs_filos *filos)
{
	int ret = 0;

	if (filos_isopen(filos)) {
		ret = filos_sync_cached(filos);
	}
	return ret;
}

static int filos_spawn_blob(struct silofs_filos *filos,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobfile **out_bf)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	bf = filos_lookup_cached_bf(filos, blobid);
	if (bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	bf = filos_new_bf(filos, blobid);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_create(bf, filos->los_dfd);
	if (err) {
		filos_del_bf(filos, bf);
		return err;
	}
	*out_bf = bf;
	return 0;
}

static int filos_spawn_and_cache_bf(struct silofs_filos *filos,
                                    const struct silofs_blobid *blobid,
                                    struct silofs_blobfile **out_bf)
{
	int err;

	*out_bf = filos_lookup_cached_bf(filos, blobid);
	if (*out_bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	filos_relax_cache(filos);

	err = filos_spawn_blob(filos, blobid, out_bf);
	if (err) {
		return err;
	}
	filos_insert_cached_bf(filos, *out_bf);
	return 0;
}

static int filos_stage_blob(struct silofs_filos *filos,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobfile **out_bf)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	bf = filos_new_bf(filos, blobid);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_open(bf, filos->los_dfd);
	if (err) {
		filos_del_bf(filos, bf);
		return err;
	}
	*out_bf = bf;
	return err;
}

static int filos_stage_and_cache_bf(struct silofs_filos *filos,
                                    const struct silofs_blobid *blobid,
                                    struct silofs_blobfile **out_bf)
{
	int err;

	*out_bf = filos_lookup_cached_bf(filos, blobid);
	if (*out_bf != nullptr) {
		return 0; /* cache hit */
	}
	filos_relax_cache(filos);

	err = filos_stage_blob(filos, blobid, out_bf);
	if (err) {
		return err;
	}
	filos_insert_cached_bf(filos, *out_bf);
	return 0;
}

int silofs_filos_spawn_blob(struct silofs_filos *filos,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;

	return filos_spawn_and_cache_bf(filos, blobid, &bf);
}

int silofs_filos_remove_blob(struct silofs_filos *filos,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = filos_stage_and_cache_bf(filos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_unlink(bf, filos->los_dfd);
	if (err) {
		return err;
	}
	filos_forget_cached_bf(filos, bf);
	return 0;
}

int silofs_filos_stat_blob(struct silofs_filos *filos,
                           const struct silofs_blobid *blobid,
                           struct stat *out_st)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = filos_stage_and_cache_bf(filos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_stat(bf, out_st);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_filos_stage_blob(struct silofs_filos *filos,
                            const struct silofs_blobid *blobid)
{
	struct stat st;

	return silofs_filos_stat_blob(filos, blobid, &st);
}

int silofs_filos_require_blob(struct silofs_filos *filos,
                              const struct silofs_blobid *blobid)
{
	struct stat st;
	int err;

	err = silofs_filos_stat_blob(filos, blobid, &st);
	if (err && (err == -ENOENT)) {
		err = silofs_filos_spawn_blob(filos, blobid);
	}
	return err;
}

int silofs_filos_require_bpos(struct silofs_filos *filos,
                              const struct silofs_blobid *blobid, off_t pos)
{
	struct stat st = { .st_size = -1 };
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = silofs_filos_require_blob(filos, blobid);
	if (err) {
		return err;
	}
	err = filos_stage_and_cache_bf(filos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_stat(bf, &st);
	if (err) {
		return err;
	}
	if (pos <= st.st_size) {
		return 0;
	}
	err = bf_truncate(bf, pos);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_filos_access_bpos(struct silofs_filos *filos,
                             const struct silofs_blobid *blobid, off_t pos)
{
	struct stat st = { .st_size = -1 };
	struct silofs_blobfile *bf = nullptr;
	int err;

	err = filos_stage_and_cache_bf(filos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_stat(bf, &st);
	if (err) {
		return err;
	}
	if (pos > st.st_size) {
		return -SILOFS_ERANGE;
	}
	return 0;
}

int silofs_filos_flush_blob(struct silofs_filos *filos,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = filos_stage_and_cache_bf(filos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_sync(bf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_filos_punch_blob(struct silofs_filos *filos,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = filos_stage_and_cache_bf(filos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_punch(bf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_filos_write_blob(struct silofs_filos *filos,
                            const struct silofs_paddr *paddr,
                            const struct silofs_rovec *rovec)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = filos_stage_and_cache_bf(filos, &paddr->blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_write(bf, paddr->pos, rovec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_filos_writev_blob(struct silofs_filos *filos,
                             const struct silofs_paddr *paddr,
                             const struct iovec *iov, size_t cnt)
{
	struct silofs_blobfile *bf = nullptr;
	const off_t pos = paddr->pos;
	int err = 0;
	bool sync = false; /* TODO: revisit */

	err = filos_stage_and_cache_bf(filos, &paddr->blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_writev(bf, pos, iov, cnt);
	if (err) {
		return err;
	}
	return sync ? bf_sync_range(bf, pos, silofs_iov_length(iov, cnt)) : 0;
}

int silofs_filos_read_blob(struct silofs_filos *filos,
                           const struct silofs_paddr *paddr,
                           const struct silofs_rwvec *rwvec)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = filos_stage_and_cache_bf(filos, &paddr->blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_read(bf, paddr->pos, rwvec);
	if (err) {
		return err;
	}
	return 0;
}
