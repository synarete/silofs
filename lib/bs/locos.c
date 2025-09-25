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
#include "str.h"
#include "locos.h"

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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_blobfile {
	struct silofs_list_head bf_htb_lh;
	struct silofs_list_head bf_lru_lh;
	struct silofs_blobid bf_blobid;
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
	silofs_blobid_to_sbuf(&bf->bf_blobid, out_name);
}

static int bf_open(struct silofs_blobfile *bf, int dfd)
{
	struct silofs_strbuf sbuf;

	bf_name(bf, &sbuf);
	return do_openat(dfd, sbuf.str, O_RDWR, 0, &bf->bf_fd);
}

static int bf_create(struct silofs_blobfile *bf, int dfd)
{
	struct silofs_strbuf sbuf;

	bf_name(bf, &sbuf);
	return do_openat(dfd, sbuf.str, O_RDWR | O_CREAT, 0600, &bf->bf_fd);
}

static int bf_unlink(const struct silofs_blobfile *bf, int dfd)
{
	struct silofs_strbuf sbuf;

	bf_name(bf, &sbuf);
	return do_unlinkat(dfd, sbuf.str, 0);
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

static int bf_write(const struct silofs_blobfile *bf, off_t pos,
                    const struct silofs_rovec *rov)
{
	return do_pwriten(bf->bf_fd, rov->rov_base, rov->rov_len, pos);
}

static int bf_read(const struct silofs_blobfile *bf, off_t pos,
                   const struct silofs_rwvec *rwv)
{
	return do_preadn(bf->bf_fd, rwv->rwv_base, rwv->rwv_len, pos);
}

static void
bf_init(struct silofs_blobfile *bf, const struct silofs_blobid *bid)
{
	silofs_list_head_init(&bf->bf_htb_lh);
	silofs_list_head_init(&bf->bf_lru_lh);
	silofs_blobid_assign(&bf->bf_blobid, bid);
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
bf_new(const struct silofs_blobid *bid, struct silofs_alloc *alloc)
{
	struct silofs_blobfile *bf;

	bf = silofs_memalloc(alloc, sizeof(*bf), 0);
	if (bf != nullptr) {
		bf_init(bf, bid);
	}
	return bf;
}

static void bf_del(struct silofs_blobfile *bf, struct silofs_alloc *alloc)
{
	bf_fini(bf);
	silofs_memfree(alloc, bf, sizeof(*bf), 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int lhq_init(struct silofs_locos_hq *lhq, struct silofs_alloc *alloc)
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

static void lhq_fini(struct silofs_locos_hq *lhq, struct silofs_alloc *alloc)
{
	silofs_listq_fini(&lhq->lhq_lru);
	silofs_lista_del(lhq->lhq_htb, lhq->lhq_htb_nelems, alloc);
	lhq->lhq_htb = nullptr;
	lhq->lhq_htb_nelems = 0;
}

static size_t lhq_htb_slot_of(const struct silofs_locos_hq *lhq,
                              const struct silofs_blobid *blobid)
{
	const uint64_t hash = silofs_blobid_hash64(blobid, 0);

	return hash % lhq->lhq_htb_nelems;
}

static const struct silofs_list_head *
lhq_htb_list_of(const struct silofs_locos_hq *lhq,
                const struct silofs_blobid *blobid)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobid);

	return &lhq->lhq_htb[slot];
}

static struct silofs_list_head *
lhq_htb_list_of2(struct silofs_locos_hq *lhq,
                 const struct silofs_blobid *blobid)
{
	const size_t slot = lhq_htb_slot_of(lhq, blobid);

	return &lhq->lhq_htb[slot];
}

static void
lhq_insert_htb(struct silofs_locos_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_list_head *lst = lhq_htb_list_of2(lhq, &bf->bf_blobid);

	list_push_front(lst, &bf->bf_htb_lh);
}

static void
lhq_insert_lru(struct silofs_locos_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_push_front(&lhq->lhq_lru, &bf->bf_lru_lh);
}

static void lhq_insert(struct silofs_locos_hq *lhq, struct silofs_blobfile *bf)
{
	if (!bf->bf_mapped) {
		lhq_insert_htb(lhq, bf);
		lhq_insert_lru(lhq, bf);
		bf->bf_mapped = true;
	}
}

static void
lhq_promote_lru(struct silofs_locos_hq *lhq, struct silofs_blobfile *bf)
{
	struct silofs_listq *lru = &lhq->lhq_lru;
	struct silofs_list_head *lh = &bf->bf_lru_lh;

	silofs_assert_gt(lru->sz, 0);
	if (silofs_listq_front(lru) != lh) {
		silofs_listq_remove(lru, lh);
		silofs_listq_push_front(lru, lh);
	}
}

static struct silofs_blobfile *lhq_get_lru_tail(struct silofs_locos_hq *lhq)
{
	struct silofs_listq *lru = &lhq->lhq_lru;

	return bf_from_lru_link(silofs_listq_back(lru));
}

static struct silofs_blobfile *
lhq_lookup_htb(const struct silofs_locos_hq *lhq,
               const struct silofs_blobid *blobid)
{
	const struct silofs_list_head *lst = nullptr;
	const struct silofs_list_head *itr = nullptr;
	const struct silofs_blobfile *bf = nullptr;

	lst = lhq_htb_list_of(lhq, blobid);
	itr = lst->next;
	while (itr != lst) {
		bf = bf_from_htb_link(itr);
		if (bf_has_blobid(bf, blobid)) {
			return bf_unconst(bf);
		}
		itr = itr->next;
	}
	return nullptr;
}

static struct silofs_blobfile *
lhq_lookup(struct silofs_locos_hq *lhq, const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;

	if (silofs_listq_isempty(&lhq->lhq_lru)) {
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
lhq_remove_htb(struct silofs_locos_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_assert_gt(lhq->lhq_lru.sz, 0);

	silofs_list_head_remove(&bf->bf_htb_lh);
}

static void
lhq_remove_lru(struct silofs_locos_hq *lhq, struct silofs_blobfile *bf)
{
	silofs_listq_remove(&lhq->lhq_lru, &bf->bf_lru_lh);
}

static void lhq_remove(struct silofs_locos_hq *lhq, struct silofs_blobfile *bf)
{
	if (bf->bf_mapped) {
		lhq_remove_htb(lhq, bf);
		lhq_remove_lru(lhq, bf);
		bf->bf_mapped = false;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blobfile *
locos_lookup_cached_bf(struct silofs_locos *locos,
                       const struct silofs_blobid *blobid)
{
	return lhq_lookup(&locos->los_hq, blobid);
}

static void
locos_insert_cached_bf(struct silofs_locos *locos, struct silofs_blobfile *bf)
{
	lhq_insert(&locos->los_hq, bf);
}

static void
locos_remove_cached_bf(struct silofs_locos *locos, struct silofs_blobfile *bf)
{
	lhq_remove(&locos->los_hq, bf);
}

static struct silofs_blobfile *
locos_new_bf(struct silofs_locos *locos, const struct silofs_blobid *blobid)
{
	return bf_new(blobid, locos->los_alloc);
}

static void
locos_del_bf(struct silofs_locos *locos, struct silofs_blobfile *bf)
{
	bf_close(bf);
	bf_del(bf, locos->los_alloc);
}

static void
locos_forget_cached_bf(struct silofs_locos *locos, struct silofs_blobfile *bf)
{
	locos_remove_cached_bf(locos, bf);
	locos_del_bf(locos, bf);
}

static void locos_drop_cache(struct silofs_locos *locos)
{
	struct silofs_blobfile *bf;

	bf = lhq_get_lru_tail(&locos->los_hq);
	while (bf != nullptr) {
		locos_forget_cached_bf(locos, bf);
		bf = lhq_get_lru_tail(&locos->los_hq);
	}
}

static bool locos_cache_need_relax(const struct silofs_locos *locos)
{
	return (locos->los_hq.lhq_lru.sz > SILOFS_LACOS_CACHE_LIM);
}

static void locos_relax_cache(struct silofs_locos *locos)
{
	struct silofs_blobfile *bf = nullptr;

	while (locos_cache_need_relax(locos)) {
		bf = lhq_get_lru_tail(&locos->los_hq);
		locos_forget_cached_bf(locos, bf);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void locos_close(struct silofs_locos *locos)
{
	do_closefd(&locos->los_dfd);
}

int silofs_locos_init(struct silofs_locos *locos, struct silofs_alloc *alloc)
{
	locos->los_alloc = alloc;
	locos->los_dfd = -1;
	return lhq_init(&locos->los_hq, locos->los_alloc);
}

void silofs_locos_fini(struct silofs_locos *locos)
{
	locos_drop_cache(locos);
	locos_close(locos);
	lhq_fini(&locos->los_hq, locos->los_alloc);
	locos->los_alloc = nullptr;
}

static bool locos_isopen(const struct silofs_locos *locos)
{
	return locos->los_dfd >= 0;
}

static void blobs_pathname(struct silofs_strbuf *sbuf)
{
	const char *dots = SILOFS_REPO_DOTS_DIRNAME;
	const char *subd = SILOFS_REPO_BLOBS_DIRNAME;

	silofs_strbuf_sprintf(sbuf, "%s/%s", dots, subd);
}

static int
locos_open(struct silofs_locos *locos, const struct silofs_strview *repodir)
{
	struct silofs_strbuf sbuf;
	int root_dfd = -1;
	int err;

	err = do_opendir(repodir->str, &root_dfd);
	if (err) {
		goto out;
	}
	blobs_pathname(&sbuf);
	err = do_opendirat(root_dfd, sbuf.str, &locos->los_dfd);
	if (err) {
		goto out;
	}
out:
	do_closefd(&root_dfd);
	return err;
}

int silofs_locos_open(struct silofs_locos *locos,
                      const struct silofs_strview *repodir)
{
	int ret = -SILOFS_EALREADY;

	if (!locos_isopen(locos)) {
		ret = locos_open(locos, repodir);
	}
	return ret;
}

void silofs_locos_close(struct silofs_locos *locos)
{
	locos_drop_cache(locos);
	if (locos_isopen(locos)) {
		locos_close(locos);
	}
}

void silofs_locos_relax_cache(struct silofs_locos *locos)
{
	if (locos_isopen(locos)) {
		locos_relax_cache(locos);
	}
}

void silofs_locos_drop_cache(struct silofs_locos *locos)
{
	if (locos_isopen(locos)) {
		locos_drop_cache(locos);
	}
}

static int locos_spawn_blob(struct silofs_locos *locos,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobfile **out_bf)
{
	struct silofs_blobfile *bf = nullptr;
	int err;

	bf = locos_lookup_cached_bf(locos, blobid);
	if (bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	bf = locos_new_bf(locos, blobid);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_create(bf, locos->los_dfd);
	if (err) {
		locos_del_bf(locos, bf);
		return err;
	}
	*out_bf = bf;
	return 0;
}

static int locos_spawn_cached_bf(struct silofs_locos *locos,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blobfile **out_bf)
{
	int err;

	*out_bf = locos_lookup_cached_bf(locos, blobid);
	if (*out_bf != nullptr) {
		return -SILOFS_EEXIST;
	}
	locos_relax_cache(locos);

	err = locos_spawn_blob(locos, blobid, out_bf);
	if (err) {
		return err;
	}
	locos_insert_cached_bf(locos, *out_bf);
	return 0;
}

static int locos_stage_blob(struct silofs_locos *locos,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobfile **out_bf)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	bf = locos_new_bf(locos, blobid);
	if (bf == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = bf_open(bf, locos->los_dfd);
	if (err) {
		locos_del_bf(locos, bf);
		return err;
	}
	*out_bf = bf;
	return err;
}

static int locos_stage_cached_bf(struct silofs_locos *locos,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blobfile **out_bf)
{
	int err;

	*out_bf = locos_lookup_cached_bf(locos, blobid);
	if (*out_bf != nullptr) {
		return 0; /* cache hit */
	}
	locos_relax_cache(locos);

	err = locos_stage_blob(locos, blobid, out_bf);
	if (err) {
		return err;
	}
	locos_insert_cached_bf(locos, *out_bf);
	return 0;
}

int silofs_locos_create_blob(struct silofs_locos *locos,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;

	return locos_spawn_cached_bf(locos, blobid, &bf);
}

int silofs_locos_remove_blob(struct silofs_locos *locos,
                             const struct silofs_blobid *blobid)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = locos_stage_cached_bf(locos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_unlink(bf, locos->los_dfd);
	if (err) {
		return err;
	}
	locos_forget_cached_bf(locos, bf);
	return 0;
}

int silofs_locos_stat_blob(struct silofs_locos *locos,
                           const struct silofs_blobid *blobid, size_t *out_sz)
{
	struct stat st = { .st_size = -1 };
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = locos_stage_cached_bf(locos, blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_stat(bf, &st);
	if (err) {
		return err;
	}
	*out_sz = (size_t)st.st_size;
	return 0;
}

int silofs_locos_require_blob(struct silofs_locos *locos,
                              const struct silofs_blobid *blobid)
{
	size_t sz = 0;
	int err;

	err = silofs_locos_stat_blob(locos, blobid, &sz);
	if (err && (err == -ENOENT)) {
		err = silofs_locos_create_blob(locos, blobid);
	}
	return err;
}

int silofs_locos_write_blob(struct silofs_locos *locos,
                            const struct silofs_baddr *baddr,
                            const struct silofs_rovec *rovec)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = locos_stage_cached_bf(locos, &baddr->blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_write(bf, baddr->pos, rovec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_locos_read_blob(struct silofs_locos *locos,
                           const struct silofs_baddr *baddr,
                           struct silofs_rwvec *rwvec)
{
	struct silofs_blobfile *bf = nullptr;
	int err = 0;

	err = locos_stage_cached_bf(locos, &baddr->blobid, &bf);
	if (err) {
		return err;
	}
	err = bf_read(bf, baddr->pos, rwvec);
	if (err) {
		return err;
	}
	return 0;
}
