/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/infra.h>
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#define OSDC_NSUBS 256

typedef bool (*silofs_bli_pred_fn)(const struct silofs_blob_info *);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t blobid_to_index(const struct silofs_blobid *bid,
                              const size_t index_max)
{
	return silofs_blobid_as_u64(bid) % index_max;
}

static size_t index_to_name(size_t idx, char *name, size_t nmax)
{
	int n;

	n = snprintf(name, nmax, "%02x", (int)idx);
	return (n <= (int)nmax) ? (size_t)n : nmax;
}

static void index_to_namebuf(size_t idx, struct silofs_namebuf *nb)
{
	size_t len;

	len = index_to_name(idx, nb->name, sizeof(nb->name) - 1);
	nb->name[len] = '\0';
}

static int blobid_to_pathname(const struct silofs_blobid *bid,
                              size_t nsubs, struct silofs_namebuf *out_nb)
{
	int err;
	size_t len = 0;
	size_t nlen = 0;
	size_t idx;
	char *nbuf = out_nb->name;
	const size_t nmax = sizeof(out_nb->name);

	idx = blobid_to_index(bid, nsubs);
	len += index_to_name(idx, nbuf, nmax);
	if (len > (nmax / 2)) {
		return -EINVAL;
	}
	nbuf[len++] = '/';
	err = silofs_blobid_to_name(bid, nbuf + len, nmax - len - 1, &nlen);
	if (err) {
		return err;
	}
	len += nlen;
	nbuf[len] = '\0';
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fdsz_reset(struct silofs_blob_fdsz *fdsz)
{
	fdsz->fd = -1;
	fdsz->sz = 0;
}

static void fdsz_setup(struct silofs_blob_fdsz *fdsz, int fd, int sz)
{
	fdsz->fd = fd;
	fdsz->sz = sz;
}

static void fdsz_copyto(const struct silofs_blob_fdsz *fdsz,
                        struct silofs_blob_fdsz *other)
{
	other->sz = fdsz->sz;
	other->fd = fdsz->fd;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blob_info *
bli_unconst(const struct silofs_blob_info *bli)
{
	union {
		const struct silofs_blob_info *p;
		struct silofs_blob_info *q;
	} u = {
		.p = bli
	};
	return u.q;
}

static struct silofs_blob_info *
bli_from_fiovref(const struct silofs_fiovref *fvr)
{
	const struct silofs_blob_info *bli = NULL;

	bli = container_of2(fvr, struct silofs_blob_info, bl_fir);
	return bli_unconst(bli);
}

static void bli_fiov_pre(struct silofs_fiovref *fir)
{
	struct silofs_blob_info *bli = bli_from_fiovref(fir);

	silofs_bli_incref(bli);
}

static void bli_fiov_post(struct silofs_fiovref *fir)
{
	struct silofs_blob_info *bli = bli_from_fiovref(fir);

	silofs_bli_decref(bli);
}

void silofs_bli_init(struct silofs_blob_info *bli,
                     const struct silofs_blobid *bid)
{
	blobid_assign(&bli->bl_bid, bid);
	fdsz_reset(&bli->bl_fdsz);
	silofs_ce_init(&bli->bl_ce);
	silofs_fiovref_init(&bli->bl_fir, bli_fiov_pre, bli_fiov_post);
	bli->bl_hkey = silofs_blobid_hkey(bid);

	silofs_ckey_by_blobid(&bli->bl_ce.ce_ckey, &bli->bl_bid);
}

void silofs_bli_fini(struct silofs_blob_info *bli)
{
	blobid_reset(&bli->bl_bid);
	fdsz_reset(&bli->bl_fdsz);
	silofs_ce_fini(&bli->bl_ce);
	silofs_fiovref_fini(&bli->bl_fir);
}

static void bli_set_fds(struct silofs_blob_info *bli,
                        const struct silofs_blob_fdsz *fds)
{
	silofs_assert_lt(bli->bl_fdsz.fd, 0);

	fdsz_copyto(fds, &bli->bl_fdsz);
}

struct silofs_blob_info *
silofs_bli_new(struct silofs_alloc_if *alif, const struct silofs_blobid *bid)
{
	struct silofs_blob_info *bli;

	bli = silofs_allocate(alif, sizeof(*bli));
	if (bli != NULL) {
		silofs_bli_init(bli, bid);
	}
	return bli;
}

void silofs_bli_del(struct silofs_blob_info *bli, struct silofs_alloc_if *alif)
{
	silofs_assert_lt(bli->bl_fdsz.fd, 0);

	silofs_bli_fini(bli);
	silofs_deallocate(alif, bli, sizeof(*bli));
}

static size_t bli_size(const struct silofs_blob_info *bli)
{
	return blobid_size(&bli->bl_bid);
}

static loff_t bli_off_end(const struct silofs_blob_info *bli)
{
	return (loff_t)bli_size(bli);
}

static int bli_check_range(const struct silofs_blob_info *bli,
                           loff_t off, size_t len)
{
	const loff_t end1 = off_end(off, len);
	const loff_t end2 = bli_off_end(bli);

	if (off < 0) {
		return -EINVAL;
	}
	if (end1 > (end2 + SILOFS_BK_SIZE)) {
		return -EINVAL;
	}
	return 0;
}

static void bli_resolve_range(struct silofs_blob_info *bli,
                              loff_t off, size_t len,
                              struct silofs_fiovec *fiov)
{
	fiov->fv_off = off;
	fiov->fv_len = len;
	fiov->fv_base = NULL;
	fiov->fv_fd = bli->bl_fdsz.fd;
	fiov->fv_ref = &bli->bl_fir;
}

int silofs_bli_resolve(struct silofs_blob_info *bli,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_fiovec *fiov)
{
	int err;
	const loff_t off = oaddr->pos;
	const size_t len = oaddr->len;

	silofs_assert_gt(bli->bl_fdsz.fd, 0);

	err = bli_check_range(bli, off, len);
	if (!err) {
		bli_resolve_range(bli, off, len, fiov);
	}
	return err;
}

int silofs_bli_resolve_bk(struct silofs_blob_info *bli,
                          const struct silofs_oaddr *oaddr,
                          struct silofs_fiovec *fiov)
{
	struct silofs_oaddr bk_oaddr;

	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->bid, oaddr_lba(oaddr));
	return silofs_bli_resolve(bli, &bk_oaddr, fiov);
}

int silofs_bli_datasync(const struct silofs_blob_info *bli)
{
	silofs_assert_gt(bli->bl_fdsz.fd, 0);

	return silofs_sys_fdatasync(bli->bl_fdsz.fd);
}

int silofs_bli_store(struct silofs_blob_info *bli,
                     const struct silofs_oaddr *oaddr, const void *obj)
{
	int err;
	struct silofs_fiovec fiov = { .fv_off = -1 };

	err = silofs_bli_resolve(bli, oaddr, &fiov);
	if (err) {
		return err;
	}
	err = silofs_sys_pwriten(fiov.fv_fd, obj, fiov.fv_len, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}

static size_t iovec_length(const struct iovec *iov, size_t cnt)
{
	size_t len = 0;

	for (size_t i = 0; i < cnt; ++i) {
		len += iov[i].iov_len;
	}
	return len;
}

static int check_oaddr_iovec(const struct silofs_oaddr *oaddr,
                             const struct iovec *iov, size_t cnt)
{
	return (iovec_length(iov, cnt) == oaddr->len) ? 0 : -EINVAL;
}

int silofs_bli_storev(struct silofs_blob_info *bli,
                      const struct silofs_oaddr *oaddr,
                      const struct iovec *iov, size_t cnt)
{
	int err;
	struct silofs_fiovec fiov = { .fv_off = -1 };

	err = check_oaddr_iovec(oaddr, iov, cnt);
	if (err) {
		return err;
	}
	err = silofs_bli_resolve(bli, oaddr, &fiov);
	if (err) {
		return err;
	}
	err = silofs_sys_pwritevn(fiov.fv_fd, iov, (int)cnt, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bli_load(struct silofs_blob_info *bli,
                    const struct silofs_oaddr *oaddr, void *bobj)
{
	int err;
	struct silofs_fiovec fiov = { .fv_off = -1 };

	err = silofs_bli_resolve(bli, oaddr, &fiov);
	if (err) {
		return err;
	}
	err = silofs_sys_preadn(fiov.fv_fd, bobj, fiov.fv_len, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bli_close(struct silofs_blob_info *bli)
{
	int err;

	err = silofs_sys_closefd(&bli->bl_fdsz.fd);
	if (err) {
		log_warn("close error: fd=%d err=%d", bli->bl_fdsz.fd, err);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bli_load_bk(struct silofs_blob_info *bli, struct silofs_block *bk,
                       const struct silofs_oaddr *oaddr)
{
	struct silofs_oaddr bk_oaddr;

	silofs_assert_not_null(bk);

	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->bid, oaddr_lba(oaddr));
	return silofs_bli_load(bli, &bk_oaddr, bk);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_objs_lookup_cached_bli(const struct silofs_repo *repo,
                                       const struct silofs_blobid *bid,
                                       struct silofs_blob_info **out_bli)
{
	*out_bli = silofs_cache_lookup_blob(repo->re_cache, bid);

	return (*out_bli == NULL) ? -ENOENT : 0;
}

static int repo_objs_spawn_cached_bli(const struct silofs_repo *repo,
                                      const struct silofs_blobid *bid,
                                      struct silofs_blob_info **out_bli)
{
	*out_bli = silofs_cache_spawn_blob(repo->re_cache, bid);

	return (*out_bli == NULL) ? -ENOMEM : 0;
}

static void repo_objs_evict_cached_bli(const struct silofs_repo *repo,
                                       struct silofs_blob_info *bli)
{
	silofs_cache_evict_blob(repo->re_cache, bli);
}

static int repo_objs_relax_cached_blis(const struct silofs_repo *repo)
{
	const size_t ncached = repo->re_cache->c_bli_lm.lm_htbl_sz;

	if (ncached > 64) { /* XXX make upper bound tweak */
		silofs_cache_relax_blobs(repo->re_cache);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_objs_close(struct silofs_repo *repo)
{
	return silofs_sys_closefd(&repo->re_objs_dfd);
}

static int repo_objs_open(struct silofs_repo *repo)
{
	int err;

	silofs_assert_lt(repo->re_objs_dfd, 0);

	err = silofs_sys_opendirat(repo->re_base_dfd, repo->re_objs_name,
	                           &repo->re_objs_dfd);
	if (err) {
		return err;
	}
	/* XXX TODO: check validity of subdirs */
	return 0;
}

static int repo_objs_format_sub(const struct silofs_repo *repo, size_t idx)
{
	int err;
	struct stat st;
	struct silofs_namebuf nb;

	index_to_namebuf(idx, &nb);
	err = silofs_sys_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_err("exists but not dir: %s", nb.name);
			return -ENOTDIR;
		}
		err = silofs_sys_faccessat(repo->re_objs_dfd,
		                           nb.name, R_OK | X_OK, 0);
		if (err) {
			return err;
		}
	} else {
		err = silofs_sys_mkdirat(repo->re_objs_dfd, nb.name, 0700);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int repo_objs_format(struct silofs_repo *repo)
{
	int err;

	for (size_t i = 0; i < repo->re_objs_nsubs; ++i) {
		err = repo_objs_format_sub(repo, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int repo_objs_sub_pathname_of(const struct silofs_repo *repo,
                                     const struct silofs_blobid *bid,
                                     struct silofs_namebuf *out_nb)
{
	return blobid_to_pathname(bid, repo->re_objs_nsubs, out_nb);
}

static int repo_objs_create_blob(const struct silofs_repo *repo,
                                 const struct silofs_blobid *bid,
                                 struct silofs_blob_fdsz *out_fdsz)
{
	int err;
	int fd = -1;
	int len = 0;
	size_t bsz;
	struct stat st;
	struct silofs_namebuf nb;

	err = repo_objs_sub_pathname_of(repo, bid, &nb);
	if (err) {
		return err;
	}
	err = silofs_sys_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err != -ENOENT) {
		log_err("can not create blob: name=%s err=%d", nb.name, err);
		return err;
	}
	err = silofs_sys_openat(repo->re_objs_dfd, nb.name,
	                        O_CREAT | O_RDWR | O_TRUNC, 0600, &fd);
	if (err) {
		return err;
	}
	bsz = blobid_size(bid);
	if (bsz >= INT_MAX) {
		log_err("illegal blob size: name=%s bsz=%lu", nb.name, bsz);
		return -EINVAL;
	}
	len = (int)silofs_max(bsz, SILOFS_BK_SIZE);
	err = silofs_sys_ftruncate(fd, len);
	if (err) {
		goto out_err;
	}
	fdsz_setup(out_fdsz, fd, len);
	return 0;
out_err:
	silofs_sys_unlinkat(repo->re_objs_dfd, nb.name, 0);
	silofs_sys_closefd(&fd);
	return err;
}

static int repo_objs_open_blob(const struct silofs_repo *repo,
                               const struct silofs_blobid *bid,
                               struct silofs_blob_fdsz *out_fdsz)
{
	int err;
	int fd = -1;
	ssize_t len = 0;
	struct stat st;
	struct silofs_namebuf nb;

	err = repo_objs_sub_pathname_of(repo, bid, &nb);
	if (err) {
		return err;
	}
	err = silofs_sys_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err) {
		return err;
	}
	len = silofs_blobid_ssize(bid);
	if (st.st_size < len) {
		log_warn("blob-size mismatch: %s len=%lu st_size=%ld",
		         nb.name, len, st.st_size);
		err = -ENOENT;
		return err;
	}
	err = silofs_sys_openat(repo->re_objs_dfd, nb.name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	fdsz_setup(out_fdsz, fd, (int)len);
	return 0;
}

static int repo_objs_close_blob(const struct silofs_repo *repo,
                                const struct silofs_blobid *bid,
                                struct silofs_blob_fdsz *fdsz)
{
	int err;
	struct stat st;
	struct silofs_namebuf nb;

	err = repo_objs_sub_pathname_of(repo, bid, &nb);
	if (err) {
		return err;
	}
	err = silofs_sys_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err) {
		log_warn("missing blob: name=%s err=%d", nb.name, err);
	}
	err = silofs_sys_closefd(&fdsz->fd);
	if (err) {
		log_warn("close error: name=%s err=%d", nb.name, err);
		return err;
	}
	return 0;
}

static int repo_objs_unlink_blob(const struct silofs_repo *repo,
                                 const struct silofs_blobid *bid)
{
	int err;
	struct stat st;
	struct silofs_namebuf nb;

	err = repo_objs_sub_pathname_of(repo, bid, &nb);
	if (err) {
		return err;
	}
	err = silofs_sys_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err) {
		log_dbg("can not unlink blob: %s err=%d", nb.name, err);
		return err;
	}
	err = silofs_sys_unlinkat(repo->re_objs_dfd, nb.name, 0);
	if (err) {
		log_warn("unlink blob failed: %s err=%d", nb.name, err);
		return err;
	}
	return 0;
}

static int repo_objs_open_blob_of(const struct silofs_repo *repo,
                                  const struct silofs_blobid *bid,
                                  struct silofs_blob_info **out_bli)
{
	int err;
	struct silofs_blob_fdsz fdsz = { .fd = -1 };

	err = repo_objs_relax_cached_blis(repo);
	if (err) {
		return err;
	}
	err = repo_objs_open_blob(repo, bid, &fdsz);
	if (err) {
		return err;
	}
	err = repo_objs_spawn_cached_bli(repo, bid, out_bli);
	if (err) {
		repo_objs_close_blob(repo, bid, &fdsz);
		return err;
	}
	bli_set_fds(*out_bli, &fdsz);
	return 0;
}

static int repo_objs_create_blob_of(const struct silofs_repo *repo,
                                    const struct silofs_blobid *bid,
                                    struct silofs_blob_info **out_bli)
{
	int err;
	struct silofs_blob_fdsz fdsz = { .fd = -1 };

	err = repo_objs_relax_cached_blis(repo);
	if (err) {
		return err;
	}
	err = repo_objs_create_blob(repo, bid, &fdsz);
	if (err) {
		return err;
	}
	err = repo_objs_spawn_cached_bli(repo, bid, out_bli);
	if (err) {
		return err;
	}
	bli_set_fds(*out_bli, &fdsz);
	return 0;
}

int silofs_repo_spawn_blob(const struct silofs_repo *repo,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli)
{
	int err;

	err = repo_objs_lookup_cached_bli(repo, bid, out_bli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_blob_of(repo, bid, out_bli);
	if (err != -ENOENT) {
		return err;
	}
	err = repo_objs_create_blob_of(repo, bid, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stage_blob(const struct silofs_repo *repo,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli)
{
	int err;

	silofs_assert_ge(bid->size, SILOFS_BK_SIZE);

	err = repo_objs_lookup_cached_bli(repo, bid, out_bli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_blob_of(repo, bid, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_allocate_buf(const struct silofs_repo *repo,
                             size_t bsz, void **buf)
{
	struct silofs_alloc_if *alif = repo->re_cache->c_alif;

	*buf = silofs_allocate(alif, bsz);
	return (*buf == NULL) ? -ENOMEM : 0;
}

static void repo_deallocate_buf(const struct silofs_repo *repo,
                                void *buf, size_t bsz)
{
	struct silofs_alloc_if *alif = repo->re_cache->c_alif;

	silofs_deallocate(alif, buf, bsz);
}

static int repo_objs_clone_blob(const struct silofs_repo *repo,
                                const struct silofs_blob_info *bli_src,
                                struct silofs_blob_info *bli_dst)
{
	int err;
	loff_t pos;
	size_t cnt = 0;
	size_t len_max;
	void *buf = NULL;
	const size_t bsz = SILOFS_MEGA;
	const struct silofs_blob_fdsz *fdsz_src = &bli_src->bl_fdsz;
	struct silofs_blob_fdsz *fdsz_dst = &bli_dst->bl_fdsz;

	err = repo_allocate_buf(repo, bsz, &buf);
	if (err) {
		return err;
	}
	err = silofs_sys_ftruncate(fdsz_dst->fd, fdsz_src->sz);
	if (err) {
		log_warn("ftruncate error: fd=%d sz=%d err=%d",
		         fdsz_dst->fd, fdsz_src->sz, err);
		goto out;
	}
	fdsz_dst->sz = fdsz_src->sz;

	err = silofs_sys_ioctl_ficlone(fdsz_dst->fd, fdsz_src->fd);
	if (err) {
		log_dbg("ficlone error: src_fd=%d dst_fd=%d sz=%d err=%d",
		        fdsz_src->fd, fdsz_dst->fd, fdsz_src->sz, err);
	} else {
		goto out; /* good-path: cow */
	}
	len_max = (size_t)fdsz_src->sz;
	for (size_t len = 0; len < len_max; len += cnt) {
		cnt = min(bsz, len_max - len);
		pos = (loff_t)len;
		err = silofs_sys_preadn(fdsz_src->fd, buf, cnt, pos);
		if (err) {
			log_warn("preadn error: fd=%d cnt=%lu pos=%ld err=%d",
			         fdsz_src->fd, cnt, pos, err);
			goto out;
		}
		err = silofs_sys_pwriten(fdsz_dst->fd, buf, cnt, pos);
		if (err) {
			log_warn("pwriten error: fd=%d cnt=%lu pos=%ld err=%d",
			         fdsz_dst->fd, cnt, pos, err);
			goto out;
		}
	}
out:
	repo_deallocate_buf(repo, buf, bsz);
	return err;
}

static void repo_objs_remove_blob(const struct silofs_repo *repo,
                                  struct silofs_blob_info *bli)
{
	struct silofs_blobid bid;

	blobid_assign(&bid, &bli->bl_bid);
	repo_objs_evict_cached_bli(repo, bli);
	repo_objs_unlink_blob(repo, &bid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_clone_blob(const struct silofs_repo *repo,
                           const struct silofs_blob_info *bli_src,
                           const struct silofs_blobid *bid_dst,
                           struct silofs_blob_info **out_bli_dst)
{
	int err;
	struct silofs_blob_info *bli_dst = NULL;

	err = silofs_repo_spawn_blob(repo, bid_dst, &bli_dst);
	if (err) {
		return err;
	}
	err = repo_objs_clone_blob(repo, bli_src, bli_dst);
	if (err) {
		repo_objs_remove_blob(repo, bli_dst);
		return err;
	}
	*out_bli_dst = bli_dst;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_sgvec {
	struct iovec iov[SILOFS_NKB_IN_BK];
	struct silofs_blobid bid;
	loff_t off;
	size_t len;
	size_t cnt;
	size_t lim;
};

static void sgvec_setup(struct silofs_sgvec *sgv)
{
	sgv->bid.size = 0;
	sgv->off = -1;
	sgv->lim = 2 * SILOFS_MEGA;
	sgv->cnt = 0;
	sgv->len = 0;
}

static bool sgvec_isappendable(const struct silofs_sgvec *sgv,
                               const struct silofs_oaddr *oaddr)
{
	if (sgv->cnt == 0) {
		return true;
	}
	if (sgv->cnt == ARRAY_SIZE(sgv->iov)) {
		return false;
	}
	if (oaddr->pos != off_end(sgv->off, sgv->len)) {
		return false;
	}
	silofs_assert_lt(oaddr->len, sgv->lim);
	if ((sgv->len + oaddr->len) > sgv->lim) {
		return false;
	}
	if (!blobid_isequal(&oaddr->bid, &sgv->bid)) {
		return false;
	}
	return true;
}

static int sgvec_append(struct silofs_sgvec *sgv,
                        const struct silofs_oaddr *oaddr, const void *dat)
{
	const size_t idx = sgv->cnt;

	if (idx == 0) {
		blobid_assign(&sgv->bid, &oaddr->bid);
		sgv->off = oaddr->pos;
	}
	sgv->iov[idx].iov_base = unconst(dat);
	sgv->iov[idx].iov_len = oaddr->len;
	sgv->len += oaddr->len;
	sgv->cnt += 1;
	return 0;
}

static int ti_resolve_oaddr(const struct silofs_tnode_info *ti,
                            struct silofs_oaddr *out_oaddr)
{
	int err;

	err = ti->t_vtbl->resolve(ti, out_oaddr);
	if (err) {
		log_warn("failed to resolve oaddr: stype=%d err=%d",
		         ti->t_stype, err);
	}
	return err;
}

static int sgvec_populate(struct silofs_sgvec *sgv,
                          struct silofs_tnode_info **tiq)
{
	int err;
	struct silofs_oaddr oaddr;
	struct silofs_tnode_info *ti;

	while (*tiq != NULL) {
		ti = *tiq;
		err = ti_resolve_oaddr(ti, &oaddr);
		if (err) {
			return err;
		}
		if (!sgvec_isappendable(sgv, &oaddr)) {
			break;
		}
		err = sgvec_append(sgv, &oaddr, ti->t_view);
		if (err) {
			return err;
		}
		*tiq = ti->t_ds_next;
	}
	return 0;
}

static int sgvec_store_in_blob(const struct silofs_sgvec *sgv,
                               struct silofs_repo *repo)
{
	int err;
	struct silofs_oaddr oaddr;
	struct silofs_blob_info *bli = NULL;

	if (sgv->cnt == 0) {
		return 0;
	}
	oaddr_setup(&oaddr, &sgv->bid, sgv->len, sgv->off);
	err = silofs_repo_stage_blob(repo, &oaddr.bid, &bli);
	if (err) {
		return err;
	}
	err = silofs_bli_storev(bli, &oaddr, sgv->iov, sgv->cnt);
	if (err) {
		return err;
	}
	return 0;
}

static int sgvec_flush_dset(struct silofs_sgvec *sgv,
                            const struct silofs_dset *dset,
                            struct silofs_repo *repo)
{
	int err;
	struct silofs_tnode_info *tiq = dset->ds_tiq;

	while (tiq != NULL) {
		sgvec_setup(sgv);
		err = sgvec_populate(sgv, &tiq);
		if (err) {
			return err;
		}
		err = sgvec_store_in_blob(sgv, repo);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long ckey_compare(const void *x, const void *y)
{
	const struct silofs_ckey *ckey_x = x;
	const struct silofs_ckey *ckey_y = y;

	return silofs_ckey_compare(ckey_x, ckey_y);
}

static struct silofs_tnode_info *
avl_node_to_ti(const struct silofs_avl_node *an)
{
	const struct silofs_tnode_info *ti;

	ti = container_of2(an, struct silofs_tnode_info, t_ds_an);
	return unconst(ti);
}

static const void *ti_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_tnode_info *ti = avl_node_to_ti(an);

	return &ti->t_ce.ce_ckey;
}

static void ti_visit_reinit(struct silofs_avl_node *an, void *p)
{
	struct silofs_tnode_info *ti = avl_node_to_ti(an);

	silofs_avl_node_init(&ti->t_ds_an);
	unused(p);
}

static void dset_clear_map(struct silofs_dset *dset)
{
	const struct silofs_avl_node_functor fn = {
		.fn = ti_visit_reinit,
		.ctx = NULL
	};

	silofs_avl_clear(&dset->ds_avl, &fn);
}

static void dset_add_dirty(struct silofs_dset *dset,
                           struct silofs_tnode_info *ti)
{
	silofs_avl_insert(&dset->ds_avl, &ti->t_ds_an);
}

static void dset_init(struct silofs_dset *dset)
{
	silofs_avl_init(&dset->ds_avl, ti_getkey, ckey_compare, dset);
	dset->ds_tiq = NULL;
	dset->ds_add_fn = dset_add_dirty;
}

static void dset_fini(struct silofs_dset *dset)
{
	silofs_avl_fini(&dset->ds_avl);
	dset->ds_tiq = NULL;
	dset->ds_add_fn = NULL;
}

static void dset_push_front_tiq(struct silofs_dset *dset,
                                struct silofs_tnode_info *ti)
{
	ti->t_ds_next = dset->ds_tiq;
	dset->ds_tiq = ti;
}

static void dset_make_fifo(struct silofs_dset *dset)
{
	struct silofs_tnode_info *ti;
	const struct silofs_avl_node *end;
	const struct silofs_avl_node *itr;
	const struct silofs_avl *avl = &dset->ds_avl;

	dset->ds_tiq = NULL;
	end = silofs_avl_end(avl);
	itr = silofs_avl_rbegin(avl);
	while (itr != end) {
		ti = avl_node_to_ti(itr);
		dset_push_front_tiq(dset, ti);
		itr = silofs_avl_prev(avl, itr);
	}
}

static void dset_seal_all(const struct silofs_dset *dset)
{
	struct silofs_tnode_info *ti = dset->ds_tiq;

	while (ti != NULL) {
		ti->t_vtbl->seal(ti);
		ti = ti->t_ds_next;
	}
}

static int dset_flush(const struct silofs_dset *dset,
                      struct silofs_repo *repo)
{
	struct silofs_sgvec sgv;

	return sgvec_flush_dset(&sgv, dset, repo);
}

static int dset_collect_flush(struct silofs_dset *dset,
                              struct silofs_repo *repo)
{
	int err;
	struct silofs_cache *cache = repo->re_cache;

	silofs_cache_fill_into_dset(cache, dset);
	dset_make_fifo(dset);
	dset_seal_all(dset);
	err = dset_flush(dset, repo);
	if (!err) {
		silofs_cache_undirtify_by_dset(cache, dset);
	}
	dset_clear_map(dset);
	return err;
}

static int repo_collect_flush_dirty(struct silofs_repo *repo)
{
	int err;
	struct silofs_dset dset;

	dset_init(&dset);
	err = dset_collect_flush(&dset, repo);
	dset_fini(&dset);
	return err;
}

static int repo_objs_sync(struct silofs_repo *repo)
{
	silofs_unused(repo);
	return 0;
}

static int repo_objs_commit_last(struct silofs_repo *repo, int flags)
{
	return (flags & SILOFS_F_NOW) ? repo_objs_sync(repo) : 0;
}

static bool repo_cache_need_flush(const struct silofs_repo *repo, int flags)
{
	return silofs_cache_need_flush(repo->re_cache, flags);
}

int silofs_repo_collect_flush(struct silofs_repo *repo, int flags)
{
	int err;

	if (!repo_cache_need_flush(repo, flags)) {
		return 0;
	}
	err = repo_collect_flush_dirty(repo);
	if (err) {
		return err;
	}
	err = repo_objs_commit_last(repo, flags);
	if (err) {
		return err;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_init(struct silofs_repo *repo,
                     struct silofs_cache *cache,
                     const char *basedir, bool rw)
{
	repo->re_cache = cache;
	repo->re_base_dir = basedir;
	repo->re_base_dfd = -1;
	repo->re_lock_name = "lock";
	repo->re_lock_fd = -1;
	repo->re_objs_name = "objs";
	repo->re_objs_dfd = -1;
	repo->re_objs_nsubs = OSDC_NSUBS;
	repo->re_refs_name = "refs";
	repo->re_refs_dfd = -1;
	repo->re_rw = rw;
	return 0;
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	silofs_repo_close(repo);
	repo->re_cache = NULL;
	repo->re_base_dir = NULL;
	repo->re_base_dfd = -1;
	repo->re_lock_name = NULL;
	repo->re_lock_fd = -1;
	repo->re_objs_name = NULL;
	repo->re_objs_dfd = -1;
	repo->re_objs_nsubs = OSDC_NSUBS;
	repo->re_refs_name = NULL;
	repo->re_refs_dfd = -1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_refs_close(struct silofs_repo *repo)
{
	return silofs_sys_closefd(&repo->re_refs_dfd);
}

static int repo_refs_open(struct silofs_repo *repo)
{
	int err;

	silofs_assert_lt(repo->re_refs_dfd, 0);

	err = silofs_sys_opendirat(repo->re_base_dfd, repo->re_refs_name,
	                           &repo->re_refs_dfd);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_acquire_lock(struct silofs_repo *repo)
{
	int err;
	const int o_flags = repo->re_rw ? O_RDWR : O_RDONLY;
	struct flock fl = {
		.l_type = repo->re_rw ? F_WRLCK : F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	err = silofs_sys_openat(repo->re_base_dfd, repo->re_lock_name,
	                        o_flags, 0, &repo->re_lock_fd);
	if (err) {
		log_warn("failed to open: %s err=%d",
		         repo->re_lock_name, err);
		return err;
	}
	err = silofs_sys_fcntl_flock(repo->re_lock_fd, F_SETLK, &fl);
	if (err) {
		log_warn("failed to flock: %s err=%d",
		         repo->re_lock_name, err);
		return err;
	}
	return 0;
}

static int repo_release_lock(struct silofs_repo *repo)
{
	int err = 0;
	struct flock fl = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	if (repo->re_lock_fd > 0) {
		err = silofs_sys_fcntl_flock(repo->re_lock_fd, F_SETLK, &fl);
		if (err) {
			log_warn("funlock failure: %s err=%d",
			         repo->re_lock_name, err);
		}
		silofs_sys_closefd(&repo->re_lock_fd);
	}
	return err;
}

static int repo_create_skel_subdir(const struct silofs_repo *repo,
                                   const char *name, mode_t mode)
{
	int err;
	struct stat st = { .st_size = 0 };

	err = silofs_sys_mkdirat(repo->re_base_dfd, name, mode);
	if (err && (err != -EEXIST)) {
		log_warn("mkdirat failed: %s err=%d", name, err);
		return err;
	}
	err = silofs_sys_fstatat(repo->re_base_dfd, name, &st, 0);
	if (err) {
		log_warn("fstatat error: %s err=%d", name, err);
		return err;
	}
	if ((st.st_mode & S_IRWXU) != S_IRWXU) {
		log_warn("bad access: %s mode=0%o", name, st.st_mode);
		return -EACCES;
	}
	return 0;
}

static int repo_create_skel_subfile(const struct silofs_repo *repo,
                                    const char *name, mode_t mode)
{
	int err;
	int fd = -1;

	err = silofs_sys_openat(repo->re_base_dfd, name,
	                        O_CREAT | O_RDWR, mode, &fd);
	if (err) {
		log_warn("failed to create: %s err=%d", name, err);
		return err;
	}
	err = silofs_sys_closefd(&fd);
	if (err) {
		log_warn("failed to closefd: %s err=%d", name, err);
		return err;
	}
	return 0;
}

static int repo_create_skel(const struct silofs_repo *repo)
{
	int err;

	silofs_assert_gt(repo->re_base_dfd, 0);

	err = repo_create_skel_subdir(repo, repo->re_objs_name, 0700);
	if (err) {
		return err;
	}
	err = repo_create_skel_subdir(repo, repo->re_refs_name, 0700);
	if (err) {
		return err;
	}
	err = repo_create_skel_subfile(repo, repo->re_lock_name, 0600);
	if (err) {
		return err;
	}
	return 0;
}

static int
repo_require_skel_subdir(const struct silofs_repo *repo, const char *name)
{
	int err;
	struct stat st = { .st_size = 0 };

	err = silofs_sys_fstatat(repo->re_base_dfd, name, &st, 0);
	if (err) {
		log_warn("fstatat error: %s err=%d", name, err);
		return err;
	}
	if (!S_ISDIR(st.st_mode)) {
		log_warn("not a directory: %s", name);
		return -ENOTDIR;
	}
	return 0;
}

static int
repo_require_skel_subfile(const struct silofs_repo *repo, const char *name)
{
	int err;
	struct stat st = { .st_size = 0 };

	err = silofs_sys_fstatat(repo->re_base_dfd, name, &st, 0);
	if (err) {
		log_warn("fstatat error: %s err=%d", name, err);
		return err;
	}
	if (!S_ISREG(st.st_mode)) {
		log_warn("not a regular file: %s", name);
		return S_ISDIR(st.st_mode) ? -EISDIR : -EINVAL;
	}
	return 0;
}

static int repo_require_skel(const struct silofs_repo *repo)
{
	int err;

	silofs_assert_gt(repo->re_base_dfd, 0);

	err = silofs_sys_access(repo->re_base_dir, R_OK | W_OK | X_OK);
	if (err) {
		log_warn("no access: %s err=%d", repo->re_base_dir, err);
		return err;
	}
	err = repo_require_skel_subdir(repo, repo->re_objs_name);
	if (err) {
		return err;
	}
	err = repo_require_skel_subdir(repo, repo->re_refs_name);
	if (err) {
		return err;
	}
	err = repo_require_skel_subfile(repo, repo->re_lock_name);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_open_basedir(struct silofs_repo *repo)
{
	int err;

	silofs_assert_not_null(repo->re_base_dir);
	silofs_assert_lt(repo->re_base_dfd, 0);

	err = silofs_sys_opendir(repo->re_base_dir, &repo->re_base_dfd);
	if (err) {
		log_err("failed to open repo dir: %s err=%d",
		        repo->re_base_dir, err);
		return err;
	}
	return 0;
}

int silofs_repo_format(struct silofs_repo *repo)
{
	int err;

	err = repo_open_basedir(repo);
	if (err) {
		return err;
	}
	err = repo_create_skel(repo);
	if (err) {
		return err;
	}
	err = repo_refs_open(repo);
	if (err) {
		return err;
	}
	err = repo_objs_open(repo);
	if (err) {
		return err;
	}
	err = repo_objs_format(repo);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_open(struct silofs_repo *repo)
{
	int err;

	err = repo_open_basedir(repo);
	if (err) {
		return err;
	}
	err = repo_require_skel(repo);
	if (err) {
		return err;
	}
	err = repo_acquire_lock(repo);
	if (err) {
		return err;
	}
	err = repo_refs_open(repo);
	if (err) {
		return err;
	}
	err = repo_objs_open(repo);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_close_basedir(struct silofs_repo *repo)
{
	int err;

	err = silofs_sys_closefd(&repo->re_base_dfd);
	if (err) {
		log_err("close basedir: %s err=%d", repo->re_base_dir, err);
		return err;
	}
	return 0;
}

int silofs_repo_close(struct silofs_repo *repo)
{
	int err;

	if (repo->re_base_dfd < 0) {
		return 0;
	}
	err = repo_objs_close(repo);
	if (err) {
		return err;
	}
	err = repo_refs_close(repo);
	if (err) {
		return err;
	}
	err = repo_release_lock(repo);
	if (err) {
		return err;
	}
	err = repo_close_basedir(repo);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_save_ref(const struct silofs_repo *repo,
                         const struct silofs_namestr *namestr,
                         const struct silofs_main_bootrec *mbr)
{
	int err;
	int fd = -1;
	const int dfd = repo->re_refs_dfd;
	const char *name = namestr->str.str;

	silofs_assert_gt(dfd, 0);

	err = silofs_mbr_check(mbr);
	if (err) {
		log_warn("illegal mbr for: %s", repo->re_base_dir);
		return err;
	}
	err = silofs_sys_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		log_warn("failed to create: %s err=%d", name, err);
		return err;
	}
	err = silofs_sys_pwriten(fd, mbr, sizeof(*mbr), 0);
	if (err) {
		log_warn("write error: %s err=%d", name, err);
		goto out;
	}
	err = silofs_sys_fsync(fd);
	if (err) {
		log_warn("fsync error: %s err=%d", name, err);
		goto out;
	}
out:
	silofs_sys_closefd(&fd);
	return err;
}

int silofs_repo_load_ref(const struct silofs_repo *repo,
                         const struct silofs_namestr *namestr,
                         struct silofs_main_bootrec *mbr)
{
	int err;
	int fd = -1;
	const int dfd = repo->re_refs_dfd;
	const char *name = namestr->str.str;

	silofs_assert_gt(dfd, 0);

	err = silofs_sys_openat(dfd, name, O_RDONLY, 0600, &fd);
	if (err) {
		log_warn("failed to open: %s err=%d", name, err);
		return err;
	}
	err = silofs_sys_preadn(fd, mbr, sizeof(*mbr), 0);
	if (err) {
		log_warn("read error: %s err=%d", name, err);
		goto out;
	}
	err = silofs_mbr_check(mbr);
	if (err) {
		log_warn("illegal mbr at: %s", name);
		goto out;
	}
out:
	silofs_sys_closefd(&fd);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_resolve_sb_path(const struct silofs_main_bootrec *mbr,
                           struct silofs_namebuf *out_nb)
{
	int err;
	struct silofs_uaddr uaddr;

	err = silofs_mbr_check(mbr);
	if (err) {
		return err;
	}
	silofs_mbr_sb_ref(mbr, &uaddr);
	err = blobid_to_pathname(&uaddr.oaddr.bid, OSDC_NSUBS, out_nb);
	if (err) {
		return err;
	}
	return 0;
}

