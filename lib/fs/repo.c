/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

#define METAF_SIZE 4096
#define LOCKF_SIZE 4096
#define OSDC_NSUBS 256

typedef bool (*silofs_bli_pred_fn)(const struct silofs_blob_info *);

struct silofs_repo_defs {
	size_t re_objs_nsubs;
	const char *re_objs_name;
	const char *re_meta_name;
	const char *re_lock_name;
};

static const struct silofs_repo_defs repo_defs = {
	.re_objs_nsubs = OSDC_NSUBS,
	.re_objs_name  = ".objs",
	.re_meta_name  = ".meta",
	.re_lock_name  = ".lock",
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static uint64_t rmeta_magic(const struct silofs_repo_meta *rm)
{
	return silofs_le64_to_cpu(rm->rm_magic);
}

static void rmeta_set_magic(struct silofs_repo_meta *rm, uint64_t m)
{
	rm->rm_magic = silofs_cpu_to_le64(m);
}

static uint32_t rmeta_version(const struct silofs_repo_meta *rm)
{
	return silofs_le32_to_cpu(rm->rm_version);
}

static void rmeta_set_version(struct silofs_repo_meta *rm, uint32_t v)
{
	rm->rm_version = silofs_cpu_to_le32(v);
}

static void rmeta_init(struct silofs_repo_meta *rm)
{
	silofs_memzero(rm, sizeof(*rm));
	rmeta_set_magic(rm, SILOFS_REPO_META_MAGIC);
	rmeta_set_version(rm, SILOFS_REPO_VERSION);
}

static int rmeta_check(const struct silofs_repo_meta *rm)
{
	uint64_t magic;
	uint32_t version;

	magic = rmeta_magic(rm);
	if (magic != SILOFS_REPO_META_MAGIC) {
		log_dbg("bad repo meta: magic=%lx", magic);
		return -EFSCORRUPTED;
	}
	version = rmeta_version(rm);
	if (version != SILOFS_REPO_VERSION) {
		log_dbg("bad repo meta: version=%lx", version);
		return -EFSCORRUPTED;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int do_fchmod(int fd, mode_t mode)
{
	int err;

	err = silofs_sys_fchmod(fd, mode);
	if (err && (err != -ENOENT)) {
		log_warn("fchmod error: fd=%d mode=0%o err=%d", fd, mode, err);
	}
	return err;
}

static int do_fchmodat(int dfd, const char *pathname, mode_t mode)
{
	int err;

	err = silofs_sys_fchmodat(dfd, pathname, mode, 0);
	if (err && (err != -ENOENT)) {
		log_warn("fchmodat error: dfd=%d mode=0%o "
		         "err=%d", dfd, mode, err);
	}
	return err;
}

static int do_unlinkat(int dfd, const char *pathname, int flags)
{
	int err;

	err = silofs_sys_unlinkat(dfd, pathname, flags);
	if (err && (err != -ENOENT)) {
		log_warn("unlinkat error: dfd=%d pathname=%s err=%d",
		         dfd, pathname, err);
	}
	return err;
}

static int do_openat(int dfd, const char *pathname,
                     int flags, mode_t mode, int *out_fd)
{
	int err;

	err = silofs_sys_openat(dfd, pathname, flags, mode, out_fd);
	if (err && (err != -ENOENT)) {
		log_warn("openat error: dfd=%d pathname=%s flags=0x%x "
		         "mode=0%o err=%d", dfd, pathname, flags, mode, err);
	}
	return err;
}

static int do_closefd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		log_warn("close error: fd=%d err=%d", *pfd, err);
	}
	return err;
}

static int do_fdatasync(int fd)
{
	int err;

	err = silofs_sys_fdatasync(fd);
	if (err) {
		log_warn("fdatasync error: fd=%d err=%d", fd, err);
	}
	return err;
}

static int do_fsync(int fd)
{
	int err;

	err = silofs_sys_fsync(fd);
	if (err) {
		log_warn("fsync error: fd=%d err=%d", fd, err);
	}
	return err;
}

static int do_renameat(int dfd, const char *nold, const char *nnew)
{
	int err;

	err = silofs_sys_renameat(dfd, nold, dfd, nnew);
	if (err) {
		log_warn("renameat error: dfd=%d err=%d", dfd, err);
	}
	return err;
}

static int do_pwriten(int fd, const void *buf, size_t cnt, loff_t off)
{
	int err;

	err = silofs_sys_pwriten(fd, buf, cnt, off);
	if (err) {
		log_warn("pwriten error: fd=%d cnt=%lu off=%ld err=%d",
		         fd, cnt, off, err);
	}
	return err;
}

static int do_preadn(int fd, void *buf, size_t cnt, loff_t off)
{
	int err;

	err = silofs_sys_preadn(fd, buf, cnt, off);
	if (err) {
		log_warn("preadn error: fd=%d cnt=%lu off=%ld err=%d",
		         fd, cnt, off, err);
	}
	return err;
}

static int do_ftruncate(int fd, loff_t len)
{
	int err;

	err = silofs_sys_ftruncate(fd, len);
	if (err) {
		log_warn("ftruncate error: fd=%d len=%ld err=%d",
		         fd, len, err);
	}
	return err;
}

static int do_fstatat(int dirfd, const char *pathname,
                      struct stat *st, int flags)
{
	int err;

	err = silofs_sys_fstatat(dirfd, pathname, st, flags);
	if (err && (err != -ENOENT)) {
		log_warn("fstatat error: dirfd=%d pathname=%s flags=%d err=%d",
		         dirfd, pathname, flags, err);
	}
	return err;
}

static int do_fstat(int fd, struct stat *st)
{
	int err;

	err = silofs_sys_fstat(fd, st);
	if (err && (err != -ENOENT)) {
		log_warn("fstat error: fd=%d err=%d", fd, st);
	}
	return err;
}

static int do_pwritevn(int fd, const struct iovec *iov, size_t cnt, loff_t off)
{
	int err;

	err = silofs_sys_pwritevn(fd, iov, (int)cnt, off);
	if (err) {
		log_warn("pwritevn error: fd=%d iov_cnt=%lu off=%ld err=%d",
		         fd, cnt, off, err);
	}
	return err;
}

static int do_opendir(const char *path, int *out_fd)
{
	int err;

	err = silofs_sys_opendir(path, out_fd);
	if (err) {
		log_warn("opendir error: path=%s err=%d", path, err);
	}
	return err;
}

static int do_opendirat(int dirfd, const char *pathname, int *out_fd)
{
	int err;

	err = silofs_sys_opendirat(dirfd, pathname, out_fd);
	if (err) {
		log_warn("opendirat error: dirfd=%d pathname=%s err=%d",
		         dirfd, pathname, err);
	}
	return err;
}

static int do_access(const char *path, int mode)
{
	int err;

	err = silofs_sys_access(path, mode);
	if (err) {
		log_warn("access error: path=%s mode=0x%x err=%d",
		         path, mode, err);
	}
	return err;
}

static int do_faccessat(int dirfd, const char *pathname, int mode, int flags)
{
	int err;

	err = silofs_sys_faccessat(dirfd, pathname, mode, flags);
	if (err) {
		log_warn("faccessat error: dirfd=%d pathname=%s "
		         "mode=0%o flags=%d err=%d", dirfd, pathname, mode,
		         flags, err);
	}
	return err;
}

static int do_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	int err;

	err = silofs_sys_mkdirat(dirfd, pathname, mode);
	if (err) {
		log_warn("mkdirat error: dirfd=%d pathname=%s mode=0%o err=%d",
		         dirfd, pathname, mode, err);
	}
	return err;
}

static int do_fcntl_flock(int fd, int cmd, struct flock *fl)
{
	int err;

	err = silofs_sys_fcntl_flock(fd, cmd, fl);
	if (err && (err != -EAGAIN)) {
		log_warn("flock error: fd=%d cmd=%d err=%d", fd, cmd, err);
	}
	return err;
}

static int do_flock(int fd, bool rw)
{
	struct stat st;
	struct flock fl = {
		.l_type = rw ? F_WRLCK : F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};
	int err;

	err = do_fstat(fd, &st);
	if (err) {
		return err;
	}
	fl.l_len = st.st_size;
	err = do_fcntl_flock(fd, F_SETLK, &fl);
	if (err) {
		return err;
	}
	return 0;
}

static int do_funlock(int fd)
{
	struct stat st;
	struct flock fl = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};
	int err;

	err = do_fstat(fd, &st);
	if (err) {
		return err;
	}
	fl.l_len = st.st_size;
	err = do_fcntl_flock(fd, F_SETLK, &fl);
	if (err) {
		return err;
	}
	return 0;
}

static int do_acquire_flock(int dfd, const char *name, bool rw, int *out_fd)
{
	int err;
	int fd = -1;
	const int o_flags = rw ? O_RDWR : O_RDONLY;

	err = do_openat(dfd, name, o_flags, 0, &fd);
	if (err) {
		return err;
	}
	err = do_flock(fd, rw);
	if (err) {
		do_closefd(&fd);
		return err;
	}
	*out_fd = fd;
	return 0;
}

static int do_release_flock(int *pfd)
{
	int err;

	err = do_funlock(*pfd);
	if (err) {
		return err;
	}
	do_closefd(pfd);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t blobid_to_index(const struct silofs_blobid *blobid,
                              const size_t index_max)
{
	return silofs_blobid_as_u64(blobid) % index_max;
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

static int blobid_to_pathname(const struct silofs_blobid *blobid,
                              size_t nsubs, struct silofs_namebuf *out_nb)
{
	size_t len = 0;
	size_t nlen = 0;
	size_t idx;
	char *nbuf = out_nb->name;
	const size_t nmax = sizeof(out_nb->name);
	int err;

	idx = blobid_to_index(blobid, nsubs);
	len += index_to_name(idx, nbuf, nmax);
	if (len > (nmax / 2)) {
		return -EINVAL;
	}
	nbuf[len++] = '/';
	err = silofs_blobid_to_name(blobid, nbuf + len, nmax - len - 1, &nlen);
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

static void fdsz_setup(struct silofs_blob_fdsz *fdsz, int fd, size_t sz)
{
	fdsz->fd = fd;
	fdsz->sz = sz;
}

static void fdsz_assign(struct silofs_blob_fdsz *fdsz,
                        const struct silofs_blob_fdsz *other)
{
	fdsz->sz = other->sz;
	fdsz->fd = other->fd;
}

static int fdsz_close(struct silofs_blob_fdsz *fdsz)
{
	return do_closefd(&fdsz->fd);
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
                     const struct silofs_blobid *blobid)
{
	blobid_assign(&bli->blobid, blobid);
	fdsz_reset(&bli->bl_fdsz);
	silofs_ce_init(&bli->bl_ce);
	silofs_fiovref_init(&bli->bl_fir, bli_fiov_pre, bli_fiov_post);
	bli->bl_hkey = silofs_blobid_hkey(blobid);

	silofs_ckey_by_blobid(&bli->bl_ce.ce_ckey, &bli->blobid);
}

void silofs_bli_fini(struct silofs_blob_info *bli)
{
	blobid_reset(&bli->blobid);
	fdsz_reset(&bli->bl_fdsz);
	silofs_ce_fini(&bli->bl_ce);
	silofs_fiovref_fini(&bli->bl_fir);
}

static void bli_set_fds(struct silofs_blob_info *bli,
                        const struct silofs_blob_fdsz *fds)
{
	fdsz_assign(&bli->bl_fdsz, fds);
}

struct silofs_blob_info *
silofs_bli_new(struct silofs_alloc_if *alif,
               const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli;

	bli = silofs_allocate(alif, sizeof(*bli));
	if (bli != NULL) {
		silofs_bli_init(bli, blobid);
	}
	return bli;
}

void silofs_bli_del(struct silofs_blob_info *bli, struct silofs_alloc_if *alif)
{
	silofs_bli_fini(bli);
	silofs_deallocate(alif, bli, sizeof(*bli));
}

static size_t bli_size(const struct silofs_blob_info *bli)
{
	return blobid_size(&bli->blobid);
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
	const loff_t off = oaddr->pos;
	const size_t len = oaddr->len;
	int err;

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

	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->blobid, oaddr_lba(oaddr));
	return silofs_bli_resolve(bli, &bk_oaddr, fiov);
}

int silofs_bli_datasync(const struct silofs_blob_info *bli)
{
	return do_fdatasync(bli->bl_fdsz.fd);
}

int silofs_bli_store(struct silofs_blob_info *bli,
                     const struct silofs_oaddr *oaddr,
                     const struct silofs_bytebuf *bb)
{
	struct silofs_fiovec fiov = { .fv_off = -1 };
	int err;

	err = silofs_bli_resolve(bli, oaddr, &fiov);
	if (err) {
		return err;
	}
	if (bb->len < fiov.fv_len) {
		return -EINVAL;
	}
	err = do_pwriten(fiov.fv_fd, bb->ptr, fiov.fv_len, fiov.fv_off);
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
	struct silofs_fiovec fiov = { .fv_off = -1 };
	int err;

	err = check_oaddr_iovec(oaddr, iov, cnt);
	if (err) {
		return err;
	}
	err = silofs_bli_resolve(bli, oaddr, &fiov);
	if (err) {
		return err;
	}
	err = do_pwritevn(fiov.fv_fd, iov, cnt, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bli_load(struct silofs_blob_info *bli,
                    const struct silofs_oaddr *oaddr,
                    struct silofs_bytebuf *bb)
{
	struct silofs_fiovec fiov = { .fv_off = -1 };
	void *bobj = NULL;
	int err;

	err = silofs_bli_resolve(bli, oaddr, &fiov);
	if (err) {
		return err;
	}
	if (!silofs_bytebuf_has_free(bb, !fiov.fv_len)) {
		return -EINVAL;
	}
	bobj = silofs_bytebuf_end(bb);
	err = do_preadn(fiov.fv_fd, bobj, fiov.fv_len, fiov.fv_off);
	if (err) {
		return err;
	}
	bb->len += fiov.fv_len;
	return 0;
}

static int bli_close(struct silofs_blob_info *bli)
{
	return fdsz_close(&bli->bl_fdsz);
}

int silofs_bli_shut(struct silofs_blob_info *bli)
{
	int err;

	err = bli_close(bli);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bli_load_bk(struct silofs_blob_info *bli, struct silofs_block *bk,
                       const struct silofs_oaddr *oaddr)
{
	struct silofs_oaddr bk_oaddr;
	struct silofs_bytebuf bb;

	silofs_assert_not_null(bk);
	silofs_bytebuf_init(&bb, bk, sizeof(*bk));
	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->blobid, oaddr_lba(oaddr));
	return silofs_bli_load(bli, &bk_oaddr, &bb);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_lookup_cached_bli(const struct silofs_repo *repo,
                                  const struct silofs_blobid *blobid,
                                  struct silofs_blob_info **out_bli)
{
	*out_bli = silofs_cache_lookup_blob(repo->re_cache, blobid);

	return (*out_bli == NULL) ? -ENOENT : 0;
}

static int repo_spawn_cached_bli(const struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blob_info **out_bli)
{
	*out_bli = silofs_cache_spawn_blob(repo->re_cache, blobid);

	return (*out_bli == NULL) ? -ENOMEM : 0;
}

static void repo_evict_cached_bli(const struct silofs_repo *repo,
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
	return do_closefd(&repo->re_objs_dfd);
}

static int repo_objs_open(struct silofs_repo *repo)
{
	int err;

	silofs_assert_lt(repo->re_objs_dfd, 0);

	err = do_opendirat(repo->re_base_dfd, repo->re_defs->re_objs_name,
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
	err = do_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_err("exists but not dir: %s", nb.name);
			return -ENOTDIR;
		}
		err = do_faccessat(repo->re_objs_dfd, nb.name, R_OK | X_OK, 0);
		if (err) {
			return err;
		}
	} else {
		err = do_mkdirat(repo->re_objs_dfd, nb.name, 0700);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int repo_objs_format(struct silofs_repo *repo)
{
	int err;

	for (size_t i = 0; i < repo->re_defs->re_objs_nsubs; ++i) {
		err = repo_objs_format_sub(repo, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int repo_objs_sub_pathname_of(const struct silofs_repo *repo,
                                     const struct silofs_blobid *blobid,
                                     struct silofs_namebuf *out_nb)
{
	const size_t nsubs = repo->re_defs->re_objs_nsubs;

	silofs_unused(repo);
	return blobid_to_pathname(blobid, nsubs, out_nb);
}

static int repo_objs_create_blob(const struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blob_fdsz *out_fdsz)
{
	int err;
	int fd = -1;
	size_t len = 0;
	size_t bsz;
	struct stat st;
	struct silofs_namebuf nb;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err == 0) {
		log_err("blob already exists: name=%s", nb.name);
		return -EEXIST;
	}
	if (err != -ENOENT) {
		log_err("can not create blob: name=%s err=%d", nb.name, err);
		return err;
	}
	err = do_openat(repo->re_objs_dfd, nb.name,
	                O_CREAT | O_RDWR | O_TRUNC, 0600, &fd);
	if (err) {
		return err;
	}
	bsz = blobid_size(blobid);
	if (bsz >= INT_MAX) {
		log_err("illegal blob size: name=%s bsz=%lu", nb.name, bsz);
		return -EINVAL;
	}
	len = max(bsz, SILOFS_BK_SIZE);
	err = do_ftruncate(fd, (loff_t)len);
	if (err) {
		goto out_err;
	}
	fdsz_setup(out_fdsz, fd, len);
	return 0;
out_err:
	do_unlinkat(repo->re_objs_dfd, nb.name, 0);
	do_closefd(&fd);
	return err;
}

static int repo_objs_open_blob(const struct silofs_repo *repo,
                               const struct silofs_blobid *blobid, bool rw,
                               struct silofs_blob_fdsz *out_fdsz)
{
	struct silofs_namebuf nb;
	struct stat st;
	size_t len = 0;
	int flags;
	int fd = -1;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err) {
		goto out_err;
	}
	len = blobid_size(blobid);
	if (st.st_size < (loff_t)len) {
		log_warn("blob-size mismatch: %s len=%lu st_size=%ld",
		         nb.name, len, st.st_size);
		err = -EIO;
		goto out_err;
	}
	flags = rw ? O_RDWR : O_RDONLY;
	err = do_openat(repo->re_objs_dfd, nb.name, flags, 0600, &fd);
	if (err) {
		goto out_err;
	}
	fdsz_setup(out_fdsz, fd, len);
	return 0;
out_err:
	/*
	 * When higher layer wants to open a blob, it should exist. Do not
	 * return -ENOENT as this may be interpreted as non-error by caller.
	 *
	 * TODO-0032: Consider using EFSCORRUPTED
	 */
	if (err == -ENOENT) {
		return -EIO;
	}

	return (err == -ENOENT) ? -EIO : err;
}

static int repo_objs_close_blob(const struct silofs_repo *repo,
                                const struct silofs_blobid *blobid,
                                struct silofs_blob_fdsz *fdsz)
{
	struct silofs_namebuf nb;
	struct stat st;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err) {
		log_warn("missing blob: name=%s err=%d", nb.name, err);
	}
	err = do_closefd(&fdsz->fd);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_objs_unlink_blob(const struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid)
{
	struct silofs_namebuf nb;
	struct stat st;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(repo->re_objs_dfd, nb.name, &st, 0);
	if (err) {
		log_dbg("can not unlink blob: %s err=%d", nb.name, err);
		return err;
	}
	err = do_unlinkat(repo->re_objs_dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_objs_open_blob_of(const struct silofs_repo *repo,
                                  const struct silofs_blobid *blobid,
                                  struct silofs_blob_info **out_bli)
{
	struct silofs_blob_fdsz fdsz = { .fd = -1 };
	int err;

	err = repo_objs_relax_cached_blis(repo);
	if (err) {
		return err;
	}
	err = repo_objs_open_blob(repo, blobid, true, &fdsz);
	if (err) {
		return err;
	}
	err = repo_spawn_cached_bli(repo, blobid, out_bli);
	if (err) {
		repo_objs_close_blob(repo, blobid, &fdsz);
		return err;
	}
	bli_set_fds(*out_bli, &fdsz);
	return 0;
}

static int repo_objs_stat_blob(const struct silofs_repo *repo,
                               const struct silofs_blobid *blobid,
                               struct stat *out_st)
{
	struct silofs_namebuf nb;
	size_t len = 0;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(repo->re_objs_dfd, nb.name, out_st, 0);
	if (err) {
		return err;
	}
	len = blobid_size(blobid);
	if (out_st->st_size < (loff_t)len) {
		log_warn("blob-size mismatch: %s len=%lu st_size=%ld",
		         nb.name, len, out_st->st_size);
		return -EIO;
	}
	return 0;
}

static int repo_objs_create_blob_of(const struct silofs_repo *repo,
                                    const struct silofs_blobid *blobid,
                                    struct silofs_blob_info **out_bli)
{
	struct silofs_blob_fdsz fdsz = { .fd = -1 };
	int err;

	err = repo_objs_relax_cached_blis(repo);
	if (err) {
		return err;
	}
	err = repo_objs_create_blob(repo, blobid, &fdsz);
	if (err) {
		return err;
	}
	err = repo_spawn_cached_bli(repo, blobid, out_bli);
	if (err) {
		return err;
	}
	bli_set_fds(*out_bli, &fdsz);
	return 0;
}

int silofs_repo_lookup_blob(const struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct stat st;
	struct silofs_blob_info *bli = NULL;
	int err;

	err = repo_lookup_cached_bli(repo, blobid, &bli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_stat_blob(repo, blobid, &st);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_spawn_blob(const struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blob_info **out_bli)
{
	struct stat st;
	int err;

	err = repo_lookup_cached_bli(repo, blobid, out_bli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_stat_blob(repo, blobid, &st);
	if (!err) {
		return -EEXIST;
	}
	if (err != -ENOENT) {
		return err;
	}
	err = repo_objs_create_blob_of(repo, blobid, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stage_blob(const struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blob_info **out_bli)
{
	int err;

	err = repo_lookup_cached_bli(repo, blobid, out_bli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_blob_of(repo, blobid, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_remove_blob(const struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = repo_objs_unlink_blob(repo, blobid);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_bli(repo, blobid, &bli);
	if (!err) {
		repo_evict_cached_bli(repo, bli);
	}
	return 0;
}

int silofs_repo_read_raw_blob(const struct silofs_repo *repo,
                              const struct silofs_blobid *blobid, void *buf)
{
	struct silofs_blob_fdsz fdsz = { .fd = -1 };
	int err;

	err = repo_objs_open_blob(repo, blobid, false, &fdsz);
	if (err) {
		return err;
	}
	err = do_preadn(fdsz.fd, buf, fdsz.sz, 0);
	if (err) {
		goto out;
	}
out:
	fdsz_close(&fdsz);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_sgvec {
	struct iovec iov[SILOFS_NKB_IN_BK];
	struct silofs_blobid blobid;
	loff_t off;
	size_t len;
	size_t cnt;
	size_t lim;
};

static void sgvec_setup(struct silofs_sgvec *sgv)
{
	sgv->blobid.size = 0;
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
	if (!blobid_isequal(&oaddr->blobid, &sgv->blobid)) {
		return false;
	}
	return true;
}

static int sgvec_append(struct silofs_sgvec *sgv,
                        const struct silofs_oaddr *oaddr, const void *dat)
{
	const size_t idx = sgv->cnt;

	if (idx == 0) {
		blobid_assign(&sgv->blobid, &oaddr->blobid);
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
	oaddr_setup(&oaddr, &sgv->blobid, sgv->len, sgv->off);
	err = silofs_repo_stage_blob(repo, &oaddr.blobid, &bli);
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

int silofs_repo_init(struct silofs_repo *repo, struct silofs_cache *cache,
                     struct silofs_crypto *crypto, const char *base, bool rw)
{
	repo->re_defs = &repo_defs;
	repo->re_cache = cache;
	repo->re_alif = cache->c_alif;
	repo->re_crypto = crypto;
	repo->re_base_dir = base;
	repo->re_base_dfd = -1;
	repo->re_objs_dfd = -1;
	repo->re_lock_fd = -1;
	repo->re_rw = rw;
	return 0;
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	silofs_repo_close(repo);
	repo->re_crypto = NULL;
	repo->re_cache = NULL;
	repo->re_alif = NULL;
	repo->re_base_dir = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_create_skel_subdir(const struct silofs_repo *repo,
                                   const char *name, mode_t mode)
{
	struct stat st = { .st_size = 0 };
	int err;

	err = do_mkdirat(repo->re_base_dfd, name, mode);
	if (err && (err != -EEXIST)) {
		return err;
	}
	err = do_fstatat(repo->re_base_dfd, name, &st, 0);
	if (err) {
		return err;
	}
	if ((st.st_mode & S_IRWXU) != S_IRWXU) {
		log_warn("bad access: %s mode=0%o", name, st.st_mode);
		return -EACCES;
	}
	return 0;
}

static int repo_create_skel_subfile(const struct silofs_repo *repo,
                                    const char *name, mode_t mode, loff_t len)
{
	int fd = -1;
	int err;

	err = do_unlinkat(repo->re_base_dfd, name, 0);
	if (err && (err != -ENOENT)) {
		return err;
	}
	err = do_openat(repo->re_base_dfd, name, O_CREAT | O_RDWR, mode, &fd);
	if (err) {
		return err;
	}
	err = do_ftruncate(fd, len);
	if (err) {
		do_closefd(&fd);
		return err;
	}
	err = do_closefd(&fd);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_create_skel(const struct silofs_repo *repo)
{
	const char *name;
	int err;

	name = repo->re_defs->re_objs_name;
	err = repo_create_skel_subdir(repo, name, 0700);
	if (err) {
		return err;
	}
	name = repo->re_defs->re_lock_name;
	err = repo_create_skel_subfile(repo, name, 0600, LOCKF_SIZE);
	if (err) {
		return err;
	}
	name = repo->re_defs->re_meta_name;
	err = repo_create_skel_subfile(repo, name, 0600, METAF_SIZE);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_require_skel_subdir(const struct silofs_repo *repo,
                                    const char *name)
{
	struct stat st = { .st_size = 0 };
	int err;

	err = do_fstatat(repo->re_base_dfd, name, &st, 0);
	if (err) {
		return err;
	}
	if (!S_ISDIR(st.st_mode)) {
		log_warn("not a directory: %s", name);
		return -ENOTDIR;
	}
	return 0;
}

static int repo_require_skel_subfile(const struct silofs_repo *repo,
                                     const char *name, loff_t min_size)
{
	struct stat st = { .st_size = 0 };
	int err;

	err = do_fstatat(repo->re_base_dfd, name, &st, 0);
	if (err) {
		return err;
	}
	if (!S_ISREG(st.st_mode)) {
		log_warn("not a regular file: %s", name);
		return S_ISDIR(st.st_mode) ? -EISDIR : -EINVAL;
	}
	if (st.st_size < min_size) {
		log_warn("illegal size: %s %ld", name, st.st_size);
		return -EUCLEAN;
	}
	return 0;
}

static int repo_require_skel(const struct silofs_repo *repo)
{
	const char *name;
	int err;

	err = do_access(repo->re_base_dir, R_OK | W_OK | X_OK);
	if (err) {
		return err;
	}
	name = repo->re_defs->re_lock_name;
	err = repo_require_skel_subfile(repo, name, LOCKF_SIZE);
	if (err) {
		return err;
	}
	name = repo->re_defs->re_meta_name;
	err = repo_require_skel_subfile(repo, name, METAF_SIZE);
	if (err) {
		return err;
	}
	name = repo->re_defs->re_objs_name;
	err = repo_require_skel_subdir(repo, name);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_open_basedir(struct silofs_repo *repo)
{
	silofs_assert_not_null(repo->re_base_dir);
	silofs_assert_lt(repo->re_base_dfd, 0);

	return do_opendir(repo->re_base_dir, &repo->re_base_dfd);
}

static int repo_format_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name = repo->re_defs->re_meta_name;
	int fd = -1;
	int err;

	STATICASSERT_LT(sizeof(rmeta), METAF_SIZE);

	rmeta_init(&rmeta);
	err = do_openat(repo->re_base_dfd, name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	err = do_pwriten(fd, &rmeta, sizeof(rmeta), 0);
	if (err) {
		goto out;
	}
	err = do_fchmod(fd, 0400);
	if (err) {
		goto out;
	}
out:
	do_closefd(&fd);
	return err;
}

static int repo_require_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name = repo->re_defs->re_meta_name;
	int fd = -1;
	int err;

	STATICASSERT_LT(sizeof(rmeta), METAF_SIZE);

	rmeta_init(&rmeta);
	err = do_openat(repo->re_base_dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		return err;
	}
	err = do_preadn(fd, &rmeta, sizeof(rmeta), 0);
	if (err) {
		goto out;
	}
	err = rmeta_check(&rmeta);
	if (err) {
		goto out;
	}
out:
	do_closefd(&fd);
	return err;
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
	err = repo_objs_open(repo);
	if (err) {
		return err;
	}
	err = repo_objs_format(repo);
	if (err) {
		return err;
	}
	err = repo_format_meta(repo);
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
	err = repo_objs_open(repo);
	if (err) {
		return err;
	}
	err = repo_require_meta(repo);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_close_locks(struct silofs_repo *repo)
{
	return silofs_repo_unlock(repo);
}

static int repo_close_basedir(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_base_dfd);
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
	err = repo_close_locks(repo);
	if (err) {
		return err;
	}
	err = repo_close_basedir(repo);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_lock(struct silofs_repo *repo)
{
	const char *name = repo->re_defs->re_lock_name;
	const int dfd = repo->re_base_dfd;
	int *pfd = &repo->re_lock_fd;

	return (*pfd < 0) ? do_acquire_flock(dfd, name, true, pfd) : 0;
}

int silofs_repo_unlock(struct silofs_repo *repo)
{
	int *pfd = &repo->re_lock_fd;

	return (*pfd < 0) ? 0 : do_release_flock(pfd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bootsec4k *
repo_new_bootsec4k(const struct silofs_repo *repo)
{
	struct silofs_bootsec4k *bor;

	bor = silofs_allocate(repo->re_alif, sizeof(*bor));
	if (bor != NULL) {
		silofs_bsec4k_init(bor);
	}
	return bor;
}

static void repo_del_bootsec4k(const struct silofs_repo *repo,
                               struct silofs_bootsec4k *bor)
{
	if (bor != NULL) {
		silofs_bsec4k_fini(bor);
		silofs_deallocate(repo->re_alif, bor, sizeof(*bor));
	}
}

int silofs_repo_load_bsec(const struct silofs_repo *repo,
                          const struct silofs_namestr *nstr,
                          struct silofs_bootsec *out_bsec)
{
	struct silofs_bootsec4k *bsec = NULL;
	const char *name = nstr->str.str;
	const int dfd = repo->re_base_dfd;
	int fd = -1;
	int err;

	bsec = repo_new_bootsec4k(repo);
	if (bsec == NULL) {
		return -ENOMEM;
	}
	err = do_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		goto out;
	}
	err = do_preadn(fd, bsec, sizeof(*bsec), 0);
	if (err) {
		goto out;
	}
	err = silofs_bsec4k_verify(bsec, &repo->re_crypto->md);
	if (err) {
		goto out;
	}
	silofs_bsec4k_parse(bsec, out_bsec);
	silofs_bootsec_set_name(out_bsec, nstr);
out:
	repo_del_bootsec4k(repo, bsec);
	do_closefd(&fd);
	return err;
}

static void namebuf_mktmp(struct silofs_namebuf *nb)
{
	long t[2];

	t[0] = (long)silofs_time_now();
	silofs_getentropy(&t[1], sizeof(t[1]));

	snprintf(nb->name, sizeof(nb->name) - 1, ".%ld%ld", t[0], t[1]);
}

int silofs_repo_save_bsec(const struct silofs_repo *repo,
                          const struct silofs_bootsec *bsec,
                          const struct silofs_namestr *nstr)
{
	struct silofs_namebuf nbuf;
	struct silofs_bootsec4k *bsc = NULL;
	const int dfd = repo->re_base_dfd;
	int fd = -1;
	int err;

	namebuf_mktmp(&nbuf);
	bsc = repo_new_bootsec4k(repo);
	if (bsc == NULL) {
		return -ENOMEM;
	}
	silofs_bsec4k_set(bsc, bsec);
	silofs_bsec4k_stamp(bsc, &repo->re_crypto->md);

	err = do_openat(dfd, nbuf.name, O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		goto out;
	}
	err = do_fchmod(fd, 0400);
	if (err) {
		goto out;
	}
	err = do_pwriten(fd, bsc, sizeof(*bsc), 0);
	if (err) {
		goto out;
	}
	err = do_fsync(fd);
	if (err) {
		goto out;
	}
	err = do_renameat(dfd, nbuf.name, nstr->str.str);
	if (err) {
		goto out;
	}
out:
	repo_del_bootsec4k(repo, bsc);
	do_closefd(&fd);
	if (err) {
		do_unlinkat(dfd, nbuf.name, 0);
	}
	return err;
}

int silofs_repo_remove_bsec(const struct silofs_repo *repo,
                            const struct silofs_namestr *nstr)
{
	struct silofs_bootsec4k *bsec = NULL;
	const char *name = nstr->str.str;
	const int dfd = repo->re_base_dfd;
	int fd = -1;
	int err;

	bsec = repo_new_bootsec4k(repo);
	if (bsec == NULL) {
		return -ENOMEM;
	}
	err = do_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		goto out;
	}
	err = do_preadn(fd, bsec, sizeof(*bsec), 0);
	if (err) {
		goto out;
	}
	err = silofs_bsec4k_verify(bsec, &repo->re_crypto->md);
	if (err) {
		goto out;
	}
	err = do_fchmodat(dfd, name, 0600);
	if (err) {
		goto out;
	}
	err = do_unlinkat(dfd, name, 0);
	if (err) {
		goto out;
	}
out:
	repo_del_bootsec4k(repo, bsec);
	do_closefd(&fd);
	return err;
}

int silofs_repo_lock_bsec(const struct silofs_repo *repo,
                          const struct silofs_namestr *nstr, int *out_fd)
{
	const char *name = nstr->str.str;
	const int dfd = repo->re_base_dfd;
	int fd = -1;
	int err;

	err = do_fchmodat(dfd, name, 0600);
	if (err) {
		goto out;
	}
	err = do_openat(dfd, name, O_RDWR, 0, &fd);
	if (err) {
		goto out;
	}
	err = do_fchmodat(dfd, name, 0400);
	if (err) {
		goto out;
	}
	err = do_flock(fd, true);
	if (err) {
		goto out;
	}
out:
	if (err) {
		do_closefd(&fd);
	}
	*out_fd = fd;
	return err;
}

int silofs_repo_unlock_bsec(const struct silofs_repo *repo,
                            const struct silofs_namestr *nstr, int *pfd)
{
	struct stat st[2];
	const char *name = nstr->str.str;
	const int dfd = repo->re_base_dfd;
	int fd = -1;
	int err;

	err = do_fstat(*pfd, &st[0]);
	if (err) {
		return err;
	}
	err = do_funlock(*pfd);
	if (err) {
		return err;
	}
	do_closefd(pfd);

	err = do_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		err = 0;
		goto out;
	}
	err = do_fstat(fd, &st[1]);
	if (err) {
		goto out;
	}
	if (st[0].st_ino != st[1].st_ino) {
		err = -ENOENT; /* underlying file changed */
	}
out:
	do_closefd(&fd);
	return err;
}


