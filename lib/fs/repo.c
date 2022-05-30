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
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#define REPO_METAF_SIZE (4096)
#define REPO_OBJS_NSUBS (256)

typedef bool (*silofs_bli_pred_fn)(const struct silofs_blob_info *);

struct silofs_repo_defs {
	const char *re_dots_name;
	const char *re_meta_name;
	const char *re_objs_name;
	size_t re_objs_nsubs;
};

static const struct silofs_repo_defs repo_defs = {
	.re_dots_name  = ".silofs",
	.re_meta_name  = "meta",
	.re_objs_name  = "objs",
	.re_objs_nsubs = REPO_OBJS_NSUBS,
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

static int do_fallocate(int fd, int mode, loff_t off, loff_t len)
{
	int err;

	err = silofs_sys_fallocate(fd, mode, off, len);
	if (err && (err != -ENOTSUP)) {
		log_warn("fallocate error: fd=%d mode=%o "
		         "off=%ld len=%ld err=%d", fd, mode, off, len, err);
	}
	return err;
}

static int do_fallocate_punch_hole(int fd, loff_t off, size_t len)
{
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	return do_fallocate(fd, mode, off, (loff_t)len);
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

	silofs_memzero(out_nb, sizeof(*out_nb));
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
bli_from_xiovref(const struct silofs_xiovref *fvr)
{
	const struct silofs_blob_info *bli = NULL;

	bli = container_of2(fvr, struct silofs_blob_info, bl_xior);
	return bli_unconst(bli);
}

static void bli_xiov_pre(struct silofs_xiovref *fir)
{
	struct silofs_blob_info *bli = bli_from_xiovref(fir);

	silofs_bli_incref(bli);
}

static void bli_xiov_post(struct silofs_xiovref *fir)
{
	struct silofs_blob_info *bli = bli_from_xiovref(fir);

	silofs_bli_decref(bli);
}

static void bli_init(struct silofs_blob_info *bli,
                     const struct silofs_blobid *blobid)
{
	blobid_assign(&bli->blobid, blobid);
	fdsz_reset(&bli->bl_fdsz);
	silofs_ce_init(&bli->bl_ce);
	silofs_xiovref_init(&bli->bl_xior, bli_xiov_pre, bli_xiov_post);
	bli->bl_hkey = silofs_blobid_hkey(blobid);
	silofs_ckey_by_blobid(&bli->bl_ce.ce_ckey, &bli->blobid);
}

static void bli_fini(struct silofs_blob_info *bli)
{
	blobid_reset(&bli->blobid);
	fdsz_reset(&bli->bl_fdsz);
	silofs_ce_fini(&bli->bl_ce);
	silofs_xiovref_fini(&bli->bl_xior);
}

static void bli_set_fds(struct silofs_blob_info *bli,
                        const struct silofs_blob_fdsz *fds)
{
	fdsz_assign(&bli->bl_fdsz, fds);
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

static void bli_setup_xiovec(const struct silofs_blob_info *bli,
                             loff_t off, size_t len,
                             struct silofs_xiovec *xiov)
{
	xiov->xiov_off = off;
	xiov->xiov_len = len;
	xiov->xiov_base = NULL;
	xiov->xiov_fd = bli->bl_fdsz.fd;
	xiov->xiov_ref = NULL;
}

static void bli_setup_xiovec_ref(struct silofs_blob_info *bli,
                                 struct silofs_xiovec *xiov)
{
	xiov->xiov_ref = &bli->bl_xior;
}

static int bli_xiovec_at(const struct silofs_blob_info *bli,
                         loff_t off, size_t len, struct silofs_xiovec *xiov)
{
	int err;

	err = bli_check_range(bli, off, len);
	if (!err) {
		bli_setup_xiovec(bli, off, len, xiov);
	}
	return err;
}

static int bli_xiovec_of(const struct silofs_blob_info *bli,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_xiovec *xiov)
{
	return bli_xiovec_at(bli, oaddr->pos, oaddr->len, xiov);
}

int silofs_bli_resolve(struct silofs_blob_info *bli,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_xiovec *xiov)
{
	int err;

	err = bli_xiovec_of(bli, oaddr, xiov);
	if (err) {
		return err;
	}
	bli_setup_xiovec_ref(bli, xiov);
	return 0;
}

int silofs_bli_datasync(const struct silofs_blob_info *bli)
{
	return do_fdatasync(bli->bl_fdsz.fd);
}

int silofs_bli_store(const struct silofs_blob_info *bli,
                     const struct silofs_oaddr *oaddr,
                     const struct silofs_bytebuf *bb)
{
	struct silofs_xiovec xiov = { .xiov_off = -1 };
	int err;

	err = bli_xiovec_of(bli, oaddr, &xiov);
	if (err) {
		return err;
	}
	if (bb->len < xiov.xiov_len) {
		return -EINVAL;
	}
	err = do_pwriten(xiov.xiov_fd, bb->ptr, xiov.xiov_len, xiov.xiov_off);
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

int silofs_bli_storev2(const struct silofs_blob_info *bli, loff_t off,
                       const struct iovec *iov, size_t cnt)
{
	struct silofs_xiovec xiov = { .xiov_off = -1 };
	const size_t len = iovec_length(iov, cnt);
	int err;

	err = bli_xiovec_at(bli, off, len, &xiov);
	if (err) {
		return err;
	}
	if (len != xiov.xiov_len) {
		return -EINVAL;
	}
	err = do_pwritevn(xiov.xiov_fd, iov, cnt, xiov.xiov_off);
	if (err) {
		return err;
	}
	return 0;
}

static int check_oaddr_iovec(const struct silofs_oaddr *oaddr,
                             const struct iovec *iov, size_t cnt)
{
	return (iovec_length(iov, cnt) == oaddr->len) ? 0 : -EINVAL;
}

int silofs_bli_storev(const struct silofs_blob_info *bli,
                      const struct silofs_oaddr *oaddr,
                      const struct iovec *iov, size_t cnt)
{
	struct silofs_xiovec xiov = { .xiov_off = -1 };
	int err;

	err = check_oaddr_iovec(oaddr, iov, cnt);
	if (err) {
		return err;
	}
	err = bli_xiovec_of(bli, oaddr, &xiov);
	if (err) {
		return err;
	}
	err = do_pwritevn(xiov.xiov_fd, iov, cnt, xiov.xiov_off);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bli_load(const struct silofs_blob_info *bli,
                    const struct silofs_oaddr *oaddr,
                    struct silofs_bytebuf *bb)
{
	struct silofs_xiovec xiov = { .xiov_off = -1 };
	void *bobj = NULL;
	int err;

	err = bli_xiovec_of(bli, oaddr, &xiov);
	if (err) {
		return err;
	}
	if (!silofs_bytebuf_has_free(bb, !xiov.xiov_len)) {
		return -EINVAL;
	}
	bobj = silofs_bytebuf_end(bb);
	err = do_preadn(xiov.xiov_fd, bobj, xiov.xiov_len, xiov.xiov_off);
	if (err) {
		return err;
	}
	bb->len += xiov.xiov_len;
	return 0;
}

int silofs_bli_load_bk(const struct silofs_blob_info *bli,
                       const struct silofs_bkaddr *bkaddr,
                       struct silofs_block *bk)
{
	struct silofs_oaddr bk_oaddr;
	struct silofs_bytebuf bb;

	silofs_bytebuf_init(&bb, bk, sizeof(*bk));
	silofs_oaddr_of_bk(&bk_oaddr, &bkaddr->blobid, bkaddr->lba);
	return silofs_bli_load(bli, &bk_oaddr, &bb);
}

int silofs_bli_store_bk(const struct silofs_blob_info *bli,
                        const struct silofs_bkaddr *bkaddr,
                        struct silofs_block *bk)
{
	struct silofs_oaddr bk_oaddr;
	struct silofs_bytebuf bb;

	silofs_bytebuf_init2(&bb, bk, sizeof(*bk));
	silofs_oaddr_of_bk(&bk_oaddr, &bkaddr->blobid, bkaddr->lba);
	return silofs_bli_store(bli, &bk_oaddr, &bb);
}

static int bli_trim_by_ftruncate(const struct silofs_blob_info *bli)
{
	const struct silofs_blob_fdsz *fdsz = &bli->bl_fdsz;
	int err;

	err = do_ftruncate(fdsz->fd, 0);
	if (err) {
		return err;
	}
	err = do_ftruncate(fdsz->fd, (long)fdsz->sz);
	if (err) {
		return err;
	}
	return 0;
}

static int bli_trim_by_punch(const struct silofs_blob_info *bli)
{
	const struct silofs_blob_fdsz *fdsz = &bli->bl_fdsz;

	return do_fallocate_punch_hole(fdsz->fd, 0, fdsz->sz);
}

int silofs_bli_trim(const struct silofs_blob_info *bli)
{
	int err;

	err = bli_trim_by_punch(bli);
	if (err == -ENOTSUP) {
		err = bli_trim_by_ftruncate(bli);
	}
	return err;
}

static int bli_close(struct silofs_blob_info *bli)
{
	return fdsz_close(&bli->bl_fdsz);
}

struct silofs_blob_info *
silofs_bli_new(struct silofs_alloc *alloc,
               const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli;

	bli = silofs_allocate(alloc, sizeof(*bli));
	if (bli != NULL) {
		bli_init(bli, blobid);
	}
	return bli;
}

void silofs_bli_del(struct silofs_blob_info *bli, struct silofs_alloc *alloc)
{
	bli_close(bli);
	bli_fini(bli);
	silofs_deallocate(alloc, bli, sizeof(*bli));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_lookup_cached_bli(struct silofs_repo *repo,
                                  const struct silofs_blobid *blobid,
                                  struct silofs_blob_info **out_bli)
{
	*out_bli = silofs_cache_lookup_blob(&repo->re_cache, blobid);

	return (*out_bli == NULL) ? -ENOENT : 0;
}

static int repo_spawn_cached_bli(struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blob_info **out_bli)
{
	*out_bli = silofs_cache_spawn_blob(&repo->re_cache, blobid);

	return (*out_bli == NULL) ? -ENOMEM : 0;
}

static void repo_evict_cached_bli(struct silofs_repo *repo,
                                  struct silofs_blob_info *bli)
{
	silofs_cache_evict_blob(&repo->re_cache, bli);
}

static int repo_objs_relax_cached_blis(struct silofs_repo *repo)
{
	const size_t ncached = repo->re_cache.c_bli_lm.lm_htbl_sz;

	if (ncached > 256) { /* XXX make upper bound tweak */
		silofs_cache_relax_blobs(&repo->re_cache);
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
	const char *name = repo->re_defs->re_objs_name;
	const int dfd = repo->re_dots_dfd;
	int err;

	err = do_opendirat(dfd, name, &repo->re_objs_dfd);
	if (err) {
		return err;
	}
	/* XXX TODO: check validity of subdirs */
	return 0;
}

static int repo_objs_format_sub(const struct silofs_repo *repo, size_t idx)
{
	struct silofs_namebuf nb;
	struct stat st;
	const int dfd = repo->re_objs_dfd;
	int err;

	index_to_namebuf(idx, &nb);
	err = do_fstatat(dfd, nb.name, &st, 0);
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_err("exists but not dir: %s", nb.name);
			return -ENOTDIR;
		}
		err = do_faccessat(dfd, nb.name, R_OK | X_OK, 0);
		if (err) {
			return err;
		}
	} else {
		err = do_mkdirat(dfd, nb.name, 0700);
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

static void rehash_blobid(const struct silofs_blobid *blobid,
                          const struct silofs_mdigest *md,
                          struct silofs_blobid *out_blobid)
{
	struct silofs_hash256 hash;

	SILOFS_STATICASSERT_EQ(sizeof(hash), sizeof(blobid->xxid));
	silofs_sha256_of(md, &blobid->xxid, sizeof(blobid->xxid), &hash);
	silofs_blobid_make_cas(out_blobid, &hash, blobid->size);
}

static const struct silofs_mdigest *
repo_mdigest(const struct silofs_repo *repo)
{
	return &repo->re_bootldr.btl_md;
}

static int repo_objs_sub_pathname_of(const struct silofs_repo *repo,
                                     const struct silofs_blobid *blobid,
                                     struct silofs_namebuf *out_nb)
{
	struct silofs_blobid hashed_blobid = { .size = 0 };
	const size_t nsubs = repo->re_defs->re_objs_nsubs;

	rehash_blobid(blobid, repo_mdigest(repo), &hashed_blobid);
	return blobid_to_pathname(&hashed_blobid, nsubs, out_nb);
}

static int repo_objs_create_blob(const struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blob_fdsz *out_fdsz)
{
	struct silofs_namebuf nb;
	struct stat st;
	size_t len = 0;
	size_t bsz = 0;
	const int dfd = repo->re_objs_dfd;
	int fd = -1;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(dfd, nb.name, &st, 0);
	if (err == 0) {
		log_err("blob already exists: name=%s", nb.name);
		return -EEXIST;
	}
	if (err != -ENOENT) {
		log_err("can not create blob: name=%s err=%d", nb.name, err);
		return err;
	}
	err = do_openat(dfd, nb.name, O_CREAT | O_RDWR | O_TRUNC, 0600, &fd);
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
	const int dfd = repo->re_objs_dfd;
	int fd = -1;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(dfd, nb.name, &st, 0);
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
	err = do_openat(dfd, nb.name, rw ? O_RDWR : O_RDONLY, 0600, &fd);
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

	return err;
}

static int repo_objs_close_blob(const struct silofs_repo *repo,
                                const struct silofs_blobid *blobid,
                                struct silofs_blob_fdsz *fdsz)
{
	struct silofs_namebuf nb;
	struct stat st;
	const int dfd = repo->re_objs_dfd;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	err = do_fstatat(dfd, nb.name, &st, 0);
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

static int repo_objs_open_blob_of(struct silofs_repo *repo,
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

static int repo_objs_create_blob_of(struct silofs_repo *repo,
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
		repo_objs_close_blob(repo, blobid, &fdsz);
		return err;
	}
	bli_set_fds(*out_bli, &fdsz);
	return 0;
}

static int repo_check_open(const struct silofs_repo *repo)
{
	return likely(repo->re_bootldr.btl_dfd > 0) ? 0 : -EBADF;
}

static int repo_check_writable(const struct silofs_repo *repo)
{
	if (!repo->re_rw) {
		log_dbg("read-only repo: %s", repo->re_bootpath.repodir.str);
		return -EPERM;
	}
	return 0;
}

static int repo_check_open_rw(const struct silofs_repo *repo)
{
	int err;

	err = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_check_writable(repo);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_lookup_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct stat st;
	struct silofs_blob_info *bli = NULL;
	int err;

	err  = repo_check_open(repo);
	if (err) {
		return err;
	}
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

int silofs_repo_spawn_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blob_info **out_bli)
{
	struct stat st;
	int err;

	err = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
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

int silofs_repo_stage_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blob_info **out_bli)
{
	int err;

	err  = repo_check_open(repo);
	if (err) {
		return err;
	}
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

int silofs_repo_remove_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
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

int silofs_repo_require_blob(struct silofs_repo *repo,
                             const struct silofs_blobid *blobid,
                             struct silofs_blob_info **out_bli)
{
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		err = silofs_repo_stage_blob(repo, blobid, out_bli);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(repo, blobid, out_bli);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_init_cache(struct silofs_repo *repo, size_t memsz_hint)
{
	return silofs_cache_init(&repo->re_cache, repo->re_alloc, memsz_hint);
}

static void repo_fini_cache(struct silofs_repo *repo)
{
	silofs_cache_fini(&repo->re_cache);
}

static int repo_init_bootldr(struct silofs_repo *repo)
{
	return silofs_bootldr_init(&repo->re_bootldr);
}

static void repo_fini_bootldr(struct silofs_repo *repo)
{
	silofs_bootldr_fini(&repo->re_bootldr);
}

int silofs_repo_init(struct silofs_repo *repo, struct silofs_alloc *alloc,
                     const struct silofs_bootpath *bpath, size_t msz, bool rw)
{
	int err;

	repo->re_defs = &repo_defs;
	repo->re_alloc = alloc;
	repo->re_dots_dfd = -1;
	repo->re_objs_dfd = -1;
	repo->re_rw = rw;
	repo->re_inited = false;
	silofs_bootpath_assign(&repo->re_bootpath, bpath);
	err = repo_init_cache(repo, msz);
	if (err) {
		return err;
	}
	err = repo_init_bootldr(repo);
	if (err) {
		return err;
	}
	repo->re_inited = true;
	return 0;
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	silofs_repo_close(repo);
	repo_fini_cache(repo);
	repo_fini_bootldr(repo);
	repo->re_alloc = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_create_skel_subdir(const struct silofs_repo *repo,
                                   const char *name, mode_t mode)
{
	struct stat st = { .st_size = 0 };
	const int dfd = repo->re_dots_dfd;
	int err;

	err = do_mkdirat(dfd, name, mode);
	if (err && (err != -EEXIST)) {
		return err;
	}
	err = do_fstatat(dfd, name, &st, 0);
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
	const int dfd = repo->re_dots_dfd;
	int fd = -1;
	int err;

	err = do_unlinkat(dfd, name, 0);
	if (err && (err != -ENOENT)) {
		return err;
	}
	err = do_openat(dfd, name, O_CREAT | O_RDWR, mode, &fd);
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
	name = repo->re_defs->re_meta_name;
	err = repo_create_skel_subfile(repo, name, 0600, REPO_METAF_SIZE);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_require_skel_subdir(const struct silofs_repo *repo,
                                    const char *name)
{
	struct stat st = { .st_size = 0 };
	const int dfd = repo->re_dots_dfd;
	int err;

	err = do_fstatat(dfd, name, &st, 0);
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
	const int dfd = repo->re_dots_dfd;
	int err;

	err = do_fstatat(dfd, name, &st, 0);
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

	err = do_access(repo->re_bootpath.repodir.str, R_OK | W_OK | X_OK);
	if (err) {
		return err;
	}
	name = repo->re_defs->re_meta_name;
	err = repo_require_skel_subfile(repo, name, REPO_METAF_SIZE);
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

static int repo_open_rootdir(struct silofs_repo *repo)
{
	return silofs_bootldr_open(&repo->re_bootldr, &repo->re_bootpath);
}

static int repo_create_dotsdir(const struct silofs_repo *repo)
{
	const char *name = repo->re_defs->re_dots_name;
	int err;

	err = do_mkdirat(repo->re_bootldr.btl_dfd, name, 0700);
	if (err && (err != -EEXIST)) {
		return err;
	}
	return 0;
}

static int repo_open_dotsdir(struct silofs_repo *repo)
{
	return do_opendirat(repo->re_bootldr.btl_dfd,
	                    repo->re_defs->re_dots_name,
	                    &repo->re_dots_dfd);
}

static int repo_format_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name = repo->re_defs->re_meta_name;
	const int dfd = repo->re_dots_dfd;
	int fd = -1;
	int err;

	STATICASSERT_LT(sizeof(rmeta), REPO_METAF_SIZE);

	rmeta_init(&rmeta);
	err = do_openat(dfd, name, O_RDWR, 0600, &fd);
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
	const int dfd = repo->re_dots_dfd;
	int fd = -1;
	int err;

	STATICASSERT_LT(sizeof(rmeta), REPO_METAF_SIZE);

	rmeta_init(&rmeta);
	err = do_openat(dfd, name, O_RDONLY, 0, &fd);
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

	err = repo_open_rootdir(repo);
	if (err) {
		return err;
	}
	err = repo_create_dotsdir(repo);
	if (err) {
		return err;
	}
	err = repo_open_dotsdir(repo);
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

	err = repo_open_rootdir(repo);
	if (err) {
		return err;
	}
	err = repo_open_dotsdir(repo);
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

static int repo_close_basedir(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_dots_dfd);
}

static int repo_close_rootdir(struct silofs_repo *repo)
{
	return silofs_bootldr_close(&repo->re_bootldr);
}

int silofs_repo_close(struct silofs_repo *repo)
{
	int err;

	if (repo->re_bootldr.btl_dfd < 0) {
		return 0;
	}
	err = repo_objs_close(repo);
	if (err) {
		return err;
	}
	err = repo_close_basedir(repo);
	if (err) {
		return err;
	}
	err = repo_close_rootdir(repo);
	if (err) {
		return err;
	}
	silofs_repo_drop_cache(repo);
	return 0;
}

void silofs_repo_drop_cache(struct silofs_repo *repo)
{
	silofs_cache_drop(&repo->re_cache);
}

void silofs_repo_relax_cache(struct silofs_repo *repo, int flags)
{
	silofs_cache_relax(&repo->re_cache, flags);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int repo_lookup_cached_ubi(struct silofs_repo *repo,
                                  const struct silofs_bkaddr *bkaddr,
                                  struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_lookup_ubk(&repo->re_cache, bkaddr);
	return (*out_ubi != NULL) ? 0 : -ENOENT;
}

static void repo_forget_cached_ubi(struct silofs_repo *repo,
                                   struct silofs_ubk_info *ubi)
{
	silofs_cache_forget_ubk(&repo->re_cache, ubi);
}

static int repo_spawn_cached_ubi(struct silofs_repo *repo,
                                 const struct silofs_bkaddr *bkaddr,
                                 struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_spawn_ubk(&repo->re_cache, bkaddr);
	return (*out_ubi != NULL) ? 0 : -ENOMEM;
}

static int repo_spawn_attach_ubi(struct silofs_repo *repo,
                                 struct silofs_blob_info *bli,
                                 const struct silofs_bkaddr *bkaddr,
                                 struct silofs_ubk_info **out_ubi)
{
	int err;

	bli_incref(bli);
	err = repo_spawn_cached_ubi(repo, bkaddr, out_ubi);
	if (!err) {
		silofs_ubi_attach(*out_ubi, bli);
	}
	bli_decref(bli);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_spawn_ubk(struct silofs_repo *repo,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubi)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = repo_lookup_cached_ubi(repo, bkaddr, out_ubi);
	if (!err) {
		return -EEXIST;
	}
	err = silofs_repo_require_blob(repo, &bkaddr->blobid, &bli);
	if (err) {
		return err;
	}
	err = repo_spawn_attach_ubi(repo, bli, bkaddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_spawn_ubk(struct silofs_repo *repo,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubi)
{
	int err;

	err  = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
	err = repo_spawn_ubk(repo, bkaddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_stage_ubk(struct silofs_repo *repo,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubi)
{
	struct silofs_blob_info *bli = NULL;
	struct silofs_ubk_info *ubi = NULL;
	int err;

	err = repo_lookup_cached_ubi(repo, bkaddr, out_ubi);
	if (!err) {
		return 0; /* cache hit */
	}
	err = silofs_repo_stage_blob(repo, &bkaddr->blobid, &bli);
	if (err) {
		return err;
	}
	err = repo_spawn_attach_ubi(repo, bli, bkaddr, &ubi);
	if (err) {
		return err;
	}
	err = silofs_bli_load_bk(bli, bkaddr, ubi->ubk);
	if (err) {
		repo_forget_cached_ubi(repo, ubi);
		return err;
	}
	*out_ubi = ubi;
	return 0;
}

int silofs_repo_stage_ubk(struct silofs_repo *repo,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubi)
{
	int err;

	err  = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_stage_ubk(repo, bkaddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}
