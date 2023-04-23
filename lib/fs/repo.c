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
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <limits.h>


struct silofs_repo_defs {
	const char     *re_dots_name;
	const char     *re_meta_name;
	const char     *re_blobs_name;
	unsigned int    re_objs_nsubs;
};

static const struct silofs_repo_defs repo_defs = {
	.re_dots_name   = SILOFS_REPO_DOTS_DIRNAME,
	.re_meta_name   = SILOFS_REPO_META_FILENAME,
	.re_blobs_name  = SILOFS_REPO_BLOBS_DIRNAME,
	.re_objs_nsubs  = SILOFS_REPO_OBJSDIR_NSUBS,
};

/* local functions */
static int repo_close(struct silofs_repo *repo);


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static void rmeta_set_mode(struct silofs_repo_meta *rm, uint32_t repo_mode)
{
	rm->rm_mode = silofs_cpu_to_le32(repo_mode);
}

static void rmeta_init(struct silofs_repo_meta *rm)
{
	silofs_memzero(rm, sizeof(*rm));
	rmeta_set_magic(rm, SILOFS_REPO_META_MAGIC);
	rmeta_set_version(rm, SILOFS_REPO_VERSION);
	rmeta_set_mode(rm, 1);
}

static int rmeta_check(const struct silofs_repo_meta *rm)
{
	uint64_t magic;
	uint32_t version;

	magic = rmeta_magic(rm);
	if (magic != SILOFS_REPO_META_MAGIC) {
		log_dbg("bad repo meta: magic=%lx", magic);
		return -SILOFS_EFSCORRUPTED;
	}
	version = rmeta_version(rm);
	if (version != SILOFS_REPO_VERSION) {
		log_dbg("bad repo meta: version=%lx", version);
		return -SILOFS_EFSCORRUPTED;
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
                     int o_flags, mode_t mode, int *out_fd)
{
	int err;

	err = silofs_sys_openat(dfd, pathname, o_flags, mode, out_fd);
	if (err && (err != -ENOENT)) {
		log_warn("openat error: dfd=%d pathname=%s o_flags=0x%x "
		         "mode=0%o err=%d", dfd, pathname, o_flags, mode, err);
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

static int do_sync_file_range(int fd, loff_t off,
                              loff_t nbytes, unsigned int flags)
{
	int err;

	err = silofs_sys_sync_file_range(fd, off, nbytes, flags);
	if (err && (err != -ENOSYS)) {
		log_warn("sync_file_range error: fd=%d off=%ld nbytes=%ld "
		         "flags=%u err=%d", fd, off, nbytes, flags, err);
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

static int do_fallocate_punch_hole(int fd, loff_t off, loff_t len)
{
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	return do_fallocate(fd, mode, off, len);
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

static int do_opendir(const char *path, int *out_fd)
{
	int err;

	err = silofs_sys_opendir(path, out_fd);
	if (err) {
		log_warn("opendir failed: %s err=%d", path, err);
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

static int do_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
	int err;

	err = silofs_sys_fchmodat(dirfd, pathname, mode, flags);
	if (err && (err != -ENOENT)) {
		log_warn("fchmodat error: dirfd=%d pathname=%s mode=0%o "
		         "err=%d", dirfd, pathname, mode, err);
	}
	return err;
}

static int do_flock(int fd, int op)
{
	int err;

	err = silofs_sys_flock(fd, op);
	if (err) {
		log_dbg("flock error: fd=%d op=%d err=%d", fd, op, err);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t
blobid_to_index(const struct silofs_blobid *blobid, uint32_t index_max)
{
	uint64_t h[2];
	uint64_t leh[2];
	uint32_t xx;
	uint32_t idx;

	silofs_blobid_as_u128(blobid, h);
	leh[0] = silofs_cpu_to_le64(h[0]);
	leh[1] = silofs_cpu_to_le64(h[1]);
	xx = silofs_hash_xxh32(leh, sizeof(leh), 0);
	idx = xx % index_max;
	return idx;
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

static int make_pathname(const struct silofs_hash256 *hash, size_t idx,
                         struct silofs_namebuf *out_nb)
{
	size_t len;
	size_t nlim;
	size_t nlen;
	char *nbuf = out_nb->name;
	const size_t nmax = sizeof(out_nb->name);

	silofs_memzero(out_nb, sizeof(*out_nb));
	len = index_to_name(idx, nbuf, nmax);
	if (len > (nmax / 2)) {
		return -SILOFS_EINVAL;
	}
	nbuf[len++] = '/';
	nlim = nmax - len - 1;
	nlen = silofs_hash256_to_name(hash, nbuf + len, nlim);
	if (nlen >= nlim) {
		return -SILOFS_EINVAL;
	}
	len += nlen;
	nbuf[len] = '\0';
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blobf *blobf_unconst(const struct silofs_blobf *blobf)
{
	union {
		const struct silofs_blobf *p;
		struct silofs_blobf *q;
	} u = {
		.p = blobf
	};
	return u.q;
}

static struct silofs_blobf *
blobf_from_iovref(const struct silofs_iovref *iovr)
{
	const struct silofs_blobf *blobf = NULL;

	blobf = container_of2(iovr, struct silofs_blobf, b_iovref);
	return blobf_unconst(blobf);
}

static void blobf_iov_pre(struct silofs_iovref *iovr)
{
	struct silofs_blobf *blobf = blobf_from_iovref(iovr);

	silofs_blobf_incref(blobf);
}

static void blobf_iov_post(struct silofs_iovref *iovr)
{
	struct silofs_blobf *blobf = blobf_from_iovref(iovr);

	silofs_blobf_decref(blobf);
}

static int blobf_init(struct silofs_blobf *blobf,
                      const struct silofs_blobid *blobid)
{
	blobid_assign(&blobf->b_blobid, blobid);
	silofs_ce_init(&blobf->b_ce);
	silofs_iovref_init(&blobf->b_iovref, blobf_iov_pre, blobf_iov_post);
	silofs_ckey_by_blobid(&blobf->b_ce.ce_ckey, &blobf->b_blobid);
	blobf->b_size = 0;
	blobf->b_fd = -1;
	blobf->b_flocked = false;
	blobf->b_rdonly = false;
	return silofs_rwlock_init(&blobf->b_rwlock);
}

static void blobf_fini(struct silofs_blobf *blobf)
{
	silofs_rwlock_fini(&blobf->b_rwlock);
	blobid_reset(&blobf->b_blobid);
	silofs_ce_fini(&blobf->b_ce);
	silofs_iovref_fini(&blobf->b_iovref);
	blobf->b_size = -1;
	blobf->b_fd = -1;
}

static void blobf_rdlock(struct silofs_blobf *blobf)
{
	silofs_rwlock_rdlock(&blobf->b_rwlock);
}

static void blobf_wrlock(struct silofs_blobf *blobf)
{
	silofs_rwlock_wrlock(&blobf->b_rwlock);
}

static void blobf_unlock(struct silofs_blobf *blobf)
{
	silofs_rwlock_unlock(&blobf->b_rwlock);
}

static ssize_t blobf_capacity(const struct silofs_blobf *blobf)
{
	return (ssize_t)blobid_size(&blobf->b_blobid);
}

static ssize_t blobf_size(const struct silofs_blobf *blobf)
{
	return silofs_atomic_getl(&blobf->b_size);
}

static void blobf_set_size(struct silofs_blobf *blobf, ssize_t sz)
{
	silofs_atomic_setl(&blobf->b_size, sz);
}

static void blobf_bindto(struct silofs_blobf *blobf, int fd, bool rw)
{
	blobf->b_fd = fd;
	blobf->b_rdonly = !rw;
}

static int blobf_check_range(const struct silofs_blobf *blobf,
                             loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t cap = blobf_capacity(blobf);

	if (off < 0) {
		return -SILOFS_EINVAL;
	}
	if (end > (cap + SILOFS_LBK_SIZE)) {
		return -SILOFS_EBLOB;
	}
	return 0;
}

static int blobf_inspect_size(struct silofs_blobf *blobf)
{
	struct stat st;
	ssize_t cap;
	int err;

	err = do_fstat(blobf->b_fd, &st);
	if (err) {
		return err;
	}
	if (st.st_size % SILOFS_LBK_SIZE) {
		log_warn("blob-size not aligned: blob=%s size=%ld",
		         blobf->b_name.name, st.st_size);
		return -SILOFS_EBLOB;
	}
	cap = blobf_capacity(blobf);
	if (st.st_size > (cap + SILOFS_LBK_SIZE)) {
		log_warn("blob-size mismatch: blob=%s size=%ld cap=%ld",
		         blobf->b_name.name, st.st_size, cap);
		return -SILOFS_EBLOB;
	}
	blobf_set_size(blobf, st.st_size);
	return 0;
}

static int blobf_check_writable(const struct silofs_blobf *blobf)
{
	return blobf->b_rdonly ? -SILOFS_ERDONLY : 0;
}

static int blobf_reassign_size(struct silofs_blobf *blobf, loff_t off)
{
	ssize_t len;
	int err;

	err = blobf_check_range(blobf, off, 0);
	if (err) {
		return err;
	}
	err = blobf_check_writable(blobf);
	if (err) {
		return err;
	}
	len = off_align_to_lbk(off + SILOFS_LBK_SIZE - 1);
	err = do_ftruncate(blobf->b_fd, len);
	if (err) {
		return err;
	}
	blobf_set_size(blobf, len);
	return 0;
}

static int blobf_require_size_ge(struct silofs_blobf *blobf,
                                 loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const ssize_t bsz = blobf_size(blobf);

	return (bsz >= end) ? 0 : blobf_reassign_size(blobf, end);
}

static int blobf_check_size_ge(struct silofs_blobf *blobf,
                               loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const ssize_t bsz = blobf_size(blobf);

	return (bsz >= end) ? 0 : -SILOFS_ERANGE;
}

static void blobf_make_iovec(const struct silofs_blobf *blobf,
                             loff_t off, size_t len, struct silofs_iovec *siov)
{
	siov->iov_off = off;
	siov->iov_len = len;
	siov->iov_base = NULL;
	siov->iov_fd = blobf->b_fd;
	siov->iov_ref = NULL;
}

static void blobf_setup_iovec_ref(struct silofs_blobf *blobf,
                                  struct silofs_iovec *siov)
{
	siov->iov_ref = &blobf->b_iovref;
}

static int blobf_iovec_at(const struct silofs_blobf *blobf,
                          loff_t off, size_t len, struct silofs_iovec *siov)
{
	int err;

	err = blobf_check_range(blobf, off, len);
	if (!err) {
		blobf_make_iovec(blobf, off, len, siov);
	}
	return err;
}

static int blobf_iovec_of(const struct silofs_blobf *blobf,
                          const struct silofs_oaddr *oaddr,
                          struct silofs_iovec *siov)
{
	return blobf_iovec_at(blobf, oaddr->pos, oaddr->len, siov);
}

static int blobf_resolve(struct silofs_blobf *blobf,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_iovec *siov)
{
	int err;

	err = blobf_iovec_of(blobf, oaddr, siov);
	if (err) {
		return err;
	}
	blobf_setup_iovec_ref(blobf, siov);
	return 0;
}

int silofs_blobf_resolve(struct silofs_blobf *blobf,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_iovec *siov)
{
	int ret;

	blobf_rdlock(blobf);
	ret = blobf_resolve(blobf, oaddr, siov);
	blobf_unlock(blobf);
	return ret;
}

static int blobf_store_by(struct silofs_blobf *blobf,
                          const struct silofs_iovec *siov,
                          const void *ptr, size_t len)
{
	int err;

	if (unlikely(blobf->b_fd != siov->iov_fd)) {
		return -SILOFS_EINVAL;
	}
	if (unlikely(len != siov->iov_len)) {
		return -SILOFS_EINVAL;
	}
	err = blobf_require_size_ge(blobf, siov->iov_off, len);
	if (err) {
		return err;
	}
	err = do_pwriten(siov->iov_fd, ptr, len, siov->iov_off);
	if (err) {
		return err;
	}
	return 0;
}

static int blobf_sync_by(const struct silofs_blobf *blobf,
                         const struct silofs_iovec *siov)
{
	unsigned int flags;
	int err;

	if (unlikely(blobf->b_fd != siov->iov_fd)) {
		return -SILOFS_EINVAL;
	}
	flags = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE |
	        SYNC_FILE_RANGE_WAIT_AFTER;
	err = do_sync_file_range(blobf->b_fd, siov->iov_off,
	                         (loff_t)siov->iov_len, flags);
	if (err && (err != -ENOSYS)) {
		return err;
	}
	return 0;
}

static int blobf_pwriten(struct silofs_blobf *blobf, loff_t off,
                         const void *buf, size_t len, bool sync)
{
	struct silofs_iovec siov = { .iov_off = -1 };
	int err;

	err = blobf_require_size_ge(blobf, off, len);
	if (err) {
		return err;
	}
	err = blobf_iovec_at(blobf, off, len, &siov);
	if (err) {
		return err;
	}
	err = blobf_store_by(blobf, &siov, buf, len);
	if (err) {
		return err;
	}
	if (sync) {
		err = blobf_sync_by(blobf, &siov);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_blobf_pwriten(struct silofs_blobf *blobf, loff_t off,
                         const void *buf, size_t len, bool sync)
{
	int ret;

	blobf_wrlock(blobf);
	ret = blobf_pwriten(blobf, off, buf, len, sync);
	blobf_unlock(blobf);
	return ret;
}

static int blobf_read_blob(const struct silofs_blobf *blobf,
                           void *buf, size_t len)
{
	uint8_t *dat;
	size_t bsz;
	size_t rem;
	size_t cnt;
	int err;

	err = blobf_check_range(blobf, 0, len);
	if (err) {
		return err;
	}
	bsz = (size_t)blobf_size(blobf);
	cnt = min(len, bsz);
	dat = buf;
	err = do_preadn(blobf->b_fd, dat, cnt, 0);
	if (err) {
		return err;
	}
	dat += cnt;
	rem = (len > bsz) ? (len - bsz) : 0;
	silofs_memzero(dat, rem);
	return 0;
}

int silofs_blobf_read_blob(struct silofs_blobf *blobf, void *buf, size_t len)
{
	int ret;

	blobf_rdlock(blobf);
	ret = blobf_read_blob(blobf, buf, len);
	blobf_unlock(blobf);
	return ret;
}

static int blobf_load_bb(const struct silofs_blobf *blobf,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_bytebuf *bb)
{
	struct silofs_iovec siov = { .iov_off = -1 };
	struct stat st;
	loff_t end;
	void *bobj;
	int err;

	err = blobf_iovec_of(blobf, oaddr, &siov);
	if (err) {
		return err;
	}
	if (!silofs_bytebuf_has_free(bb, !siov.iov_len)) {
		return -SILOFS_EINVAL;
	}
	err = do_fstat(siov.iov_fd, &st);
	if (err) {
		return err;
	}
	silofs_assert_eq(st.st_size % SILOFS_KB_SIZE, 0);

	bobj = silofs_bytebuf_end(bb);
	end = off_end(siov.iov_off, siov.iov_len);
	if (end > st.st_size) {
		memset(bobj, 0, siov.iov_len);
		goto out;
	}
	err = do_preadn(siov.iov_fd, bobj, siov.iov_len, siov.iov_off);
	if (err) {
		return err;
	}
out:
	bb->len += siov.iov_len;
	return 0;
}

static int blobf_load_bk(const struct silofs_blobf *blobf,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_lblock *lbk)
{
	struct silofs_oaddr oaddr;
	struct silofs_bytebuf bb;

	silofs_bytebuf_init(&bb, lbk, sizeof(*lbk));
	silofs_oaddr_of_bk(&oaddr, &bkaddr->blobid, bkaddr->lba);
	return blobf_load_bb(blobf, &oaddr, &bb);
}

static int blobf_require_bk_of(struct silofs_blobf *blobf,
                               const struct silofs_bkaddr *bkaddr)
{
	struct silofs_oaddr oaddr;

	silofs_oaddr_of_bk(&oaddr, &bkaddr->blobid, bkaddr->lba);
	return blobf_require_size_ge(blobf, oaddr.pos, oaddr.len);
}

static int blobf_check_bk_of(struct silofs_blobf *blobf,
                             const struct silofs_bkaddr *bkaddr)
{
	struct silofs_oaddr oaddr;

	silofs_oaddr_of_bk(&oaddr, &bkaddr->blobid, bkaddr->lba);
	return blobf_check_size_ge(blobf, oaddr.pos, oaddr.len);
}

static int blobf_load_bk_at(struct silofs_blobf *blobf,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_lbk_info *lbki)
{
	int err;

	err = blobf_check_bk_of(blobf, bkaddr);
	/* XXX HACK FIXME */
	if (err == -SILOFS_ERANGE) {
		err = blobf_require_bk_of(blobf, bkaddr);
	}
	if (err) {
		return err;
	}
	err = blobf_load_bk(blobf, bkaddr, lbki->lbk);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_blobf_load_bk(struct silofs_blobf *blobf,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_lbk_info *lbki)
{
	int ret;

	blobf_rdlock(blobf);
	ret = blobf_load_bk_at(blobf, bkaddr, lbki);
	blobf_unlock(blobf);
	return ret;
}

static int blobf_trim_by_ftruncate(const struct silofs_blobf *blobf)
{
	int err;

	err = do_ftruncate(blobf->b_fd, 0);
	if (err) {
		return err;
	}
	err = do_ftruncate(blobf->b_fd, blobf_size(blobf));
	if (err) {
		return err;
	}
	return 0;
}

static int blobf_trim_by_punch(const struct silofs_blobf *blobf,
                               loff_t from, loff_t to)
{
	return do_fallocate_punch_hole(blobf->b_fd, from, off_len(from, to));
}

static int blobf_trim_nbks(const struct silofs_blobf *blobf,
                           const struct silofs_bkaddr *bkaddr, size_t cnt)
{
	struct silofs_oaddr bk_oaddr;
	silofs_lba_t beg_lba;
	silofs_lba_t end_lba;
	loff_t beg;
	loff_t end;
	ssize_t cap;
	int err;

	silofs_oaddr_of_bk(&bk_oaddr, &bkaddr->blobid, bkaddr->lba);
	beg_lba = off_to_lba(bk_oaddr.pos);
	end_lba = lba_plus(beg_lba, cnt);
	beg = lba_to_off(beg_lba);
	end = lba_to_off(end_lba);
	cap = blobf_capacity(blobf);
	if ((beg == 0) && (off_len(beg, end) == cap)) {
		err = blobf_trim_by_ftruncate(blobf);
	} else {
		err = blobf_trim_by_punch(blobf, beg, end);
	}
	return err;
}

int silofs_blobf_trim_nbks(struct silofs_blobf *blobf,
                           const struct silofs_bkaddr *bkaddr, size_t cnt)
{
	int ret;

	blobf_wrlock(blobf);
	ret = blobf_trim_nbks(blobf, bkaddr, cnt);
	blobf_unlock(blobf);
	return ret;
}

int silofs_blobf_require_bk(struct silofs_blobf *blobf,
                            const struct silofs_bkaddr *bkaddr)
{
	int ret;

	blobf_wrlock(blobf);
	ret = blobf_require_bk_of(blobf, bkaddr);
	blobf_unlock(blobf);
	return ret;
}

int silofs_blobf_check_bk(struct silofs_blobf *blobf,
                          const struct silofs_bkaddr *bkaddr)
{
	int ret;

	blobf_wrlock(blobf);
	ret = blobf_check_bk_of(blobf, bkaddr);
	blobf_unlock(blobf);
	return ret;
}

int silofs_blobf_flock(struct silofs_blobf *blobf)
{
	int err = 0;

	blobf_wrlock(blobf);
	if (!blobf->b_flocked) {
		err = do_flock(blobf->b_fd, LOCK_EX | LOCK_NB);
		blobf->b_flocked = (err == 0);
	}
	blobf_unlock(blobf);
	return err;
}

int silofs_blobf_funlock(struct silofs_blobf *blobf)
{
	int err = 0;

	blobf_wrlock(blobf);
	if (blobf->b_flocked) {
		err = do_flock(blobf->b_fd, LOCK_UN);
		blobf->b_flocked = !(err == 0);
	}
	blobf_unlock(blobf);
	return err;
}

static int blobf_close(struct silofs_blobf *blobf)
{
	silofs_blobf_funlock(blobf);
	return do_closefd(&blobf->b_fd);
}

struct silofs_blobf *
silofs_blobf_new(struct silofs_alloc *alloc,
                 const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf;
	int err;

	blobf = silofs_allocate(alloc, sizeof(*blobf));
	if (blobf == NULL) {
		return NULL;
	}
	err = blobf_init(blobf, blobid);
	if (err) {
		silofs_deallocate(alloc, blobf, sizeof(*blobf));
		return NULL;
	}
	return blobf;
}

void silofs_blobf_del(struct silofs_blobf *blobf,
                      struct silofs_alloc *alloc)
{
	blobf_close(blobf);
	blobf_fini(blobf);
	silofs_deallocate(alloc, blobf, sizeof(*blobf));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_cache *repo_cache(const struct silofs_repo *repo)
{
	return repo->re.cache;
}

static int repo_lookup_cached_blobf(struct silofs_repo *repo,
                                    const struct silofs_blobid *blobid,
                                    struct silofs_blobf **out_blobf)
{
	*out_blobf = silofs_cache_lookup_blob(repo_cache(repo), blobid);
	return (*out_blobf == NULL) ? -SILOFS_ENOENT : 0;
}

static int repo_spawn_cached_blobf(struct silofs_repo *repo,
                                   const struct silofs_blobid *blobid,
                                   struct silofs_blobf **out_blobf)
{
	*out_blobf = silofs_cache_spawn_blob(repo_cache(repo), blobid);
	return (*out_blobf == NULL) ? -SILOFS_ENOMEM : 0;
}

static void repo_forget_cached_blobf(struct silofs_repo *repo,
                                     struct silofs_blobf *blobf)
{
	silofs_cache_evict_blob(repo_cache(repo), blobf, true);
}

static void repo_try_evict_cached_blobf(struct silofs_repo *repo,
                                        struct silofs_blobf *blobf)
{
	silofs_cache_evict_blob(repo_cache(repo), blobf, false);
}

static int repo_objs_relax_cached_blobfs(struct silofs_repo *repo)
{
	silofs_cache_relax_blobs(repo_cache(repo));
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_blobs_dfd(const struct silofs_repo *repo)
{
	return repo->re_blobs_dfd;
}

static int repo_objs_format_sub(const struct silofs_repo *repo, size_t idx)
{
	struct silofs_namebuf nb;
	struct stat st;
	int dfd;
	int err;

	index_to_namebuf(idx, &nb);
	dfd = repo_blobs_dfd(repo);
	err = do_fstatat(dfd, nb.name, &st, 0);
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_err("exists but not dir: %s", nb.name);
			return -SILOFS_ENOTDIR;
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

	for (size_t i = 0; i < repo_defs.re_objs_nsubs; ++i) {
		err = repo_objs_format_sub(repo, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static const struct silofs_mdigest *
repo_mdigest(const struct silofs_repo *repo)
{
	return &repo->re_mdigest;
}

static void repo_hash_blobid(const struct silofs_repo *repo,
                             const struct silofs_blobid *blobid,
                             struct silofs_hash256 *out_hash)
{
	struct silofs_blobid40b blobid40;
	const struct silofs_mdigest *md = repo_mdigest(repo);

	silofs_blobid40b_set(&blobid40, blobid);
	silofs_sha256_of(md, &blobid40, sizeof(blobid40), out_hash);
}

static int repo_objs_sub_pathname_of(const struct silofs_repo *repo,
                                     const struct silofs_blobid *blobid,
                                     struct silofs_namebuf *out_nb)
{
	struct silofs_hash256 hash;
	size_t idx;

	idx = blobid_to_index(blobid, repo_defs.re_objs_nsubs);
	repo_hash_blobid(repo, blobid, &hash);

	return make_pathname(&hash, idx, out_nb);
}

static int repo_objs_setup_pathname_of(const struct silofs_repo *repo,
                                       struct silofs_blobf *blobf)
{
	return repo_objs_sub_pathname_of(repo, &blobf->b_blobid,
	                                 &blobf->b_name);
}

static int repo_objs_require_noblob(const struct silofs_repo *repo,
                                    const struct silofs_namebuf *nb)
{
	struct stat st = { .st_size = 0 };
	const int dfd = repo_blobs_dfd(repo);
	int err;

	err = do_fstatat(dfd, nb->name, &st, 0);
	if (err == 0) {
		log_err("blob already exists: name=%s", nb->name);
		return -SILOFS_EEXIST;
	}
	if (err != -ENOENT) {
		log_err("blob stat error: name=%s err=%d", nb->name, err);
		return err;
	}
	return 0;
}

static int repo_objs_create_blob_of(const struct silofs_repo *repo,
                                    struct silofs_blobf *blobf)
{
	const int dfd = repo_blobs_dfd(repo);
	const int o_flags = O_CREAT | O_RDWR | O_TRUNC;
	int fd = -1;
	int err;

	err = do_openat(dfd, blobf->b_name.name, o_flags, 0600, &fd);
	if (err) {
		return err;
	}
	blobf_bindto(blobf, fd, true);
	err = blobf_reassign_size(blobf, blobf_capacity(blobf));
	if (err) {
		do_unlinkat(dfd, blobf->b_name.name, 0);
		return err;
	}
	return 0;
}

static int repo_objs_open_blob_of(const struct silofs_repo *repo,
                                  struct silofs_blobf *blobf, bool rw)
{
	const int o_flags = rw ? O_RDWR : O_RDONLY;
	const int dfd = repo_blobs_dfd(repo);
	int fd = -1;
	int err;

	silofs_assert_lt(blobf->b_fd, 0);

	err = do_openat(dfd, blobf->b_name.name, o_flags, 0600, &fd);
	if (err) {
		/*
		 * TODO-0032: Consider using SILOFS_EFSCORRUPTED
		 *
		 * When higher layer wants to open a blob, it should exist.
		 */
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	blobf_bindto(blobf, fd, rw);
	err = blobf_inspect_size(blobf);
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
	int dfd;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	dfd = repo_blobs_dfd(repo);
	err = do_fstatat(dfd, nb.name, &st, 0);
	if (err) {
		log_dbg("can not unlink blob: %s err=%d", nb.name, err);
		return err;
	}
	err = do_unlinkat(dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_objs_open_blob(struct silofs_repo *repo, bool rw,
                               const struct silofs_blobid *blobid,
                               struct silofs_blobf **out_blobf)
{
	struct silofs_blobf *blobf = NULL;
	int err;

	err = repo_spawn_cached_blobf(repo, blobid, &blobf);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, blobf);
	if (err) {
		goto out_err;
	}
	err = repo_objs_open_blob_of(repo, blobf, rw);
	if (err) {
		goto out_err;
	}
	*out_blobf = blobf;
	return 0;
out_err:
	repo_forget_cached_blobf(repo, blobf);
	return err;
}

static int repo_objs_stat_blob(const struct silofs_repo *repo,
                               const struct silofs_blobid *blobid,
                               struct stat *out_st)
{
	struct silofs_namebuf nb;
	size_t len = 0;
	int dfd = -1;
	int err;

	err = repo_objs_sub_pathname_of(repo, blobid, &nb);
	if (err) {
		return err;
	}
	dfd = repo_blobs_dfd(repo);
	err = do_fstatat(dfd, nb.name, out_st, 0);
	if (err) {
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	len = blobid_size(blobid);
	if (out_st->st_size > (loff_t)(len + SILOFS_LBK_SIZE)) {
		log_warn("blob-size mismatch: %s len=%lu st_size=%ld",
		         nb.name, len, out_st->st_size);
		return -SILOFS_EIO;
	}
	return 0;
}

static int repo_objs_create_blob(struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blobf **out_blobf)
{
	struct silofs_blobf *blobf = NULL;
	int err;

	err = repo_spawn_cached_blobf(repo, blobid, &blobf);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, blobf);
	if (err) {
		goto out_err;
	}
	err = repo_objs_require_noblob(repo, &blobf->b_name);
	if (err) {
		goto out_err;
	}
	err = repo_objs_create_blob_of(repo, blobf);
	if (err) {
		goto out_err;
	}
	*out_blobf = blobf;
	return 0;
out_err:
	repo_forget_cached_blobf(repo, blobf);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_check_open(const struct silofs_repo *repo)
{
	return likely(repo->re_root_dfd > 0) ? 0 : -SILOFS_EBADF;
}

static int repo_check_writable(const struct silofs_repo *repo)
{
	const struct silofs_bootpath *bootpath;

	if (repo->re.flags & SILOFS_REPOF_RDONLY) {
		bootpath = &repo->re.bootpath;
		log_dbg("read-only repo: %s", bootpath->repodir.str);
		return -SILOFS_EPERM;
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

static int repo_stat_blob(struct silofs_repo *repo,
                          const struct silofs_blobid *blobid, struct stat *st)
{
	int err;

	err = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_objs_stat_blob(repo, blobid, st);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_lookup_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct stat st;
	struct silofs_blobf *blobf = NULL;
	int err;

	err = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_blobf(repo, blobid, &blobf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_stat_blob(repo, blobid, &st);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_spawn_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobf **out_blobf)
{
	int err;

	err = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_blobf(repo, blobid, out_blobf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_create_blob(repo, blobid, out_blobf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_stage_blob(struct silofs_repo *repo, bool rw,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobf **out_blobf)
{
	int err;

	err  = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_blobf(repo, blobid, out_blobf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_blob(repo, rw, blobid, out_blobf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_remove_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf = NULL;
	int err;

	err = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
	err = repo_objs_unlink_blob(repo, blobid);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_blobf(repo, blobid, &blobf);
	if (!err) {
		repo_try_evict_cached_blobf(repo, blobf);
	}
	return 0;
}

static int repo_require_blob(struct silofs_repo *repo, bool rw,
                             const struct silofs_blobid *blobid,
                             struct silofs_blobf **out_blobf)
{
	int err;

	err = repo_lookup_blob(repo, blobid);
	if (!err) {
		err = repo_stage_blob(repo, rw, blobid, out_blobf);
	} else if ((err == -ENOENT) && rw) {
		err = repo_spawn_blob(repo, blobid, out_blobf);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_drop_cache(struct silofs_repo *repo)
{
	silofs_cache_drop(repo_cache(repo));
}

static int repo_init_mdigest(struct silofs_repo *repo)
{
	return silofs_mdigest_init(&repo->re_mdigest);
}

static void repo_fini_mdigest(struct silofs_repo *repo)
{
	silofs_mdigest_fini(&repo->re_mdigest);
}

int silofs_repo_init(struct silofs_repo *repo,
                     const struct silofs_repo_base *re_base)
{
	memcpy(&repo->re, re_base, sizeof(repo->re));
	repo->re_root_dfd = -1;
	repo->re_dots_dfd = -1;
	repo->re_blobs_dfd = -1;
	return repo_init_mdigest(repo);
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	repo_close(repo);
	repo_drop_cache(repo);
	repo_fini_mdigest(repo);
}

static void repo_pre_op(struct silofs_repo *repo)
{
	repo_objs_relax_cached_blobfs(repo);
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
		log_warn("repo mkdirat failed: name=%s mode=%o err=%d",
		         name, mode, err);
		return err;
	}
	err = do_fstatat(dfd, name, &st, 0);
	if (err) {
		return err;
	}
	if ((st.st_mode & S_IRWXU) != S_IRWXU) {
		log_warn("bad access: %s mode=0%o", name, st.st_mode);
		return -SILOFS_EACCES;
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
	loff_t size;
	int err;

	name = repo_defs.re_blobs_name;
	err = repo_create_skel_subdir(repo, name, 0700);
	if (err) {
		return err;
	}
	name = repo_defs.re_meta_name;
	size = SILOFS_REPO_METADATA_SIZE;
	err = repo_create_skel_subfile(repo, name, 0600, size);
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
		return -SILOFS_ENOTDIR;
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
		return S_ISDIR(st.st_mode) ? -SILOFS_EISDIR : -SILOFS_EINVAL;
	}
	if (st.st_size < min_size) {
		log_warn("illegal size: %s %ld", name, st.st_size);
		return -SILOFS_EBADREPO;
	}
	return 0;
}

static int repo_require_skel(const struct silofs_repo *repo)
{
	const struct silofs_bootpath *bootpath = &repo->re.bootpath;
	const char *name;
	loff_t size;
	int err;

	err = do_access(bootpath->repodir.str, R_OK | W_OK | X_OK);
	if (err) {
		return err;
	}
	name = repo_defs.re_meta_name;
	size = SILOFS_REPO_METADATA_SIZE;
	err = repo_require_skel_subfile(repo, name, size);
	if (err) {
		return err;
	}
	name = repo_defs.re_blobs_name;
	err = repo_require_skel_subdir(repo, name);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_open_rootdir(struct silofs_repo *repo)
{
	const struct silofs_bootpath *bootpath = &repo->re.bootpath;
	int err;

	if (repo->re_root_dfd > 0) {
		return -SILOFS_EALREADY;
	}
	err = do_opendir(bootpath->repodir.str, &repo->re_root_dfd);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_create_dotsdir(const struct silofs_repo *repo)
{
	const char *name = repo_defs.re_dots_name;
	int err;

	err = do_mkdirat(repo->re_root_dfd, name, 0700);
	if (err && (err != -EEXIST)) {
		return err;
	}
	return 0;
}

static int repo_open_dotsdir(struct silofs_repo *repo)
{
	const char *name = repo_defs.re_dots_name;

	return do_opendirat(repo->re_root_dfd, name, &repo->re_dots_dfd);
}

static int repo_format_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name = repo_defs.re_meta_name;
	const int dfd = repo->re_dots_dfd;
	int fd = -1;
	int err;

	rmeta_init(&rmeta);
	err = do_openat(dfd, name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	err = do_pwriten(fd, &rmeta, sizeof(rmeta), 0);
	if (err) {
		goto out;
	}
	err = do_fdatasync(fd);
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
	const char *name = repo_defs.re_meta_name;
	const int dfd = repo->re_dots_dfd;
	int fd = -1;
	int err;

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

static int repo_open_blobs_dir(struct silofs_repo *repo)
{
	return do_opendirat(repo->re_dots_dfd, repo_defs.re_blobs_name,
	                    &repo->re_blobs_dfd);
}

static int repo_format_blobs_subs(struct silofs_repo *repo)
{
	return repo_objs_format(repo);
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
	err = repo_open_blobs_dir(repo);
	if (err) {
		return err;
	}
	err = repo_format_blobs_subs(repo);
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
	err = repo_require_meta(repo);
	if (err) {
		return err;
	}
	err = repo_open_blobs_dir(repo);
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
	return do_closefd(&repo->re_root_dfd);
}

static int repo_close_blobs_dir(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_blobs_dfd);
}

static int repo_close(struct silofs_repo *repo)
{
	int err;

	err = repo_close_blobs_dir(repo);
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
	return 0;
}

int silofs_repo_close(struct silofs_repo *repo)
{
	int err;

	if (repo->re_root_dfd < 0) {
		return 0;
	}
	err = repo_close(repo);
	if (err) {
		return err;
	}
	repo_drop_cache(repo);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int repo_lookup_cached_ubki(struct silofs_repo *repo,
                                   const struct silofs_bkaddr *bkaddr,
                                   struct silofs_ubk_info **out_ubki)
{
	*out_ubki = silofs_cache_lookup_ubk(repo_cache(repo), bkaddr);
	return (*out_ubki == NULL) ? -SILOFS_ENOENT : 0;
}

static void repo_forget_cached_ubki(struct silofs_repo *repo,
                                    struct silofs_ubk_info *ubki)
{
	silofs_cache_forget_ubk(repo_cache(repo), ubki);
}

static int repo_spawn_cached_ubki(struct silofs_repo *repo,
                                  const struct silofs_bkaddr *bkaddr,
                                  struct silofs_ubk_info **out_ubki)
{
	*out_ubki = silofs_cache_spawn_ubk(repo_cache(repo), bkaddr);
	return (*out_ubki == NULL) ? -SILOFS_ENOMEM : 0;
}

static int repo_spawn_attach_ubki(struct silofs_repo *repo,
                                  struct silofs_blobf *blobf,
                                  const struct silofs_bkaddr *bkaddr,
                                  struct silofs_ubk_info **out_ubki)
{
	int err;

	blobf_incref(blobf);
	err = repo_spawn_cached_ubki(repo, bkaddr, out_ubki);
	if (!err) {
		silofs_ubki_attach(*out_ubki, blobf);
	}
	blobf_decref(blobf);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_spawn_ubk_at(struct silofs_repo *repo, bool rw,
                             const struct silofs_bkaddr *bkaddr,
                             struct silofs_ubk_info **out_ubki)
{
	struct silofs_blobf *blobf = NULL;
	int err;

	err = repo_lookup_cached_ubki(repo, bkaddr, out_ubki);
	if (!err) {
		return -SILOFS_EEXIST;
	}
	err = repo_require_blob(repo, rw, &bkaddr->blobid, &blobf);
	if (err) {
		return err;
	}
	err = blobf_require_bk_of(blobf, bkaddr);
	if (err) {
		return err;
	}
	err = repo_spawn_attach_ubki(repo, blobf, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_spawn_ubk(struct silofs_repo *repo, bool rw,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki)
{
	int err;

	err = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
	err = repo_spawn_ubk_at(repo, rw, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_stage_ubk_at(struct silofs_repo *repo, bool rw,
                             const struct silofs_bkaddr *bkaddr,
                             struct silofs_ubk_info **out_ubki)
{
	struct silofs_blobf *blobf = NULL;
	struct silofs_ubk_info *ubki = NULL;
	int err;

	err = repo_lookup_cached_ubki(repo, bkaddr, out_ubki);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_stage_blob(repo, rw, &bkaddr->blobid, &blobf);
	if (err) {
		return err;
	}
	err = repo_spawn_attach_ubki(repo, blobf, bkaddr, &ubki);
	if (err) {
		return err;
	}
	err = silofs_blobf_load_bk(blobf, bkaddr, &ubki->ubk);
	if (err) {
		repo_forget_cached_ubki(repo, ubki);
		return err;
	}
	*out_ubki = ubki;
	return 0;
}

static int repo_stage_ubk(struct silofs_repo *repo, bool rw,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki)
{
	int err;

	err = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_stage_ubk_at(repo, rw, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_require_ubk(struct silofs_repo *repo, bool rw,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_ubk_info **out_ubki)
{
	int err;

	err = repo_lookup_cached_ubki(repo, bkaddr, out_ubki);
	if (!err) {
		return 0;
	}
	err = repo_lookup_blob(repo, &bkaddr->blobid);
	if (!err) {
		err = repo_stage_ubk(repo, rw, bkaddr, out_ubki);
	} else if (err == -SILOFS_ENOENT) {
		err = repo_spawn_ubk(repo, rw, bkaddr, out_ubki);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void repo_bootsec_name(const struct silofs_repo *repo,
                              const struct silofs_uuid *uuid,
                              struct silofs_namebuf *out_nb)
{
	silofs_uuid_name(uuid, out_nb);
	unused(repo);
}

static int repo_encode_bsec1k(const struct silofs_repo *repo,
                              const struct silofs_bootsec *bsec,
                              struct silofs_bootsec1k *bsc)
{
	/* TODO: verify input bsec */
	silofs_bsec1k_set(bsc, bsec);
	silofs_bsec1k_stamp(bsc, repo_mdigest(repo));
	return 0;
}

static int repo_verify_bsec1k(const struct silofs_repo *repo,
                              const struct silofs_bootsec1k *bsc)
{
	return silofs_bsec1k_verify(bsc, repo_mdigest(repo));
}

static int repo_decode_bsec1k(const struct silofs_repo *repo,
                              const struct silofs_bootsec1k *bsc,
                              struct silofs_bootsec *out_bsec)
{
	int err;

	err = repo_verify_bsec1k(repo, bsc);
	if (err) {
		return err;
	}
	silofs_bsec1k_parse(bsc, out_bsec);
	return 0;
}

static int
repo_save_bootsec1k(const struct silofs_repo *repo,
                    const struct silofs_namebuf *nb,
                    const struct silofs_bootsec1k *bsc)
{
	int dfd = -1;
	int fd = -1;
	int o_flags;
	int err;

	dfd = repo_blobs_dfd(repo);
	err = do_fchmodat(dfd, nb->name, 0600, 0);
	if (!err) {
		o_flags = O_RDWR;
	} else if (err == -ENOENT) {
		o_flags = O_RDWR | O_CREAT;
	} else {
		goto out;
	}
	err = do_openat(dfd, nb->name, o_flags, 0600, &fd);
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
	err = do_fdatasync(fd);
	if (err) {
		goto out;
	}
out:
	do_closefd(&fd);
	return err;
}

static int repo_save_bootsec(const struct silofs_repo *repo,
                             const struct silofs_uuid *uuid,
                             const struct silofs_bootsec *bsec)
{
	struct silofs_bootsec1k bsc;
	struct silofs_namebuf nb;
	int err;

	err = repo_encode_bsec1k(repo, bsec, &bsc);
	if (err) {
		return err;
	}
	repo_bootsec_name(repo, uuid, &nb);
	err = repo_save_bootsec1k(repo, &nb, &bsc);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_load_bootsec1k(const struct silofs_repo *repo,
                               const struct silofs_namebuf *nb,
                               struct silofs_bootsec1k *bsc)
{
	int dfd = -1;
	int fd = -1;
	int err;

	dfd = repo_blobs_dfd(repo);
	err = do_openat(dfd, nb->name, O_RDONLY, 0, &fd);
	if (err) {
		goto out;
	}
	err = do_preadn(fd, bsc, sizeof(*bsc), 0);
	if (err) {
		goto out;
	}
out:
	do_closefd(&fd);
	return (err == -ENOENT) ? -SILOFS_ENOBOOT : err;
}

static int repo_load_bootsec(const struct silofs_repo *repo,
                             const struct silofs_uuid *uuid,
                             struct silofs_bootsec *out_bsec)
{
	struct silofs_bootsec1k bsc;
	struct silofs_namebuf nb;
	int err;

	repo_bootsec_name(repo, uuid, &nb);
	err = repo_load_bootsec1k(repo, &nb, &bsc);
	if (err) {
		return err;
	}
	err = repo_decode_bsec1k(repo, &bsc, out_bsec);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_stat_bootsec1k(const struct silofs_repo *repo,
                               const struct silofs_namebuf *nb,
                               struct stat *out_st)
{
	mode_t mode;
	int dfd;
	int err;

	dfd = repo_blobs_dfd(repo);
	err = do_fstatat(dfd, nb->name, out_st, AT_SYMLINK_NOFOLLOW);
	if (err) {
		return err;
	}
	mode = out_st->st_mode;
	if (S_ISDIR(mode)) {
		return -SILOFS_EISDIR;
	}
	if (!S_ISREG(mode)) {
		return -SILOFS_ENOENT   ;
	}
	return 0;
}

static int repo_stat_bootsec(const struct silofs_repo *repo,
                             const struct silofs_uuid *uuid)
{
	struct stat st;
	struct silofs_namebuf nb;
	int err;

	repo_bootsec_name(repo, uuid, &nb);
	err = repo_stat_bootsec1k(repo, &nb, &st);
	if (err) {
		return err;
	}
	if (st.st_size != sizeof(struct silofs_bootsec1k)) {
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

static int repo_unlink_bootsec(const struct silofs_repo *repo,
                               const struct silofs_uuid *uuid)
{
	struct silofs_namebuf nb;
	int dfd;
	int err;

	repo_bootsec_name(repo, uuid, &nb);
	dfd = repo_blobs_dfd(repo);
	err = do_unlinkat(dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_save_bootsec(struct silofs_repo *repo,
                             const struct silofs_uuid *uuid,
                             const struct silofs_bootsec *bsec)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_save_bootsec(repo, uuid, bsec);
	return ret;
}

int silofs_repo_load_bootsec(struct silofs_repo *repo,
                             const struct silofs_uuid *uuid,
                             struct silofs_bootsec *out_bsec)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_load_bootsec(repo, uuid, out_bsec);
	return ret;
}

int silofs_repo_stat_bootsec(struct silofs_repo *repo,
                             const struct silofs_uuid *uuid)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_stat_bootsec(repo, uuid);
	return ret;
}

int silofs_repo_unlink_bootsec(struct silofs_repo *repo,
                               const struct silofs_uuid *uuid)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_unlink_bootsec(repo, uuid);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stat_blob(struct silofs_repo *repo,
                          const struct silofs_blobid *blobid,
                          struct stat *out_st)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_stat_blob(repo, blobid, out_st);
	return ret;
}

int silofs_repo_lookup_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_lookup_blob(repo, blobid);
	return ret;
}

int silofs_repo_spawn_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobf **out_blobf)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_spawn_blob(repo, blobid, out_blobf);
	return ret;
}

int silofs_repo_stage_blob(struct silofs_repo *repo, bool rw,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobf **out_blobf)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_stage_blob(repo, rw, blobid, out_blobf);
	return ret;
}

int silofs_repo_remove_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_remove_blob(repo, blobid);
	return ret;
}

int silofs_repo_require_blob(struct silofs_repo *repo,
                             const struct silofs_blobid *blobid,
                             struct silofs_blobf **out_blobf)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_require_blob(repo, true, blobid, out_blobf);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stage_ubk(struct silofs_repo *repo, bool rw,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_stage_ubk(repo, rw, bkaddr, out_ubki);
	return ret;
}

int silofs_repo_spawn_ubk(struct silofs_repo *repo, bool rw,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_spawn_ubk(repo, rw, bkaddr, out_ubki);
	return ret;
}

int silofs_repo_require_ubk(struct silofs_repo *repo,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_ubk_info **out_ubki)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_require_ubk(repo, true, bkaddr, out_ubki);
	return ret;
}
