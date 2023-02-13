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
	.re_dots_name   = SILOFS_REPO_DOTSDIR_NAME,
	.re_meta_name   = SILOFS_REPO_METAFILE_NAME,
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

static enum silofs_repo_mode rmeta_mode(const struct silofs_repo_meta *rm)
{
	const uint32_t mode = silofs_le32_to_cpu(rm->rm_mode);

	return (enum silofs_repo_mode)mode;
}

static void rmeta_set_mode(struct silofs_repo_meta *rm,
                           enum silofs_repo_mode repo_mode)
{
	rm->rm_mode = silofs_cpu_to_le32((uint32_t)repo_mode);
}

static void rmeta_init(struct silofs_repo_meta *rm,
                       enum silofs_repo_mode repo_mode)
{
	silofs_memzero(rm, sizeof(*rm));
	rmeta_set_magic(rm, SILOFS_REPO_META_MAGIC);
	rmeta_set_version(rm, SILOFS_REPO_VERSION);
	rmeta_set_mode(rm, repo_mode);
}

static int rmeta_check(const struct silofs_repo_meta *rm)
{
	uint64_t magic;
	uint32_t version;
	enum silofs_repo_mode repo_mode;

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
	repo_mode = rmeta_mode(rm);
	switch (repo_mode) {
	case SILOFS_REPO_LOCAL:
	case SILOFS_REPO_ATTIC:
		break;
	case SILOFS_REPO_NONE:
	default:
		log_dbg("bad repo meta: repo_mode=%d", (int)repo_mode);
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
		silofs_assert_ne(err, -EBADF);
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
		silofs_assert_ne(err, -EBADF);
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
		silofs_assert_gt(fd, 0);
		silofs_assert_ne(err, -EBADF);
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
		return -EINVAL;
	}
	nbuf[len++] = '/';
	nlim = nmax - len - 1;
	nlen = silofs_hash256_to_name(hash, nbuf + len, nlim);
	if (nlen >= nlim) {
		return -EINVAL;
	}
	len += nlen;
	nbuf[len] = '\0';
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blobref_info *
bri_unconst(const struct silofs_blobref_info *bri)
{
	union {
		const struct silofs_blobref_info *p;
		struct silofs_blobref_info *q;
	} u = {
		.p = bri
	};
	return u.q;
}

static struct silofs_blobref_info *
bri_from_iovref(const struct silofs_iovref *iovr)
{
	const struct silofs_blobref_info *bri = NULL;

	bri = container_of2(iovr, struct silofs_blobref_info, br_ior);
	return bri_unconst(bri);
}

static void bri_iov_pre(struct silofs_iovref *iovr)
{
	struct silofs_blobref_info *bri = bri_from_iovref(iovr);

	silofs_bri_incref(bri);
}

static void bri_iov_post(struct silofs_iovref *iovr)
{
	struct silofs_blobref_info *bri = bri_from_iovref(iovr);

	silofs_bri_decref(bri);
}

static void bri_init(struct silofs_blobref_info *bri,
                     const struct silofs_blobid *blobid)
{
	blobid_assign(&bri->br_blobid, blobid);
	silofs_ce_init(&bri->br_ce);
	silofs_iovref_init(&bri->br_ior, bri_iov_pre, bri_iov_post);
	silofs_ckey_by_blobid(&bri->br_ce.ce_ckey, &bri->br_blobid);
	bri->br_size = 0;
	bri->br_fd = -1;
	bri->br_locked = false;
	bri->br_rdonly = false;
}

static void bri_fini(struct silofs_blobref_info *bri)
{
	blobid_reset(&bri->br_blobid);
	silofs_ce_fini(&bri->br_ce);
	silofs_iovref_fini(&bri->br_ior);
	bri->br_size = -1;
	bri->br_fd = -1;
}

static ssize_t bri_capacity(const struct silofs_blobref_info *bri)
{
	return (ssize_t)blobid_size(&bri->br_blobid);
}

static void bri_bindto(struct silofs_blobref_info *bri, int fd, bool rw)
{
	bri->br_fd = fd;
	bri->br_rdonly = !rw;
}

static int bri_check_range(const struct silofs_blobref_info *bri,
                           loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t cap = bri_capacity(bri);

	if (off < 0) {
		return -EINVAL;
	}
	if (end > (cap + SILOFS_BK_SIZE)) {
		return -SILOFS_EBLOB;
	}
	return 0;
}

static int bri_inspect_size(struct silofs_blobref_info *bri)
{
	struct stat st;
	ssize_t cap;
	int err;

	err = do_fstat(bri->br_fd, &st);
	if (err) {
		return err;
	}
	if (st.st_size % SILOFS_BK_SIZE) {
		log_warn("blob-size not aligned: blob=%s size=%ld",
		         bri->br_nb.name, st.st_size);
		return -SILOFS_EBLOB;
	}
	cap = bri_capacity(bri);
	if (st.st_size > (cap + SILOFS_BK_SIZE)) {
		log_warn("blob-size mismatch: blob=%s size=%ld cap=%ld",
		         bri->br_nb.name, st.st_size, cap);
		return -SILOFS_EBLOB;
	}
	bri->br_size = st.st_size;
	return 0;
}

static int bri_check_writable(const struct silofs_blobref_info *bri)
{
	return bri->br_rdonly ? -SILOFS_ERDONLY : 0;
}

static int bri_reassign_size(struct silofs_blobref_info *bri, loff_t off)
{
	loff_t len;
	int err;

	err = bri_check_range(bri, off, 0);
	if (err) {
		return err;
	}
	err = bri_check_writable(bri);
	if (err) {
		return err;
	}
	len = off_align_to_bk(off + SILOFS_BK_SIZE - 1);
	err = do_ftruncate(bri->br_fd, len);
	if (err) {
		return err;
	}
	bri->br_size = len;
	return 0;
}

static int bri_require_size_ge(struct silofs_blobref_info *bri,
                               loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);

	return (bri->br_size >= end) ? 0 : bri_reassign_size(bri, end);
}

static void bri_make_iovec(const struct silofs_blobref_info *bri,
                           loff_t off, size_t len, struct silofs_iovec *siov)
{
	siov->iov_off = off;
	siov->iov_len = len;
	siov->iov_base = NULL;
	siov->iov_fd = bri->br_fd;
	siov->iov_ref = NULL;
}

static void bri_setup_iovec_ref(struct silofs_blobref_info *bri,
                                struct silofs_iovec *siov)
{
	siov->iov_ref = &bri->br_ior;
}

static int bri_iovec_at(const struct silofs_blobref_info *bri,
                        loff_t off, size_t len, struct silofs_iovec *siov)
{
	int err;

	err = bri_check_range(bri, off, len);
	if (!err) {
		bri_make_iovec(bri, off, len, siov);
	}
	return err;
}

static int bri_iovec_of(const struct silofs_blobref_info *bri,
                        const struct silofs_oaddr *oaddr,
                        struct silofs_iovec *siov)
{
	return bri_iovec_at(bri, oaddr->pos, oaddr->len, siov);
}

int silofs_bri_resolve(struct silofs_blobref_info *bri,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_iovec *siov)
{
	int err;

	err = bri_iovec_of(bri, oaddr, siov);
	if (err) {
		return err;
	}
	bri_setup_iovec_ref(bri, siov);
	return 0;
}

static int bri_store_by(struct silofs_blobref_info *bri,
                        const struct silofs_iovec *siov,
                        const void *ptr, size_t len)
{
	int err;

	if (unlikely(bri->br_fd != siov->iov_fd)) {
		return -EINVAL;
	}
	if (unlikely(len != siov->iov_len)) {
		return -EINVAL;
	}
	err = bri_require_size_ge(bri, siov->iov_off, len);
	if (err) {
		return err;
	}
	err = do_pwriten(siov->iov_fd, ptr, len, siov->iov_off);
	if (err) {
		return err;
	}
	return 0;
}

static int bri_sync_by(const struct silofs_blobref_info *bri,
                       const struct silofs_iovec *siov)
{
	unsigned int flags;
	int err;

	if (unlikely(bri->br_fd != siov->iov_fd)) {
		return -EINVAL;
	}
	flags = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE |
	        SYNC_FILE_RANGE_WAIT_AFTER;
	err = do_sync_file_range(bri->br_fd, siov->iov_off,
	                         (loff_t)siov->iov_len, flags);
	if (err && (err != -ENOSYS)) {
		return err;
	}
	return 0;
}

int silofs_bri_pwriten(struct silofs_blobref_info *bri, loff_t off,
                       const void *buf, size_t len, bool sync)
{
	struct silofs_iovec siov = { .iov_off = -1 };
	int err;

	err = bri_require_size_ge(bri, off, len);
	if (err) {
		return err;
	}
	err = bri_iovec_at(bri, off, len, &siov);
	if (err) {
		return err;
	}
	err = bri_store_by(bri, &siov, buf, len);
	if (err) {
		return err;
	}
	if (sync) {
		err = bri_sync_by(bri, &siov);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_bri_read_blob(const struct silofs_blobref_info *bri,
                         void *buf, size_t len)
{
	uint8_t *dat;
	size_t bsz;
	size_t rem;
	size_t cnt;
	int err;

	err = bri_check_range(bri, 0, len);
	if (err) {
		return err;
	}
	bsz = (size_t)bri->br_size;
	cnt = min(len, bsz);
	dat = buf;
	err = do_preadn(bri->br_fd, dat, cnt, 0);
	if (err) {
		return err;
	}
	dat += cnt;
	rem = (len > bsz) ? (len - bsz) : 0;
	silofs_memzero(dat, rem);
	return 0;
}

static int bri_load_bb(const struct silofs_blobref_info *bri,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_bytebuf *bb)
{
	struct silofs_iovec siov = { .iov_off = -1 };
	struct stat st;
	loff_t end;
	void *bobj;
	int err;

	err = bri_iovec_of(bri, oaddr, &siov);
	if (err) {
		return err;
	}
	if (!silofs_bytebuf_has_free(bb, !siov.iov_len)) {
		return -EINVAL;
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

static int bri_load_bk(const struct silofs_blobref_info *bri,
                       const struct silofs_bkaddr *bkaddr,
                       struct silofs_block *bk)
{
	struct silofs_oaddr oaddr;
	struct silofs_bytebuf bb;

	silofs_bytebuf_init(&bb, bk, sizeof(*bk));
	silofs_oaddr_of_bk(&oaddr, &bkaddr->blobid, bkaddr->lba);
	return bri_load_bb(bri, &oaddr, &bb);
}

static int bri_require_bk_of(struct silofs_blobref_info *bri,
                             const struct silofs_bkaddr *bkaddr)
{
	struct silofs_oaddr oaddr;

	silofs_oaddr_of_bk(&oaddr, &bkaddr->blobid, bkaddr->lba);
	return bri_require_size_ge(bri, oaddr.pos, oaddr.len);
}

int silofs_bri_load_ubk(struct silofs_blobref_info *bri,
                        const struct silofs_bkaddr *bkaddr,
                        struct silofs_ubk_info *ubki)
{
	int err;

	err = bri_require_bk_of(bri, bkaddr);
	if (err) {
		return err;
	}
	err = bri_load_bk(bri, bkaddr, ubki->ubk_base.bk);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bri_load_vbk(struct silofs_blobref_info *bri,
                        const struct silofs_bkaddr *bkaddr,
                        struct silofs_vbk_info *vbki)
{
	int err;

	err = bri_require_bk_of(bri, bkaddr);
	if (err) {
		return err;
	}
	err = bri_load_bk(bri, bkaddr, vbki->vbk_base.bk);
	if (err) {
		return err;
	}
	return 0;
}

static int bri_trim_by_ftruncate(const struct silofs_blobref_info *bri)
{
	int err;

	err = do_ftruncate(bri->br_fd, 0);
	if (err) {
		return err;
	}
	err = do_ftruncate(bri->br_fd, bri->br_size);
	if (err) {
		return err;
	}
	return 0;
}

static int bri_trim_by_punch(const struct silofs_blobref_info *bri,
                             loff_t from, loff_t to)
{
	return do_fallocate_punch_hole(bri->br_fd, from, off_len(from, to));
}

int silofs_bri_trim_nbks(const struct silofs_blobref_info *bri,
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
	cap = bri_capacity(bri);
	if ((beg == 0) && (off_len(beg, end) == cap)) {
		err = bri_trim_by_ftruncate(bri);
	} else {
		err = bri_trim_by_punch(bri, beg, end);
	}
	return err;
}

int silofs_bri_flock(struct silofs_blobref_info *bri)
{
	int err = 0;

	if (!bri->br_locked) {
		err = do_flock(bri->br_fd, LOCK_EX | LOCK_NB);
		bri->br_locked = (err == 0);
	}
	return err;
}

int silofs_bri_funlock(struct silofs_blobref_info *bri)
{
	int err = 0;

	if (bri->br_locked) {
		err = do_flock(bri->br_fd, LOCK_UN);
		bri->br_locked = !(err == 0);
	}
	return err;
}

static int bri_close(struct silofs_blobref_info *bri)
{
	silofs_bri_funlock(bri);
	return do_closefd(&bri->br_fd);
}

struct silofs_blobref_info *
silofs_bri_new(struct silofs_alloc *alloc,
               const struct silofs_blobid *blobid)
{
	struct silofs_blobref_info *bri;

	bri = silofs_allocate(alloc, sizeof(*bri));
	if (bri != NULL) {
		bri_init(bri, blobid);
	}
	return bri;
}

void silofs_bri_del(struct silofs_blobref_info *bri,
                    struct silofs_alloc *alloc)
{
	bri_close(bri);
	bri_fini(bri);
	silofs_deallocate(alloc, bri, sizeof(*bri));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int repo_lookup_cached_bri(struct silofs_repo *repo,
                                  const struct silofs_blobid *blobid,
                                  struct silofs_blobref_info **out_bri)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (unlikely(!cache->c_inited)) {
		return -ENOENT;
	}
	*out_bri = silofs_cache_lookup_blob(cache, blobid);
	if (*out_bri == NULL) {
		return -ENOENT;
	}
	return 0;
}

static int repo_spawn_cached_bri(struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blobref_info **out_bri)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (unlikely(!cache->c_inited)) {
		return -ENOENT;
	}
	*out_bri = silofs_cache_spawn_blob(cache, blobid);
	if (*out_bri == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static void repo_forget_cached_bri(struct silofs_repo *repo,
                                   struct silofs_blobref_info *bri)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (likely(cache->c_inited)) {
		silofs_cache_evict_blob(cache, bri, true);
	}
}

static void repo_try_evict_cached_bri(struct silofs_repo *repo,
                                      struct silofs_blobref_info *bri)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (likely(cache->c_inited)) {
		silofs_cache_evict_blob(cache, bri, false);
	}
}

static int repo_objs_relax_cached_bris(struct silofs_repo *repo)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (cache->c_inited) {
		silofs_cache_relax_blobs(cache);
	}
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
                                       struct silofs_blobref_info *bri)
{
	return repo_objs_sub_pathname_of(repo, &bri->br_blobid, &bri->br_nb);
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
		return -EEXIST;
	}
	if (err != -ENOENT) {
		log_err("blob stat error: name=%s err=%d", nb->name, err);
		return err;
	}
	return 0;
}

static int repo_objs_create_blob_of(const struct silofs_repo *repo,
                                    struct silofs_blobref_info *bri)
{
	const int dfd = repo_blobs_dfd(repo);
	const int o_flags = O_CREAT | O_RDWR | O_TRUNC;
	int fd = -1;
	int err;

	err = do_openat(dfd, bri->br_nb.name, o_flags, 0600, &fd);
	if (err) {
		return err;
	}
	bri_bindto(bri, fd, true);
	err = bri_reassign_size(bri, SILOFS_BK_SIZE);
	if (err) {
		do_unlinkat(dfd, bri->br_nb.name, 0);
		return err;
	}
	return 0;
}

static int repo_objs_open_blob_of(const struct silofs_repo *repo,
                                  struct silofs_blobref_info *bri, bool rw)
{
	const int o_flags = rw ? O_RDWR : O_RDONLY;
	const int dfd = repo_blobs_dfd(repo);
	int fd = -1;
	int err;

	silofs_assert_lt(bri->br_fd, 0);

	err = do_openat(dfd, bri->br_nb.name, o_flags, 0600, &fd);
	if (err) {
		/*
		 * TODO-0032: Consider using SILOFS_EFSCORRUPTED
		 *
		 * When higher layer wants to open a blob, it should exist.
		 * Do not return -ENOENT as this may be interpreted as no-error
		 * by caller.
		 */
		return (err == -ENOENT) ? -EIO : err;
	}
	bri_bindto(bri, fd, rw);
	err = bri_inspect_size(bri);
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
                               struct silofs_blobref_info **out_bri)
{
	struct silofs_blobref_info *bri = NULL;
	int err;

	err = repo_objs_relax_cached_bris(repo);
	if (err) {
		return err;
	}
	err = repo_spawn_cached_bri(repo, blobid, &bri);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, bri);
	if (err) {
		goto out_err;
	}
	err = repo_objs_open_blob_of(repo, bri, rw);
	if (err) {
		goto out_err;
	}
	*out_bri = bri;
	return 0;
out_err:
	repo_forget_cached_bri(repo, bri);
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
		return err;
	}
	len = blobid_size(blobid);
	if (out_st->st_size > (loff_t)(len + SILOFS_BK_SIZE)) {
		log_warn("blob-size mismatch: %s len=%lu st_size=%ld",
		         nb.name, len, out_st->st_size);
		return -EIO;
	}
	return 0;
}

static int repo_objs_create_blob(struct silofs_repo *repo,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_blobref_info **out_bri)
{
	struct silofs_blobref_info *bri = NULL;
	int err;

	err = repo_objs_relax_cached_bris(repo);
	if (err) {
		return err;
	}
	err = repo_spawn_cached_bri(repo, blobid, &bri);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, bri);
	if (err) {
		goto out_err;
	}
	err = repo_objs_require_noblob(repo, &bri->br_nb);
	if (err) {
		goto out_err;
	}
	err = repo_objs_create_blob_of(repo, bri);
	if (err) {
		goto out_err;
	}
	*out_bri = bri;
	return 0;
out_err:
	repo_forget_cached_bri(repo, bri);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_check_open(const struct silofs_repo *repo)
{
	return likely(repo->re_root_dfd > 0) ? 0 : -EBADF;
}

static int repo_check_writable(const struct silofs_repo *repo)
{
	const struct silofs_bootpath *bootpath;

	if (repo->re_cfg.rc_rdonly) {
		bootpath = &repo->re_cfg.rc_bootpath;
		log_dbg("read-only repo: %s", bootpath->repodir.str);
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

static int repo_lookup_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct stat st;
	struct silofs_blobref_info *bri = NULL;
	int err;

	err = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_bri(repo, blobid, &bri);
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
                           struct silofs_blobref_info **out_bri)
{
	int err;

	err = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_bri(repo, blobid, out_bri);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_create_blob(repo, blobid, out_bri);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_stage_blob(struct silofs_repo *repo, bool rw,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobref_info **out_bri)
{
	int err;

	err  = repo_check_open(repo);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_bri(repo, blobid, out_bri);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_blob(repo, rw, blobid, out_bri);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_remove_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid)
{
	struct silofs_blobref_info *bri = NULL;
	int err;

	err = repo_check_open_rw(repo);
	if (err) {
		return err;
	}
	err = repo_objs_unlink_blob(repo, blobid);
	if (err) {
		return err;
	}
	err = repo_lookup_cached_bri(repo, blobid, &bri);
	if (!err) {
		repo_try_evict_cached_bri(repo, bri);
	}
	return 0;
}

static int repo_require_blob(struct silofs_repo *repo, bool rw,
                             const struct silofs_blobid *blobid,
                             struct silofs_blobref_info **out_bri)
{
	int err;

	err = repo_lookup_blob(repo, blobid);
	if (!err) {
		err = repo_stage_blob(repo, rw, blobid, out_bri);
	} else if ((err == -ENOENT) && rw) {
		err = repo_spawn_blob(repo, blobid, out_bri);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool repo_enabled(const struct silofs_repo *repo)
{
	return (repo != NULL) && repo->re_cache.c_inited &&
	       (repo->re_cfg.rc_repo_mode != SILOFS_REPO_NONE);
}

static int repo_init_cache(struct silofs_repo *repo)
{
	struct silofs_cache *cache = &repo->re_cache;
	struct silofs_alloc *alloc = repo->re_cfg.rc_alloc;
	const size_t memsz_hint = repo->re_cfg.rc_memhint;

	return silofs_cache_init(cache, alloc, memsz_hint);
}

static void repo_fini_cache(struct silofs_repo *repo)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (cache->c_inited) {
		silofs_cache_fini(cache);
	}
}

static int repo_init_mdigest(struct silofs_repo *repo)
{
	return silofs_mdigest_init(&repo->re_mdigest);
}

static void repo_fini_mdigest(struct silofs_repo *repo)
{
	silofs_mdigest_fini(&repo->re_mdigest);
}

static void repocfg_assign(struct silofs_repocfg *rcfg,
                           const struct silofs_repocfg *other)
{
	silofs_bootpath_assign(&rcfg->rc_bootpath, &other->rc_bootpath);
	rcfg->rc_alloc = other->rc_alloc;
	rcfg->rc_memhint = other->rc_memhint;
	rcfg->rc_repo_mode = other->rc_repo_mode;
	rcfg->rc_rdonly = other->rc_rdonly;
}

static int repo_init(struct silofs_repo *repo,
                     const struct silofs_repocfg *rcfg)
{
	int err;

	repocfg_assign(&repo->re_cfg, rcfg);
	repo->re_root_dfd = -1;
	repo->re_dots_dfd = -1;
	repo->re_blobs_dfd = -1;
	err = repo_init_cache(repo);
	if (err) {
		return err;
	}
	err = repo_init_mdigest(repo);
	if (err) {
		repo_fini_cache(repo);
		return err;
	}
	return 0;
}

static void repo_fini(struct silofs_repo *repo)
{
	repo_close(repo);
	repo_fini_cache(repo);
	repo_fini_mdigest(repo);
	silofs_memzero(repo, sizeof(*repo));
}

static void repo_drop_cache(struct silofs_repo *repo)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (cache->c_inited) {
		silofs_cache_drop(cache);
	}
}

static void repo_pre_op(struct silofs_repo *repo)
{
	silofs_unused(repo);
}

static void repo_post_op(struct silofs_repo *repo)
{
	silofs_unused(repo);
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
		return -SILOFS_EBADREPO;
	}
	return 0;
}

static int repo_require_skel(const struct silofs_repo *repo)
{
	const struct silofs_bootpath *bootpath = &repo->re_cfg.rc_bootpath;
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
	const struct silofs_bootpath *bootpath = &repo->re_cfg.rc_bootpath;
	int err;

	if (repo->re_root_dfd > 0) {
		return -EALREADY;
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

	rmeta_init(&rmeta, repo->re_cfg.rc_repo_mode);
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

static int repo_require_meta_mode(const struct silofs_repo *repo,
                                  const struct silofs_repo_meta *rmeta)
{
	const enum silofs_repo_mode want = repo->re_cfg.rc_repo_mode;
	const enum silofs_repo_mode have = rmeta_mode(rmeta);

	if (want == have) {
		return 0;
	}
	if ((want == SILOFS_REPO_LOCAL) && (have == SILOFS_REPO_ATTIC)) {
		return -SILOFS_EATTIC;
	}
	if ((want == SILOFS_REPO_ATTIC) && (have == SILOFS_REPO_LOCAL)) {
		return -SILOFS_ENOATTIC;
	}
	log_dbg("repo mode mismatch: want=%d have=%d", (int)want, (int)have);
	return -SILOFS_EFSCORRUPTED;
}

static int repo_require_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name = repo_defs.re_meta_name;
	const int dfd = repo->re_dots_dfd;
	int fd = -1;
	int err;

	rmeta_init(&rmeta, repo->re_cfg.rc_repo_mode);
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
	err = repo_require_meta_mode(repo, &rmeta);
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

static int repo_format(struct silofs_repo *repo)
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

static int repo_open(struct silofs_repo *repo)
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

	if (repo->re_root_dfd < 0) {
		return 0;
	}
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
	repo_drop_cache(repo);
	return 0;
}

static void repo_relax_cache(struct silofs_repo *repo, int flags)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (cache->c_inited) {
		silofs_cache_relax(cache, flags);
	}
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int repo_lookup_cached_ubki(struct silofs_repo *repo,
                                   const struct silofs_bkaddr *bkaddr,
                                   struct silofs_ubk_info **out_ubki)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (unlikely(!cache->c_inited)) {
		return -ENOENT;
	}
	*out_ubki = silofs_cache_lookup_ubk(cache, bkaddr);
	if (*out_ubki == NULL) {
		return -ENOENT;
	}
	return 0;
}

static void repo_forget_cached_ubki(struct silofs_repo *repo,
                                    struct silofs_ubk_info *ubki)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (likely(cache->c_inited)) {
		silofs_cache_forget_ubk(cache, ubki);
	}
}

static int repo_spawn_cached_ubki(struct silofs_repo *repo,
                                  const struct silofs_bkaddr *bkaddr,
                                  struct silofs_ubk_info **out_ubki)
{
	struct silofs_cache *cache = &repo->re_cache;

	if (unlikely(!cache->c_inited)) {
		return -ENOENT;
	}
	*out_ubki = silofs_cache_spawn_ubk(cache, bkaddr);
	if (*out_ubki == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static int repo_spawn_attach_ubki(struct silofs_repo *repo,
                                  struct silofs_blobref_info *bri,
                                  const struct silofs_bkaddr *bkaddr,
                                  struct silofs_ubk_info **out_ubki)
{
	int err;

	bri_incref(bri);
	err = repo_spawn_cached_ubki(repo, bkaddr, out_ubki);
	if (!err) {
		silofs_ubki_attach(*out_ubki, bri);
	}
	bri_decref(bri);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_spawn_ubk_at(struct silofs_repo *repo, bool rw,
                             const struct silofs_bkaddr *bkaddr,
                             struct silofs_ubk_info **out_ubki)
{
	struct silofs_blobref_info *bri = NULL;
	int err;

	err = repo_lookup_cached_ubki(repo, bkaddr, out_ubki);
	if (!err) {
		return -EEXIST;
	}
	err = repo_require_blob(repo, rw, &bkaddr->blobid, &bri);
	if (err) {
		return err;
	}
	err = bri_require_bk_of(bri, bkaddr);
	if (err) {
		return err;
	}
	err = repo_spawn_attach_ubki(repo, bri, bkaddr, out_ubki);
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
	struct silofs_blobref_info *bri = NULL;
	struct silofs_ubk_info *ubki = NULL;
	int err;

	err = repo_lookup_cached_ubki(repo, bkaddr, out_ubki);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_stage_blob(repo, rw, &bkaddr->blobid, &bri);
	if (err) {
		return err;
	}
	err = repo_spawn_attach_ubki(repo, bri, bkaddr, &ubki);
	if (err) {
		return err;
	}
	err = silofs_bri_load_ubk(bri, bkaddr, ubki);
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
	} else if (err == -ENOENT) {
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
		return -EISDIR;
	}
	if (!S_ISREG(mode)) {
		return -ENOENT;
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define check_ok_or_bailout(err_) \
	do { if (err_) return (err_); } while (0)

int silofs_repos_init(struct silofs_repos *repos,
                      const struct silofs_repocfg rcfg[2])
{
	int err;

	if (rcfg[0].rc_repo_mode != SILOFS_REPO_NONE) {
		err = repo_init(&repos->repo[0], &rcfg[0]);
		if (err) {
			return err;
		}
	}
	if (rcfg[1].rc_repo_mode != SILOFS_REPO_NONE) {
		err = repo_init(&repos->repo[1], &rcfg[1]);
		if (err) {
			return err;
		}
	}
	return 0;
}

struct silofs_repo *silofs_repos_get(const struct silofs_repos *repos,
                                     enum silofs_repo_mode repo_mode)
{
	const struct silofs_repo *repo;

	switch (repo_mode) {
	case SILOFS_REPO_LOCAL:
		repo = &repos->repo[0];
		break;
	case SILOFS_REPO_ATTIC:
		repo = &repos->repo[1];
		break;
	default:
	case SILOFS_REPO_NONE:
		repo = NULL;
		break;
	}
	return repo_enabled(repo) ? unconst(repo) : NULL;
}

void silofs_repos_fini(struct silofs_repos *repos)
{
	struct silofs_repo *repo = NULL;

	repo = silofs_repos_get(repos, SILOFS_REPO_LOCAL);
	if (repo_enabled(repo)) {
		repo_fini(repo);
	}
	repo = silofs_repos_get(repos, SILOFS_REPO_ATTIC);
	if (repo_enabled(repo)) {
		repo_fini(repo);
	}
}

int silofs_repos_format(struct silofs_repos *repos)
{
	struct silofs_repo *repo = NULL;
	int err;

	repo = silofs_repos_get(repos, SILOFS_REPO_LOCAL);
	if (repo_enabled(repo)) {
		err = repo_format(repo);
		check_ok_or_bailout(err);
	}
	repo = silofs_repos_get(repos, SILOFS_REPO_ATTIC);
	if (repo_enabled(repo)) {
		err = repo_format(repo);
		check_ok_or_bailout(err);
	}
	return 0;
}

int silofs_repos_open(struct silofs_repos *repos)
{
	struct silofs_repo *repo = NULL;
	int err;

	repo = silofs_repos_get(repos, SILOFS_REPO_LOCAL);
	if (repo_enabled(repo)) {
		err = repo_open(repo);
		check_ok_or_bailout(err);
	}
	repo = silofs_repos_get(repos, SILOFS_REPO_ATTIC);
	if (repo_enabled(repo)) {
		err = repo_open(repo);
		check_ok_or_bailout(err);
	}
	return 0;
}

int silofs_repos_close(struct silofs_repos *repos)
{
	struct silofs_repo *repo = NULL;
	int err = 0;

	for (size_t i = 0; !err && (i < ARRAY_SIZE(repos->repo)); ++i) {
		repo = &repos->repo[i];
		if (repo_enabled(repo)) {
			err = repo_close(repo);
		}
	}
	return err;
}

void silofs_repos_drop_cache(struct silofs_repos *repos)
{
	struct silofs_repo *repo = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(repos->repo); ++i) {
		repo = &repos->repo[i];
		if (repo_enabled(repo)) {
			repo_pre_op(repo);
			repo_drop_cache(repo);
			repo_post_op(repo);
		}
	}
}

void silofs_repos_relax_cache(struct silofs_repos *repos, int flags)
{
	struct silofs_repo *repo = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(repos->repo); ++i) {
		repo = &repos->repo[i];
		if (repo_enabled(repo)) {
			repo_pre_op(repo);
			repo_relax_cache(repo, flags);
			repo_post_op(repo);
		}
	}
}

void silofs_repos_pre_forkfs(struct silofs_repos *repos)
{
	struct silofs_repo *repo = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(repos->repo); ++i) {
		repo = &repos->repo[i];
		if (repo_enabled(repo)) {
			repo_pre_op(repo);
			silofs_cache_forget_uaddrs(&repo->re_cache);
			repo_post_op(repo);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repos_save_bootsec(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid,
                              const struct silofs_bootsec *bsec)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_save_bootsec(repo, uuid, bsec);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_load_bootsec(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid,
                              struct silofs_bootsec *out_bsec)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_load_bootsec(repo, uuid, out_bsec);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_stat_bootsec(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_stat_bootsec(repo, uuid);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_unlink_bootsec(struct silofs_repos *repos,
                                enum silofs_repo_mode repo_mode,
                                const struct silofs_uuid *uuid)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_unlink_bootsec(repo, uuid);
		repo_post_op(repo);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repos_lookup_blob(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_blobid *blobid)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_lookup_blob(repo, blobid);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_spawn_blob(struct silofs_repos *repos,
                            enum silofs_repo_mode repo_mode,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobref_info **out_bri)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_spawn_blob(repo, blobid, out_bri);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_stage_blob(struct silofs_repos *repos, bool rw,
                            enum silofs_repo_mode repo_mode,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobref_info **out_bri)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_stage_blob(repo, rw, blobid, out_bri);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_remove_blob(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_blobid *blobid)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_remove_blob(repo, blobid);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_require_blob(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_blobid *blobid,
                              struct silofs_blobref_info **out_bri)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_require_blob(repo, true, blobid, out_bri);
		repo_post_op(repo);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repos_stage_ubk(struct silofs_repos *repos, bool rw,
                           enum silofs_repo_mode repo_mode,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_stage_ubk(repo, rw, bkaddr, out_ubki);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_spawn_ubk(struct silofs_repos *repos, bool rw,
                           enum silofs_repo_mode repo_mode,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_spawn_ubk(repo, rw, bkaddr, out_ubki);
		repo_post_op(repo);
	}
	return ret;
}

int silofs_repos_require_ubk(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_bkaddr *bkaddr,
                             struct silofs_ubk_info **out_ubki)
{
	struct silofs_repo *repo = silofs_repos_get(repos, repo_mode);
	int ret = -SILOFS_ENOREPO;

	if (likely(repo != NULL)) {
		repo_pre_op(repo);
		ret = repo_require_ubk(repo, true, bkaddr, out_ubki);
		repo_post_op(repo);
	}
	return ret;
}
