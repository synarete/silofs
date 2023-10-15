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
	const char     *re_lexts_name;
	unsigned int    re_objs_nsubs;
};

static const struct silofs_repo_defs repo_defs = {
	.re_dots_name   = SILOFS_REPO_DOTS_DIRNAME,
	.re_meta_name   = SILOFS_REPO_META_FILENAME,
	.re_lexts_name  = SILOFS_REPO_LEXTS_DIRNAME,
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

static int do_fsync(int fd)
{
	int err;

	err = silofs_sys_fsync(fd);
	if (err && (err != -ENOSYS)) {
		log_warn("fsync error: fd=%d err=%d", fd, err);
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

static int do_pwritevn(int fd, const struct iovec *iov, size_t cnt, loff_t off)
{
	int err;

	err = silofs_sys_pwritevn(fd, iov, (int)cnt, off);
	if (err) {
		log_warn("pwritevn error: fd=%d cnt=%lu off=%ld err=%d",
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
lextid_to_index(const struct silofs_lextid *lextid, uint32_t index_max)
{
	const uint64_t bh = silofs_lextid_hash64(lextid);

	return (uint32_t)(bh ^ (bh >> 32)) % index_max;
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

static struct silofs_lextf *
lextf_from_htb_link(const struct silofs_list_head *lh)
{
	const struct silofs_lextf *lextf;

	lextf = container_of2(lh, struct silofs_lextf, lex_htb_lh);
	return unconst(lextf);
}

static struct silofs_lextf *
lextf_from_lsq_link(const struct silofs_list_head *lh)
{
	const struct silofs_lextf *lextf;

	lextf = container_of2(lh, struct silofs_lextf, lex_lsq_lh);
	return unconst(lextf);
}

static int lextf_init(struct silofs_lextf *lextf,
                      const struct silofs_lextid *lextid)
{
	lextid_assign(&lextf->lex_id, lextid);
	list_head_init(&lextf->lex_htb_lh);
	list_head_init(&lextf->lex_lsq_lh);
	lextf->lex_size = 0;
	lextf->lex_fd = -1;
	lextf->lex_refcnt = 0;
	lextf->lex_flocked = false;
	lextf->lex_rdonly = false;
	return 0;
}

static void lextf_fini(struct silofs_lextf *lextf)
{
	silofs_assert_eq(lextf->lex_refcnt, 0);

	lextid_reset(&lextf->lex_id);
	list_head_fini(&lextf->lex_htb_lh);
	list_head_fini(&lextf->lex_lsq_lh);
	lextf->lex_size = -1;
	lextf->lex_fd = -1;
}

static bool lextf_has_id(const struct silofs_lextf *lextf,
                         const struct silofs_lextid *lextid)
{
	return silofs_lextid_isequal(&lextf->lex_id, lextid);
}

static int lextf_refcnt_atomic(const struct silofs_lextf *lextf)
{
	silofs_assert_ge(lextf->lex_refcnt, 0);
	return silofs_atomic_get(&lextf->lex_refcnt);
}

void silofs_lextf_incref(struct silofs_lextf *lextf)
{
	silofs_atomic_add(&lextf->lex_refcnt, 1);
}

void silofs_lextf_decref(struct silofs_lextf *lextf)
{
	silofs_assert_gt(lextf->lex_refcnt, 0);
	silofs_atomic_sub(&lextf->lex_refcnt, 1);
}

static bool lextf_is_evictable_atomic(const struct silofs_lextf *lextf)
{
	return (lextf_refcnt_atomic(lextf) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lextf_lock(struct silofs_lextf *lextf)
{
	/* no-op for now */
	silofs_unused(lextf);
}

static void lextf_unlock(struct silofs_lextf *lextf)
{
	/* no-op for now */
	silofs_unused(lextf);
}

static ssize_t lextf_capacity(const struct silofs_lextf *lextf)
{
	return (ssize_t)lextid_size(&lextf->lex_id);
}

static ssize_t lextf_size(const struct silofs_lextf *lextf)
{
	return silofs_atomic_getl(&lextf->lex_size);
}

static void lextf_set_size(struct silofs_lextf *lextf, ssize_t sz)
{
	silofs_atomic_setl(&lextf->lex_size, sz);
}

static void lextf_bindto(struct silofs_lextf *lextf, int fd, bool rw)
{
	lextf->lex_fd = fd;
	lextf->lex_rdonly = !rw;
}

static int lextf_check_range(const struct silofs_lextf *lextf,
                             loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t cap = lextf_capacity(lextf);

	if (off < 0) {
		return -SILOFS_EINVAL;
	}
	if (end > (cap + SILOFS_LBK_SIZE)) {
		return -SILOFS_ELEXT;
	}
	return 0;
}

static int lextf_stat(const struct silofs_lextf *lextf, struct stat *out_st)
{
	return do_fstat(lextf->lex_fd, out_st);
}

static int lextf_inspect_size(struct silofs_lextf *lextf)
{
	struct stat st;
	ssize_t cap;
	int err;

	err = lextf_stat(lextf, &st);
	if (err) {
		return err;
	}
	if (st.st_size % SILOFS_LBK_SIZE) {
		log_warn("lext-size not aligned: lext=%s size=%ld",
		         lextf->lex_name.name, st.st_size);
		return -SILOFS_ELEXT;
	}
	cap = lextf_capacity(lextf);
	if (st.st_size > (cap + SILOFS_LBK_SIZE)) {
		log_warn("lext-size mismatch: lext=%s size=%ld cap=%ld",
		         lextf->lex_name.name, st.st_size, cap);
		return -SILOFS_ELEXT;
	}
	lextf_set_size(lextf, st.st_size);
	return 0;
}

static int lextf_check_writable(const struct silofs_lextf *lextf)
{
	return lextf->lex_rdonly ? -SILOFS_ERDONLY : 0;
}

static int lextf_reassign_size(struct silofs_lextf *lextf, loff_t off)
{
	ssize_t len;
	int err;

	err = lextf_check_range(lextf, off, 0);
	if (err) {
		return err;
	}
	err = lextf_check_writable(lextf);
	if (err) {
		return err;
	}
	len = off_align_to_lbk(off + SILOFS_LBK_SIZE - 1);
	err = do_ftruncate(lextf->lex_fd, len);
	if (err) {
		return err;
	}
	lextf_set_size(lextf, len);
	return 0;
}

static int lextf_require_size_ge(struct silofs_lextf *lextf,
                                 loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const ssize_t bsz = lextf_size(lextf);

	return (bsz >= end) ? 0 : lextf_reassign_size(lextf, end);
}

static int lextf_require_laddr(struct silofs_lextf *lextf,
                               const struct silofs_laddr *laddr)
{
	return lextf_require_size_ge(lextf, laddr->pos, laddr->len);
}

static int lextf_check_size_ge(const struct silofs_lextf *lextf,
                               loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const ssize_t bsz = lextf_size(lextf);

	return (bsz >= end) ? 0 : -SILOFS_ERANGE;
}

static void lextf_make_iovec(const struct silofs_lextf *lextf,
                             loff_t off, size_t len, struct silofs_iovec *siov)
{
	siov->iov_off = off;
	siov->iov_len = len;
	siov->iov_base = NULL;
	siov->iov_fd = lextf->lex_fd;
	siov->iov_ref = NULL;
}

static int lextf_iovec_at(const struct silofs_lextf *lextf,
                          loff_t off, size_t len, struct silofs_iovec *siov)
{
	int err;

	err = lextf_check_range(lextf, off, len);
	if (!err) {
		lextf_make_iovec(lextf, off, len, siov);
	}
	return err;
}

static int lextf_iovec_of(const struct silofs_lextf *lextf,
                          const struct silofs_laddr *laddr,
                          struct silofs_iovec *siov)
{
	return lextf_iovec_at(lextf, laddr->pos, laddr->len, siov);
}

int silofs_lextf_resolve(struct silofs_lextf *lextf,
                         const struct silofs_laddr *laddr,
                         struct silofs_iovec *siov)
{
	int ret;

	lextf_lock(lextf);
	ret = lextf_iovec_of(lextf, laddr, siov);
	lextf_unlock(lextf);
	return ret;
}

static int lextf_sync_range(const struct silofs_lextf *lextf,
                            loff_t off, size_t len)
{
	int err;

	err = do_sync_file_range(lextf->lex_fd, off, (loff_t)len,
	                         SYNC_FILE_RANGE_WAIT_BEFORE |
	                         SYNC_FILE_RANGE_WRITE |
	                         SYNC_FILE_RANGE_WAIT_AFTER);
	if (err && (err != -ENOSYS)) {
		return err;
	}
	return 0;
}

static int lextf_pwriten(struct silofs_lextf *lextf, loff_t off,
                         const void *buf, size_t len)
{
	int err;

	err = lextf_require_size_ge(lextf, off, len);
	if (err) {
		return err;
	}
	err = lextf_check_range(lextf, off, len);
	if (err) {
		return err;
	}
	err = do_pwriten(lextf->lex_fd, buf, len, off);
	if (err) {
		return err;
	}
	return 0;
}

static size_t length_of(const struct iovec *iov, size_t cnt)
{
	size_t len = 0;

	for (size_t i = 0; i < cnt; ++i) {
		len += iov[i].iov_len;
	}
	return len;
}

static int lextf_pwritevn(struct silofs_lextf *lextf, loff_t off,
                          const struct iovec *iov, size_t cnt)
{
	const size_t len = length_of(iov, cnt);
	int err;

	err = lextf_require_size_ge(lextf, off, len);
	if (err) {
		return err;
	}
	err = lextf_check_range(lextf, off, len);
	if (err) {
		return err;
	}
	err = do_pwritevn(lextf->lex_fd, iov, cnt, off);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_lextf_pwriten(struct silofs_lextf *lextf, loff_t off,
                         const void *buf, size_t len, bool sync)
{
	int err;

	lextf_lock(lextf);
	err = lextf_pwriten(lextf, off, buf, len);
	if (!err && sync) {
		err = lextf_sync_range(lextf, off, len);
	}
	lextf_unlock(lextf);
	return err;
}

int silofs_lextf_pwritevn(struct silofs_lextf *lextf, loff_t off,
                          const struct iovec *iov, size_t cnt, bool sync)
{
	int err;

	lextf_lock(lextf);
	err = lextf_pwritevn(lextf, off, iov, cnt);
	if (!err && sync) {
		err = lextf_sync_range(lextf, off, length_of(iov, cnt));
	}
	lextf_unlock(lextf);
	return err;
}

static int lextf_load_bb(const struct silofs_lextf *lextf,
                         const struct silofs_laddr *laddr,
                         struct silofs_bytebuf *bb)
{
	struct silofs_iovec siov = { .iov_off = -1 };
	struct stat st;
	loff_t end;
	void *bobj;
	int err;

	err = lextf_iovec_of(lextf, laddr, &siov);
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

static int lextf_load_bk(const struct silofs_lextf *lextf,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_lblock *lbk)
{
	struct silofs_bytebuf bb;

	silofs_bytebuf_init(&bb, lbk, sizeof(*lbk));
	return lextf_load_bb(lextf, &bkaddr->laddr, &bb);
}

int silofs_lextf_require_bk_of(struct silofs_lextf *lextf,
                               const struct silofs_bkaddr *bkaddr)
{
	return lextf_require_laddr(lextf, &bkaddr->laddr);
}

static int lextf_check_laddr(const struct silofs_lextf *lextf,
                             const struct silofs_laddr *laddr)
{
	return lextf_check_size_ge(lextf, laddr->pos, laddr->len);
}

static int lextf_check_bk_of(const struct silofs_lextf *lextf,
                             const struct silofs_bkaddr *bkaddr)
{
	return lextf_check_laddr(lextf, &bkaddr->laddr);
}

static int lextf_do_load_bk_at(struct silofs_lextf *lextf,
                               const struct silofs_bkaddr *bkaddr,
                               struct silofs_lbk_info *lbki)
{
	int err;

	err = lextf_check_bk_of(lextf, bkaddr);
	if (err) {
		silofs_assert_ne(err, -SILOFS_ERANGE);
		return err;
	}
	err = lextf_load_bk(lextf, bkaddr, lbki->lbk);
	if (err) {
		return err;
	}
	return 0;
}

static int lextf_load_bk_at(struct silofs_lextf *lextf,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_lbk_info *lbki)
{
	int ret;

	lextf_lock(lextf);
	ret = lextf_do_load_bk_at(lextf, bkaddr, lbki);
	lextf_unlock(lextf);
	return ret;
}

int silofs_lextf_load_bk(struct silofs_lextf *lextf,
                         const struct silofs_laddr *laddr,
                         struct silofs_lbk_info *lbki)
{
	struct silofs_bkaddr bkaddr;

	bkaddr_by_laddr(&bkaddr, laddr);
	return lextf_load_bk_at(lextf, &bkaddr, lbki);
}

static int lextf_trim_by_ftruncate(const struct silofs_lextf *lextf)
{
	int err;

	err = do_ftruncate(lextf->lex_fd, 0);
	if (err) {
		return err;
	}
	err = do_ftruncate(lextf->lex_fd, lextf_size(lextf));
	if (err) {
		return err;
	}
	return 0;
}

static int lextf_trim_by_punch(const struct silofs_lextf *lextf,
                               loff_t from, loff_t to)
{
	return do_fallocate_punch_hole(lextf->lex_fd, from, off_len(from, to));
}

static int lextf_trim_all(const struct silofs_lextf *lextf)
{
	struct stat st;
	int err;

	err = lextf_stat(lextf, &st);
	if (err) {
		goto out;
	}
	if (st.st_blocks == 0) {
		goto out; /* ok */
	}
	err = lextf_trim_by_punch(lextf, 0, lextf_size(lextf));
	if (err != -ENOTSUP) {
		goto out; /* ok-or-error */
	}
	err = lextf_trim_by_ftruncate(lextf);
out:
	return err;
}

int silofs_lextf_trim(struct silofs_lextf *lextf)
{
	int ret;

	lextf_lock(lextf);
	ret = lextf_trim_all(lextf);
	lextf_unlock(lextf);
	return ret;
}

int silofs_lextf_require(struct silofs_lextf *lextf,
                         const struct silofs_laddr *laddr)
{
	int ret;

	lextf_lock(lextf);
	ret = lextf_require_laddr(lextf, laddr);
	lextf_unlock(lextf);
	return ret;
}

int silofs_lextf_check(struct silofs_lextf *lextf,
                       const struct silofs_laddr *laddr)
{
	int ret;

	lextf_lock(lextf);
	ret = lextf_check_laddr(lextf, laddr);
	lextf_unlock(lextf);
	return ret;
}

int silofs_lextf_stat(struct silofs_lextf *lextf, struct stat *out_st)
{
	int ret;

	lextf_lock(lextf);
	ret = lextf_stat(lextf, out_st);
	lextf_unlock(lextf);
	return ret;
}

int silofs_lextf_flock(struct silofs_lextf *lextf)
{
	int err = 0;

	lextf_lock(lextf);
	if (!lextf->lex_flocked) {
		err = do_flock(lextf->lex_fd, LOCK_EX | LOCK_NB);
		lextf->lex_flocked = (err == 0);
	}
	lextf_unlock(lextf);
	return err;
}

int silofs_lextf_funlock(struct silofs_lextf *lextf)
{
	int err = 0;

	lextf_lock(lextf);
	if (lextf->lex_flocked) {
		err = do_flock(lextf->lex_fd, LOCK_UN);
		lextf->lex_flocked = !(err == 0);
	}
	lextf_unlock(lextf);
	return err;
}

static int lextf_fsync(struct silofs_lextf *lextf)
{
	int err;

	lextf_lock(lextf);
	err = do_fsync(lextf->lex_fd);
	lextf_unlock(lextf);
	return err;
}

static int lextf_fsync2(struct silofs_lextf *lextf)
{
	return !lextf->lex_rdonly ? lextf_fsync(lextf) : 0;
}

static int lextf_close(struct silofs_lextf *lextf)
{
	silofs_lextf_funlock(lextf);
	return do_closefd(&lextf->lex_fd);
}

static int lextf_close2(struct silofs_lextf *lextf)
{
	int err1 = 0;
	int err2 = 0;

	if (lextf->lex_fd > 0) {
		err1 = lextf_fsync2(lextf);
		err2 = lextf_close(lextf);
	}
	return err1 ? err1 : err2;
}

int silofs_lextf_fsync(struct silofs_lextf *lextf)
{
	return lextf_fsync2(lextf);
}

struct silofs_lextf *
silofs_lextf_new(struct silofs_alloc *alloc,
                 const struct silofs_lextid *lextid)
{
	struct silofs_lextf *lextf;
	int err;

	lextf = silofs_allocate(alloc, sizeof(*lextf), SILOFS_ALLOCF_BZERO);
	if (lextf == NULL) {
		return NULL;
	}
	err = lextf_init(lextf, lextid);
	if (err) {
		silofs_deallocate(alloc, lextf, sizeof(*lextf), 0);
		return NULL;
	}
	return lextf;
}

void silofs_lextf_del(struct silofs_lextf *lextf,
                      struct silofs_alloc *alloc)
{
	silofs_assert_eq(lextf->lex_refcnt, 0);

	lextf_close2(lextf);
	lextf_fini(lextf);
	silofs_deallocate(alloc, lextf, sizeof(*lextf), 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int repo_htbl_init(struct silofs_repo *repo)
{
	const size_t nelems = 4096;

	repo->re_htbl.rh_arr = silofs_lista_new(repo->re.alloc, nelems);
	if (repo->re_htbl.rh_arr == NULL) {
		return -SILOFS_ENOMEM;
	}
	repo->re_htbl.rh_nelems = nelems;
	repo->re_htbl.rh_size = 0;
	return 0;
}

static void repo_htbl_fini(struct silofs_repo *repo)
{
	if (repo->re_htbl.rh_arr != NULL) {
		silofs_lista_del(repo->re_htbl.rh_arr,
		                 repo->re_htbl.rh_nelems,
		                 repo->re.alloc);
		repo->re_htbl.rh_arr = NULL;
		repo->re_htbl.rh_nelems = 0;
		repo->re_htbl.rh_size = 0;
	}
}

static size_t repo_htbl_slot_of(const struct silofs_repo *repo,
                                const struct silofs_lextid *lextid)
{
	const uint64_t hash = silofs_lextid_hash64(lextid);

	return hash % repo->re_htbl.rh_nelems;
}

static struct silofs_list_head *
repo_htbl_list_at(const struct silofs_repo *repo, size_t slot)
{
	const struct silofs_list_head *lst = &repo->re_htbl.rh_arr[slot];

	silofs_assert_lt(slot, repo->re_htbl.rh_nelems);

	return unconst(lst);
}

static struct silofs_list_head *
repo_htbl_list_of(const struct silofs_repo *repo,
                  const struct silofs_lextid *lextid)
{
	const size_t slot = repo_htbl_slot_of(repo, lextid);

	return repo_htbl_list_at(repo, slot);
}

static struct silofs_lextf *
repo_htbl_lookup(const struct silofs_repo *repo,
                 const struct silofs_lextid *lextid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_lextf *lextf;

	lst = repo_htbl_list_of(repo, lextid);
	itr = lst->next;
	while (itr != lst) {
		lextf = lextf_from_htb_link(itr);
		if (lextf_has_id(lextf, lextid)) {
			return unconst(lextf);
		}
		itr = itr->next;
	}
	return NULL;
}

static void repo_htbl_insert(struct silofs_repo *repo,
                             struct silofs_lextf *lextf)
{
	struct silofs_list_head *lst = repo_htbl_list_of(repo, &lextf->lex_id);

	list_push_front(lst, &lextf->lex_htb_lh);
	repo->re_htbl.rh_size += 1;
}

static void
repo_htbl_remove(struct silofs_repo *repo, struct silofs_lextf *lextf)
{
	silofs_assert_gt(repo->re_htbl.rh_size, 0);

	list_head_remove(&lextf->lex_htb_lh);
	repo->re_htbl.rh_size -= 1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_lstq_insert(struct silofs_repo *repo,
                             struct silofs_lextf *lextf)
{
	listq_push_front(&repo->re_lstq, &lextf->lex_lsq_lh);
}

static void repo_lstq_remove(struct silofs_repo *repo,
                             struct silofs_lextf *lextf)
{
	listq_remove(&repo->re_lstq, &lextf->lex_lsq_lh);
}

static void repo_lstq_requeue(struct silofs_repo *repo,
                              struct silofs_lextf *lextf)
{
	listq_remove(&repo->re_lstq, &lextf->lex_lsq_lh);
	listq_push_back(&repo->re_lstq, &lextf->lex_lsq_lh);
}

static struct silofs_lextf *repo_lstq_front(const struct silofs_repo *repo)
{
	struct silofs_lextf *lextf = NULL;
	struct silofs_list_head *lh;

	lh = listq_front(&repo->re_lstq);
	if (lh != NULL) {
		lextf = lextf_from_lsq_link(lh);
	}
	return lextf;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
repo_create_lextf(struct silofs_repo *repo,
                  const struct silofs_lextid *lextid,
                  struct silofs_lextf **out_lextf)
{
	struct silofs_lextf *lextf = NULL;

	lextf = silofs_lextf_new(repo->re.alloc, lextid);
	if (lextf == NULL) {
		return -SILOFS_ENOMEM;
	}
	repo_htbl_insert(repo, lextf);
	repo_lstq_insert(repo, lextf);
	*out_lextf = lextf;
	return 0;
}

static void repo_evict_lextf(struct silofs_repo *repo,
                             struct silofs_lextf *lextf)
{
	repo_htbl_remove(repo, lextf);
	repo_lstq_remove(repo, lextf);
	silofs_lextf_del(lextf, repo->re.alloc);
}

static struct silofs_lextf *
repo_nextof(const struct silofs_repo *repo, const struct silofs_lextf *lextf)
{
	struct silofs_list_head *lh_next;

	if (lextf == NULL) {
		return repo_lstq_front(repo);
	}
	lh_next = listq_next(&repo->re_lstq, &lextf->lex_lsq_lh);
	if (lh_next != NULL) {
		return lextf_from_lsq_link(lh_next);
	}
	return NULL;
}

int silofs_repo_fsync_all(struct silofs_repo *repo)
{
	struct silofs_lextf *lextf;
	int ret = 0;
	int err;

	lextf = repo_nextof(repo, NULL);
	while (lextf != NULL) {
		err = lextf_fsync2(lextf);
		ret = err || ret;
		lextf = repo_nextof(repo, lextf);
	}
	return ret;
}

static void repo_evict_all(struct silofs_repo *repo)
{
	struct silofs_lextf *lextf;

	lextf = repo_nextof(repo, NULL);
	while (lextf != NULL) {
		repo_evict_lextf(repo, lextf);
		lextf = repo_nextof(repo, NULL);
	}
}

static void repo_requeue_lextf(struct silofs_repo *repo,
                               struct silofs_lextf *lextf)
{
	repo_lstq_requeue(repo, lextf);
}

static void repo_evict_or_requeue(struct silofs_repo *repo, size_t niter)
{
	struct silofs_lextf *lextf;
	struct silofs_lextf *lextf_next;

	lextf = repo_nextof(repo, NULL);
	while ((lextf != NULL) && (niter > 0)) {
		lextf_next = repo_nextof(repo, lextf);
		if (lextf_is_evictable_atomic(lextf)) {
			repo_evict_lextf(repo, lextf);
		} else {
			repo_requeue_lextf(repo, lextf);
		}
		lextf = lextf_next;
		niter -= 1;
	}
}

/*
 * TODO-0035: Define proper upper-bound.
 *
 * Have explicit upper-limit to cached lexts, based on the process' rlimit
 * RLIMIT_NOFILE and memory limits.
 */
static void repo_evict_overpop(struct silofs_repo *repo)
{
	const size_t qcur = repo->re_lstq.sz;
	const size_t qmax = 128;

	if (qcur > qmax) {
		repo_evict_or_requeue(repo, min(qcur - qmax, 2));
	}
}

void silofs_repo_relax(struct silofs_repo *repo)
{
	repo_evict_or_requeue(repo, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_fetch_cached_lextf(const struct silofs_repo *repo,
                                   const struct silofs_lextid *lextid,
                                   struct silofs_lextf **out_lextf)
{
	*out_lextf = repo_htbl_lookup(repo, lextid);
	return (*out_lextf == NULL) ? -SILOFS_ENOENT : 0;
}

static int repo_create_cached_lextf(struct silofs_repo *repo,
                                    const struct silofs_lextid *lextid,
                                    struct silofs_lextf **out_lextf)
{
	repo_evict_overpop(repo);
	return repo_create_lextf(repo, lextid, out_lextf);
}

static void repo_forget_cached_lextf(struct silofs_repo *repo,
                                     struct silofs_lextf *lextf)
{
	repo_evict_lextf(repo, lextf);
}

static void repo_try_evict_cached_lextf(struct silofs_repo *repo,
                                        struct silofs_lextf *lextf)
{
	if (lextf_is_evictable_atomic(lextf)) {
		repo_evict_lextf(repo, lextf);
	}
}

static int repo_objs_relax_cached_lextfs(struct silofs_repo *repo)
{
	/* TODO: try evict first */
	unused(repo);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_lexts_dfd(const struct silofs_repo *repo)
{
	return repo->re_lexts_dfd;
}

static int repo_objs_format_sub(const struct silofs_repo *repo, size_t idx)
{
	struct silofs_namebuf nb;
	struct stat st;
	int dfd;
	int err;

	index_to_namebuf(idx, &nb);
	dfd = repo_lexts_dfd(repo);
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

static void repo_hash_lextid(const struct silofs_repo *repo,
                             const struct silofs_lextid *lextid,
                             struct silofs_hash256 *out_hash)
{
	struct silofs_lextid32b lextid32;
	const struct silofs_mdigest *md = repo_mdigest(repo);

	silofs_lextid32b_htox(&lextid32, lextid);
	silofs_sha256_of(md, &lextid32, sizeof(lextid32), out_hash);
}

static int repo_objs_sub_pathname_of(const struct silofs_repo *repo,
                                     const struct silofs_lextid *lextid,
                                     struct silofs_namebuf *out_nb)
{
	struct silofs_hash256 hash;
	size_t idx;

	idx = lextid_to_index(lextid, repo_defs.re_objs_nsubs);
	repo_hash_lextid(repo, lextid, &hash);

	return make_pathname(&hash, idx, out_nb);
}

static int repo_objs_setup_pathname_of(const struct silofs_repo *repo,
                                       struct silofs_lextf *lextf)
{
	return repo_objs_sub_pathname_of(repo, &lextf->lex_id,
	                                 &lextf->lex_name);
}

static int repo_objs_require_nolext(const struct silofs_repo *repo,
                                    const struct silofs_namebuf *nb)
{
	struct stat st = { .st_size = 0 };
	const int dfd = repo_lexts_dfd(repo);
	int err;

	err = do_fstatat(dfd, nb->name, &st, 0);
	if (err == 0) {
		log_err("lext already exists: name=%s", nb->name);
		return -SILOFS_EEXIST;
	}
	if (err != -ENOENT) {
		log_err("lext stat error: name=%s err=%d", nb->name, err);
		return err;
	}
	return 0;
}

static int repo_objs_create_lext_of(const struct silofs_repo *repo,
                                    struct silofs_lextf *lextf)
{
	const int dfd = repo_lexts_dfd(repo);
	const int o_flags = O_CREAT | O_RDWR | O_TRUNC;
	int fd = -1;
	int err;

	err = do_openat(dfd, lextf->lex_name.name, o_flags, 0600, &fd);
	if (err) {
		return err;
	}
	lextf_bindto(lextf, fd, true);
	err = lextf_reassign_size(lextf, lextf_capacity(lextf));
	if (err) {
		do_unlinkat(dfd, lextf->lex_name.name, 0);
		return err;
	}
	return 0;
}

static int repo_objs_open_lext_of(const struct silofs_repo *repo,
                                  struct silofs_lextf *lextf, bool rw)
{
	const int o_flags = rw ? O_RDWR : O_RDONLY;
	const int dfd = repo_lexts_dfd(repo);
	int fd = -1;
	int err;

	silofs_assert_lt(lextf->lex_fd, 0);

	err = do_openat(dfd, lextf->lex_name.name, o_flags, 0600, &fd);
	if (err) {
		/*
		 * TODO-0032: Consider using SILOFS_EFSCORRUPTED
		 *
		 * When higher layer wants to open a lext, it should exist.
		 */
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	lextf_bindto(lextf, fd, rw);
	err = lextf_inspect_size(lextf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_objs_unlink_lext(const struct silofs_repo *repo,
                                 const struct silofs_lextid *lextid)
{
	struct silofs_namebuf nb;
	struct stat st;
	int dfd;
	int err;

	err = repo_objs_sub_pathname_of(repo, lextid, &nb);
	if (err) {
		return err;
	}
	dfd = repo_lexts_dfd(repo);
	err = do_fstatat(dfd, nb.name, &st, 0);
	if (err) {
		log_dbg("can not unlink lext: %s err=%d", nb.name, err);
		return err;
	}
	err = do_unlinkat(dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_objs_open_lext(struct silofs_repo *repo, bool rw,
                               const struct silofs_lextid *lextid,
                               struct silofs_lextf **out_lextf)
{
	struct silofs_lextf *lextf = NULL;
	int err;

	err = repo_create_cached_lextf(repo, lextid, &lextf);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, lextf);
	if (err) {
		goto out_err;
	}
	err = repo_objs_open_lext_of(repo, lextf, rw);
	if (err) {
		goto out_err;
	}
	*out_lextf = lextf;
	return 0;
out_err:
	repo_forget_cached_lextf(repo, lextf);
	return err;
}

static int repo_objs_stat_lext(const struct silofs_repo *repo,
                               const struct silofs_lextid *lextid,
                               struct stat *out_st)
{
	struct silofs_namebuf nb;
	size_t len = 0;
	int dfd = -1;
	int err;

	err = repo_objs_sub_pathname_of(repo, lextid, &nb);
	if (err) {
		return err;
	}
	dfd = repo_lexts_dfd(repo);
	err = do_fstatat(dfd, nb.name, out_st, 0);
	if (err) {
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	len = lextid_size(lextid);
	if (out_st->st_size > (loff_t)(len + SILOFS_LBK_SIZE)) {
		log_warn("lext-size mismatch: %s len=%lu st_size=%ld",
		         nb.name, len, out_st->st_size);
		return -SILOFS_EIO;
	}
	return 0;
}

static int repo_objs_create_lext(struct silofs_repo *repo,
                                 const struct silofs_lextid *lextid,
                                 struct silofs_lextf **out_lextf)
{
	struct silofs_lextf *lextf = NULL;
	int err;

	err = repo_create_cached_lextf(repo, lextid, &lextf);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, lextf);
	if (err) {
		goto out_err;
	}
	err = repo_objs_require_nolext(repo, &lextf->lex_name);
	if (err) {
		goto out_err;
	}
	err = repo_objs_create_lext_of(repo, lextf);
	if (err) {
		goto out_err;
	}
	*out_lextf = lextf;
	return 0;
out_err:
	repo_forget_cached_lextf(repo, lextf);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_check_root_dfd(const struct silofs_repo *repo)
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

static int repo_check_open(const struct silofs_repo *repo, bool rw)
{
	int err;

	err = repo_check_root_dfd(repo);
	if (err) {
		return err;
	}
	if (!rw) {
		return 0;
	}
	err = repo_check_writable(repo);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stat_lext(const struct silofs_repo *repo,
                          const struct silofs_lextid *lextid,
                          bool allow_cache, struct stat *out_st)
{
	struct silofs_lextf *lextf = NULL;
	int err;

	err = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lextf(repo, lextid, &lextf);
	if (!err && allow_cache) {
		return silofs_lextf_stat(lextf, out_st);
	}
	err = repo_objs_stat_lext(repo, lextid, out_st);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_spawn_lext(struct silofs_repo *repo,
                           const struct silofs_lextid *lextid,
                           struct silofs_lextf **out_lextf)
{
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lextf(repo, lextid, out_lextf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_create_lext(repo, lextid, out_lextf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_stage_lext(struct silofs_repo *repo, bool rw,
                           const struct silofs_lextid *lextid,
                           struct silofs_lextf **out_lextf)
{
	int err;

	err  = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lextf(repo, lextid, out_lextf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_lext(repo, rw, lextid, out_lextf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_remove_lext(struct silofs_repo *repo,
                            const struct silofs_lextid *lextid)
{
	struct silofs_lextf *lextf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_objs_unlink_lext(repo, lextid);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lextf(repo, lextid, &lextf);
	if (!err) {
		repo_try_evict_cached_lextf(repo, lextf);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	int err;

	memcpy(&repo->re, re_base, sizeof(repo->re));
	listq_init(&repo->re_lstq);
	repo->re_root_dfd = -1;
	repo->re_dots_dfd = -1;
	repo->re_lexts_dfd = -1;
	err = repo_init_mdigest(repo);
	if (err) {
		return err;
	}
	err = repo_htbl_init(repo);
	if (err) {
		repo_fini_mdigest(repo);
		return err;
	}
	return 0;
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	repo_close(repo);
	repo_evict_all(repo);
	repo_htbl_fini(repo);
	repo_fini_mdigest(repo);
	listq_fini(&repo->re_lstq);
}

void silofs_repo_drop_some(struct silofs_repo *repo)
{
	silofs_repo_fsync_all(repo);
	repo_evict_or_requeue(repo, repo->re_lstq.sz);
}

static void repo_pre_op(struct silofs_repo *repo)
{
	repo_objs_relax_cached_lextfs(repo);
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

	name = repo_defs.re_lexts_name;
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
	name = repo_defs.re_lexts_name;
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

static int repo_open_lexts_dir(struct silofs_repo *repo)
{
	return do_opendirat(repo->re_dots_dfd, repo_defs.re_lexts_name,
	                    &repo->re_lexts_dfd);
}

static int repo_format_lexts_subs(struct silofs_repo *repo)
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
	err = repo_open_lexts_dir(repo);
	if (err) {
		return err;
	}
	err = repo_format_lexts_subs(repo);
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
	err = repo_open_lexts_dir(repo);
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

static int repo_close_lexts_dir(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_lexts_dfd);
}

static int repo_close(struct silofs_repo *repo)
{
	int err;

	err = repo_close_lexts_dir(repo);
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
	repo_evict_all(repo);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void repo_bootrec_name(const struct silofs_repo *repo,
                              const struct silofs_laddr *laddr,
                              struct silofs_namebuf *out_nb)
{
	silofs_uuid_name(&laddr->lextid.treeid.uuid, out_nb);
	unused(repo);
}

static int
repo_save_bootrec1k(const struct silofs_repo *repo,
                    const struct silofs_namebuf *nb,
                    const struct silofs_bootrec1k *brec1k)
{
	int dfd = -1;
	int fd = -1;
	int o_flags;
	int err;

	dfd = repo_lexts_dfd(repo);
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
	err = do_pwriten(fd, brec1k, sizeof(*brec1k), 0);
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

static int repo_save_bootrec(const struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             const struct silofs_bootrec1k *brec1k)
{
	struct silofs_namebuf nb;

	repo_bootrec_name(repo, laddr, &nb);
	return repo_save_bootrec1k(repo, &nb, brec1k);
}

static int repo_load_bootrec1k(const struct silofs_repo *repo,
                               const struct silofs_namebuf *nb,
                               struct silofs_bootrec1k *bsc)
{
	int dfd = -1;
	int fd = -1;
	int err;

	dfd = repo_lexts_dfd(repo);
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

static int repo_load_bootrec(const struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             struct silofs_bootrec1k *out_brec1k)
{
	struct silofs_namebuf nb;

	repo_bootrec_name(repo, laddr, &nb);
	return repo_load_bootrec1k(repo, &nb, out_brec1k);
}

static int repo_stat_bootrec1k(const struct silofs_repo *repo,
                               const struct silofs_namebuf *nb,
                               struct stat *out_st)
{
	mode_t mode;
	int dfd;
	int err;

	dfd = repo_lexts_dfd(repo);
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

static int repo_stat_bootrec(const struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             struct stat *out_st)
{
	struct silofs_namebuf nb;
	int err;

	repo_bootrec_name(repo, laddr, &nb);
	err = repo_stat_bootrec1k(repo, &nb, out_st);
	if (err) {
		return err;
	}
	if (out_st->st_size != sizeof(struct silofs_bootrec1k)) {
		log_warn("bad boot-record: name=%s size=%ld",
		         nb.name, out_st->st_size);
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

static int repo_unlink_bootrec(const struct silofs_repo *repo,
                               const struct silofs_laddr *laddr)
{
	struct silofs_namebuf nb;
	int dfd;
	int err;

	repo_bootrec_name(repo, laddr, &nb);
	dfd = repo_lexts_dfd(repo);
	err = do_unlinkat(dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_save_bootrec(struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             const struct silofs_bootrec1k *brec1k)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_save_bootrec(repo, laddr, brec1k);
	return ret;
}

int silofs_repo_load_bootrec(struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             struct silofs_bootrec1k *out_brec1k)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_load_bootrec(repo, laddr, out_brec1k);
	return ret;
}

int silofs_repo_stat_bootrec(struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             struct stat *out_st)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_stat_bootrec(repo, laddr, out_st);
	return ret;
}

int silofs_repo_unlink_bootrec(struct silofs_repo *repo,
                               const struct silofs_laddr *laddr)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_unlink_bootrec(repo, laddr);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_spawn_lext(struct silofs_repo *repo,
                           const struct silofs_lextid *lextid,
                           struct silofs_lextf **out_lextf)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_spawn_lext(repo, lextid, out_lextf);
	return ret;
}

int silofs_repo_stage_lext(struct silofs_repo *repo, bool rw,
                           const struct silofs_lextid *lextid,
                           struct silofs_lextf **out_lextf)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_stage_lext(repo, rw, lextid, out_lextf);
	return ret;
}

int silofs_repo_remove_lext(struct silofs_repo *repo,
                            const struct silofs_lextid *lextid)
{
	int ret;

	repo_pre_op(repo);
	ret = repo_remove_lext(repo, lextid);
	return ret;
}
