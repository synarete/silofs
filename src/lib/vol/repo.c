/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/vol.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <limits.h>


/* logical-segment control file */
struct silofs_lsegf {
	struct silofs_strbuf            lsf_name;
	struct silofs_lsegid            lsf_id;
	struct silofs_list_head         lsf_htb_lh;
	struct silofs_list_head         lsf_lru_lh;
	long                            lsf_size;
	int                             lsf_fd;
	int                             lsf_refcnt;
	bool                            lsf_rdonly;
};

/* well-know repository meta file-names and sub-directories */
struct silofs_repo_defs {
	const char     *re_dots_name;
	const char     *re_meta_name;
	const char     *re_lock_name;
	const char     *re_blobs_name;
	const char     *re_pack_name;
	const char     *re_objs_name;
	uint32_t        re_objs_nsubs;
};

static const struct silofs_repo_defs repo_defs = {
	.re_dots_name   = SILOFS_REPO_DOTS_DIRNAME,
	.re_meta_name   = SILOFS_REPO_META_FILENAME,
	.re_lock_name   = SILOFS_REPO_LOCK_FILENAME,
	.re_blobs_name  = SILOFS_REPO_BLOBS_DIRNAME,
	.re_pack_name   = SILOFS_REPO_PACK_DIRNAME,
	.re_objs_name   = SILOFS_REPO_OBJS_DIRNAME,
	.re_objs_nsubs  = SILOFS_REPO_OBJS_NSUBS,
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

static int do_fstatat_reg(int dfd, const char *pathname, struct stat *out_st)
{
	mode_t mode;
	int err;

	err = do_fstatat(dfd, pathname, out_st, 0);
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

static int do_save_obj(int dirfd, const char *pathname,
                       const void *dat, size_t len)
{
	const int o_flags = O_RDWR | O_CREAT;
	int fd = -1;
	int err;

	err = do_fchmodat(dirfd, pathname, 0600, 0);
	if (err && (err != -ENOENT)) {
		return err;
	}
	err = do_openat(dirfd, pathname, o_flags, 0600, &fd);
	if (err) {
		goto out;
	}
	err = do_fchmod(fd, 0400);
	if (err) {
		goto out;
	}
	err = do_pwriten(fd, dat, len, 0);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t
lsegid_to_index(const struct silofs_lsegid *lsegid, uint32_t index_max)
{
	const uint64_t h = silofs_lsegid_hash64(lsegid);

	return (uint32_t)(h ^ (h >> 32)) % index_max;
}

static void index_to_name(size_t idx, struct silofs_strbuf *out_name)
{
	const size_t nmax = sizeof(out_name->str);

	snprintf(out_name->str, nmax - 1, "%02x", (int)idx);
}

static int make_pathname(const struct silofs_hash256 *hash, size_t idx,
                         struct silofs_strbuf *out_name)
{
	struct silofs_strbuf hash_name;
	const size_t nmax = sizeof(out_name->str);
	int n;

	silofs_hash256_to_name(hash, &hash_name);
	n = snprintf(out_name->str, nmax, "%02x/%s", (int)idx, hash_name.str);
	return (n < (int)nmax) ? 0 : -SILOFS_EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lsegf *
lsegf_from_htb_link(const struct silofs_list_head *lh)
{
	const struct silofs_lsegf *lsegf;

	lsegf = container_of2(lh, struct silofs_lsegf, lsf_htb_lh);
	return unconst(lsegf);
}

static struct silofs_lsegf *
lsegf_from_lru_link(const struct silofs_list_head *lh)
{
	const struct silofs_lsegf *lsegf;

	lsegf = container_of2(lh, struct silofs_lsegf, lsf_lru_lh);
	return unconst(lsegf);
}

static int lsegf_init(struct silofs_lsegf *lsegf,
                      const struct silofs_lsegid *lsegid)
{
	lsegid_assign(&lsegf->lsf_id, lsegid);
	list_head_init(&lsegf->lsf_htb_lh);
	list_head_init(&lsegf->lsf_lru_lh);
	lsegf->lsf_size = 0;
	lsegf->lsf_fd = -1;
	lsegf->lsf_refcnt = 0;
	lsegf->lsf_rdonly = false;
	return 0;
}

static void lsegf_fini(struct silofs_lsegf *lsegf)
{
	silofs_assert_eq(lsegf->lsf_refcnt, 0);

	lsegid_reset(&lsegf->lsf_id);
	list_head_fini(&lsegf->lsf_htb_lh);
	list_head_fini(&lsegf->lsf_lru_lh);
	lsegf->lsf_size = -1;
	lsegf->lsf_fd = -1;
}

static bool lsegf_has_id(const struct silofs_lsegf *lsegf,
                         const struct silofs_lsegid *lsegid)
{
	return silofs_lsegid_isequal(&lsegf->lsf_id, lsegid);
}

static int lsegf_refcnt(const struct silofs_lsegf *lsegf)
{
	silofs_assert_ge(lsegf->lsf_refcnt, 0);
	return silofs_atomic_get(&lsegf->lsf_refcnt);
}

static bool lsegf_is_evictable(const struct silofs_lsegf *lsegf)
{
	return (lsegf_refcnt(lsegf) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ssize_t lsegf_capacity(const struct silofs_lsegf *lsegf)
{
	return (ssize_t)lsegid_size(&lsegf->lsf_id);
}

static ssize_t lsegf_size(const struct silofs_lsegf *lsegf)
{
	return silofs_atomic_getl(&lsegf->lsf_size);
}

static void lsegf_set_size(struct silofs_lsegf *lsegf, ssize_t sz)
{
	silofs_atomic_setl(&lsegf->lsf_size, sz);
}

static void lsegf_bindto(struct silofs_lsegf *lsegf, int fd, bool rw)
{
	lsegf->lsf_fd = fd;
	lsegf->lsf_rdonly = !rw;
}

static int lsegf_check_range(const struct silofs_lsegf *lsegf,
                             loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t cap = lsegf_capacity(lsegf);

	if (off < 0) {
		return -SILOFS_EINVAL;
	}
	if (end > (cap + SILOFS_LBK_SIZE)) {
		return -SILOFS_ELSEG;
	}
	return 0;
}

static int lsegf_stat(const struct silofs_lsegf *lsegf, struct stat *out_st)
{
	return do_fstat(lsegf->lsf_fd, out_st);
}

static int lsegf_inspect_size(struct silofs_lsegf *lsegf)
{
	struct stat st;
	ssize_t cap;
	int err;

	err = lsegf_stat(lsegf, &st);
	if (err) {
		return err;
	}
	if (st.st_size % SILOFS_LBK_SIZE) {
		log_warn("lseg-size not aligned: lseg=%s size=%ld",
		         lsegf->lsf_name.str, st.st_size);
		return -SILOFS_ELSEG;
	}
	cap = lsegf_capacity(lsegf);
	if (st.st_size > (cap + SILOFS_LBK_SIZE)) {
		log_warn("lseg-size mismatch: lseg=%s size=%ld cap=%ld",
		         lsegf->lsf_name.str, st.st_size, cap);
		return -SILOFS_ELSEG;
	}
	lsegf_set_size(lsegf, st.st_size);
	return 0;
}

static int lsegf_check_writable(const struct silofs_lsegf *lsegf)
{
	return lsegf->lsf_rdonly ? -SILOFS_ERDONLY : 0;
}

static int lsegf_reassign_size(struct silofs_lsegf *lsegf, loff_t off)
{
	ssize_t len;
	int err;

	err = lsegf_check_range(lsegf, off, 0);
	if (err) {
		return err;
	}
	err = lsegf_check_writable(lsegf);
	if (err) {
		return err;
	}
	len = off_align_to_lbk(off + SILOFS_LBK_SIZE - 1);
	err = do_ftruncate(lsegf->lsf_fd, len);
	if (err) {
		return err;
	}
	lsegf_set_size(lsegf, len);
	return 0;
}

static int lsegf_require_size_ge(struct silofs_lsegf *lsegf,
                                 loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t nxt = off_next_lbk(off);
	const ssize_t want_size = off_max(end, nxt);
	const ssize_t curr_size = lsegf_size(lsegf);

	return (curr_size >= want_size) ? 0 :
	       lsegf_reassign_size(lsegf, want_size);
}

static int lsegf_require_laddr(struct silofs_lsegf *lsegf,
                               const struct silofs_laddr *laddr)
{
	return lsegf_require_size_ge(lsegf, laddr->pos, laddr->len);
}

static int lsegf_check_size_ge(const struct silofs_lsegf *lsegf,
                               loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const ssize_t bsz = lsegf_size(lsegf);

	return (bsz >= end) ? 0 : -SILOFS_ERANGE;
}

static void lsegf_make_iovec(const struct silofs_lsegf *lsegf,
                             loff_t off, size_t len, struct silofs_iovec *siov)
{
	siov->iov_off = off;
	siov->iov_len = len;
	siov->iov_base = NULL;
	siov->iov_fd = lsegf->lsf_fd;
	siov->iov_backref = NULL;
}

static int lsegf_iovec_at(const struct silofs_lsegf *lsegf,
                          loff_t off, size_t len, struct silofs_iovec *siov)
{
	int err;

	err = lsegf_check_range(lsegf, off, len);
	if (!err) {
		lsegf_make_iovec(lsegf, off, len, siov);
	}
	return err;
}

static int lsegf_iovec_of(const struct silofs_lsegf *lsegf,
                          const struct silofs_laddr *laddr,
                          struct silofs_iovec *siov)
{
	return lsegf_iovec_at(lsegf, laddr->pos, laddr->len, siov);
}

static int lsegf_sync_range(const struct silofs_lsegf *lsegf,
                            loff_t off, size_t len)
{
	int err;

	err = do_sync_file_range(lsegf->lsf_fd, off, (loff_t)len,
	                         SYNC_FILE_RANGE_WAIT_BEFORE |
	                         SYNC_FILE_RANGE_WRITE |
	                         SYNC_FILE_RANGE_WAIT_AFTER);
	if (err && (err != -ENOSYS)) {
		return err;
	}
	return 0;
}

static int lsegf_pwriten(struct silofs_lsegf *lsegf, loff_t off,
                         const void *buf, size_t len)
{
	int err;

	err = lsegf_require_size_ge(lsegf, off, len);
	if (err) {
		return err;
	}
	err = lsegf_check_range(lsegf, off, len);
	if (err) {
		return err;
	}
	err = do_pwriten(lsegf->lsf_fd, buf, len, off);
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

static int lsegf_pwritevn(struct silofs_lsegf *lsegf, loff_t off,
                          const struct iovec *iov, size_t cnt)
{
	const size_t len = length_of(iov, cnt);
	int err;

	err = lsegf_require_size_ge(lsegf, off, len);
	if (err) {
		return err;
	}
	err = lsegf_check_range(lsegf, off, len);
	if (err) {
		return err;
	}
	err = do_pwritevn(lsegf->lsf_fd, iov, cnt, off);
	if (err) {
		return err;
	}
	return 0;
}

static int lsegf_writev(struct silofs_lsegf *lsegf, loff_t off,
                        const struct iovec *iov, size_t cnt, bool sync)
{
	size_t len = 0;
	int err;

	if (cnt == 1) {
		len = iov->iov_len;
		err = lsegf_pwriten(lsegf, off, iov->iov_base, len);
	} else {
		len = length_of(iov, cnt);
		err = lsegf_pwritevn(lsegf, off, iov, cnt);
	}
	if (!err && sync) {
		err = lsegf_sync_range(lsegf, off, len);
	}
	return err;
}

static int lsegf_load_bb(const struct silofs_lsegf *lsegf,
                         const struct silofs_laddr *laddr,
                         struct silofs_bytebuf *bb)
{
	struct silofs_iovec siov = { .iov_off = -1 };
	struct stat st;
	loff_t end;
	void *bobj;
	int err;

	err = lsegf_iovec_of(lsegf, laddr, &siov);
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

static int lsegf_load_buf(const struct silofs_lsegf *lsegf,
                          const struct silofs_laddr *laddr, void *buf)
{
	struct silofs_bytebuf bb;

	silofs_bytebuf_init(&bb, buf, laddr->len);
	return lsegf_load_bb(lsegf, laddr, &bb);
}

static int lsegf_check_laddr(const struct silofs_lsegf *lsegf,
                             const struct silofs_laddr *laddr)
{
	return lsegf_check_size_ge(lsegf, laddr->pos, laddr->len);
}

static int lsegf_punch_with_ftruncate(const struct silofs_lsegf *lsegf)
{
	int err;

	err = do_ftruncate(lsegf->lsf_fd, 0);
	if (err) {
		return err;
	}
	err = do_ftruncate(lsegf->lsf_fd, lsegf_size(lsegf));
	if (err) {
		return err;
	}
	return 0;
}

static int lsegf_punch_with_fallocate(const struct silofs_lsegf *lsegf,
                                      loff_t from, loff_t to)
{
	return do_fallocate_punch_hole(lsegf->lsf_fd, from, off_len(from, to));
}

static int lsegf_do_punch_all(const struct silofs_lsegf *lsegf)
{
	struct stat st;
	ssize_t len;
	int err;

	err = lsegf_stat(lsegf, &st);
	if (err) {
		goto out;
	}
	if (st.st_blocks == 0) {
		goto out; /* ok */
	}
	len = lsegf_size(lsegf);
	err = lsegf_punch_with_fallocate(lsegf, 0, len);
	if (err != -ENOTSUP) {
		goto out; /* ok-or-error */
	}
	err = lsegf_punch_with_ftruncate(lsegf);
out:
	return err;
}

static int lsegf_punch(struct silofs_lsegf *lsegf)
{
	return lsegf_do_punch_all(lsegf);
}

static int lsegf_fsync(struct silofs_lsegf *lsegf)
{
	return do_fsync(lsegf->lsf_fd);
}

static int lsegf_fsync2(struct silofs_lsegf *lsegf)
{
	return !lsegf->lsf_rdonly ? lsegf_fsync(lsegf) : 0;
}

static int lsegf_close(struct silofs_lsegf *lsegf)
{
	return do_closefd(&lsegf->lsf_fd);
}

static int lsegf_close2(struct silofs_lsegf *lsegf)
{
	int err1 = 0;
	int err2 = 0;

	if (lsegf->lsf_fd > 0) {
		err1 = lsegf_fsync2(lsegf);
		err2 = lsegf_close(lsegf);
	}
	return err1 ? err1 : err2;
}

static struct silofs_lsegf *
lsegf_new(struct silofs_alloc *alloc, const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegf *lsegf;
	int err;

	lsegf = silofs_memalloc(alloc, sizeof(*lsegf), SILOFS_ALLOCF_BZERO);
	if (lsegf == NULL) {
		return NULL;
	}
	err = lsegf_init(lsegf, lsegid);
	if (err) {
		silofs_memfree(alloc, lsegf, sizeof(*lsegf), 0);
		return NULL;
	}
	return lsegf;
}

static void lsegf_del(struct silofs_lsegf *lsegf, struct silofs_alloc *alloc)
{
	silofs_assert_eq(lsegf->lsf_refcnt, 0);

	lsegf_close2(lsegf);
	lsegf_fini(lsegf);
	silofs_memfree(alloc, lsegf, sizeof(*lsegf), 0);
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
                                const struct silofs_lsegid *lsegid)
{
	const uint64_t hash = silofs_lsegid_hash64(lsegid);

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
                  const struct silofs_lsegid *lsegid)
{
	const size_t slot = repo_htbl_slot_of(repo, lsegid);

	return repo_htbl_list_at(repo, slot);
}

static struct silofs_lsegf *
repo_htbl_lookup(const struct silofs_repo *repo,
                 const struct silofs_lsegid *lsegid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_lsegf *lsegf;

	lst = repo_htbl_list_of(repo, lsegid);
	itr = lst->next;
	while (itr != lst) {
		lsegf = lsegf_from_htb_link(itr);
		if (lsegf_has_id(lsegf, lsegid)) {
			return unconst(lsegf);
		}
		itr = itr->next;
	}
	return NULL;
}

static void repo_htbl_insert(struct silofs_repo *repo,
                             struct silofs_lsegf *lsegf)
{
	struct silofs_list_head *lst = repo_htbl_list_of(repo, &lsegf->lsf_id);

	list_push_front(lst, &lsegf->lsf_htb_lh);
	repo->re_htbl.rh_size += 1;
}

static void
repo_htbl_remove(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	silofs_assert_gt(repo->re_htbl.rh_size, 0);

	list_head_remove(&lsegf->lsf_htb_lh);
	repo->re_htbl.rh_size -= 1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_lruq_insert(struct silofs_repo *repo,
                             struct silofs_lsegf *lsegf)
{
	listq_push_front(&repo->re_lruq, &lsegf->lsf_lru_lh);
}

static void repo_lruq_remove(struct silofs_repo *repo,
                             struct silofs_lsegf *lsegf)
{
	listq_remove(&repo->re_lruq, &lsegf->lsf_lru_lh);
}

static void repo_lruq_requeue(struct silofs_repo *repo,
                              struct silofs_lsegf *lsegf)
{
	listq_remove(&repo->re_lruq, &lsegf->lsf_lru_lh);
	listq_push_front(&repo->re_lruq, &lsegf->lsf_lru_lh);
}

static struct silofs_lsegf *repo_lruq_back(const struct silofs_repo *repo)
{
	struct silofs_lsegf *lsegf = NULL;
	struct silofs_list_head *lh;

	lh = listq_back(&repo->re_lruq);
	if (lh != NULL) {
		lsegf = lsegf_from_lru_link(lh);
	}
	return lsegf;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_lock(struct silofs_repo *repo)
{
	silofs_mutex_lock(&repo->re_mutex);
}

static void repo_unlock(struct silofs_repo *repo)
{
	silofs_mutex_unlock(&repo->re_mutex);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
repo_create_lsegf(struct silofs_repo *repo,
                  const struct silofs_lsegid *lsegid,
                  struct silofs_lsegf **out_lsegf)
{
	struct silofs_lsegf *lsegf = NULL;

	lsegf = lsegf_new(repo->re.alloc, lsegid);
	if (lsegf == NULL) {
		return -SILOFS_ENOMEM;
	}
	repo_htbl_insert(repo, lsegf);
	repo_lruq_insert(repo, lsegf);
	*out_lsegf = lsegf;
	return 0;
}

static void repo_evict_lsegf(struct silofs_repo *repo,
                             struct silofs_lsegf *lsegf)
{
	silofs_assert(lsegf_is_evictable(lsegf));

	repo_htbl_remove(repo, lsegf);
	repo_lruq_remove(repo, lsegf);
	lsegf_del(lsegf, repo->re.alloc);
}

static struct silofs_lsegf *
repo_prevof(const struct silofs_repo *repo, const struct silofs_lsegf *lsegf)
{
	struct silofs_list_head *lh_prev;

	if (lsegf == NULL) {
		return repo_lruq_back(repo);
	}
	lh_prev = listq_prev(&repo->re_lruq, &lsegf->lsf_lru_lh);
	if (lh_prev != NULL) {
		return lsegf_from_lru_link(lh_prev);
	}
	return NULL;
}

static int repo_do_fsync_all(struct silofs_repo *repo)
{
	struct silofs_lsegf *lsegf;
	int ret = 0;
	int err;

	lsegf = repo_prevof(repo, NULL);
	while (lsegf != NULL) {
		err = lsegf_fsync2(lsegf);
		ret = err || ret;
		lsegf = repo_prevof(repo, lsegf);
	}
	return ret;
}

int silofs_repo_fsync_all(struct silofs_repo *repo)
{
	int err;

	repo_lock(repo);
	err = repo_do_fsync_all(repo);
	repo_unlock(repo);
	return err;
}

static void repo_evict_all(struct silofs_repo *repo)
{
	struct silofs_lsegf *lsegf;

	lsegf = repo_lruq_back(repo);
	while (lsegf != NULL) {
		repo_evict_lsegf(repo, lsegf);
		lsegf = repo_lruq_back(repo);
	}
}

static void repo_requeue_lsegf(struct silofs_repo *repo,
                               struct silofs_lsegf *lsegf)
{
	repo_lruq_requeue(repo, lsegf);
}

static void repo_evict_some(struct silofs_repo *repo, size_t niter_max)
{
	struct silofs_lsegf *lsegf = NULL;
	struct silofs_lsegf *lsegf_prev = NULL;
	size_t niter = min(niter_max, repo->re_lruq.sz);

	lsegf = repo_prevof(repo, NULL);
	while ((lsegf != NULL) && (niter-- > 0)) {
		lsegf_prev = repo_prevof(repo, lsegf);
		if (lsegf_is_evictable(lsegf)) {
			repo_evict_lsegf(repo, lsegf);
		} else {
			repo_requeue_lsegf(repo, lsegf);
		}
		lsegf = lsegf_prev;
	}
}

static void repo_evict_many(struct silofs_repo *repo)
{
	repo_evict_some(repo, repo->re_lruq.sz);
}

/*
 * TODO-0035: Define proper upper-bound.
 *
 * Have explicit upper-limit to cached lsegs, based on the process' rlimit
 * RLIMIT_NOFILE and memory limits.
 */
static void repo_try_evict_overpop(struct silofs_repo *repo)
{
	const size_t qcur = repo->re_lruq.sz;
	const size_t qmax = 256;

	if (qcur > qmax) {
		repo_evict_some(repo, min(qcur - qmax, 2));
	}
}

void silofs_repo_relax(struct silofs_repo *repo)
{
	repo_lock(repo);
	repo_evict_some(repo, 1);
	repo_unlock(repo);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_fetch_cached_lsegf(const struct silofs_repo *repo,
                                   const struct silofs_lsegid *lsegid,
                                   struct silofs_lsegf **out_lsegf)
{
	*out_lsegf = repo_htbl_lookup(repo, lsegid);
	return (*out_lsegf == NULL) ? -SILOFS_ENOENT : 0;
}

static int repo_fetch_cached_lsegf2(struct silofs_repo *repo,
                                    const struct silofs_lsegid *lsegid,
                                    struct silofs_lsegf **out_lsegf)
{
	*out_lsegf = repo_htbl_lookup(repo, lsegid);
	if (*out_lsegf == NULL) {
		return -SILOFS_ENOENT;
	}
	repo_requeue_lsegf(repo, *out_lsegf);
	return 0;
}

static int repo_create_cached_lsegf(struct silofs_repo *repo,
                                    const struct silofs_lsegid *lsegid,
                                    struct silofs_lsegf **out_lsegf)
{
	repo_try_evict_overpop(repo);
	return repo_create_lsegf(repo, lsegid, out_lsegf);
}

static void repo_forget_cached_lsegf(struct silofs_repo *repo,
                                     struct silofs_lsegf *lsegf)
{
	repo_evict_lsegf(repo, lsegf);
}

static void repo_try_evict_cached_lsegf(struct silofs_repo *repo,
                                        struct silofs_lsegf *lsegf)
{
	if (lsegf_is_evictable(lsegf)) {
		repo_evict_lsegf(repo, lsegf);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_objs_format_sub(const struct silofs_repo *repo, size_t idx)
{
	struct silofs_strbuf name;
	struct stat st = { .st_mode = 0 };
	const int dfd = repo->re_objs_dfd;
	int err;

	index_to_name(idx, &name);
	err = do_fstatat(dfd, name.str, &st, 0);
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_err("exists but not dir: %s", name.str);
			return -SILOFS_ENOTDIR;
		}
		err = do_faccessat(dfd, name.str, R_OK | X_OK, 0);
		if (err) {
			return err;
		}
	} else {
		err = do_mkdirat(dfd, name.str, 0700);
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

static void repo_hash_lsegid(const struct silofs_repo *repo,
                             const struct silofs_lsegid *lsegid,
                             struct silofs_hash256 *out_hash)
{
	struct silofs_lsegid32b lsegid32;
	const struct silofs_mdigest *md = &repo->re_mdigest;

	silofs_lsegid32b_htox(&lsegid32, lsegid);
	silofs_sha256_of(md, &lsegid32, sizeof(lsegid32), out_hash);
}

static int repo_objs_sub_pathname_of(const struct silofs_repo *repo,
                                     const struct silofs_lsegid *lsegid,
                                     struct silofs_strbuf *out_name)
{
	struct silofs_hash256 hash;
	size_t idx;

	idx = lsegid_to_index(lsegid, repo->re_defs->re_objs_nsubs);
	repo_hash_lsegid(repo, lsegid, &hash);

	return make_pathname(&hash, idx, out_name);
}

static void repo_objs_pathname_by(const struct silofs_repo *repo,
                                  const struct silofs_laddr *laddr,
                                  struct silofs_strbuf *out_name)
{
	repo_objs_sub_pathname_of(repo, &laddr->lsegid, out_name);
}

static int repo_objs_setup_pathname_of(const struct silofs_repo *repo,
                                       struct silofs_lsegf *lsegf)
{
	return repo_objs_sub_pathname_of(repo, &lsegf->lsf_id,
	                                 &lsegf->lsf_name);
}

static int repo_objs_require_nolseg(const struct silofs_repo *repo,
                                    const struct silofs_strbuf *sbuf)
{
	struct stat st = { .st_size = 0 };
	const int dfd = repo->re_objs_dfd;
	int err;

	err = do_fstatat(dfd, sbuf->str, &st, 0);
	if (err == 0) {
		log_err("lseg already exists: name=%s", sbuf->str);
		return -SILOFS_EEXIST;
	}
	if (err != -ENOENT) {
		log_err("lseg stat error: name=%s err=%d", sbuf->str, err);
		return err;
	}
	return 0;
}

static int repo_objs_create_lseg_of(const struct silofs_repo *repo,
                                    struct silofs_lsegf *lsegf)
{
	const int dfd = repo->re_objs_dfd;
	const int o_flags = O_CREAT | O_RDWR | O_TRUNC;
	int fd = -1;
	int err;

	err = do_openat(dfd, lsegf->lsf_name.str, o_flags, 0600, &fd);
	if (err) {
		return err;
	}
	lsegf_bindto(lsegf, fd, true);
	err = lsegf_reassign_size(lsegf, lsegf_capacity(lsegf));
	if (err) {
		do_unlinkat(dfd, lsegf->lsf_name.str, 0);
		return err;
	}
	return 0;
}

static int repo_objs_open_lseg_of(const struct silofs_repo *repo,
                                  struct silofs_lsegf *lsegf, bool rw)
{
	const int o_flags = rw ? O_RDWR : O_RDONLY;
	const int dfd = repo->re_objs_dfd;
	int fd = -1;
	int err;

	silofs_assert_lt(lsegf->lsf_fd, 0);

	err = do_openat(dfd, lsegf->lsf_name.str, o_flags, 0600, &fd);
	if (err) {
		/*
		 * TODO-0032: Consider using SILOFS_EFSCORRUPTED
		 *
		 * When higher layer wants to open a lseg, it should exist.
		 */
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	lsegf_bindto(lsegf, fd, rw);
	err = lsegf_inspect_size(lsegf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_objs_unlink_lseg(const struct silofs_repo *repo,
                                 const struct silofs_lsegid *lsegid)
{
	struct silofs_strbuf sbuf;
	struct stat st = { .st_size = -1 };
	const int dfd = repo->re_objs_dfd;
	int err;

	err = repo_objs_sub_pathname_of(repo, lsegid, &sbuf);
	if (err) {
		return err;
	}
	err = do_fstatat(dfd, sbuf.str, &st, 0);
	if (err) {
		log_dbg("can not unlink lseg: %s err=%d", sbuf.str, err);
		return err;
	}
	err = do_unlinkat(dfd, sbuf.str, 0);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_objs_open_lseg(struct silofs_repo *repo, bool rw,
                               const struct silofs_lsegid *lsegid,
                               struct silofs_lsegf **out_lsegf)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_create_cached_lsegf(repo, lsegid, &lsegf);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, lsegf);
	if (err) {
		goto out_err;
	}
	err = repo_objs_open_lseg_of(repo, lsegf, rw);
	if (err) {
		goto out_err;
	}
	*out_lsegf = lsegf;
	return 0;
out_err:
	repo_forget_cached_lsegf(repo, lsegf);
	return err;
}

static int repo_objs_stat_lseg(const struct silofs_repo *repo,
                               const struct silofs_lsegid *lsegid,
                               struct stat *out_st)
{
	struct silofs_strbuf sbuf;
	const int dfd = repo->re_objs_dfd;
	size_t len = 0;
	int err;

	err = repo_objs_sub_pathname_of(repo, lsegid, &sbuf);
	if (err) {
		return err;
	}
	err = do_fstatat(dfd, sbuf.str, out_st, 0);
	if (err) {
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	len = lsegid_size(lsegid);
	if (out_st->st_size > (loff_t)(len + SILOFS_LBK_SIZE)) {
		log_warn("lseg-size mismatch: %s len=%lu st_size=%ld",
		         sbuf.str, len, out_st->st_size);
		return -SILOFS_EIO;
	}
	return 0;
}

static int repo_objs_create_lseg(struct silofs_repo *repo,
                                 const struct silofs_lsegid *lsegid,
                                 struct silofs_lsegf **out_lsegf)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_create_cached_lsegf(repo, lsegid, &lsegf);
	if (err) {
		return err;
	}
	err = repo_objs_setup_pathname_of(repo, lsegf);
	if (err) {
		goto out_err;
	}
	err = repo_objs_require_nolseg(repo, &lsegf->lsf_name);
	if (err) {
		goto out_err;
	}
	err = repo_objs_create_lseg_of(repo, lsegf);
	if (err) {
		goto out_err;
	}
	*out_lsegf = lsegf;
	return 0;
out_err:
	repo_forget_cached_lsegf(repo, lsegf);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_check_root_dfd(const struct silofs_repo *repo)
{
	return likely(repo->re_root_dfd > 0) ? 0 : -SILOFS_EBADF;
}

static int repo_check_writable(const struct silofs_repo *repo)
{
	if (repo->re.flags & SILOFS_REPOF_RDONLY) {
		log_dbg("read-only repo: %s", repo->re.repodir.str);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_init_mdigest(struct silofs_repo *repo)
{
	return silofs_mdigest_init(&repo->re_mdigest);
}

static void repo_fini_mdigest(struct silofs_repo *repo)
{
	silofs_mdigest_fini(&repo->re_mdigest);
}

static int repo_init_mutex(struct silofs_repo *repo)
{
	return silofs_mutex_init(&repo->re_mutex);
}

static void repo_fini_mutex(struct silofs_repo *repo)
{
	silofs_mutex_fini(&repo->re_mutex);
}

static int repo_init_bstore(struct silofs_repo *repo)
{
	return silofs_bstore_init(&repo->re_bstore, repo->re.alloc);
}

static void repo_fini_bstore(struct silofs_repo *repo)
{
	silofs_bstore_fini(&repo->re_bstore);
}


int silofs_repo_init(struct silofs_repo *repo,
                     const struct silofs_repo_base *re_base)
{
	int err;

	memset(repo, 0, sizeof(*repo));
	memcpy(&repo->re, re_base, sizeof(repo->re));
	repo->re_defs = &repo_defs;
	listq_init(&repo->re_lruq);
	repo->re_root_dfd = -1;
	repo->re_dots_dfd = -1;
	repo->re_objs_dfd = -1;
	err = repo_init_mdigest(repo);
	if (err) {
		return err;
	}
	err = repo_htbl_init(repo);
	if (err) {
		goto out_err;
	}
	err = repo_init_mutex(repo);
	if (err) {
		goto out_err;
	}
	err = repo_init_bstore(repo);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	repo_fini_bstore(repo);
	repo_fini_mutex(repo);
	repo_fini_mdigest(repo);
	return err;
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	repo_close(repo);
	repo_evict_all(repo);
	repo_htbl_fini(repo);
	repo_fini_bstore(repo);
	repo_fini_mdigest(repo);
	repo_fini_mutex(repo);
	listq_fini(&repo->re_lruq);
}

void silofs_repo_drop_some(struct silofs_repo *repo)
{
	repo_lock(repo);
	repo_do_fsync_all(repo);
	repo_evict_many(repo);
	repo_unlock(repo);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_create_skel_subdir(const struct silofs_repo *repo,
                                   const char *name, mode_t mode)
{
	struct stat st = { .st_size = 0 };
	int err;

	err = do_mkdirat(repo->re_dots_dfd, name, mode);
	if (err && (err != -EEXIST)) {
		log_warn("repo mkdirat failed: name=%s mode=%o err=%d",
		         name, mode, err);
		return err;
	}
	err = do_fstatat(repo->re_dots_dfd, name, &st, 0);
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
	int fd = -1;
	int err;

	err = do_unlinkat(repo->re_dots_dfd, name, 0);
	if (err && (err != -ENOENT)) {
		return err;
	}
	err = do_openat(repo->re_dots_dfd, name, O_CREAT | O_RDWR, mode, &fd);
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
	const char *name = NULL;
	loff_t size = 0;
	int err;

	name = repo->re_defs->re_blobs_name;
	err = repo_create_skel_subdir(repo, name, 0700);
	if (err) {
		return err;
	}

	name = repo->re_defs->re_pack_name;
	err = repo_create_skel_subdir(repo, name, 0700);
	if (err) {
		return err;
	}

	name = repo->re_defs->re_objs_name;
	err = repo_create_skel_subdir(repo, name, 0700);
	if (err) {
		return err;
	}

	size = SILOFS_REPO_METAFILE_SIZE;
	name = repo->re_defs->re_meta_name;
	err = repo_create_skel_subfile(repo, name, 0600, size);
	if (err) {
		return err;
	}

	name = repo->re_defs->re_lock_name;
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
	int err;

	err = do_fstatat(repo->re_dots_dfd, name, &st, 0);
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
	const char *name = NULL;
	loff_t size;
	int err;

	err = do_access(repo->re.repodir.str, R_OK | W_OK | X_OK);
	if (err) {
		return err;
	}

	name = repo->re_defs->re_meta_name;
	size = SILOFS_REPO_METAFILE_SIZE;
	err = repo_require_skel_subfile(repo, name, size);
	if (err) {
		return err;
	}

	name = repo->re_defs->re_objs_name;
	err = repo_require_skel_subdir(repo, name);
	if (err) {
		return err;
	}

	name = repo->re_defs->re_blobs_name;
	err = repo_require_skel_subdir(repo, name);
	if (err) {
		return err;
	}

	name = repo->re_defs->re_pack_name;
	err = repo_require_skel_subdir(repo, name);
	if (err) {
		return err;
	}

	return 0;
}

static int repo_open_rootdir(struct silofs_repo *repo)
{
	int err;

	if (repo->re_root_dfd > 0) {
		return -SILOFS_EALREADY;
	}
	err = do_opendir(repo->re.repodir.str, &repo->re_root_dfd);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_create_dotsdir(const struct silofs_repo *repo)
{
	const char *name = repo->re_defs->re_dots_name;
	int err;

	err = do_mkdirat(repo->re_root_dfd, name, 0700);
	if (err && (err != -EEXIST)) {
		return err;
	}
	return 0;
}

static int repo_open_dotsdir(struct silofs_repo *repo)
{
	const char *name = repo->re_defs->re_dots_name;

	return do_opendirat(repo->re_root_dfd, name, &repo->re_dots_dfd);
}

static int repo_format_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name = repo->re_defs->re_meta_name;
	int fd = -1;
	int err;

	err = do_openat(repo->re_dots_dfd, name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	rmeta_init(&rmeta);
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

static int repo_format_lock(const struct silofs_repo *repo)
{
	char data[SILOFS_REPO_METAFILE_SIZE] = "SILOFS_LOCK\n";
	const char *name = repo->re_defs->re_lock_name;
	int fd = -1;
	int err;

	err = do_openat(repo->re_dots_dfd, name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	err = do_pwriten(fd, data, sizeof(data), 0);
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

static int repo_require_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name = repo->re_defs->re_meta_name;
	int fd = -1;
	int err;

	err = do_openat(repo->re_dots_dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		return err;
	}
	rmeta_init(&rmeta);
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

static int repo_require_lock(const struct silofs_repo *repo)
{
	char data[SILOFS_REPO_METAFILE_SIZE] = "";
	const char *name = repo->re_defs->re_lock_name;
	int fd = -1;
	int err;

	err = do_openat(repo->re_dots_dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		return err;
	}
	err = do_preadn(fd, data, sizeof(data), 0);
	if (err) {
		goto out;
	}
	err = strncmp(data, "SILOFS_LOCK", 11) ? -SILOFS_EBADREPO : 0;
out:
	do_closefd(&fd);
	return err;
}

static int repo_open_objs_dir(struct silofs_repo *repo)
{
	return do_opendirat(repo->re_dots_dfd,
	                    repo->re_defs->re_objs_name,
	                    &repo->re_objs_dfd);
}

static int repo_format_objs_subs(struct silofs_repo *repo)
{
	return repo_objs_format(repo);
}

static int repo_do_format(struct silofs_repo *repo)
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
	err = repo_open_objs_dir(repo);
	if (err) {
		return err;
	}
	err = repo_format_objs_subs(repo);
	if (err) {
		return err;
	}
	err = repo_format_meta(repo);
	if (err) {
		return err;
	}
	err = repo_format_lock(repo);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_format(struct silofs_repo *repo)
{
	int err;

	repo_lock(repo);
	err = repo_do_format(repo);
	repo_unlock(repo);
	return err;
}

static int repo_open_bstore(struct silofs_repo *repo)
{
	return silofs_bstore_openat(&repo->re_bstore,
	                            repo->re_dots_dfd,
	                            repo->re_defs->re_blobs_name);
}

static int repo_do_open(struct silofs_repo *repo)
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
	err = repo_require_lock(repo);
	if (err) {
		return err;
	}
	err = repo_open_objs_dir(repo);
	if (err) {
		return err;
	}
	err = repo_open_bstore(repo);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_open(struct silofs_repo *repo)
{
	int err;

	repo_lock(repo);
	err = repo_do_open(repo);
	repo_unlock(repo);
	return err;
}

static int repo_close_basedir(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_dots_dfd);
}

static int repo_close_rootdir(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_root_dfd);
}

static int repo_close_objs_dir(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_objs_dfd);
}

static int repo_close_bstore(struct silofs_repo *repo)
{
	return silofs_bstore_close(&repo->re_bstore);
}

static int repo_close(struct silofs_repo *repo)
{
	int err;

	err = repo_close_bstore(repo);
	if (err) {
		return err;
	}
	err = repo_close_objs_dir(repo);
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

static int repo_do_close(struct silofs_repo *repo)
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

int silofs_repo_close(struct silofs_repo *repo)
{
	int err;

	repo_lock(repo);
	err = repo_do_close(repo);
	repo_unlock(repo);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_do_stat_lseg(const struct silofs_repo *repo,
                             const struct silofs_lsegid *lsegid,
                             bool allow_cache, struct stat *out_st)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lsegf(repo, lsegid, &lsegf);
	if (!err && allow_cache) {
		return lsegf_stat(lsegf, out_st);
	}
	err = repo_objs_stat_lseg(repo, lsegid, out_st);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stat_lseg(struct silofs_repo *repo,
                          const struct silofs_lsegid *lsegid,
                          bool allow_cache, struct stat *out_st)
{
	int err;

	repo_lock(repo);
	err = repo_do_stat_lseg(repo, lsegid, allow_cache, out_st);
	repo_unlock(repo);
	return err;
}

static int repo_do_spawn_lseg(struct silofs_repo *repo,
                              const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lsegf2(repo, lsegid, &lsegf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_create_lseg(repo, lsegid, &lsegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_spawn_lseg(struct silofs_repo *repo,
                           const struct silofs_lsegid *lsegid)
{
	int err;

	repo_lock(repo);
	err = repo_do_spawn_lseg(repo, lsegid);
	repo_unlock(repo);
	return err;
}

static int repo_stage_lseg_of(struct silofs_repo *repo, bool rw,
                              const struct silofs_lsegid *lsegid,
                              struct silofs_lsegf **out_lsegf)
{
	int err;

	err = repo_fetch_cached_lsegf2(repo, lsegid, out_lsegf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_lseg(repo, rw, lsegid, out_lsegf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_do_stage_lseg(struct silofs_repo *repo, bool rw,
                              const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err  = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, rw, lsegid, &lsegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stage_lseg(struct silofs_repo *repo, bool rw,
                           const struct silofs_lsegid *lsegid)
{
	int err;

	repo_lock(repo);
	err = repo_do_stage_lseg(repo, rw, lsegid);
	repo_unlock(repo);
	return err;
}

static int repo_do_remove_lseg(struct silofs_repo *repo,
                               const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_objs_unlink_lseg(repo, lsegid);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lsegf(repo, lsegid, &lsegf);
	if (!err) {
		repo_try_evict_cached_lsegf(repo, lsegf);
	}
	return 0;
}

int silofs_repo_remove_lseg(struct silofs_repo *repo,
                            const struct silofs_lsegid *lsegid)
{
	int err;

	repo_lock(repo);
	err = repo_do_remove_lseg(repo, lsegid);
	repo_unlock(repo);
	return err;
}

static int repo_do_punch_lseg(struct silofs_repo *repo,
                              const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, true, lsegid, &lsegf);
	if (err) {
		return err;
	}
	err = lsegf_punch(lsegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_punch_lseg(struct silofs_repo *repo,
                           const struct silofs_lsegid *lsegid)
{
	int err;

	repo_lock(repo);
	err = repo_do_punch_lseg(repo, lsegid);
	repo_unlock(repo);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_do_require_laddr(struct silofs_repo *repo,
                                 const struct silofs_laddr *laddr)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, true, &laddr->lsegid, &lsegf);
	if (err) {
		return err;
	}
	err = lsegf_require_laddr(lsegf, laddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_require_laddr(struct silofs_repo *repo,
                              const struct silofs_laddr *laddr)
{
	int err;

	repo_lock(repo);
	err = repo_do_require_laddr(repo, laddr);
	repo_unlock(repo);
	return err;
}

static int repo_do_writev_at(struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             const struct iovec *iov, size_t cnt)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, true, &laddr->lsegid, &lsegf);
	if (err) {
		return err;
	}
	err = lsegf_writev(lsegf, laddr->pos, iov, cnt, false);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_writev_at(struct silofs_repo *repo,
                          const struct silofs_laddr *laddr,
                          const struct iovec *iov, size_t cnt)
{
	int err;

	repo_lock(repo);
	err = repo_do_writev_at(repo, laddr, iov, cnt);
	repo_unlock(repo);
	return err;
}

static int repo_do_read_at(struct silofs_repo *repo,
                           const struct silofs_laddr *laddr, void *buf)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, false, &laddr->lsegid, &lsegf);
	if (err) {
		return err;
	}
	err = lsegf_check_laddr(lsegf, laddr);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	err = lsegf_load_buf(lsegf, laddr, buf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_read_at(struct silofs_repo *repo,
                        const struct silofs_laddr *laddr, void *buf)
{
	int err;

	repo_lock(repo);
	err = repo_do_read_at(repo, laddr, buf);
	repo_unlock(repo);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int repo_stat_lobj_at(const struct silofs_repo *repo,
                             const struct silofs_strbuf *sbuf,
                             struct stat *out_st)
{
	return do_fstatat_reg(repo->re_objs_dfd, sbuf->str, out_st);
}

int silofs_repo_stat_lobj(struct silofs_repo *repo,
                          const struct silofs_laddr *laddr, ssize_t *out_sz)
{
	struct silofs_strbuf name;
	struct stat st = { .st_size = -1 };
	int err;

	repo_lock(repo);
	repo_objs_pathname_by(repo, laddr, &name);
	err = repo_stat_lobj_at(repo, &name, &st);
	*out_sz = st.st_size;
	repo_unlock(repo);
	return err;
}

static int repo_save_lobj_at(const struct silofs_repo *repo,
                             const struct silofs_strbuf *sbuf,
                             const void *dat, size_t len)
{
	return do_save_obj(repo->re_objs_dfd, sbuf->str, dat, len);
}

int silofs_repo_save_lobj(struct silofs_repo *repo,
                          const struct silofs_laddr *laddr, const void *buf)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_lock(repo);
	repo_objs_pathname_by(repo, laddr, &sbuf);
	err = repo_save_lobj_at(repo, &sbuf, buf, laddr->len);
	repo_unlock(repo);
	return err;
}

static int repo_load_lobj_at(const struct silofs_repo *repo,
                             const struct silofs_strbuf *sbuf,
                             void *buf, size_t len)
{
	const int dfd = repo->re_objs_dfd;
	int fd = -1;
	int err;

	err = do_openat(dfd, sbuf->str, O_RDONLY, 0, &fd);
	if (err) {
		goto out;
	}
	err = do_preadn(fd, buf, len, 0);
	if (err) {
		goto out;
	}
out:
	do_closefd(&fd);
	return (err == -ENOENT) ? -SILOFS_ENOBOOT : err;
}

int silofs_repo_load_lobj(struct silofs_repo *repo,
                          const struct silofs_laddr *laddr, void *buf)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_lock(repo);
	repo_objs_pathname_by(repo, laddr, &sbuf);
	err = repo_load_lobj_at(repo, &sbuf, buf, laddr->len);
	repo_unlock(repo);
	return err;
}

int silofs_repo_unlink_lobj(struct silofs_repo *repo,
                            const struct silofs_laddr *laddr)
{
	struct silofs_strbuf name;
	const int dfd = repo->re_objs_dfd;
	int err;

	repo_lock(repo);
	repo_objs_pathname_by(repo, laddr, &name);
	err = do_unlinkat(dfd, name.str, 0);
	repo_unlock(repo);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void repo_packid_pathname(const struct silofs_repo *repo,
                                 const struct silofs_packid *packid,
                                 struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf name;

	silofs_packid_to_name(packid, &name);
	silofs_strbuf_sprintf(out_sbuf, "%s/%s",
	                      repo->re_defs->re_pack_name, name.str);
}

static int repo_stat_pack_at(const struct silofs_repo *repo,
                             const struct silofs_strbuf *sbuf,
                             struct stat *out_st)
{
	return do_fstatat_reg(repo->re_dots_dfd, sbuf->str, out_st);
}

int silofs_repo_stat_pack(struct silofs_repo *repo,
                          const struct silofs_packid *packid, ssize_t *out_sz)
{
	struct silofs_strbuf name;
	struct stat st = { .st_size = -1 };
	int err;

	repo_packid_pathname(repo, packid, &name);
	repo_lock(repo);
	err = repo_stat_pack_at(repo, &name, &st);
	repo_unlock(repo);
	*out_sz = st.st_size;
	return err;
}

static int repo_save_pack_at(const struct silofs_repo *repo,
                             const struct silofs_strbuf *sbuf,
                             const struct silofs_bytebuf *bb)
{
	return do_save_obj(repo->re_dots_dfd, sbuf->str, bb->ptr, bb->len);
}

int silofs_repo_save_pack(struct silofs_repo *repo,
                          const struct silofs_packid *packid,
                          const struct silofs_bytebuf *bb)
{
	struct silofs_strbuf name;
	int err;

	repo_packid_pathname(repo, packid, &name);
	repo_lock(repo);
	err = repo_save_pack_at(repo, &name, bb);
	repo_unlock(repo);
	return err;
}
