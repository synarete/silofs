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
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/ps.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>

#define RCEK_PSID 1
#define RCEK_LSID 2

/* repo cached element key */
struct silofs_repo_cek {
	union {
		struct silofs_lsid lsid;
		struct silofs_psid psid;
	} u;
	int kind;
};

/* repo cached element */
struct silofs_repo_ce {
	struct silofs_repo_cek rce_key;
	struct silofs_list_head rce_htb_lh;
	struct silofs_list_head rce_lru_lh;
};

/* persistent-segment control file */
struct silofs_psegf {
	struct silofs_repo_ce psf_rce;
	ssize_t psf_size;
	int psf_fd;
};

/* logical-segment control file */
struct silofs_lsegf {
	struct silofs_repo_ce lsf_rce;
	ssize_t lsf_size;
	int lsf_fd;
	bool lsf_rdonly;
};

/* well-know repository meta file-names and sub-directories */
struct silofs_repo_defs {
	const char *re_dots_name;
	const char *re_meta_name;
	const char *re_lock_name;
	const char *re_refs_name;
	const char *re_blobs_name;
	const char *re_pack_name;
	const char *re_objs_name;
	uint32_t re_objs_nsubs;
	uint32_t re_pack_nsubs;
};

static const struct silofs_repo_defs repo_defs = {
	.re_dots_name = SILOFS_REPO_DOTS_DIRNAME,
	.re_meta_name = SILOFS_REPO_META_FILENAME,
	.re_lock_name = SILOFS_REPO_LOCK_FILENAME,
	.re_refs_name = SILOFS_REPO_REFS_DIRNAME,
	.re_blobs_name = SILOFS_REPO_BLOBS_DIRNAME,
	.re_pack_name = SILOFS_REPO_PACK_DIRNAME,
	.re_objs_name = SILOFS_REPO_OBJS_DIRNAME,
	.re_objs_nsubs = SILOFS_REPO_OBJS_NSUBS,
	.re_pack_nsubs = SILOFS_REPO_OBJS_NSUBS, /* TODO: use dedicated def */
};

/* local functions */
static int repo_close(struct silofs_repo *repo);
static void
repo_evict_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf);

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
		log_dbg("bad repo meta: version=%x", version);
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
		log_warn("unlinkat error: dfd=%d pathname=%s err=%d", dfd,
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

static int
do_sync_file_range(int fd, loff_t off, loff_t nbytes, unsigned int flags)
{
	int err;

	err = silofs_sys_sync_file_range(fd, off, nbytes, flags);
	if (err && (err != -ENOSYS)) {
		log_warn("sync_file_range error: fd=%d off=%ld nbytes=%ld "
		         "flags=%u err=%d",
		         fd, off, nbytes, flags, err);
	}
	return err;
}

static int do_pwriten(int fd, const void *buf, size_t cnt, loff_t off)
{
	int err;

	err = silofs_sys_pwriten(fd, buf, cnt, off);
	if (err) {
		log_warn("pwriten error: fd=%d cnt=%lu off=%ld err=%d", fd,
		         cnt, off, err);
	}
	return err;
}

static int do_pwritevn(int fd, const struct iovec *iov, size_t cnt, loff_t off)
{
	int err;

	err = silofs_sys_pwritevn(fd, iov, (int)cnt, off);
	if (err) {
		log_warn("pwritevn error: fd=%d cnt=%lu off=%ld err=%d", fd,
		         cnt, off, err);
	}
	return err;
}

static int do_preadn(int fd, void *buf, size_t cnt, loff_t off)
{
	int err;

	err = silofs_sys_preadn(fd, buf, cnt, off);
	if (err) {
		log_warn("preadn error: fd=%d cnt=%lu off=%ld err=%d", fd, cnt,
		         off, err);
	}
	return err;
}

static int do_ftruncate(int fd, loff_t len)
{
	int err;

	err = silofs_sys_ftruncate(fd, len);
	if (err) {
		log_warn("ftruncate error: fd=%d len=%ld err=%d", fd, len,
		         err);
	}
	return err;
}

static int do_fallocate(int fd, int mode, loff_t off, loff_t len)
{
	int err;

	err = silofs_sys_fallocate(fd, mode, off, len);
	if (err && (err != -ENOTSUP)) {
		log_warn("fallocate error: fd=%d mode=%o "
		         "off=%ld len=%ld err=%d",
		         fd, mode, off, len, err);
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

static int
do_fstatat(int dirfd, const char *pathname, struct stat *st, int flags)
{
	int err;

	err = silofs_sys_fstatat(dirfd, pathname, st, flags);
	if (err && (err != -ENOENT)) {
		log_warn("fstatat error: dirfd=%d pathname=%s flags=%d err=%d",
		         dirfd, pathname, flags, err);
	}
	return err;
}

static int do_fstatat_dir(int dirfd, const char *pathname, struct stat *out_st)
{
	mode_t mode;
	int err;

	err = do_fstatat(dirfd, pathname, out_st, 0);
	if (err) {
		return err;
	}
	mode = out_st->st_mode;
	if (!S_ISDIR(mode)) {
		return -SILOFS_ENOTDIR;
	}
	return 0;
}

static int do_fstatat_dir2(int dirfd, const char *pathname)
{
	struct stat st = { .st_size = -1 };

	return do_fstatat_dir(dirfd, pathname, &st);
}

static int do_fstatat_reg(int dirfd, const char *pathname, struct stat *out_st)
{
	mode_t mode;
	int err;

	err = do_fstatat(dirfd, pathname, out_st, 0);
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
		log_warn("opendirat error: dirfd=%d pathname=%s err=%d", dirfd,
		         pathname, err);
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
		log_warn("access error: path=%s mode=0x%x err=%d", path, mode,
		         err);
	}
	return err;
}

static int do_faccessat(int dirfd, const char *pathname, int mode, int flags)
{
	int err;

	err = silofs_sys_faccessat(dirfd, pathname, mode, flags);
	if (err) {
		log_warn("faccessat error: dirfd=%d pathname=%s "
		         "mode=0%o flags=%d err=%d",
		         dirfd, pathname, mode, flags, err);
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

static int do_fstatat_or_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	struct stat st = { .st_mode = 0 };
	int err;

	err = do_fstatat_dir(dirfd, pathname, &st);
	return err ? do_mkdirat(dirfd, pathname, mode) : 0;
}

static int do_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
	int err;

	err = silofs_sys_fchmodat(dirfd, pathname, mode, flags);
	if (err && (err != -ENOENT)) {
		log_warn("fchmodat error: dirfd=%d pathname=%s mode=0%o "
		         "err=%d",
		         dirfd, pathname, mode, err);
	}
	return err;
}

static int
do_save_obj(int dirfd, const char *pathname, const void *dat, size_t len)
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
	if (len == 0) {
		goto out; /* ok -- zero length object */
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

static int do_load_obj(int dirfd, const char *pathname, void *dat, size_t len)
{
	int fd = -1;
	int err;

	err = do_openat(dirfd, pathname, O_RDONLY, 0, &fd);
	if (err) {
		goto out;
	}
	err = do_preadn(fd, dat, len, 0);
	if (err) {
		goto out;
	}
out:
	do_closefd(&fd);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t lsid_to_index(const struct silofs_lsid *lsid, uint32_t index_max)
{
	const uint64_t h = silofs_lsid_hash64(lsid);

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
	struct silofs_strbuf sbuf;
	const size_t nmax = sizeof(out_name->str);
	int n;

	silofs_hash256_to_name(hash, &sbuf);
	n = snprintf(out_name->str, nmax, "%02x/%s", (int)idx, sbuf.str);
	return (n < (int)nmax) ? 0 : -SILOFS_EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo_ce *rce_unconst(const struct silofs_repo_ce *p)
{
	union {
		const struct silofs_repo_ce *p;
		struct silofs_repo_ce *q;
	} u = { .p = p };
	return u.q;
}

static struct silofs_repo_ce *
rce_from_htb_link(const struct silofs_list_head *lh)
{
	const struct silofs_repo_ce *rce;

	rce = container_of2(lh, struct silofs_repo_ce, rce_htb_lh);
	return rce_unconst(rce);
}

static struct silofs_repo_ce *
rce_from_lru_link(const struct silofs_list_head *lh)
{
	const struct silofs_repo_ce *rce;

	rce = container_of2(lh, struct silofs_repo_ce, rce_lru_lh);
	return rce_unconst(rce);
}

static void
rce_init1(struct silofs_repo_ce *rce, const struct silofs_psid *psid)
{
	silofs_list_head_init(&rce->rce_htb_lh);
	silofs_list_head_init(&rce->rce_lru_lh);
	silofs_psid_assign(&rce->rce_key.u.psid, psid);
	rce->rce_key.kind = RCEK_PSID;
}

static void
rce_init2(struct silofs_repo_ce *rce, const struct silofs_lsid *lsid)
{
	silofs_list_head_init(&rce->rce_htb_lh);
	silofs_list_head_init(&rce->rce_lru_lh);
	silofs_lsid_assign(&rce->rce_key.u.lsid, lsid);
	rce->rce_key.kind = RCEK_LSID;
}

static void rce_fini(struct silofs_repo_ce *rce)
{
	silofs_list_head_fini(&rce->rce_htb_lh);
	silofs_list_head_fini(&rce->rce_lru_lh);
	silofs_lsid_reset(&rce->rce_key.u.lsid);
	rce->rce_key.kind = -1;
}

static bool
rce_has_psid(const struct silofs_repo_ce *rce, const struct silofs_psid *psid)
{
	return (rce->rce_key.kind == RCEK_PSID) &&
	       silofs_psid_isequal(&rce->rce_key.u.psid, psid);
}

static bool
rce_has_lsid(const struct silofs_repo_ce *rce, const struct silofs_lsid *lsid)
{
	return (rce->rce_key.kind == RCEK_LSID) &&
	       silofs_lsid_isequal(&rce->rce_key.u.lsid, lsid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_psegf *psegf_from_rce(const struct silofs_repo_ce *rce)
{
	const struct silofs_psegf *psegf;

	psegf = container_of2(rce, struct silofs_psegf, psf_rce);
	return unconst(psegf);
}

static int
psegf_init(struct silofs_psegf *psegf, const struct silofs_psid *psid)
{
	rce_init1(&psegf->psf_rce, psid);
	psegf->psf_size = 0;
	psegf->psf_fd = -1;
	return 0;
}

static void psegf_fini(struct silofs_psegf *psegf)
{
	rce_fini(&psegf->psf_rce);
	psegf->psf_size = -1;
	psegf->psf_fd = -1;
}

static int psegf_openat(struct silofs_psegf *psegf, int dfd, const char *name,
                        bool creat_mode)
{
	const int o_flags = creat_mode ? (O_CREAT | O_RDWR | O_TRUNC) : O_RDWR;

	silofs_assert_eq(psegf->psf_fd, -1);
	return do_openat(dfd, name, o_flags, 0600, &psegf->psf_fd);
}

static int psegf_close(struct silofs_psegf *psegf)
{
	return do_closefd(&psegf->psf_fd);
}

static int psegf_fsync(const struct silofs_psegf *psegf)
{
	return do_fsync(psegf->psf_fd);
}

static int psegf_pwriten(const struct silofs_psegf *psegf, loff_t off,
                         const void *buf, size_t len)
{
	return do_pwriten(psegf->psf_fd, buf, len, off);
}

static int psegf_preadn(const struct silofs_psegf *psegf, loff_t off,
                        void *buf, size_t len)
{
	return do_preadn(psegf->psf_fd, buf, len, off);
}

static int psegf_truncate(const struct silofs_psegf *psegf, ssize_t len)
{
	return do_ftruncate(psegf->psf_fd, len);
}

static int psegf_sync(const struct silofs_psegf *psegf)
{
	return do_fsync(psegf->psf_fd);
}

static struct silofs_psegf *
psegf_new(struct silofs_alloc *alloc, const struct silofs_psid *psid)
{
	struct silofs_psegf *psegf;
	int err;

	psegf = silofs_memalloc(alloc, sizeof(*psegf), SILOFS_ALLOCF_BZERO);
	if (psegf == NULL) {
		return NULL;
	}
	err = psegf_init(psegf, psid);
	if (err) {
		silofs_memfree(alloc, psegf, sizeof(*psegf), 0);
		return NULL;
	}
	return psegf;
}

static void psegf_del(struct silofs_psegf *psegf, struct silofs_alloc *alloc)
{
	psegf_close(psegf);
	psegf_fini(psegf);
	silofs_memfree(alloc, psegf, sizeof(*psegf), 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lsegf *lsegf_from_rce(const struct silofs_repo_ce *rce)
{
	const struct silofs_lsegf *lsegf;

	lsegf = container_of2(rce, struct silofs_lsegf, lsf_rce);
	return unconst(lsegf);
}

static int
lsegf_init(struct silofs_lsegf *lsegf, const struct silofs_lsid *lsid)
{
	rce_init2(&lsegf->lsf_rce, lsid);
	lsegf->lsf_size = 0;
	lsegf->lsf_fd = -1;
	lsegf->lsf_rdonly = false;
	return 0;
}

static void lsegf_fini(struct silofs_lsegf *lsegf)
{
	rce_fini(&lsegf->lsf_rce);
	lsegf->lsf_size = -1;
	lsegf->lsf_fd = -1;
}

static ssize_t lsegf_capacity(const struct silofs_lsegf *lsegf)
{
	const struct silofs_lsid *lsid = &lsegf->lsf_rce.rce_key.u.lsid;

	return (ssize_t)lsid_size(lsid);
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

static int
lsegf_check_range(const struct silofs_lsegf *lsegf, loff_t off, size_t len)
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
		log_warn("lseg-size not aligned: size=%ld", st.st_size);
		return -SILOFS_ELSEG;
	}
	cap = lsegf_capacity(lsegf);
	if (st.st_size > (cap + SILOFS_LBK_SIZE)) {
		log_warn("lseg-size mismatch: size=%ld cap=%ld", st.st_size,
		         cap);
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

static int
lsegf_require_size_ge(struct silofs_lsegf *lsegf, loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t nxt = off_next_lbk(off);
	const ssize_t want_size = off_max(end, nxt);
	const ssize_t curr_size = lsegf_size(lsegf);

	return (curr_size >= want_size) ?
	               0 :
	               lsegf_reassign_size(lsegf, want_size);
}

static int lsegf_require_laddr(struct silofs_lsegf *lsegf,
                               const struct silofs_laddr *laddr)
{
	return lsegf_require_size_ge(lsegf, laddr->pos, laddr->len);
}

static int
lsegf_check_size_ge(const struct silofs_lsegf *lsegf, loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const ssize_t bsz = lsegf_size(lsegf);

	return (bsz >= end) ? 0 : -SILOFS_ERANGE;
}

static void lsegf_make_iovec(const struct silofs_lsegf *lsegf, loff_t off,
                             size_t len, struct silofs_iovec *iov)
{
	iov->iov.iov_len = len;
	iov->iov.iov_base = NULL;
	iov->iov_off = off;
	iov->iov_fd = lsegf->lsf_fd;
	iov->iov_backref = NULL;
}

static int lsegf_iovec_at(const struct silofs_lsegf *lsegf, loff_t off,
                          size_t len, struct silofs_iovec *siov)
{
	int err;

	err = lsegf_check_range(lsegf, off, len);
	if (!err) {
		lsegf_make_iovec(lsegf, off, len, siov);
	}
	return err;
}

static int
lsegf_iovec_of(const struct silofs_lsegf *lsegf,
               const struct silofs_laddr *laddr, struct silofs_iovec *siov)
{
	return lsegf_iovec_at(lsegf, laddr->pos, laddr->len, siov);
}

static int
lsegf_sync_range(const struct silofs_lsegf *lsegf, loff_t off, size_t len)
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

static int
lsegf_load_bb(const struct silofs_lsegf *lsegf,
              const struct silofs_laddr *laddr, struct silofs_bytebuf *bb)
{
	struct silofs_iovec iovec = { .iov_off = -1 };
	struct stat st;
	loff_t end;
	void *bobj;
	int err;

	err = lsegf_iovec_of(lsegf, laddr, &iovec);
	if (err) {
		return err;
	}
	if (!silofs_bytebuf_has_free(bb, !iovec.iov.iov_len)) {
		return -SILOFS_EINVAL;
	}
	err = do_fstat(iovec.iov_fd, &st);
	if (err) {
		return err;
	}
	silofs_assert_eq(st.st_size % SILOFS_KB_SIZE, 0);

	bobj = silofs_bytebuf_end(bb);
	end = off_end(iovec.iov_off, iovec.iov.iov_len);
	if (end > st.st_size) {
		silofs_memzero(bobj, iovec.iov.iov_len);
		goto out;
	}
	err = do_preadn(iovec.iov_fd, bobj, iovec.iov.iov_len, iovec.iov_off);
	if (err) {
		return err;
	}
out:
	bb->len += iovec.iov.iov_len;
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

static int lsegf_fsync(const struct silofs_lsegf *lsegf)
{
	return do_fsync(lsegf->lsf_fd);
}

static int lsegf_fsync2(const struct silofs_lsegf *lsegf)
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
lsegf_new(struct silofs_alloc *alloc, const struct silofs_lsid *lsid)
{
	struct silofs_lsegf *lsegf;
	int err;

	lsegf = silofs_memalloc(alloc, sizeof(*lsegf), SILOFS_ALLOCF_BZERO);
	if (lsegf == NULL) {
		return NULL;
	}
	err = lsegf_init(lsegf, lsid);
	if (err) {
		silofs_memfree(alloc, lsegf, sizeof(*lsegf), 0);
		return NULL;
	}
	return lsegf;
}

static void lsegf_del(struct silofs_lsegf *lsegf, struct silofs_alloc *alloc)
{
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
		silofs_lista_del(repo->re_htbl.rh_arr, repo->re_htbl.rh_nelems,
		                 repo->re.alloc);
		repo->re_htbl.rh_arr = NULL;
		repo->re_htbl.rh_nelems = 0;
		repo->re_htbl.rh_size = 0;
	}
}

static size_t repo_htbl_slot_of_psid(const struct silofs_repo *repo,
                                     const struct silofs_psid *psid)
{
	const uint64_t hash = silofs_psid_hash64(psid);

	return hash % repo->re_htbl.rh_nelems;
}

static size_t repo_htbl_slot_of_lsid(const struct silofs_repo *repo,
                                     const struct silofs_lsid *lsid)
{
	const uint64_t hash = silofs_lsid_hash64(lsid);

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
repo_htbl_list_of_psid(const struct silofs_repo *repo,
                       const struct silofs_psid *psid)
{
	const size_t slot = repo_htbl_slot_of_psid(repo, psid);

	return repo_htbl_list_at(repo, slot);
}

static struct silofs_list_head *
repo_htbl_list_of_lsid(const struct silofs_repo *repo,
                       const struct silofs_lsid *lsid)
{
	const size_t slot = repo_htbl_slot_of_lsid(repo, lsid);

	return repo_htbl_list_at(repo, slot);
}

static struct silofs_psegf *
repo_htbl_lookup_psegf(const struct silofs_repo *repo,
                       const struct silofs_psid *psid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_repo_ce *rce;
	const struct silofs_psegf *psegf;

	lst = repo_htbl_list_of_psid(repo, psid);
	itr = lst->next;
	while (itr != lst) {
		rce = rce_from_htb_link(itr);
		if (rce_has_psid(rce, psid)) {
			psegf = psegf_from_rce(rce);
			return unconst(psegf);
		}
		itr = itr->next;
	}
	return NULL;
}

static struct silofs_lsegf *
repo_htbl_lookup_lsegf(const struct silofs_repo *repo,
                       const struct silofs_lsid *lsid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_repo_ce *rce;
	const struct silofs_lsegf *lsegf;

	lst = repo_htbl_list_of_lsid(repo, lsid);
	itr = lst->next;
	while (itr != lst) {
		rce = rce_from_htb_link(itr);
		if (rce_has_lsid(rce, lsid)) {
			lsegf = lsegf_from_rce(rce);
			return unconst(lsegf);
		}
		itr = itr->next;
	}
	return NULL;
}

static void
repo_htbl_insert_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	struct silofs_repo_ce *rce = &psegf->psf_rce;
	struct silofs_list_head *lst;

	lst = repo_htbl_list_of_psid(repo, &rce->rce_key.u.psid);
	list_push_front(lst, &rce->rce_htb_lh);
	repo->re_htbl.rh_size += 1;
}

static void
repo_htbl_insert_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	struct silofs_repo_ce *rce = &lsegf->lsf_rce;
	struct silofs_list_head *lst;

	lst = repo_htbl_list_of_lsid(repo, &rce->rce_key.u.lsid);
	list_push_front(lst, &rce->rce_htb_lh);
	repo->re_htbl.rh_size += 1;
}

static void
repo_htbl_remove(struct silofs_repo *repo, struct silofs_repo_ce *rce)
{
	silofs_assert_gt(repo->re_htbl.rh_size, 0);

	list_head_remove(&rce->rce_htb_lh);
	repo->re_htbl.rh_size -= 1;
}

static void
repo_htbl_remove_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	repo_htbl_remove(repo, &psegf->psf_rce);
}

static void
repo_htbl_remove_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	repo_htbl_remove(repo, &lsegf->lsf_rce);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
repo_lruq_insert(struct silofs_repo *repo, struct silofs_repo_ce *rce)
{
	listq_push_front(&repo->re_lruq, &rce->rce_lru_lh);
}

static void
repo_lruq_insert_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	repo_lruq_insert(repo, &psegf->psf_rce);
}

static void
repo_lruq_insert_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	repo_lruq_insert(repo, &lsegf->lsf_rce);
}

static void
repo_lruq_remove(struct silofs_repo *repo, struct silofs_repo_ce *rce)
{
	listq_remove(&repo->re_lruq, &rce->rce_lru_lh);
}

static void
repo_lruq_remove_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	repo_lruq_remove(repo, &psegf->psf_rce);
}

static void
repo_lruq_remove_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	repo_lruq_remove(repo, &lsegf->lsf_rce);
}

static bool repo_lruq_isfront(const struct silofs_repo *repo,
                              const struct silofs_repo_ce *rce)
{
	const struct silofs_list_head *lruq_front;

	lruq_front = silofs_listq_front(&repo->re_lruq);
	return lruq_front == &rce->rce_lru_lh;
}

static void
repo_lruq_requeue(struct silofs_repo *repo, struct silofs_repo_ce *rce)
{
	if (!repo_lruq_isfront(repo, rce)) {
		listq_remove(&repo->re_lruq, &rce->rce_lru_lh);
		listq_push_front(&repo->re_lruq, &rce->rce_lru_lh);
	}
}

static void
repo_lruq_requeue_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	repo_lruq_requeue(repo, &psegf->psf_rce);
}

static void
repo_lruq_requeue_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	repo_lruq_requeue(repo, &lsegf->lsf_rce);
}

static struct silofs_repo_ce *repo_lruq_back(const struct silofs_repo *repo)
{
	struct silofs_repo_ce *rce = NULL;
	struct silofs_list_head *lh;

	lh = listq_back(&repo->re_lruq);
	if (lh != NULL) {
		rce = rce_from_lru_link(lh);
	}
	return rce;
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
repo_create_lsegf(struct silofs_repo *repo, const struct silofs_lsid *lsid,
                  struct silofs_lsegf **out_lsegf)
{
	struct silofs_lsegf *lsegf = NULL;

	lsegf = lsegf_new(repo->re.alloc, lsid);
	if (lsegf == NULL) {
		return -SILOFS_ENOMEM;
	}
	repo_htbl_insert_lsegf(repo, lsegf);
	repo_lruq_insert_lsegf(repo, lsegf);
	*out_lsegf = lsegf;
	return 0;
}

static void
repo_evict_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	repo_htbl_remove_lsegf(repo, lsegf);
	repo_lruq_remove_lsegf(repo, lsegf);
	lsegf_del(lsegf, repo->re.alloc);
}

static struct silofs_repo_ce *
repo_prevof(const struct silofs_repo *repo, const struct silofs_repo_ce *rce)
{
	struct silofs_list_head *lh_prev;

	if (rce == NULL) {
		return repo_lruq_back(repo);
	}
	lh_prev = listq_prev(&repo->re_lruq, &rce->rce_lru_lh);
	if (lh_prev != NULL) {
		return rce_from_lru_link(lh_prev);
	}
	return NULL;
}

static int repo_do_fsync_all(struct silofs_repo *repo)
{
	const struct silofs_repo_ce *rce = NULL;
	const struct silofs_psegf *psegf = NULL;
	const struct silofs_lsegf *lsegf = NULL;
	int ret = 0;
	int err = 0;

	rce = repo_prevof(repo, NULL);
	while (rce != NULL) {
		if (rce->rce_key.kind == RCEK_PSID) {
			psegf = psegf_from_rce(rce);
			err = psegf_fsync(psegf);
		} else if (rce->rce_key.kind == RCEK_LSID) {
			lsegf = lsegf_from_rce(rce);
			err = lsegf_fsync2(lsegf);
		} else {
			silofs_panic("bad lruq: kind=%d", rce->rce_key.kind);
		}
		ret = err || ret;
		rce = repo_prevof(repo, rce);
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

static void
repo_evict_one(struct silofs_repo *repo, struct silofs_repo_ce *rce)
{
	struct silofs_psegf *psegf = NULL;
	struct silofs_lsegf *lsegf = NULL;

	if (rce->rce_key.kind == RCEK_PSID) {
		psegf = psegf_from_rce(rce);
		repo_evict_psegf(repo, psegf);
	} else if (rce->rce_key.kind == RCEK_LSID) {
		lsegf = lsegf_from_rce(rce);
		repo_evict_lsegf(repo, lsegf);
	} else {
		silofs_panic("bad lruq: kind=%d", rce->rce_key.kind);
	}
}

static void repo_evict_all(struct silofs_repo *repo)
{
	struct silofs_repo_ce *rce = NULL;

	rce = repo_lruq_back(repo);
	while (rce != NULL) {
		repo_evict_one(repo, rce);
		rce = repo_lruq_back(repo);
	}
}

static void
repo_requeue_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	repo_lruq_requeue_psegf(repo, psegf);
}

static void
repo_requeue_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	repo_lruq_requeue_lsegf(repo, lsegf);
}

static void repo_evict_some(struct silofs_repo *repo, size_t niter_max)
{
	struct silofs_repo_ce *rce = NULL;
	struct silofs_repo_ce *rce_prev = NULL;
	size_t niter = min(niter_max, repo->re_lruq.sz);

	rce = repo_prevof(repo, NULL);
	while ((rce != NULL) && (niter-- > 0)) {
		rce_prev = repo_prevof(repo, rce);
		repo_evict_one(repo, rce);
		rce = rce_prev;
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

static int
repo_create_psegf(struct silofs_repo *repo, const struct silofs_psid *psid,
                  struct silofs_psegf **out_psegf)
{
	struct silofs_psegf *psegf = NULL;

	psegf = psegf_new(repo->re.alloc, psid);
	if (psegf == NULL) {
		return -SILOFS_ENOMEM;
	}
	repo_htbl_insert_psegf(repo, psegf);
	repo_lruq_insert_psegf(repo, psegf);
	*out_psegf = psegf;
	return 0;
}

static void
repo_evict_psegf(struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	repo_htbl_remove_psegf(repo, psegf);
	repo_lruq_remove_psegf(repo, psegf);
	psegf_del(psegf, repo->re.alloc);
}

static int repo_create_cached_psegf(struct silofs_repo *repo,
                                    const struct silofs_psid *psid,
                                    struct silofs_psegf **out_psegf)
{
	repo_try_evict_overpop(repo);
	return repo_create_psegf(repo, psid, out_psegf);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_fetch_cached_lsegf(const struct silofs_repo *repo,
                                   const struct silofs_lsid *lsid,
                                   struct silofs_lsegf **out_lsegf)
{
	*out_lsegf = repo_htbl_lookup_lsegf(repo, lsid);
	return (*out_lsegf == NULL) ? -SILOFS_ENOENT : 0;
}

static int repo_fetch_cached_lsegf2(struct silofs_repo *repo,
                                    const struct silofs_lsid *lsid,
                                    struct silofs_lsegf **out_lsegf)
{
	*out_lsegf = repo_htbl_lookup_lsegf(repo, lsid);
	if (*out_lsegf == NULL) {
		return -SILOFS_ENOENT;
	}
	repo_requeue_lsegf(repo, *out_lsegf);
	return 0;
}

static int repo_create_cached_lsegf(struct silofs_repo *repo,
                                    const struct silofs_lsid *lsid,
                                    struct silofs_lsegf **out_lsegf)
{
	repo_try_evict_overpop(repo);
	return repo_create_lsegf(repo, lsid, out_lsegf);
}

static void
repo_forget_cached_lsegf(struct silofs_repo *repo, struct silofs_lsegf *lsegf)
{
	repo_evict_lsegf(repo, lsegf);
}

static void repo_try_evict_cached_lsegf(struct silofs_repo *repo,
                                        struct silofs_lsegf *lsegf)
{
	repo_evict_lsegf(repo, lsegf);
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

static void
repo_hash_lsid(const struct silofs_repo *repo, const struct silofs_lsid *lsid,
               struct silofs_hash256 *out_hash)
{
	struct silofs_lsid32b lsid32;
	const struct silofs_mdigest *md = &repo->re_mdigest;

	silofs_lsid32b_htox(&lsid32, lsid);
	silofs_sha256_of(md, &lsid32, sizeof(lsid32), out_hash);
}

static int repo_objs_sub_pathname_of(const struct silofs_repo *repo,
                                     const struct silofs_lsid *lsid,
                                     struct silofs_strbuf *out_name)
{
	struct silofs_hash256 hash;
	size_t idx;

	idx = lsid_to_index(lsid, repo->re_defs->re_objs_nsubs);
	repo_hash_lsid(repo, lsid, &hash);

	return make_pathname(&hash, idx, out_name);
}

static int repo_objs_pathname_of(const struct silofs_repo *repo,
                                 const struct silofs_lsegf *lsegf,
                                 struct silofs_strbuf *out_sbuf)
{
	const struct silofs_repo_ce *rce = &lsegf->lsf_rce;
	const struct silofs_lsid *lsid = &rce->rce_key.u.lsid;

	return repo_objs_sub_pathname_of(repo, lsid, out_sbuf);
}

static int repo_objs_require_notexists(const struct silofs_repo *repo,
                                       const struct silofs_lsegf *lsegf)
{
	struct silofs_strbuf sbuf;
	struct stat st = { .st_size = 0 };
	const int dfd = repo->re_objs_dfd;
	int err;

	err = repo_objs_pathname_of(repo, lsegf, &sbuf);
	if (err) {
		return err;
	}
	err = do_fstatat(dfd, sbuf.str, &st, 0);
	if (err == 0) {
		log_err("lseg already exists: name=%s", sbuf.str);
		return -SILOFS_EEXIST;
	}
	if (err != -ENOENT) {
		log_err("lseg stat error: name=%s err=%d", sbuf.str, err);
		return err;
	}
	return 0;
}

static int repo_objs_create_lseg_of(const struct silofs_repo *repo,
                                    struct silofs_lsegf *lsegf)
{
	struct silofs_strbuf sbuf;
	const int dfd = repo->re_objs_dfd;
	const int o_flags = O_CREAT | O_RDWR | O_TRUNC;
	int fd = -1;
	int err;

	err = repo_objs_pathname_of(repo, lsegf, &sbuf);
	if (err) {
		return err;
	}
	err = do_openat(dfd, sbuf.str, o_flags, 0600, &fd);
	if (err) {
		return err;
	}
	lsegf_bindto(lsegf, fd, true);
	err = lsegf_reassign_size(lsegf, lsegf_capacity(lsegf));
	if (err) {
		do_unlinkat(dfd, sbuf.str, 0);
		return err;
	}
	return 0;
}

static int repo_objs_open_lseg_of(const struct silofs_repo *repo,
                                  struct silofs_lsegf *lsegf, bool rw)
{
	struct silofs_strbuf sbuf;
	const int o_flags = rw ? O_RDWR : O_RDONLY;
	const int dfd = repo->re_objs_dfd;
	int fd = -1;
	int err;

	silofs_assert_lt(lsegf->lsf_fd, 0);

	err = repo_objs_pathname_of(repo, lsegf, &sbuf);
	if (err) {
		return err;
	}

	err = do_openat(dfd, sbuf.str, o_flags, 0600, &fd);
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
                                 const struct silofs_lsid *lsid)
{
	struct silofs_strbuf sbuf;
	struct stat st = { .st_size = -1 };
	const int dfd = repo->re_objs_dfd;
	int err;

	err = repo_objs_sub_pathname_of(repo, lsid, &sbuf);
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
                               const struct silofs_lsid *lsid,
                               struct silofs_lsegf **out_lsegf)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_create_cached_lsegf(repo, lsid, &lsegf);
	if (err) {
		return err;
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

static int
repo_objs_stat_lseg(const struct silofs_repo *repo,
                    const struct silofs_lsid *lsid, struct stat *out_st)
{
	struct silofs_strbuf sbuf;
	const int dfd = repo->re_objs_dfd;
	size_t len = 0;
	int err;

	err = repo_objs_sub_pathname_of(repo, lsid, &sbuf);
	if (err) {
		return err;
	}
	err = do_fstatat(dfd, sbuf.str, out_st, 0);
	if (err) {
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	len = lsid_size(lsid);
	if (out_st->st_size > (loff_t)(len + SILOFS_LBK_SIZE)) {
		log_warn("lseg-size mismatch: %s len=%lu st_size=%ld",
		         sbuf.str, len, out_st->st_size);
		return -SILOFS_EIO;
	}
	return 0;
}

static int
repo_objs_create_lseg(struct silofs_repo *repo, const struct silofs_lsid *lsid,
                      struct silofs_lsegf **out_lsegf)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_create_cached_lsegf(repo, lsid, &lsegf);
	if (err) {
		return err;
	}
	err = repo_objs_require_notexists(repo, lsegf);
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

static int repo_check_wopen(const struct silofs_repo *repo)
{
	return repo_check_open(repo, true);
}

static int repo_check_ropen(const struct silofs_repo *repo)
{
	return repo_check_open(repo, false);
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
	return 0;
out_err:
	repo_fini_mutex(repo);
	repo_fini_mdigest(repo);
	return err;
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	repo_close(repo);
	repo_evict_all(repo);
	repo_htbl_fini(repo);
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
		log_warn("repo mkdirat failed: name=%s mode=%o err=%d", name,
		         mode, err);
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

	name = repo->re_defs->re_refs_name;
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

static int
repo_require_skel_subdir(const struct silofs_repo *repo, const char *name)
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

	name = repo->re_defs->re_refs_name;
	err = repo_require_skel_subdir(repo, name);
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
	return do_opendirat(repo->re_dots_dfd, repo->re_defs->re_objs_name,
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

static int repo_close(struct silofs_repo *repo)
{
	int err;

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
                             const struct silofs_lsid *lsid, bool allow_cache,
                             struct stat *out_st)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lsegf(repo, lsid, &lsegf);
	if (!err && allow_cache) {
		return lsegf_stat(lsegf, out_st);
	}
	err = repo_objs_stat_lseg(repo, lsid, out_st);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stat_lseg(struct silofs_repo *repo,
                          const struct silofs_lsid *lsid, bool allow_cache,
                          struct stat *out_st)
{
	int err;

	repo_lock(repo);
	err = repo_do_stat_lseg(repo, lsid, allow_cache, out_st);
	repo_unlock(repo);
	return err;
}

static int
repo_do_spawn_lseg(struct silofs_repo *repo, const struct silofs_lsid *lsid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lsegf2(repo, lsid, &lsegf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_create_lseg(repo, lsid, &lsegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_spawn_lseg(struct silofs_repo *repo,
                           const struct silofs_lsid *lsid)
{
	int err;

	repo_lock(repo);
	err = repo_do_spawn_lseg(repo, lsid);
	repo_unlock(repo);
	return err;
}

static int repo_stage_lseg_of(struct silofs_repo *repo, bool rw,
                              const struct silofs_lsid *lsid,
                              struct silofs_lsegf **out_lsegf)
{
	int err;

	err = repo_fetch_cached_lsegf2(repo, lsid, out_lsegf);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_objs_open_lseg(repo, rw, lsid, out_lsegf);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_do_stage_lseg(struct silofs_repo *repo, bool rw,
                              const struct silofs_lsid *lsid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, rw, lsid, &lsegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stage_lseg(struct silofs_repo *repo, bool rw,
                           const struct silofs_lsid *lsid)
{
	int err;

	repo_lock(repo);
	err = repo_do_stage_lseg(repo, rw, lsid);
	repo_unlock(repo);
	return err;
}

static int
repo_do_remove_lseg(struct silofs_repo *repo, const struct silofs_lsid *lsid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_objs_unlink_lseg(repo, lsid);
	if (err) {
		return err;
	}
	err = repo_fetch_cached_lsegf(repo, lsid, &lsegf);
	if (!err) {
		repo_try_evict_cached_lsegf(repo, lsegf);
	}
	return 0;
}

int silofs_repo_remove_lseg(struct silofs_repo *repo,
                            const struct silofs_lsid *lsid)
{
	int err;

	repo_lock(repo);
	err = repo_do_remove_lseg(repo, lsid);
	repo_unlock(repo);
	return err;
}

static int
repo_do_punch_lseg(struct silofs_repo *repo, const struct silofs_lsid *lsid)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, true, lsid, &lsegf);
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
                           const struct silofs_lsid *lsid)
{
	int err;

	repo_lock(repo);
	err = repo_do_punch_lseg(repo, lsid);
	repo_unlock(repo);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_do_spawn_stage_lseg(struct silofs_repo *repo,
                                    const struct silofs_lsid *lsid)
{
	int err;

	err = repo_do_spawn_lseg(repo, lsid);
	if (err) {
		return err;
	}
	err = repo_do_stage_lseg(repo, true, lsid);
	if (err) {
		return err;
	}
	return 0;
}

static int
repo_do_require_lseg(struct silofs_repo *repo, const struct silofs_lsid *lsid)
{
	struct stat st = { .st_ino = 0 };
	int err;

	err = repo_do_stat_lseg(repo, lsid, true, &st);
	if (!err) {
		err = repo_do_stage_lseg(repo, true, lsid);
	} else if (err == -SILOFS_ENOENT) {
		err = repo_do_spawn_stage_lseg(repo, lsid);
	}
	return err;
}

int silofs_repo_require_lseg(struct silofs_repo *repo,
                             const struct silofs_lsid *lsid)
{
	int err;

	repo_lock(repo);
	err = repo_do_require_lseg(repo, lsid);
	repo_unlock(repo);
	return err;
}

static int repo_do_require_laddr(struct silofs_repo *repo,
                                 const struct silofs_laddr *laddr)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, false);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, true, &laddr->lsid, &lsegf);
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

static int
repo_do_writev_at(struct silofs_repo *repo, const struct silofs_laddr *laddr,
                  const struct iovec *iov, size_t cnt)
{
	struct silofs_lsegf *lsegf = NULL;
	int err;

	err = repo_check_open(repo, true);
	if (err) {
		return err;
	}
	err = repo_stage_lseg_of(repo, true, &laddr->lsid, &lsegf);
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

int silofs_repo_write_at(struct silofs_repo *repo,
                         const struct silofs_laddr *laddr, const void *buf)
{
	const struct iovec iov = {
		.iov_base = unconst(buf),
		.iov_len = laddr->len,
	};

	return silofs_repo_writev_at(repo, laddr, &iov, 1);
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
	err = repo_stage_lseg_of(repo, false, &laddr->lsid, &lsegf);
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

static int
repo_stat_subdir(const struct silofs_repo *repo,
                 const struct silofs_strbuf *sbuf, struct stat *out_st)
{
	return do_fstatat_dir(repo->re_dots_dfd, sbuf->str, out_st);
}

static int repo_stat_reg(const struct silofs_repo *repo,
                         const struct silofs_strbuf *sbuf, struct stat *out_st)
{
	return do_fstatat_reg(repo->re_dots_dfd, sbuf->str, out_st);
}

static void repo_cobj_subdir_of(const struct silofs_repo *repo,
                                const struct silofs_caddr *caddr,
                                struct silofs_strbuf *out_sbuf)
{
	silofs_unused(caddr);
	silofs_strbuf_setup_by(out_sbuf, repo->re_defs->re_blobs_name);
}

static void repo_cobj_pathname_of(const struct silofs_repo *repo,
                                  const struct silofs_caddr *caddr,
                                  struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf subdir;
	struct silofs_strbuf name;

	repo_cobj_subdir_of(repo, caddr, &subdir);
	silofs_hash256_to_name(&caddr->hash, &name);
	silofs_strbuf_sprintf(out_sbuf, "%s/%s", subdir.str, name.str);
}

static int
repo_stat_cobj_of(const struct silofs_repo *repo,
                  const struct silofs_caddr *caddr, struct stat *out_st)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_cobj_subdir_of(repo, caddr, &sbuf);
	err = repo_stat_subdir(repo, &sbuf, out_st);
	if (err) {
		return err;
	}
	repo_cobj_pathname_of(repo, caddr, &sbuf);
	err = repo_stat_reg(repo, &sbuf, out_st);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stat_cobj(struct silofs_repo *repo,
                          const struct silofs_caddr *caddr, size_t *out_sz)
{
	struct stat st = { .st_size = -1 };
	int err;

	repo_lock(repo);
	err = repo_stat_cobj_of(repo, caddr, &st);
	repo_unlock(repo);
	*out_sz = (size_t)(st.st_size);
	return err;
}

static int repo_save_cobj_at(const struct silofs_repo *repo,
                             const struct silofs_strbuf *sbuf,
                             const struct silofs_rovec *rovec)
{
	return do_save_obj(repo->re_dots_dfd, sbuf->str, rovec->rov_base,
	                   rovec->rov_len);
}

int silofs_repo_save_cobj(struct silofs_repo *repo,
                          const struct silofs_caddr *caddr,
                          const struct silofs_rovec *rovec)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_cobj_pathname_of(repo, caddr, &sbuf);
	repo_lock(repo);
	err = repo_save_cobj_at(repo, &sbuf, rovec);
	repo_unlock(repo);
	return err;
}

static int
repo_load_cobj_at(const struct silofs_repo *repo,
                  const struct silofs_strbuf *sbuf, struct silofs_rwvec *rwvec)
{
	return do_load_obj(repo->re_dots_dfd, sbuf->str, rwvec->rwv_base,
	                   rwvec->rwv_len);
}

int silofs_repo_load_cobj(struct silofs_repo *repo,
                          const struct silofs_caddr *caddr,
                          struct silofs_rwvec *rwvec)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_cobj_pathname_of(repo, caddr, &sbuf);
	repo_lock(repo);
	err = repo_load_cobj_at(repo, &sbuf, rwvec);
	repo_unlock(repo);
	return err;
}

static int repo_unlink_cobj_at(const struct silofs_repo *repo,
                               const struct silofs_strbuf *sbuf)
{
	return do_unlinkat(repo->re_dots_dfd, sbuf->str, 0);
}

int silofs_repo_unlink_cobj(struct silofs_repo *repo,
                            const struct silofs_caddr *caddr)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_cobj_pathname_of(repo, caddr, &sbuf);
	repo_lock(repo);
	err = repo_unlink_cobj_at(repo, &sbuf);
	repo_unlock(repo);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_ref_pathname_of(const struct silofs_repo *repo,
                                 const struct silofs_caddr *caddr,
                                 struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf name;

	silofs_caddr_to_name(caddr, &name);
	silofs_strbuf_sprintf(out_sbuf, "%s/%s", repo->re_defs->re_refs_name,
	                      name.str);
}

static int repo_create_ref(const struct silofs_repo *repo,
                           const struct silofs_caddr *caddr)
{
	struct silofs_strbuf sbuf;

	repo_ref_pathname_of(repo, caddr, &sbuf);
	return do_save_obj(repo->re_dots_dfd, sbuf.str, NULL, 0);
}

int silofs_repo_create_ref(struct silofs_repo *repo,
                           const struct silofs_caddr *caddr)
{
	int err;

	repo_lock(repo);
	err = repo_create_ref(repo, caddr);
	repo_unlock(repo);
	return err;
}

static int repo_remove_ref(const struct silofs_repo *repo,
                           const struct silofs_caddr *caddr)
{
	struct silofs_strbuf sbuf;

	repo_ref_pathname_of(repo, caddr, &sbuf);
	return do_unlinkat(repo->re_dots_dfd, sbuf.str, 0);
}

int silofs_repo_remove_ref(struct silofs_repo *repo,
                           const struct silofs_caddr *caddr)
{
	int err;

	repo_lock(repo);
	err = repo_remove_ref(repo, caddr);
	repo_unlock(repo);
	return err;
}

static int repo_stat_ref(const struct silofs_repo *repo,
                         const struct silofs_caddr *caddr, struct stat *out_st)
{
	struct silofs_strbuf sbuf;

	repo_ref_pathname_of(repo, caddr, &sbuf);
	return do_fstatat(repo->re_dots_dfd, sbuf.str, out_st, 0);
}

int silofs_repo_lookup_ref(struct silofs_repo *repo,
                           const struct silofs_caddr *caddr)
{
	struct stat st = { .st_size = 0 };
	int err;

	repo_lock(repo);
	err = repo_stat_ref(repo, caddr, &st);
	repo_unlock(repo);

	return (!err && st.st_size) ? -SILOFS_EBADREF : err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_pseg_pathname(const struct silofs_repo *repo,
                               const struct silofs_psid *psid,
                               struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf sbuf;
	const char *dname = repo->re_defs->re_blobs_name;

	silofs_psid_to_str(psid, &sbuf);
	silofs_strbuf_sprintf(out_sbuf, "%s/%s", dname, sbuf.str);
}

static int repo_fetch_cached_psegf(const struct silofs_repo *repo,
                                   const struct silofs_psid *psid,
                                   struct silofs_psegf **out_psegf)
{
	*out_psegf = repo_htbl_lookup_psegf(repo, psid);
	return (*out_psegf != NULL) ? 0 : -SILOFS_ENOENT;
}

static int repo_fetch_cached_psegf2(struct silofs_repo *repo,
                                    const struct silofs_psid *psid,
                                    struct silofs_psegf **out_psegf)
{
	int err;

	err = repo_fetch_cached_psegf(repo, psid, out_psegf);
	if (!err) {
		repo_requeue_psegf(repo, *out_psegf);
	}
	return err;
}

static int repo_stat_pseg(const struct silofs_repo *repo,
                          const struct silofs_psid *psid, struct stat *out_st)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_pseg_pathname(repo, psid, &sbuf);
	err = do_fstatat(repo->re_dots_dfd, sbuf.str, out_st, 0);
	if (err) {
		return (err == -ENOENT) ? -SILOFS_ENOENT : err;
	}
	if (!S_ISREG(out_st->st_mode)) {
		return -SILOFS_EBADREPO;
	}
	return 0;
}

int silofs_repo_stat_pseg(struct silofs_repo *repo,
                          const struct silofs_psid *psid, struct stat *out_st)
{
	int err;

	repo_lock(repo);
	err = repo_stat_pseg(repo, psid, out_st);
	repo_unlock(repo);
	return err;
}

static int repo_stat_no_pseg(const struct silofs_repo *repo,
                             const struct silofs_psid *psid)
{
	struct stat st;
	int ret = 0;
	int err;

	err = repo_stat_pseg(repo, psid, &st);
	if (!err) {
		ret = -SILOFS_EEXIST;
	} else if (err != -SILOFS_ENOENT) {
		ret = err;
	}
	return ret;
}

static int
repo_create_pseg_of(const struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	struct silofs_strbuf sbuf;
	const struct silofs_psid *psid = &psegf->psf_rce.rce_key.u.psid;

	repo_pseg_pathname(repo, psid, &sbuf);
	return psegf_openat(psegf, repo->re_dots_dfd, sbuf.str, true);
}

static int
repo_spawn_pseg(struct silofs_repo *repo, const struct silofs_psid *psid,
                struct silofs_psegf **out_psegf)
{
	struct silofs_psegf *psegf = NULL;
	int err;

	err = repo_create_cached_psegf(repo, psid, &psegf);
	if (err) {
		return err;
	}
	err = repo_create_pseg_of(repo, psegf);
	if (err) {
		repo_evict_psegf(repo, psegf);
		return err;
	}
	*out_psegf = psegf;
	return 0;
}

static int repo_check_no_pseg(const struct silofs_repo *repo,
                              const struct silofs_psid *psid)
{
	struct silofs_psegf *psegf = NULL;
	int err;

	err = repo_fetch_cached_psegf(repo, psid, &psegf);
	if (!err) {
		return -SILOFS_EEXIST;
	}
	err = repo_stat_no_pseg(repo, psid);
	if (err) {
		return err;
	}
	return 0;
}

static int
repo_create_pseg(struct silofs_repo *repo, const struct silofs_psid *psid)
{
	struct silofs_psegf *psegf = NULL;
	int err;

	err = repo_check_wopen(repo);
	if (err) {
		return err;
	}
	err = repo_check_no_pseg(repo, psid);
	if (err) {
		return err;
	}
	err = repo_spawn_pseg(repo, psid, &psegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_create_pseg(struct silofs_repo *repo,
                            const struct silofs_psid *psid)
{
	int err;

	repo_lock(repo);
	err = repo_create_pseg(repo, psid);
	repo_unlock(repo);
	return err;
}

static int repo_check_has_pseg(const struct silofs_repo *repo,
                               const struct silofs_psid *psid)
{
	struct stat st;
	struct silofs_psegf *psegf = NULL;
	int err;

	err = repo_fetch_cached_psegf(repo, psid, &psegf);
	if (!err) {
		return 0; /* ok -- cached */
	}
	err = repo_stat_pseg(repo, psid, &st);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_check_has_pseg_of(const struct silofs_repo *repo,
                                  const struct silofs_paddr *paddr)
{
	return repo_check_has_pseg(repo, &paddr->psid);
}

static int
repo_open_pseg_of(const struct silofs_repo *repo, struct silofs_psegf *psegf)
{
	struct silofs_strbuf sbuf;
	const struct silofs_psid *psid = &psegf->psf_rce.rce_key.u.psid;

	repo_pseg_pathname(repo, psid, &sbuf);
	return psegf_openat(psegf, repo->re_dots_dfd, sbuf.str, false);
}

static int
repo_do_stage_pseg(struct silofs_repo *repo, const struct silofs_psid *psid,
                   struct silofs_psegf **out_psegf)
{
	struct silofs_psegf *psegf = NULL;
	int err;

	err = repo_fetch_cached_psegf2(repo, psid, out_psegf);
	if (!err) {
		repo_requeue_psegf(repo, *out_psegf);
		return 0; /* OK -- cached */
	}
	err = repo_create_cached_psegf(repo, psid, &psegf);
	if (err) {
		return err;
	}
	err = repo_open_pseg_of(repo, psegf);
	if (err) {
		repo_evict_psegf(repo, psegf);
		return err;
	}
	*out_psegf = psegf;
	return 0;
}

static int
repo_stage_pseg_of(struct silofs_repo *repo, const struct silofs_paddr *paddr,
                   struct silofs_psegf **out_psegf)
{
	return repo_do_stage_pseg(repo, &paddr->psid, out_psegf);
}

static int
repo_stage_pseg(struct silofs_repo *repo, const struct silofs_psid *psid,
                struct silofs_psegf **out_psegf)
{
	int err;

	err = repo_check_wopen(repo);
	if (err) {
		return err;
	}
	err = repo_check_has_pseg(repo, psid);
	if (err) {
		return err;
	}
	err = repo_do_stage_pseg(repo, psid, out_psegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stage_pseg(struct silofs_repo *repo,
                           const struct silofs_psid *psid)
{
	struct silofs_psegf *psegf = NULL;
	int err;

	repo_lock(repo);
	err = repo_stage_pseg(repo, psid, &psegf);
	repo_unlock(repo);
	return err;
}

static int
repo_save_pobj(struct silofs_repo *repo, const struct silofs_paddr *paddr,
               const struct silofs_rovec *rovec)
{
	struct silofs_psegf *psegf = NULL;
	const size_t len = min(paddr->len, rovec->rov_len);
	int err;

	err = repo_check_wopen(repo);
	if (err) {
		return err;
	}
	err = repo_check_has_pseg_of(repo, paddr);
	if (err) {
		return err;
	}
	err = repo_stage_pseg_of(repo, paddr, &psegf);
	if (err) {
		return err;
	}
	err = psegf_pwriten(psegf, paddr->off, rovec->rov_base, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_save_pobj(struct silofs_repo *repo,
                          const struct silofs_paddr *paddr,
                          const struct silofs_rovec *rovec)
{
	int err;

	repo_lock(repo);
	err = repo_save_pobj(repo, paddr, rovec);
	repo_unlock(repo);
	return err;
}

static int
repo_load_pobj(struct silofs_repo *repo, const struct silofs_paddr *paddr,
               const struct silofs_rwvec *rwvec)
{
	struct silofs_psegf *psegf = NULL;
	const size_t len = min(paddr->len, rwvec->rwv_len);
	int err;

	err = repo_check_ropen(repo);
	if (err) {
		return err;
	}
	err = repo_check_has_pseg_of(repo, paddr);
	if (err) {
		return err;
	}
	err = repo_stage_pseg_of(repo, paddr, &psegf);
	if (err) {
		return err;
	}
	err = psegf_preadn(psegf, paddr->off, rwvec->rwv_base, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_load_pobj(struct silofs_repo *repo,
                          const struct silofs_paddr *paddr,
                          const struct silofs_rwvec *rwvec)
{
	int err;

	repo_lock(repo);
	err = repo_load_pobj(repo, paddr, rwvec);
	repo_unlock(repo);
	return err;
}

static int
repo_unlink_pseg_of(struct silofs_repo *repo, const struct silofs_psegf *psegf)
{
	struct silofs_strbuf sbuf;
	const struct silofs_psid *psid = &psegf->psf_rce.rce_key.u.psid;

	repo_pseg_pathname(repo, psid, &sbuf);
	return do_unlinkat(repo->re_dots_dfd, sbuf.str, 0);
}

static int
repo_remove_pseg(struct silofs_repo *repo, const struct silofs_psid *psid)
{
	struct silofs_psegf *psegf = NULL;
	int err;

	err = repo_check_wopen(repo);
	if (err) {
		return err;
	}
	err = repo_check_has_pseg(repo, psid);
	if (err) {
		return err;
	}
	err = repo_do_stage_pseg(repo, psid, &psegf);
	if (err) {
		return err;
	}
	err = psegf_truncate(psegf, 0);
	if (err) {
		return err;
	}
	err = repo_unlink_pseg_of(repo, psegf);
	if (err) {
		return err;
	}
	repo_evict_psegf(repo, psegf);
	return 0;
}

int silofs_repo_remove_pseg(struct silofs_repo *repo,
                            const struct silofs_psid *psid)
{
	int err;

	repo_lock(repo);
	err = repo_remove_pseg(repo, psid);
	repo_unlock(repo);
	return err;
}

static int
repo_flush_pseg(struct silofs_repo *repo, const struct silofs_psid *psid)
{
	struct silofs_psegf *psegf = NULL;
	int err;

	err = repo_check_wopen(repo);
	if (err) {
		return err;
	}
	err = repo_check_has_pseg(repo, psid);
	if (err) {
		return err;
	}
	err = repo_do_stage_pseg(repo, psid, &psegf);
	if (err) {
		return err;
	}
	err = psegf_sync(psegf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_flush_pseg(struct silofs_repo *repo,
                           const struct silofs_psid *psid)
{
	int err;

	repo_lock(repo);
	err = repo_flush_pseg(repo, psid);
	repo_unlock(repo);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void repo_pack_subdir_of(const struct silofs_repo *repo,
                                const struct silofs_caddr *caddr,
                                struct silofs_strbuf *out_sbuf)
{
	const uint32_t u = silofs_caddr_to_u32(caddr);
	const uint32_t i = u % repo->re_defs->re_pack_nsubs;

	silofs_strbuf_sprintf(out_sbuf, "%s/%02x", repo->re_defs->re_pack_name,
	                      (int)i);
}

static void repo_pack_pathname_of(const struct silofs_repo *repo,
                                  const struct silofs_caddr *caddr,
                                  struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf subdir;
	struct silofs_strbuf name;

	repo_pack_subdir_of(repo, caddr, &subdir);
	silofs_caddr_to_name(caddr, &name);
	silofs_strbuf_sprintf(out_sbuf, "%s/%s", subdir.str, name.str);
}

static int
repo_stat_pack_of(const struct silofs_repo *repo,
                  const struct silofs_caddr *caddr, struct stat *out_st)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_pack_subdir_of(repo, caddr, &sbuf);
	err = repo_stat_subdir(repo, &sbuf, out_st);
	if (err) {
		return err;
	}
	repo_pack_pathname_of(repo, caddr, &sbuf);
	err = repo_stat_reg(repo, &sbuf, out_st);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_stat_pack(struct silofs_repo *repo,
                          const struct silofs_caddr *caddr, ssize_t *out_sz)
{
	struct stat st = { .st_size = -1 };
	int err;

	repo_lock(repo);
	err = repo_stat_pack_of(repo, caddr, &st);
	repo_unlock(repo);
	*out_sz = st.st_size;
	return err;
}

static int repo_save_pack_of(const struct silofs_repo *repo,
                             const struct silofs_caddr *caddr,
                             const struct silofs_rovec *rov)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_pack_subdir_of(repo, caddr, &sbuf);
	err = do_fstatat_or_mkdirat(repo->re_dots_dfd, sbuf.str, 0700);
	if (err) {
		return err;
	}
	repo_pack_pathname_of(repo, caddr, &sbuf);
	err = do_save_obj(repo->re_dots_dfd, sbuf.str, rov->rov_base,
	                  rov->rov_len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_save_pack(struct silofs_repo *repo,
                          const struct silofs_caddr *caddr,
                          const struct silofs_rovec *rov)
{
	int err;

	repo_lock(repo);
	err = repo_save_pack_of(repo, caddr, rov);
	repo_unlock(repo);
	return err;
}

static int repo_load_pack_of(const struct silofs_repo *repo,
                             const struct silofs_caddr *caddr,
                             const struct silofs_rwvec *rwv)
{
	struct silofs_strbuf sbuf;
	int err;

	repo_pack_subdir_of(repo, caddr, &sbuf);
	err = do_fstatat_dir2(repo->re_dots_dfd, sbuf.str);
	if (err) {
		return err;
	}
	repo_pack_pathname_of(repo, caddr, &sbuf);
	err = do_load_obj(repo->re_dots_dfd, sbuf.str, rwv->rwv_base,
	                  rwv->rwv_len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_repo_load_pack(struct silofs_repo *repo,
                          const struct silofs_caddr *caddr,
                          const struct silofs_rwvec *rwv)
{
	int err;

	repo_lock(repo);
	err = repo_load_pack_of(repo, caddr, rwv);
	repo_unlock(repo);
	return err;
}
