/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>

#include <silofs/infra.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>

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
	rmeta_set_version(rm, SILOFS_REPO_REVISION);
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
	if (version != SILOFS_REPO_REVISION) {
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

static int do_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	int err;

	err = silofs_sys_mkdirat(dirfd, pathname, mode);
	if (err && (err != -EEXIST)) {
		log_warn("mkdirat error: dirfd=%d pathname=%s mode=0%o err=%d",
		         dirfd, pathname, mode, err);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void repo_lock(struct silofs_repo *repo)
{
	silofs_mutex_lock(&repo->re_mutex);
}

static void repo_unlock(struct silofs_repo *repo)
{
	silofs_mutex_unlock(&repo->re_mutex);
}

int silofs_repo_fsync_all(struct silofs_repo *repo)
{
	int err;

	repo_lock(repo);
	err = silofs_dstor_sync(&repo->re_dstor);
	repo_unlock(repo);
	return err;
}

void silofs_repo_relax(struct silofs_repo *repo)
{
	repo_lock(repo);
	silofs_dstor_relax(&repo->re_dstor);
	repo_unlock(repo);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int repo_init_mutex(struct silofs_repo *repo)
{
	return silofs_mutex_init(&repo->re_mutex);
}

static void repo_fini_mutex(struct silofs_repo *repo)
{
	silofs_mutex_fini(&repo->re_mutex);
}

static int repo_init_dstor(struct silofs_repo *repo)
{
	return silofs_dstor_init(&repo->re_dstor, repo->re_alloc);
}

static void repo_fini_dstor(struct silofs_repo *repo)
{
	silofs_dstor_fini(&repo->re_dstor);
}

int silofs_repo_init(struct silofs_repo *repo, struct silofs_alloc *alloc)
{
	int err;

	memset(repo, 0, sizeof(*repo));
	repo->re_alloc     = alloc;
	repo->re_root_dfd  = -1;
	repo->re_dots_dfd  = -1;
	repo->re_blobs_dfd = -1;
	repo->re_rdonly    = false;
	repo->re_opened    = false;

	err = repo_init_dstor(repo);
	goto_if_err(err, out_err);

	err = repo_init_mutex(repo);
	goto_if_err(err, out_err);

	return 0;
out_err:
	repo_fini_dstor(repo);
	repo_fini_mutex(repo);
	return err;
}

void silofs_repo_fini(struct silofs_repo *repo)
{
	repo_close(repo);
	repo_fini_dstor(repo);
	repo_fini_mutex(repo);
	repo->re_alloc  = nullptr;
	repo->re_rdonly = false;
	repo->re_opened = false;
}

void silofs_repo_drop_some(struct silofs_repo *repo)
{
	repo_lock(repo);
	silofs_dstor_drop(&repo->re_dstor);
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
	err = do_fstatat_dir(repo->re_dots_dfd, name, &st);
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
                                    const char *name, mode_t mode, off_t len)
{
	int err, fd = -1;

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
	const char *name = nullptr;
	off_t size       = 0;
	int err;

	name = SILOFS_REPO_BLOBSDIR_NAME;
	err  = repo_create_skel_subdir(repo, name, 0700);
	return_if_err(err);

	name = SILOFS_REPO_METAFILE_NAME;
	size = SILOFS_REPO_METAFILE_SIZE;
	err  = repo_create_skel_subfile(repo, name, 0600, size);
	return_if_err(err);

	name = SILOFS_REPO_LOCKFILE_NAME;
	err  = repo_create_skel_subfile(repo, name, 0600, size);
	return_if_err(err);

	return 0;
}

static int
repo_require_skel_subdir(const struct silofs_repo *repo, const char *name)
{
	struct stat st = { .st_size = 0 };

	return do_fstatat_dir(repo->re_dots_dfd, name, &st);
}

static int repo_require_skel_subfile(const struct silofs_repo *repo,
                                     const char *name, off_t min_size)
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
	const char *name = nullptr;
	off_t size;
	int err;

	name = SILOFS_REPO_METAFILE_NAME;
	size = SILOFS_REPO_METAFILE_SIZE;
	err  = repo_require_skel_subfile(repo, name, size);
	return_if_err(err);

	name = SILOFS_REPO_BLOBSDIR_NAME;
	err  = repo_require_skel_subdir(repo, name);
	return_if_err(err);

	return 0;
}

static int repo_check_not_open(const struct silofs_repo *repo)
{
	return repo->re_opened ? -SILOFS_EALREADY : 0;
}

static int repo_open_rootdir(struct silofs_repo *repo, const char *rootdir)
{
	return do_opendir(rootdir, &repo->re_root_dfd);
}

static int repo_create_dotsdir(const struct silofs_repo *repo)
{
	const char *name = SILOFS_REPO_DOTSDIR_NAME;
	int err;

	err = do_mkdirat(repo->re_root_dfd, name, 0700);
	if (err && (err != -EEXIST)) {
		return err;
	}
	return 0;
}

static int repo_open_dotsdir(struct silofs_repo *repo)
{
	const char *name = SILOFS_REPO_DOTSDIR_NAME;

	return do_opendirat(repo->re_root_dfd, name, &repo->re_dots_dfd);
}

static int repo_format_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name;
	int err, fd = -1;

	name = SILOFS_REPO_METAFILE_NAME;
	err  = do_openat(repo->re_dots_dfd, name, O_RDWR, 0600, &fd);
	return_if_err(err);

	rmeta_init(&rmeta);
	err = do_pwriten(fd, &rmeta, sizeof(rmeta), 0);
	goto_out_if_err(err);

	err = do_fdatasync(fd);
	goto_out_if_err(err);

	err = do_fchmod(fd, 0400);
	goto_out_if_err(err);
out:
	do_closefd(&fd);
	return err;
}

static int repo_format_lock(const struct silofs_repo *repo)
{
	char data[SILOFS_REPO_METAFILE_SIZE] = "SILOFS_LOCK\n";
	const char *name;
	int err, fd = -1;

	name = SILOFS_REPO_LOCKFILE_NAME;
	err  = do_openat(repo->re_dots_dfd, name, O_RDWR, 0600, &fd);
	return_if_err(err);

	err = do_pwriten(fd, data, sizeof(data), 0);
	goto_out_if_err(err);

	err = do_fdatasync(fd);
	goto_out_if_err(err);
out:
	do_closefd(&fd);
	return err;
}

static int repo_require_meta(const struct silofs_repo *repo)
{
	struct silofs_repo_meta rmeta;
	const char *name;
	int err, fd = -1;

	name = SILOFS_REPO_METAFILE_NAME;
	err  = do_openat(repo->re_dots_dfd, name, O_RDONLY, 0, &fd);
	return_if_err(err);

	rmeta_init(&rmeta);
	err = do_preadn(fd, &rmeta, sizeof(rmeta), 0);
	goto_out_if_err(err);

	err = rmeta_check(&rmeta);
	goto_out_if_err(err);
out:
	do_closefd(&fd);
	return err;
}

static int repo_require_lock(const struct silofs_repo *repo)
{
	char data[SILOFS_REPO_METAFILE_SIZE] = "";
	const char *name;
	int err, fd = -1;

	name = SILOFS_REPO_LOCKFILE_NAME;
	err  = do_openat(repo->re_dots_dfd, name, O_RDONLY, 0, &fd);
	return_if_err(err);

	err = do_preadn(fd, data, sizeof(data), 0);
	goto_out_if_err(err);

	err = strncmp(data, "SILOFS_LOCK", 11) ? -SILOFS_EBADREPO : 0;
	goto_out_if_err(err);
out:
	do_closefd(&fd);
	return err;
}

static int repo_open_blobsdir(struct silofs_repo *repo)
{
	const char *name = SILOFS_REPO_BLOBSDIR_NAME;

	return do_opendirat(repo->re_dots_dfd, name, &repo->re_blobs_dfd);
}

static int repo_open_dstor(struct silofs_repo *repo)
{
	return silofs_dstor_open(&repo->re_dstor, repo->re_root_dfd);
}

static int repo_do_format(struct silofs_repo *repo, const char *repodir)
{
	int err;

	err = repo_check_not_open(repo);
	return_if_err(err);

	err = repo_open_rootdir(repo, repodir);
	return_if_err(err);

	err = repo_create_dotsdir(repo);
	return_if_err(err);

	err = repo_open_dotsdir(repo);
	return_if_err(err);

	err = repo_create_skel(repo);
	return_if_err(err);

	err = repo_open_blobsdir(repo);
	return_if_err(err);

	err = repo_open_dstor(repo);
	return_if_err(err);

	err = repo_format_meta(repo);
	return_if_err(err);

	err = repo_format_lock(repo);
	return_if_err(err);

	repo->re_opened = true;
	return 0;
}

int silofs_repo_format(struct silofs_repo *repo, const char *repodir)
{
	int err;

	repo_lock(repo);
	err = repo_do_format(repo, repodir);
	repo_unlock(repo);
	return err;
}

static int
repo_do_open(struct silofs_repo *repo, const char *repodir, bool rdonly)
{
	int err;

	err = repo_check_not_open(repo);
	return_if_err(err);

	err = repo_open_rootdir(repo, repodir);
	return_if_err(err);

	err = repo_open_dotsdir(repo);
	return_if_err(err);

	err = repo_require_skel(repo);
	return_if_err(err);

	err = repo_require_meta(repo);
	return_if_err(err);

	err = repo_require_lock(repo);
	return_if_err(err);

	err = repo_open_blobsdir(repo);
	return_if_err(err);

	err = repo_open_dstor(repo);
	return_if_err(err);

	repo->re_rdonly = rdonly;
	repo->re_opened = true;
	return 0;
}

int silofs_repo_open(struct silofs_repo *repo, const char *rootdir,
                     enum silofs_flags flags)
{
	const bool rdonly = (flags & SILOFS_F_RDONLY) > 0;
	int err;

	repo_lock(repo);
	err = repo_do_open(repo, rootdir, rdonly);
	repo_unlock(repo);
	return err;
}

static int repo_close_dots_fd(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_dots_dfd);
}

static int repo_close_root_fd(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_root_dfd);
}

static int repo_close_blobs_fd(struct silofs_repo *repo)
{
	return do_closefd(&repo->re_blobs_dfd);
}

static void repo_close_dstor(struct silofs_repo *repo)
{
	silofs_dstor_close(&repo->re_dstor);
}

static int repo_close(struct silofs_repo *repo)
{
	int err;

	repo_close_dstor(repo);

	err = repo_close_blobs_fd(repo);
	return_if_err(err);

	err = repo_close_dots_fd(repo);
	return_if_err(err);

	err = repo_close_root_fd(repo);
	return_if_err(err);

	repo->re_opened = false;
	return 0;
}

static int repo_do_close(struct silofs_repo *repo)
{
	int ret = 0;

	if (repo->re_opened) {
		ret = repo_close(repo);
	}
	return ret;
}

int silofs_repo_close(struct silofs_repo *repo)
{
	int err;

	repo_lock(repo);
	err = repo_do_close(repo);
	repo_unlock(repo);
	return err;
}
