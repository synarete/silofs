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
#include <silofs/errors.h>
#include <silofs/vol.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

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

static int do_closefd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		log_warn("close error: fd=%d err=%d", *pfd, err);
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

static int do_openat(int dirfd, const char *pathname,
                     int o_flags, mode_t mode, int *out_fd)
{
	int err;

	err = silofs_sys_openat(dirfd, pathname, o_flags, mode, out_fd);
	if (err && (err != -ENOENT)) {
		log_warn("openat error: dirfd=%d pathname=%s o_flags=0x%x "
		         "mode=0%o err=%d", dirfd, pathname,
		         o_flags, mode, err);
	}
	return err;
}

static int do_unlinkat(int dirfd, const char *pathname, int flags)
{
	int err;

	err = silofs_sys_unlinkat(dirfd, pathname, flags);
	if (err && (err != -ENOENT)) {
		log_warn("unlinkat error: dirfd=%d pathname=%s err=%d",
		         dirfd, pathname, err);
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

static int do_fsync(int fd)
{
	int err;

	err = silofs_sys_fsync(fd);
	if (err && (err != -ENOSYS)) {
		log_warn("fsync error: fd=%d err=%d", fd, err);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void byte_to_ascii(unsigned int b, char *a)
{
	const uint8_t v = (uint8_t)(b & 0xff);

	a[0] = silofs_nibble_to_ascii(v >> 4);
	a[1] = silofs_nibble_to_ascii(v);
}

static void blobid_to_name(const struct silofs_blobid *blobid,
                           struct silofs_strbuf *sbuf)
{
	char *s = sbuf->str;
	unsigned int b;

	STATICASSERT_GT(sizeof(sbuf->str), 2 * sizeof(blobid->id));

	for (size_t i = 0; i < blobid->id_len; ++i) {
		b = blobid->id[i];
		byte_to_ascii(b, s);
		s += 2;
	}
	*s = '\0';
}

static struct silofs_blob_fh *
blob_fh_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_blob_fh *bfh;

	bfh = container_of2(hmqe, struct silofs_blob_fh, bf_hmqe);
	return unconst(bfh);
}

static void blob_fh_init(struct silofs_blob_fh *bfh,
                         const struct silofs_blobid *blobid)
{
	silofs_hmqe_init(&bfh->bf_hmqe);
	silofs_blobid_assign(&bfh->bf_blobid, blobid);
	silofs_hkey_by_blobid(&bfh->bf_hmqe.hme_key, &bfh->bf_blobid);
	bfh->bf_size = 0;
	bfh->bf_fd = -1;
}

static int blob_fh_closefd(struct silofs_blob_fh *bfh)
{
	return do_closefd(&bfh->bf_fd);
}

static void blob_fh_fini(struct silofs_blob_fh *bfh)
{
	blob_fh_closefd(bfh);
	silofs_hmqe_fini(&bfh->bf_hmqe);
	silofs_blobid_reset(&bfh->bf_blobid);
}

static struct silofs_blob_fh *
blob_fh_new(struct silofs_alloc *alloc, const struct silofs_blobid *blobid)
{
	struct silofs_blob_fh *bfh = NULL;

	bfh = silofs_memalloc(alloc, sizeof(*bfh), 0);
	if (bfh != NULL) {
		blob_fh_init(bfh, blobid);
	}
	return bfh;
}

static void blob_fh_del(struct silofs_blob_fh *bfh,
                        struct silofs_alloc *alloc)
{
	blob_fh_fini(bfh);
	silofs_memfree(alloc, bfh, sizeof(*bfh), 0);
}

static int blob_fh_stat(const struct silofs_blob_fh *bfh, struct stat *out_st)
{
	return do_fstat(bfh->bf_fd, out_st);
}

static int blob_fh_bindto(struct silofs_blob_fh *bfh, int fd)
{
	struct stat st = { .st_size = 0 };
	int err;

	bfh->bf_fd = fd;
	err = blob_fh_stat(bfh, &st);
	bfh->bf_size = st.st_size;
	return err;
}

static int blob_fh_append(struct silofs_blob_fh *bfh,
                          const void *buf, size_t len)
{
	int err;

	err = do_pwriten(bfh->bf_fd, buf, len, bfh->bf_size);
	if (!err) {
		bfh->bf_size += (ssize_t)len;
	}
	return err;
}

static int blob_fh_pread(struct silofs_blob_fh *bfh,
                         loff_t off, size_t len, void *buf)
{
	const loff_t end = off_end(off, len);
	int err = -SILOFS_ERANGE;

	if (end <= bfh->bf_size) {
		err = do_preadn(bfh->bf_fd, buf, len, off);
	}
	return err;
}

static int blob_fh_flush(const struct silofs_blob_fh *bfh)
{
	return do_fsync(bfh->bf_fd);
}

static bool blob_fh_is_evictable(const struct silofs_blob_fh *bfh)
{
	return silofs_hmqe_is_evictable(&bfh->bf_hmqe);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int bstore_spawn_bfh(struct silofs_bstore *bstore,
                            const struct silofs_blobid *blobid, int fd)
{
	struct silofs_blob_fh *bfh;
	int err;

	bfh = blob_fh_new(bstore->bs_alloc, blobid);
	if (bfh == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = blob_fh_bindto(bfh, fd);
	if (err) {
		blob_fh_del(bfh, bstore->bs_alloc);
		return err;
	}
	silofs_hmapq_store(&bstore->bs_hmapq, &bfh->bf_hmqe);
	return 0;
}

static int bstore_lookup_bfh(struct silofs_bstore *bstore,
                             const struct silofs_blobid *blobid,
                             struct silofs_blob_fh **out_bfh)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_blobid(&hkey, blobid);
	hmqe = silofs_hmapq_lookup(&bstore->bs_hmapq, &hkey);
	if (hmqe == NULL) {
		return -SILOFS_ENOENT;
	}
	*out_bfh = blob_fh_from_hmqe(hmqe);
	return 0;
}

static struct silofs_blob_fh *
bstore_get_bfh(struct silofs_bstore *bstore,
               const struct silofs_blobid *blobid)
{
	struct silofs_blob_fh *bfh = NULL;
	int err;

	err = bstore_lookup_bfh(bstore, blobid, &bfh);
	if (err) {
		return NULL;
	}
	silofs_hmapq_promote(&bstore->bs_hmapq, &bfh->bf_hmqe, false);
	return bfh;
}

static void bstore_remove_bfh(struct silofs_bstore *bstore,
                              struct silofs_blob_fh *bfh)
{
	silofs_assert(blob_fh_is_evictable(bfh));

	silofs_hmapq_remove(&bstore->bs_hmapq, &bfh->bf_hmqe);
	blob_fh_del(bfh, bstore->bs_alloc);
}

static int bstore_try_remove_bfh(struct silofs_bstore *bstore,
                                 const struct silofs_blobid *blobid)
{
	struct silofs_blob_fh *bfh = NULL;
	int err;

	err = bstore_lookup_bfh(bstore, blobid, &bfh);
	if (err) {
		return err;
	}
	bstore_remove_bfh(bstore, bfh);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_init(struct silofs_bstore *bstore,
                       struct silofs_alloc *alloc)
{
	int err;

	silofs_memzero(bstore, sizeof(*bstore));
	bstore->bs_dirfd = -1;
	bstore->bs_alloc = alloc;
	err = silofs_mutex_init(&bstore->bs_mutex);
	if (err) {
		return err;
	}
	err = silofs_hmapq_init(&bstore->bs_hmapq, alloc, 512);
	if (err) {
		silofs_mutex_fini(&bstore->bs_mutex);
		return err;
	}
	return 0;
}

void silofs_bstore_fini(struct silofs_bstore *bstore)
{
	silofs_bstore_close(bstore);
	silofs_hmapq_fini(&bstore->bs_hmapq, bstore->bs_alloc);
	silofs_mutex_fini(&bstore->bs_mutex);
	bstore->bs_alloc = NULL;
}

static bool bstore_isopen(const struct silofs_bstore *bstore)
{
	return !(bstore->bs_dirfd < 0);
}

static int bstore_statblob_at(const struct silofs_bstore *bstore,
                              const struct silofs_blobid *blobid,
                              struct stat *out_st)
{
	struct silofs_strbuf sbuf;

	blobid_to_name(blobid, &sbuf);
	return do_fstatat(bstore->bs_dirfd, sbuf.str, out_st, 0);
}

static int bstore_statnoblob(const struct silofs_bstore *bstore,
                             const struct silofs_blobid *blobid)
{
	struct stat st;
	int err;

	err = bstore_statblob_at(bstore, blobid, &st);
	if (!err) {
		return -SILOFS_EEXIST;
	}
	return (err == -ENOENT) ? 0 : err;
}

static int bstore_statblob(const struct silofs_bstore *bstore,
                           const struct silofs_blobid *blobid)
{
	struct stat st;

	return bstore_statblob_at(bstore, blobid, &st);
}

int silofs_bstore_openat(struct silofs_bstore *bstore,
                         int parent_dirfd, const char *name)
{

	int err;

	if (bstore_isopen(bstore)) {
		return -SILOFS_EALREADY;
	}
	err = do_opendirat(parent_dirfd, name, &bstore->bs_dirfd);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_close(struct silofs_bstore *bstore)
{
	int err;

	if (!bstore_isopen(bstore)) {
		return 0;
	}
	err = silofs_bstore_pruneall(bstore);
	if (err) {
		return err;
	}
	do_closefd(&bstore->bs_dirfd);
	return 0;
}

static int bstore_open_blob_with(struct silofs_bstore *bstore,
                                 const struct silofs_blobid *blobid,
                                 int o_flags, int *out_fd)
{
	struct silofs_strbuf sbuf;

	blobid_to_name(blobid, &sbuf);
	return do_openat(bstore->bs_dirfd, sbuf.str, o_flags, 0600, out_fd);
}

static int bstore_unlink_blob(struct silofs_bstore *bstore,
                              const struct silofs_blobid *blobid)
{
	struct silofs_strbuf sbuf;

	blobid_to_name(blobid, &sbuf);
	return do_unlinkat(bstore->bs_dirfd, sbuf.str, 0);
}

static int bstore_create_blob(struct silofs_bstore *bstore,
                              const struct silofs_blobid *blobid)
{
	const int o_flags = O_CREAT | O_RDWR | O_EXCL;
	int fd = -1;
	int err;

	err = bstore_open_blob_with(bstore, blobid, o_flags, &fd);
	if (err) {
		return err;
	}
	err = bstore_spawn_bfh(bstore, blobid, fd);
	if (err) {
		do_closefd(&fd);
		return err;
	}
	return 0;
}

static int bstore_open_blob(struct silofs_bstore *bstore,
                            const struct silofs_blobid *blobid)
{
	const int o_flags = O_RDWR;
	int fd = -1;
	int err;

	err = bstore_open_blob_with(bstore, blobid, o_flags, &fd);
	if (err) {
		return err;
	}
	err = bstore_spawn_bfh(bstore, blobid, fd);
	if (err) {
		do_closefd(&fd);
		return err;
	}
	return 0;
}

int silofs_bstore_mkblob(struct silofs_bstore *bstore,
                         const struct silofs_blobid *blobid)
{
	int err;

	if (!bstore_isopen(bstore)) {
		return -SILOFS_EBADF;
	}
	err = bstore_statnoblob(bstore, blobid);
	if (err) {
		return err;
	}
	err = bstore_create_blob(bstore, blobid);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_rmblob(struct silofs_bstore *bstore,
                         const struct silofs_blobid *blobid)
{
	int err;

	if (!bstore_isopen(bstore)) {
		return -SILOFS_EBADF;
	}
	err = bstore_statblob(bstore, blobid);
	if (err) {
		return err;
	}
	err = bstore_try_remove_bfh(bstore, blobid);
	if (err && (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = bstore_unlink_blob(bstore, blobid);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_require_bfh(struct silofs_bstore *bstore,
                              const struct silofs_blobid *blobid,
                              struct silofs_blob_fh **out_bfh)
{
	int err;

	*out_bfh = bstore_get_bfh(bstore, blobid);
	if (*out_bfh != NULL) {
		return 0; /* cache hit, already open */
	}
	err = bstore_open_blob(bstore, blobid);
	if (err) {
		return err;
	}
	err = bstore_lookup_bfh(bstore, blobid, out_bfh);
	if (err) {
		return -SILOFS_EBUG; /* internal error -- should not happen */
	}
	return 0;
}

int silofs_bstore_append(struct silofs_bstore *bstore,
                         const struct silofs_blobid *blobid,
                         const void *dat, size_t len)
{
	struct silofs_blob_fh *bfh = NULL;
	int err;

	err = bstore_require_bfh(bstore, blobid, &bfh);
	if (err) {
		return err;
	}
	err = blob_fh_append(bfh, dat, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_pread(struct silofs_bstore *bstore,
                        const struct silofs_blobid *blobid,
                        loff_t off, size_t len, void *dat)
{
	struct silofs_blob_fh *bfh = NULL;
	int err;

	err = bstore_require_bfh(bstore, blobid, &bfh);
	if (err) {
		return err;
	}
	err = blob_fh_pread(bfh, off, len, dat);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_flush(struct silofs_bstore *bstore,
                        const struct silofs_blobid *blobid)
{
	struct silofs_blob_fh *bfh = NULL;
	int err = 0;

	bfh = bstore_get_bfh(bstore, blobid);
	if (bfh != NULL) {
		err = blob_fh_flush(bfh);
	}
	return err;
}


static int try_evict_blob_fh(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_bstore *bstore = arg;
	struct silofs_blob_fh *bfh = NULL;

	bfh = blob_fh_from_hmqe(hmqe);
	if (blob_fh_is_evictable(bfh)) {
		bstore_remove_bfh(bstore, bfh);
	}
	return 0;
}

void silofs_bstore_prune(struct silofs_bstore *bstore)
{
	silofs_hmapq_riterate(&bstore->bs_hmapq,
	                      SILOFS_HMAPQ_ITERALL,
	                      try_evict_blob_fh, bstore);
}

int silofs_bstore_pruneall(struct silofs_bstore *bstore)
{
	size_t usage;

	usage = silofs_hmapq_usage(&bstore->bs_hmapq);
	if (usage > 0) {
		silofs_bstore_prune(bstore);
		usage = silofs_hmapq_usage(&bstore->bs_hmapq);
	}
	return (usage == 0) ? 0 : -SILOFS_EAGAIN;
}
