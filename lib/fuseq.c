/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/sysinfo.h>
#include <linux/fs.h>
#include <linux/fuse_kernel.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <silofs/ioctls.h>
#include <silofs/mntsvc.h>
#include "infra.h"
#include "mbr.h"
#include "vfs.h"
#include "env.h"
#include "call.h"
#include "exec.h"
#include "fuseq.h"

#if FUSE_KERNEL_VERSION != 7
#error "wrong FUSE_KERNEL_VERSION"
#endif
#if FUSE_KERNEL_MINOR_VERSION < 36
#error "wrong FUSE_KERNEL_MINOR_VERSION"
#endif

enum silofs_fuseq_consts {
	/* room needed to accommodate header (from libfuse::lib/fuse_i.h) */
	FUSE_BUFFER_HEADER_SIZE = 0x1000,
	/* max sub-commands */
	FUSEQ_CMD_MAX = 64,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define fuseq_log_dbg(fmt, ...)  silofs_log_debug("fuseq: " fmt, __VA_ARGS__)
#define fuseq_log_info(fmt, ...) silofs_log_info("fuseq: " fmt, __VA_ARGS__)
#define fuseq_log_warn(fmt, ...) silofs_log_warn("fuseq: " fmt, __VA_ARGS__)
#define fuseq_log_err(fmt, ...)  silofs_log_error("fuseq: " fmt, __VA_ARGS__)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define SILOFS_CMD_TAIL_MAX \
	(SILOFS_IO_SIZE_MAX - sizeof(struct fuse_in_header))
#define SILOFS_CMD_FORGET_ONE_MAX \
	(SILOFS_CMD_TAIL_MAX / sizeof(struct fuse_forget_one))

/*
 * Currently, there is limitation to output-size of FUSE_COPY_FILE_RANGE: the
 * reply is using fuse_write_out.size which is uint32_t. Thus, we can not
 * perform copy_file_range of more than UINT32_MAX (4G - 1), and should expect
 * the calling user-space process to iterate on the entire range if it is
 * greater than this limit. Define upper bound as 2G.
 */
#define FUSEQ_COPY_FILE_RANGE_MAX (SILOFS_GIGA * 2)

/* local functions */
static void fqs_interrupt_op(struct silofs_fuseq_sub *fqs, uint64_t uq);
static bool fqs_has_large_write_in(const struct silofs_fuseq_sub *fqs);
static bool fqs_has_large_read_in(const struct silofs_fuseq_sub *fqs);
static bool fuseq_may(const struct silofs_fuseq *fq, enum silofs_flags mode);
static bool fuseq_may_splice(const struct silofs_fuseq *fq);
static void fuseq_lock_ctl(struct silofs_fuseq *fq);
static void fuseq_unlock_ctl(struct silofs_fuseq *fq);
static void fuseq_update_nexecs(struct silofs_fuseq *fq, int n);
static bool fuseq_has_live_opers(const struct silofs_fuseq *fq);
static bool fuseq_is_active(const struct silofs_fuseq *fq);
static void fuseq_set_active(struct silofs_fuseq *fq);
static void fuseq_set_non_active(struct silofs_fuseq *fq);
static int
exec_op(struct silofs_task_ctx *task, struct silofs_call_args *args);
static const struct silofs_fuseq_cmd_desc *cmd_desc_of(unsigned int opc);

/* FUSE types per 7.34 */
struct fuse_setxattr1_in {
	uint32_t size;
	uint32_t flags;
};

/* local types */
struct silofs_fuseq_hdr_in {
	struct fuse_in_header hdr;
};

struct silofs_fuseq_cmd_in {
	struct fuse_in_header hdr;
	uint8_t cmd[SILOFS_IO_SIZE_MAX];
	uint8_t tail[SILOFS_LBK_SIZE - sizeof(struct fuse_in_header)];
};

struct silofs_fuseq_init_in {
	struct fuse_in_header hdr;
	struct fuse_init_in arg;
};

struct silofs_fuseq_setattr_in {
	struct fuse_in_header hdr;
	struct fuse_setattr_in arg;
};

struct silofs_fuseq_lookup_in {
	struct fuse_in_header hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_forget_in {
	struct fuse_in_header hdr;
	struct fuse_forget_in arg;
};

struct silofs_fuseq_batch_forget_in {
	struct fuse_in_header hdr;
	struct fuse_batch_forget_in arg;
	struct fuse_forget_one one[SILOFS_CMD_FORGET_ONE_MAX];
};

struct silofs_fuseq_getattr_in {
	struct fuse_in_header hdr;
	struct fuse_getattr_in arg;
};

struct silofs_fuseq_symlink_in {
	struct fuse_in_header hdr;
	char name_target[SILOFS_NAME_MAX + 1 + SILOFS_SYMLNK_MAX];
};

struct silofs_fuseq_mknod_in {
	struct fuse_in_header hdr;
	struct fuse_mknod_in arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_mkdir_in {
	struct fuse_in_header hdr;
	struct fuse_mkdir_in arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_unlink_in {
	struct fuse_in_header hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_rmdir_in {
	struct fuse_in_header hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_rename_in {
	struct fuse_in_header hdr;
	struct fuse_rename_in arg;
	char name_newname[2 * (SILOFS_NAME_MAX + 1)];
};

struct silofs_fuseq_link_in {
	struct fuse_in_header hdr;
	struct fuse_link_in arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_open_in {
	struct fuse_in_header hdr;
	struct fuse_open_in arg;
};

struct silofs_fuseq_release_in {
	struct fuse_in_header hdr;
	struct fuse_release_in arg;
};

struct silofs_fuseq_fsync_in {
	struct fuse_in_header hdr;
	struct fuse_fsync_in arg;
};

struct silofs_fuseq_setxattr1_in {
	struct fuse_in_header hdr;
	struct fuse_setxattr1_in arg;
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_XATTR_VALUE_MAX];
};

struct silofs_fuseq_setxattr_in {
	struct fuse_in_header hdr;
	struct fuse_setxattr_in arg;
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_XATTR_VALUE_MAX];
};

struct silofs_fuseq_getxattr_in {
	struct fuse_in_header hdr;
	struct fuse_getxattr_in arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_listxattr_in {
	struct fuse_in_header hdr;
	struct fuse_getxattr_in arg;
};

struct silofs_fuseq_removexattr_in {
	struct fuse_in_header hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_flush_in {
	struct fuse_in_header hdr;
	struct fuse_flush_in arg;
};

struct silofs_fuseq_opendir_in {
	struct fuse_in_header hdr;
	struct fuse_open_in arg;
};

struct silofs_fuseq_readdir_in {
	struct fuse_in_header hdr;
	struct fuse_read_in arg;
};

struct silofs_fuseq_releasedir_in {
	struct fuse_in_header hdr;
	struct fuse_release_in arg;
};

struct silofs_fuseq_fsyncdir_in {
	struct fuse_in_header hdr;
	struct fuse_fsync_in arg;
};

struct silofs_fuseq_access_in {
	struct fuse_in_header hdr;
	struct fuse_access_in arg;
};

struct silofs_fuseq_create_in {
	struct fuse_in_header hdr;
	struct fuse_create_in arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_interrupt_in {
	struct fuse_in_header hdr;
	struct fuse_interrupt_in arg;
};

struct silofs_fuseq_ioctl_in {
	struct fuse_in_header hdr;
	struct fuse_ioctl_in arg;
	char buf[SILOFS_PAGE_SIZE_MIN];
};

struct silofs_fuseq_fallocate_in {
	struct fuse_in_header hdr;
	struct fuse_fallocate_in arg;
};

struct silofs_fuseq_rename2_in {
	struct fuse_in_header hdr;
	struct fuse_rename2_in arg;
	char name_newname[2 * (SILOFS_NAME_MAX + 1)];
};

struct silofs_fuseq_lseek_in {
	struct fuse_in_header hdr;
	struct fuse_lseek_in arg;
};

struct silofs_fuseq_read_in {
	struct fuse_in_header hdr;
	struct fuse_read_in arg;
};

struct silofs_fuseq_write_in {
	struct fuse_in_header hdr;
	struct fuse_write_in arg;
};

struct silofs_fuseq_copy_file_range_in {
	struct fuse_in_header hdr;
	struct fuse_copy_file_range_in arg;
};

struct silofs_fuseq_syncfs_in {
	struct fuse_in_header hdr;
	struct fuse_syncfs_in arg;
};

struct silofs_fuseq_statx_in {
	struct fuse_in_header hdr;
	struct fuse_statx_in arg;
};

union silofs_fuseq_in_u {
	struct silofs_fuseq_hdr_in hdr;
	struct silofs_fuseq_cmd_in cmd;
	struct silofs_fuseq_init_in init;
	struct silofs_fuseq_setattr_in setattr;
	struct silofs_fuseq_lookup_in lookup;
	struct silofs_fuseq_forget_in forget;
	struct silofs_fuseq_batch_forget_in batch_forget;
	struct silofs_fuseq_getattr_in getattr;
	struct silofs_fuseq_symlink_in symlink;
	struct silofs_fuseq_mknod_in mknod;
	struct silofs_fuseq_mkdir_in mkdir;
	struct silofs_fuseq_unlink_in unlink;
	struct silofs_fuseq_rmdir_in rmdir;
	struct silofs_fuseq_rename_in rename;
	struct silofs_fuseq_link_in link;
	struct silofs_fuseq_open_in open;
	struct silofs_fuseq_release_in release;
	struct silofs_fuseq_fsync_in fsync;
	struct silofs_fuseq_setxattr1_in setxattr1;
	struct silofs_fuseq_setxattr_in setxattr;
	struct silofs_fuseq_getxattr_in getxattr;
	struct silofs_fuseq_listxattr_in listxattr;
	struct silofs_fuseq_removexattr_in removexattr;
	struct silofs_fuseq_flush_in flush;
	struct silofs_fuseq_opendir_in opendir;
	struct silofs_fuseq_readdir_in readdir;
	struct silofs_fuseq_releasedir_in releasedir;
	struct silofs_fuseq_fsyncdir_in fsyncdir;
	struct silofs_fuseq_access_in access;
	struct silofs_fuseq_create_in create;
	struct silofs_fuseq_interrupt_in interrupt;
	struct silofs_fuseq_ioctl_in ioctl;
	struct silofs_fuseq_fallocate_in fallocate;
	struct silofs_fuseq_rename2_in rename2;
	struct silofs_fuseq_lseek_in lseek;
	struct silofs_fuseq_read_in read;
	struct silofs_fuseq_write_in write;
	struct silofs_fuseq_copy_file_range_in copy_file_range;
	struct silofs_fuseq_statx_in statx;
};

struct silofs_fuseq_in {
	union silofs_fuseq_in_u u;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_fuseq_diter {
	uint8_t buf[8192];
	struct silofs_strbuf de_name;
	struct silofs_readdir_ctx rd_ctx;
	struct silofs_stat de_attr;
	size_t bsz;
	size_t len;
	size_t ndes;
	off_t de_off;
	size_t de_nlen;
	ino_t de_ino;
	mode_t de_dt;
	int plus;
};

struct silofs_fuseq_xiter {
	struct silofs_listxattr_ctx lxa;
	size_t cnt;
	const char *beg;
	const char *end;
	char *cur;
	char buf[64 * SILOFS_UKILO];
};

struct silofs_fuseq_wr_iter {
	struct silofs_iovec iovec[SILOFS_FILE_NITER_MAX];
	struct silofs_rwiter_ctx rwi;
	struct silofs_fuseq_sub *fqs;
	size_t cnt;
	size_t ncp;
	size_t nwr;
	size_t nwr_max;
};

struct silofs_fuseq_rd_iter {
	struct silofs_iovec iovec[SILOFS_FILE_NITER_MAX];
	struct silofs_rwiter_ctx rwi;
	struct silofs_fuseq_sub *fqs;
	struct silofs_task_ctx *task;
	size_t cnt;
	size_t ncp;
	size_t nrd;
	size_t nrd_max;
};

struct silofs_fuseq_iob {
	uint8_t b[SILOFS_LBK_SIZE + SILOFS_IO_SIZE_MAX];
};

union silofs_fuseq_inb_u {
	struct silofs_fuseq_in in;
	struct silofs_fuseq_iob iob;
};

struct silofs_fuseq_inb {
	union silofs_fuseq_inb_u u;
};

struct silofs_fuseq_databuf {
	uint8_t buf[SILOFS_IO_SIZE_MAX];
};

struct silofs_fuseq_pathbuf {
	char path[SILOFS_PATH_MAX];
};

struct silofs_fuseq_xattrbuf {
	char value[SILOFS_XATTR_VALUE_MAX];
};

union silofs_fuseq_outb_u {
	struct silofs_fuseq_databuf dab;
	struct silofs_fuseq_pathbuf pab;
	struct silofs_fuseq_xattrbuf xab;
	struct silofs_fuseq_xiter xit;
	struct silofs_fuseq_diter dit;
	struct silofs_fuseq_iob iob;
};

struct silofs_fuseq_outb {
	union silofs_fuseq_outb_u u;
};

union silofs_fuseq_rw_iter_u {
	struct silofs_fuseq_wr_iter wri;
	struct silofs_fuseq_rd_iter rdi;
};

struct silofs_fuseq_rw_iter {
	union silofs_fuseq_rw_iter_u u;
};

struct silofs_fuseq_cmd_ctx {
	struct silofs_fuseq *fq;
	struct silofs_fuseq_sub *fqs;
	struct silofs_task_ctx *task;
	struct silofs_call_args *args;
	const struct silofs_fuseq_in *in;
	ino_t ino;
};

typedef int (*silofs_fuseq_hook)(const struct silofs_fuseq_cmd_ctx *);

struct silofs_fuseq_cmd_desc {
	silofs_fuseq_hook hook;
	const char *name;
	int code;
	int realtime;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const void *after_name(const char *name)
{
	return name + silofs_str_length(name) + 1;
}

static void
ts_to_fuse_attr(const struct timespec *ts, uint64_t *sec, uint32_t *nsec)
{
	*sec = (uint64_t)ts->tv_sec;
	*nsec = (uint32_t)ts->tv_nsec;
}

static void ts_to_fuse_sx_tinme(const struct statx_timestamp *ts,
                                struct fuse_sx_time *sx_tm)
{
	sx_tm->tv_sec = ts->tv_sec;
	sx_tm->tv_nsec = (uint32_t)ts->tv_nsec;
}

static void
fuse_attr_to_timespec(uint64_t sec, uint32_t nsec, struct timespec *ts)
{
	ts->tv_sec = (time_t)sec;
	ts->tv_nsec = (long)nsec;
}

static void
stat_to_fuse_attr(const struct silofs_stat *st, struct fuse_attr *attr)
{
	attr->ino = st->st.st_ino;
	attr->mode = st->st.st_mode;
	attr->nlink = (uint32_t)st->st.st_nlink;
	attr->uid = st->st.st_uid;
	attr->gid = st->st.st_gid;
	attr->rdev = (uint32_t)st->st.st_rdev;
	attr->size = (uint64_t)st->st.st_size;
	attr->blksize = (uint32_t)st->st.st_blksize;
	attr->blocks = (uint64_t)st->st.st_blocks;
	ts_to_fuse_attr(&st->st.st_atim, &attr->atime, &attr->atimensec);
	ts_to_fuse_attr(&st->st.st_mtim, &attr->mtime, &attr->mtimensec);
	ts_to_fuse_attr(&st->st.st_ctim, &attr->ctime, &attr->ctimensec);
}

static void
stat_to_fuse_statx(const struct silofs_stat *st, struct fuse_statx *attr)
{
	attr->mask = st->stx.stx_mask;
	attr->blksize = st->stx.stx_blksize;
	attr->attributes = st->stx.stx_attributes;
	attr->nlink = st->stx.stx_nlink;
	attr->uid = st->stx.stx_uid;
	attr->gid = st->stx.stx_gid;
	attr->mode = st->stx.stx_mode;
	attr->ino = st->stx.stx_ino;
	attr->size = st->stx.stx_size;
	attr->blocks = st->stx.stx_blocks;
	attr->attributes_mask = st->stx.stx_attributes_mask;
	ts_to_fuse_sx_tinme(&st->stx.stx_atime, &attr->atime);
	ts_to_fuse_sx_tinme(&st->stx.stx_btime, &attr->btime);
	ts_to_fuse_sx_tinme(&st->stx.stx_ctime, &attr->ctime);
	ts_to_fuse_sx_tinme(&st->stx.stx_mtime, &attr->mtime);
	attr->rdev_major = st->stx.stx_rdev_major;
	attr->rdev_minor = st->stx.stx_rdev_minor;
}

static void
fuse_setattr_to_stat(const struct fuse_setattr_in *attr, struct stat *st)
{
	memset(st, 0, sizeof(*st));
	st->st_mode = attr->mode;
	st->st_uid = attr->uid;
	st->st_gid = attr->gid;
	st->st_size = (off_t)attr->size;
	fuse_attr_to_timespec(attr->atime, attr->atimensec, &st->st_atim);
	fuse_attr_to_timespec(attr->mtime, attr->mtimensec, &st->st_mtim);
	fuse_attr_to_timespec(attr->ctime, attr->ctimensec, &st->st_ctim);
}

static void
statfs_to_fuse_kstatfs(const struct statvfs *stv, struct fuse_kstatfs *kstfs)
{
	memset(kstfs, 0, sizeof(*kstfs));
	kstfs->bsize = (uint32_t)stv->f_bsize;
	kstfs->frsize = (uint32_t)stv->f_frsize;
	kstfs->blocks = stv->f_blocks;
	kstfs->bfree = stv->f_bfree;
	kstfs->bavail = stv->f_bavail;
	kstfs->files = stv->f_files;
	kstfs->ffree = stv->f_ffree;
	kstfs->namelen = (uint32_t)stv->f_namemax;
}

static void
fill_fuse_entry_out(struct fuse_entry_out *ent, const struct silofs_stat *st)
{
	memset(ent, 0, sizeof(*ent));
	ent->nodeid = st->st.st_ino;
	ent->generation = st->gen;
	ent->entry_valid = UINT_MAX;
	ent->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &ent->attr);
}

static void fill_fuse_noentry_out(struct fuse_entry_out *ent)
{
	memset(ent, 0, sizeof(*ent));
	ent->nodeid = 0;
	ent->entry_valid = UINT_MAX;
}

static void
fill_fuse_attr_out(struct fuse_attr_out *attr, const struct silofs_stat *st)
{
	memset(attr, 0, sizeof(*attr));
	attr->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &attr->attr);
}

static void
fill_fuse_statx_out(struct fuse_statx_out *attr, const struct silofs_stat *st)
{
	memset(attr, 0, sizeof(*attr));
	attr->attr_valid = UINT_MAX;
	stat_to_fuse_statx(st, &attr->stat);
}

static void
fill_fuse_open_out(struct fuse_open_out *open, bool noflush, bool isdir)
{
	memset(open, 0, sizeof(*open));
	open->open_flags = FOPEN_KEEP_CACHE;
	if (noflush) {
		open->open_flags |= FOPEN_NOFLUSH;
	}
	if (isdir) {
		open->open_flags |= FOPEN_CACHE_DIR;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
check_fh_of(const struct silofs_task_ctx *task, ino_t ino, uint64_t fh)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc;

	if (fh != 0) {
		cmd_desc = cmd_desc_of(task->t_auth.opcode);
		fuseq_log_warn("op=%s ino=%lu fh=0x%lx",
		               cmd_desc ? cmd_desc->name : "", ino, fh);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_fuseq_pipe *fqp_from_lh(struct silofs_list_head *lh)
{
	struct silofs_fuseq_pipe *fqp = nullptr;

	if (lh != nullptr) {
		fqp = container_of(lh, struct silofs_fuseq_pipe, lh);
	}
	return fqp;
}

static void fqp_init(struct silofs_fuseq_pipe *fqp)
{
	silofs_list_head_init(&fqp->lh);
	silofs_pipe_init(&fqp->pp);
}

static void fqp_fini(struct silofs_fuseq_pipe *fqp)
{
	silofs_list_head_fini(&fqp->lh);
	silofs_pipe_fini(&fqp->pp);
}

static int fqp_open(struct silofs_fuseq_pipe *fqp, size_t sz)
{
	int err;

	err = silofs_pipe_open(&fqp->pp);
	if (err) {
		fuseq_log_warn("failed to open pipe: err=%d", err);
		return err;
	}
	err = silofs_pipe_grow(&fqp->pp, sz);
	if (err) {
		fuseq_log_warn("failed to grow pipe: sz=%zu err=%d", sz, err);
		return err;
	}
	return 0;
}

static int
fqp_dispose(struct silofs_fuseq_pipe *fqp, const struct silofs_nilfd *nilfd)
{
	int err;

	err = silofs_pipe_dispose(&fqp->pp, nilfd);
	if (err) {
		fuseq_log_warn("failed to dispose pipe: pipe-fd=%d "
		               "size=%d npend=%d nil-fd=%d err=%d",
		               fqp->pp.fd[0], fqp->pp.size, fqp->pp.pend,
		               nilfd->fd, err);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fuseq_lock_ps(struct silofs_fuseq *fq)
{
	silofs_mutex_lock(&fq->fq_ps_lock);
}

static void fuseq_unlock_ps(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_ps_lock);
}

static void fuseq_lock_ch(struct silofs_fuseq *fq)
{
	silofs_mutex_lock(&fq->fq_ch_lock);
}

static void fuseq_unlock_ch(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_ch_lock);
}

static void fuseq_lock_op(struct silofs_fuseq *fq)
{
	silofs_mutex_lock(&fq->fq_op_lock);
}

static void fuseq_unlock_op(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_op_lock);
}

static void fuseq_lock_ctl(struct silofs_fuseq *fq)
{
	silofs_mutex_lock(&fq->fq_ctl_lock);
}

static void fuseq_unlock_ctl(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_ctl_lock);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
fuseq_push_pipe(struct silofs_fuseq *fq, struct silofs_fuseq_pipe *fqp)
{
	fuseq_lock_ps(fq);
	silofs_listq_push_back(&fq->fq_pipes_freeq, &fqp->lh);
	fuseq_unlock_ps(fq);
}

static struct silofs_fuseq_pipe *fuseq_pop_pipe(struct silofs_fuseq *fq)
{
	struct silofs_list_head *lh;

	fuseq_lock_ps(fq);
	lh = silofs_listq_pop_front(&fq->fq_pipes_freeq);
	fuseq_unlock_ps(fq);

	return fqp_from_lh(lh);
}

static size_t fuseq_open_pipes_max(const struct silofs_fuseq *fq)
{
	const uint32_t limit = ARRAY_SIZE(fq->fq_pipes);

	return silofs_clamp_u32(fq->fq_nprocs / 2, 1, limit);
}

static int fuseq_open_pipes(struct silofs_fuseq *fq)
{
	const size_t pipesize = fq->fq_coni.buffsize;
	const size_t lim = fuseq_open_pipes_max(fq);
	int err;

	for (size_t i = 0; i < lim; ++i) {
		struct silofs_fuseq_pipe *fqp = &fq->fq_pipes[i];

		err = fqp_open(fqp, pipesize);
		if (err) {
			// if unable to open-and-grow any pipe than fallback to
			// full non-splice copy-mode.
			return (i > 0) ? 0 : err;
		}
		fuseq_push_pipe(fq, fqp);
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t operid_of(const struct silofs_task_ctx *task)
{
	return task->t_auth.unique;
}

static uint32_t opcode_of(const struct silofs_task_ctx *task)
{
	return task->t_auth.opcode;
}

static int sanitize_err(int err, uint32_t opcode)
{
	int err2 = abs(err);

	if (unlikely(err2 >= SILOFS_ERRBASE2)) {
		fuseq_log_err("internal error: err=%d op=%u", err, opcode);
		err2 = silofs_remap_status_code(err);
	} else if (err2 >= SILOFS_ERRBASE) {
		err2 = silofs_remap_status_code(err);
	}
	return -abs(err2);
}

static int sanitize_err_by(int err, const struct silofs_task_ctx *task)
{
	return sanitize_err(err, opcode_of(task));
}

static void fill_out_header(struct fuse_out_header *out_hdr, uint64_t unique,
                            size_t len, int err)
{
	out_hdr->len = (uint32_t)len;
	out_hdr->error = -abs(err);
	out_hdr->unique = unique;
}

static void fill_out_header_ok(struct fuse_out_header *out_hdr,
                               const struct silofs_task_ctx *task, size_t xlen)
{
	fill_out_header(out_hdr, operid_of(task), sizeof(*out_hdr) + xlen, 0);
}

static void fill_out_header_err(struct fuse_out_header *out_hdr,
                                const struct silofs_task_ctx *task, int err)
{
	fill_out_header(out_hdr, operid_of(task), sizeof(*out_hdr),
	                sanitize_err_by(err, task));
}

static const struct silofs_fuseq *fqs_fuseq(const struct silofs_fuseq_sub *fqs)
{
	return fqs->fqs_th.fq;
}

static struct silofs_fuseq *fqs_fuseq2(struct silofs_fuseq_sub *fqs)
{
	return fqs->fqs_th.fq;
}

static int fqs_fuse_fd(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	return fq->fq_fuse_fd;
}

static int fqs_send_msg(struct silofs_fuseq_sub *fqs, const struct iovec *iov,
                        size_t iovcnt)
{
	size_t nwr = 0;
	int fuse_fd;
	int err;

	fuse_fd = fqs_fuse_fd(fqs);
	err = silofs_sys_writev(fuse_fd, iov, (int)iovcnt, &nwr);
	if (err && (err != -ENOENT)) {
		fuseq_log_warn("send-to-fuse failed: fuse_fd=%d "
		               "iovcnt=%lu err=%d",
		               fuse_fd, iovcnt, err);
	}
	return err;
}

static int
fqs_reply_arg(struct silofs_fuseq_sub *fqs, const struct silofs_task_ctx *task,
              const void *arg, size_t argsz)
{
	struct fuse_out_header hdr;
	struct iovec iov[2];

	silofs_assert_gt(argsz, 0);
	silofs_assert_lt(argsz, 2 * SILOFS_MEGA);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = unconst(arg);
	iov[1].iov_len = argsz;

	fill_out_header_ok(&hdr, task, argsz);
	return fqs_send_msg(fqs, iov, 2);
}

static int fqs_reply_arg2(struct silofs_fuseq_sub *fqs,
                          const struct silofs_task_ctx *task, const void *arg1,
                          size_t argsz1, const void *arg2, size_t argsz2)
{
	struct fuse_out_header hdr;
	struct iovec iov[3];

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = unconst(arg1);
	iov[1].iov_len = argsz1;
	iov[2].iov_base = unconst(arg2);
	iov[2].iov_len = argsz2;

	fill_out_header_ok(&hdr, task, argsz1 + argsz2);
	return fqs_send_msg(fqs, iov, 3);
}

static int
fqs_reply_buf(struct silofs_fuseq_sub *fqs, const struct silofs_task_ctx *task,
              const void *buf, size_t bsz)
{
	struct fuse_out_header hdr;
	struct iovec iov[2];
	size_t cnt = 1;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	if (bsz) {
		iov[1].iov_base = unconst(buf);
		iov[1].iov_len = bsz;
		cnt = 2;
	}
	fill_out_header_ok(&hdr, task, bsz);
	return fqs_send_msg(fqs, iov, cnt);
}

static int fqs_reply_err(struct silofs_fuseq_sub *fqs,
                         const struct silofs_task_ctx *task, int err)
{
	struct fuse_out_header hdr;
	const struct iovec iov = { .iov_base = &hdr, .iov_len = sizeof(hdr) };

	fill_out_header_err(&hdr, task, err);
	return fqs_send_msg(fqs, &iov, 1);
}

static int fqs_reply_intr(struct silofs_fuseq_sub *fqs,
                          const struct silofs_task_ctx *task)
{
	return fqs_reply_err(fqs, task, -EINTR);
}

static int fqs_reply_status(struct silofs_fuseq_sub *fqs,
                            const struct silofs_task_ctx *task, int status)
{
	return fqs_reply_err(fqs, task, status);
}

static int fqs_reply_none(struct silofs_fuseq_sub *fqs)
{
	unused(fqs);
	return 0;
}

static int fqs_reply_entry_ok(struct silofs_fuseq_sub *fqs,
                              const struct silofs_task_ctx *task,
                              const struct silofs_stat *st)
{
	struct fuse_entry_out arg;

	fill_fuse_entry_out(&arg, st);
	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_lookup_noent(struct silofs_fuseq_sub *fqs,
                                  const struct silofs_task_ctx *task)
{
	struct fuse_entry_out arg;

	fill_fuse_noentry_out(&arg);
	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_create_ok(struct silofs_fuseq_sub *fqs,
                               const struct silofs_task_ctx *task,
                               const struct silofs_stat *st)
{
	struct fuse_entry_out arg1;
	struct fuse_open_out arg2;

	fill_fuse_entry_out(&arg1, st);
	fill_fuse_open_out(&arg2, false, false);
	return fqs_reply_arg2(fqs, task, &arg1, sizeof(arg1), &arg2,
	                      sizeof(arg2));
}

static int fqs_reply_attr_ok(struct silofs_fuseq_sub *fqs,
                             const struct silofs_task_ctx *task,
                             const struct silofs_stat *st)
{
	struct fuse_attr_out arg;

	fill_fuse_attr_out(&arg, st);
	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_statx_ok(struct silofs_fuseq_sub *fqs,
                              const struct silofs_task_ctx *task,
                              const struct silofs_stat *st)
{
	struct fuse_statx_out arg;

	fill_fuse_statx_out(&arg, st);
	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_statfs_ok(struct silofs_fuseq_sub *fqs,
                               const struct silofs_task_ctx *task,
                               const struct statvfs *stv)
{
	struct fuse_statfs_out arg;

	statfs_to_fuse_kstatfs(stv, &arg.st);
	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_readlink_ok(struct silofs_fuseq_sub *fqs,
                                 const struct silofs_task_ctx *task,
                                 const char *lnk, size_t len)
{
	return fqs_reply_buf(fqs, task, lnk, len);
}

static int
fqs_reply_open_ok(struct silofs_fuseq_sub *fqs,
                  const struct silofs_task_ctx *task, bool noflush, bool isdir)
{
	struct fuse_open_out arg;

	fill_fuse_open_out(&arg, noflush, isdir);
	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_opendir_ok(struct silofs_fuseq_sub *fqs,
                                const struct silofs_task_ctx *task)
{
	return fqs_reply_open_ok(fqs, task, false, true);
}

static int fqs_reply_write_ok(struct silofs_fuseq_sub *fqs,
                              const struct silofs_task_ctx *task, size_t cnt)
{
	const struct fuse_write_out arg = {
		.size = (uint32_t)cnt,
		.padding = 0,
	};

	silofs_assert_lt(cnt, UINT32_MAX);

	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_lseek_ok(struct silofs_fuseq_sub *fqs,
                              const struct silofs_task_ctx *task, off_t off)
{
	const struct fuse_lseek_out arg = { .offset = (uint64_t)off };

	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_xattr_len(struct silofs_fuseq_sub *fqs,
                               const struct silofs_task_ctx *task, size_t len)
{
	const struct fuse_getxattr_out arg = {
		.size = (uint32_t)len,
		.padding = 0,
	};

	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_xattr_buf(struct silofs_fuseq_sub *fqs,
                               const struct silofs_task_ctx *task,
                               const void *buf, size_t len)
{
	return fqs_reply_buf(fqs, task, buf, len);
}

static int fqs_reply_init_ok(struct silofs_fuseq_sub *fqs,
                             const struct silofs_task_ctx *task,
                             const struct silofs_fuseq_conn_info *coni)
{
	const struct fuse_init_out arg = {
		.major = coni->proto_major,
		.minor = coni->proto_minor,
		.max_readahead = coni->max_readahead,
		.flags = coni->want_cap,
		.max_background = (uint16_t)coni->max_background,
		.congestion_threshold = (uint16_t)coni->congestion_threshold,
		.max_write = (uint32_t)coni->max_write,
		.time_gran = (uint32_t)coni->time_gran,
		.max_pages = (coni->want_cap & FUSE_MAX_PAGES) ?
		                     (uint16_t)coni->max_pages :
		                     0,
	};

	return fqs_reply_arg(fqs, task, &arg, sizeof(arg));
}

static int fqs_reply_ioctl_ok(struct silofs_fuseq_sub *fqs,
                              const struct silofs_task_ctx *task, int result,
                              const void *buf, size_t size)
{
	struct fuse_ioctl_out arg;
	int ret;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;

	if (size && buf) {
		ret = fqs_reply_arg2(fqs, task, &arg, sizeof(arg), buf, size);
	} else {
		ret = fqs_reply_arg(fqs, task, &arg, sizeof(arg));
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool task_interrupted(const struct silofs_task_ctx *task)
{
	return unlikely(task->t_interrupt > 0);
}

static int fqs_reply_attr(struct silofs_fuseq_sub *fqs,
                          const struct silofs_task_ctx *task,
                          const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_attr_ok(fqs, task, st);
	}
	return ret;
}

static int fqs_reply_statx(struct silofs_fuseq_sub *fqs,
                           const struct silofs_task_ctx *task,
                           const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_statx_ok(fqs, task, st);
	}
	return ret;
}

static int fqs_reply_entry(struct silofs_fuseq_sub *fqs,
                           const struct silofs_task_ctx *task,
                           const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_entry_ok(fqs, task, st);
	}
	return ret;
}

static int fqs_reply_lookup(struct silofs_fuseq_sub *fqs,
                            const struct silofs_task_ctx *task,
                            const struct silofs_stat *st, int err)
{
	const int status = sanitize_err_by(err, task);
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (status == -ENOENT) {
		ret = fqs_reply_lookup_noent(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_entry_ok(fqs, task, st);
	}
	return ret;
}

static int fqs_reply_create(struct silofs_fuseq_sub *fqs,
                            const struct silofs_task_ctx *task,
                            const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_create_ok(fqs, task, st);
	}
	return ret;
}

static int fqs_reply_readlink(struct silofs_fuseq_sub *fqs,
                              const struct silofs_task_ctx *task,
                              const char *lnk, size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_readlink_ok(fqs, task, lnk, len);
	}
	return ret;
}

static int fqs_reply_statfs(struct silofs_fuseq_sub *fqs,
                            const struct silofs_task_ctx *task,
                            const struct statvfs *stv, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_statfs_ok(fqs, task, stv);
	}
	return ret;
}

static int
fqs_reply_open(struct silofs_fuseq_sub *fqs,
               const struct silofs_task_ctx *task, bool noflush, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_open_ok(fqs, task, noflush, false);
	}
	return ret;
}

static int fqs_reply_xattr(struct silofs_fuseq_sub *fqs,
                           const struct silofs_task_ctx *task, const void *buf,
                           size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else if (buf == nullptr) {
		ret = fqs_reply_xattr_len(fqs, task, len);
	} else {
		ret = fqs_reply_xattr_buf(fqs, task, buf, len);
	}
	return ret;
}

static int fqs_reply_opendir(struct silofs_fuseq_sub *fqs,
                             const struct silofs_task_ctx *task, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_opendir_ok(fqs, task);
	}
	return ret;
}

static int fqs_reply_readdir(struct silofs_fuseq_sub *fqs,
                             const struct silofs_task_ctx *task,
                             const struct silofs_fuseq_diter *di, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_buf(fqs, task, di->buf, di->len);
	}
	return ret;
}

static int
fqs_reply_lseek(struct silofs_fuseq_sub *fqs,
                const struct silofs_task_ctx *task, off_t off, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_lseek_ok(fqs, task, off);
	}
	return ret;
}

static int fqs_reply_copy_file_range(struct silofs_fuseq_sub *fqs,
                                     const struct silofs_task_ctx *task,
                                     size_t cnt, int err)
{
	int ret;

	STATICASSERT_LT(FUSEQ_COPY_FILE_RANGE_MAX, UINT32_MAX);

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_write_ok(fqs, task, cnt);
	}
	return ret;
}

static int fqs_reply_init(struct silofs_fuseq_sub *fqs,
                          const struct silofs_task_ctx *task, int err)
{
	const struct silofs_fuseq *fq;
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		fq = fqs_fuseq(fqs);
		ret = fqs_reply_init_ok(fqs, task, &fq->fq_coni);
	}
	return ret;
}

static int fqs_reply_ioctl(struct silofs_fuseq_sub *fqs,
                           const struct silofs_task_ctx *task, int result,
                           const void *buf, size_t size, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_ioctl_ok(fqs, task, result, buf, size);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
fqs_reply_write(struct silofs_fuseq_sub *fqs,
                const struct silofs_task_ctx *task, size_t cnt, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_write_ok(fqs, task, cnt);
	}
	return ret;
}

static int fqs_reply_read_buf(struct silofs_fuseq_sub *fqs,
                              const struct silofs_task_ctx *task,
                              const void *dat, size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fqs_reply_buf(fqs, task, dat, len);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void iovec_reset(struct silofs_iovec *iov)
{
	silofs_iovec_reset(iov);
}

static void
iovec_assign(struct silofs_iovec *iov, const struct silofs_iovec *other)
{
	silofs_iovec_assign(iov, other);
}

static bool iovec_isfdseq(const struct silofs_iovec *iovec1,
                          const struct silofs_iovec *iovec2)
{
	const off_t end1 =
		silofs_off_end(iovec1->iov_off, iovec1->iov.iov_len);
	const off_t beg2 = iovec2->iov_off;
	const int fd1 = iovec1->iov_fd;
	const int fd2 = iovec2->iov_fd;

	return (fd1 > 0) && (fd2 > 0) && (fd1 == fd2) && (end1 == beg2);
}

static void
iovec_append_len(struct silofs_iovec *iovec, const struct silofs_iovec *other)
{
	iovec->iov.iov_len += other->iov.iov_len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pipe *fqs_cur_pipe(struct silofs_fuseq_sub *fqs)
{
	silofs_assert_not_null(fqs->fqs_pipe);

	return &fqs->fqs_pipe->pp;
}

static int
fqs_append_hdr_to_pipe(struct silofs_fuseq_sub *fqs,
                       const struct silofs_task_ctx *task, size_t len)
{
	struct fuse_out_header hdr;
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);

	fill_out_header_ok(&hdr, task, len);
	return silofs_pipe_append_from_buf(pipe, &hdr, sizeof(hdr));
}

static int
fqs_append_data_to_pipe(struct silofs_fuseq_sub *fqs,
                        const struct silofs_iovec *iovec, size_t cnt)
{
	struct iovec iov[48];
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);
	size_t ncp = 0;
	size_t cur = 0;
	int err;

	STATICASSERT_LE(ARRAY_SIZE(iov), SILOFS_FILE_NITER_MAX);

	while (ncp < cnt) {
		cur = silofs_min(cnt - ncp, ARRAY_SIZE(iov));
		for (size_t i = 0; i < cur; ++i) {
			iov[i].iov_base = iovec[ncp + i].iov.iov_base;
			iov[i].iov_len = iovec[ncp + i].iov.iov_len;
		}
		err = silofs_pipe_vmsplice_from_iov(pipe, iov, cur, 0);
		if (err) {
			return err;
		}
		ncp += cur;
	}
	return 0;
}

static int fqs_send_pipe(struct silofs_fuseq_sub *fqs)
{
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);
	const int fuse_fd = fqs_fuse_fd(fqs);

	return silofs_pipe_sendall_to_fd(pipe, fuse_fd, 0);
}

static int fqs_reply_read_data(struct silofs_fuseq_sub *fqs,
                               const struct silofs_task_ctx *task, size_t nrd,
                               const struct silofs_iovec *iovec)
{
	return fqs_reply_buf(fqs, task, iovec->iov.iov_base, nrd);
}

static int fq_rdi_reply_read_iov(struct silofs_fuseq_rd_iter *fq_rdi)
{
	const struct silofs_iovec *iov = nullptr;
	size_t rem = 0;
	int err = 0;
	int ret = 0;

	err = fqs_append_hdr_to_pipe(fq_rdi->fqs, fq_rdi->task, fq_rdi->nrd);
	if (err) {
		goto out;
	}
	if (fq_rdi->ncp < fq_rdi->cnt) {
		iov = fq_rdi->iovec + fq_rdi->ncp;
		rem = fq_rdi->cnt - fq_rdi->ncp;
		err = fqs_append_data_to_pipe(fq_rdi->fqs, iov, rem);
		if (err) {
			goto out;
		}
		fq_rdi->ncp += rem;
	}
out:
	if (err) {
		ret = fqs_reply_err(fq_rdi->fqs, fq_rdi->task, err);
	} else {
		ret = fqs_send_pipe(fq_rdi->fqs);
	}
	return ret ? ret : err;
}

static int fq_rdi_reply_read_ok(struct silofs_fuseq_rd_iter *fq_rdi)
{
	struct silofs_fuseq_sub *fqs = fq_rdi->fqs;
	struct silofs_task_ctx *task = fq_rdi->task;
	int ret;

	if ((fq_rdi->cnt <= 1) && (fq_rdi->iovec[0].iov_fd < 0)) {
		ret = fqs_reply_read_data(fqs, task, fq_rdi->nrd,
		                          fq_rdi->iovec);
	} else {
		ret = fq_rdi_reply_read_iov(fq_rdi);
	}
	return ret;
}

static int fq_rdi_reply_read_iter(struct silofs_fuseq_rd_iter *fq_rdi, int err)
{
	struct silofs_fuseq_sub *fqs = fq_rdi->fqs;
	struct silofs_task_ctx *task = fq_rdi->task;
	int ret;

	if (task->t_interrupt) {
		ret = fqs_reply_intr(fqs, task);
	} else if (unlikely(err)) {
		ret = fqs_reply_err(fqs, task, err);
	} else {
		ret = fq_rdi_reply_read_ok(fq_rdi);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fuseq_xiter *xiter_of(struct silofs_listxattr_ctx *p)
{
	return container_of(p, struct silofs_fuseq_xiter, lxa);
}

static size_t xiter_avail(const struct silofs_fuseq_xiter *xi)
{
	return (size_t)(xi->end - xi->cur);
}

static bool xiter_hasroom(const struct silofs_fuseq_xiter *xi, size_t size)
{
	const size_t avail = xiter_avail(xi);

	return (avail >= size);
}

static int
fillxent(struct silofs_listxattr_ctx *lsx, const char *name, size_t nlen)
{
	const size_t size = nlen + 1;
	struct silofs_fuseq_xiter *xi = xiter_of(lsx);

	if (xi->cur) {
		if (!xiter_hasroom(xi, size)) {
			return -ERANGE;
		}
		memcpy(xi->cur, name, nlen);
		xi->cur[nlen] = '\0';
		xi->cur += size;
	}
	xi->cnt += size;
	return 0;
}

static void xiter_prep(struct silofs_fuseq_xiter *xi, size_t size)
{
	xi->lxa.actor = fillxent;
	xi->cnt = 0;

	if (size > 0) {
		xi->beg = xi->buf;
		xi->end = xi->beg + silofs_min(size, sizeof(xi->buf));
		xi->cur = xi->buf;
	} else {
		xi->beg = nullptr;
		xi->end = nullptr;
		xi->cur = nullptr;
	}
}

static void xiter_done(struct silofs_fuseq_xiter *xi)
{
	xi->lxa.actor = nullptr;
	xi->cnt = 0;
	xi->beg = nullptr;
	xi->end = nullptr;
	xi->cur = nullptr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
emit_direntonly(void *buf, size_t bsz, const char *name, size_t nlen,
                ino_t ino, mode_t dt, off_t off, size_t *out_sz)
{
	struct fuse_dirent *fde = buf;
	size_t entlen;
	size_t entlen_padded;

	entlen = FUSE_NAME_OFFSET + nlen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if (entlen_padded > bsz) {
		return -SILOFS_EINVAL;
	}

	fde->ino = ino;
	fde->off = (uint64_t)off;
	fde->namelen = (uint32_t)nlen;
	fde->type = dt;
	memcpy(fde->name, name, nlen);
	memset(fde->name + nlen, 0, entlen_padded - entlen);

	*out_sz = entlen_padded;
	return 0;
}

static int
emit_direntplus(void *buf, size_t bsz, const char *name, size_t nlen,
                const struct silofs_stat *st, off_t off, size_t *out_sz)
{
	struct fuse_direntplus *fdp = buf;
	struct fuse_dirent *fde = &fdp->dirent;
	size_t entlen;
	size_t entlen_padded;

	entlen = FUSE_NAME_OFFSET_DIRENTPLUS + nlen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if (entlen_padded > bsz) {
		return -SILOFS_EINVAL;
	}

	memset(&fdp->entry_out, 0, sizeof(fdp->entry_out));
	fill_fuse_entry_out(&fdp->entry_out, st);

	fde->ino = st->st.st_ino;
	fde->off = (uint64_t)off;
	fde->namelen = (uint32_t)nlen;
	fde->type = IFTODT(st->st.st_mode);
	memcpy(fde->name, name, nlen);
	memset(fde->name + nlen, 0, entlen_padded - entlen);

	*out_sz = entlen_padded;
	return 0;
}

static int emit_dirent(struct silofs_fuseq_diter *di, off_t off)
{
	uint8_t *buf = di->buf + di->len;
	const size_t rem = di->bsz - di->len;
	const ino_t ino = di->de_ino;
	const size_t nlen = di->de_nlen;
	const char *name = di->de_name.str;
	size_t cnt = 0;
	int err;

	if (rem <= di->de_nlen) {
		return -SILOFS_EINVAL;
	}
	if (likely(di->plus)) {
		err = emit_direntplus(buf, rem, name, nlen, &di->de_attr, off,
		                      &cnt);
	} else {
		err = emit_direntonly(buf, rem, name, nlen, ino, di->de_dt,
		                      off, &cnt);
	}
	if (err) {
		return err;
	}
	di->ndes++;
	di->len += cnt;
	return 0;
}

static void update_dirent(struct silofs_fuseq_diter *di,
                          const struct silofs_readdir_info *rdi)
{
	const size_t nbuf_sz = sizeof(di->de_name.str);

	di->de_off = rdi->off;
	di->de_ino = rdi->ino;
	di->de_dt = rdi->dt;
	di->de_nlen = silofs_min(rdi->namelen, nbuf_sz - 1);
	memcpy(di->de_name.str, rdi->name, di->de_nlen);
	memset(di->de_name.str + di->de_nlen, 0, nbuf_sz - di->de_nlen);
	if (di->plus) {
		memcpy(&di->de_attr, &rdi->attr, sizeof(di->de_attr));
	}
}

static bool has_dirent(const struct silofs_fuseq_diter *di)
{
	return (di->de_ino > 0) && (di->de_nlen > 0);
}

static struct silofs_fuseq_diter *diter_of(struct silofs_readdir_ctx *rd_ctx)
{
	return container_of(rd_ctx, struct silofs_fuseq_diter, rd_ctx);
}

static int filldir(struct silofs_readdir_ctx *rd_ctx,
                   const struct silofs_readdir_info *rdi)
{
	int err = 0;
	struct silofs_fuseq_diter *di;

	di = diter_of(rd_ctx);
	if (has_dirent(di)) {
		err = emit_dirent(di, rdi->off);
	}
	if (!err) {
		update_dirent(di, rdi);
	}
	return err;
}

static void
diter_prep(struct silofs_fuseq_diter *di, size_t bsz, off_t pos, int plus)
{
	di->ndes = 0;
	di->de_off = 0;
	di->de_nlen = 0;
	di->de_ino = 0;
	di->de_dt = 0;
	di->de_name.str[0] = '\0';
	di->bsz = silofs_min(bsz, sizeof(di->buf));
	di->len = 0;
	di->rd_ctx.actor = filldir;
	di->rd_ctx.pos = pos;
	di->plus = plus;
	memset(&di->de_attr, 0, sizeof(di->de_attr));
}

static void diter_done(struct silofs_fuseq_diter *di)
{
	di->ndes = 0;
	di->de_off = 0;
	di->de_nlen = 0;
	di->de_ino = 0;
	di->de_dt = 0;
	di->len = 0;
	di->rd_ctx.actor = nullptr;
	di->rd_ctx.pos = 0;
	di->plus = 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define update_cap_want(coni_, cap_) update_cap_want_(coni_, cap_, #cap_)

static void update_cap_want_(struct silofs_fuseq_conn_info *coni, uint32_t cap,
                             const char *cap_name)
{
	if (coni->kern_cap & cap) {
		coni->want_cap |= cap;
		fuseq_log_info("cap want: %s", cap_name);
	} else {
		fuseq_log_warn("cap not supported: %s", cap_name);
	}
}

static int fqs_check_init(const struct silofs_fuseq_sub *fqs,
                          const struct fuse_init_in *arg)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);
	const struct silofs_fuseq_conn_info *coni = &fq->fq_coni;
	const unsigned int u_major = coni->proto_major;
	const unsigned int u_minor = coni->proto_minor;

	if ((arg->major != u_major) || (arg->minor < u_minor)) {
		fuseq_log_warn("version mismatch: "
		               "kernel=%u.%u userspace=%u.%u",
		               arg->major, arg->minor, u_major, u_minor);
	}
	/*
	 * XXX minor __should__ be 36, but allow 34 due to fuse version on
	 * github's ubuntu-22.04 runners (fuse-7.34).
	 */
	if ((arg->major != 7) || (arg->minor < 34)) {
		fuseq_log_err("unsupported fuse-protocol version: %u.%u",
		              arg->major, arg->minor);
		return -EPROTO;
	}
	return 0;
}

/*
 * TODO-0018: Enable more capabilities
 *
 * When enabling FUSE_WRITEBACK_CACHE some tests fails with meta-data issues
 * (inconsistency in st_ctime,st_blocks). Needs further investigation and
 * probably a fix on kernel side.
 */
/*
 * TODO-0025: Have support for ACLs
 *
 * Enable FUSE_POSIX_ACL (plus, "system." prefix in xattr)
 */
static void do_init_capabilities(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_conn_info *coni = &fcc->fq->fq_coni;
	const uint32_t in_flags = fcc->in->u.init.arg.flags;

	coni->kern_cap = in_flags;
	coni->want_cap |= FUSE_BIG_WRITES; /* same as in libfuse */
	update_cap_want(coni, FUSE_ASYNC_READ);
	update_cap_want(coni, FUSE_ATOMIC_O_TRUNC);
	update_cap_want(coni, FUSE_EXPORT_SUPPORT);
	update_cap_want(coni, FUSE_SPLICE_WRITE);
	update_cap_want(coni, FUSE_SPLICE_READ);
	update_cap_want(coni, FUSE_PARALLEL_DIROPS);
	update_cap_want(coni, FUSE_MAX_PAGES);
	update_cap_want(coni, FUSE_CACHE_SYMLINKS);
	update_cap_want(coni, FUSE_DO_READDIRPLUS);
	update_cap_want(coni, FUSE_READDIRPLUS_AUTO);
	update_cap_want(coni, FUSE_ASYNC_DIO);
	update_cap_want(coni, FUSE_HANDLE_KILLPRIV_V2);
	update_cap_want(coni, FUSE_SETXATTR_EXT);
	if (!fuseq_may(fcc->fq, SILOFS_F_NOWRITEBACK)) {
		update_cap_want(coni, FUSE_WRITEBACK_CACHE);
	}
	if (fuseq_may(fcc->fq, SILOFS_F_AUTOINVAL)) {
		update_cap_want(coni, FUSE_AUTO_INVAL_DATA);
	}
}

static void do_init_log_conn_info(const struct silofs_fuseq_cmd_ctx *fcc)
{
	const struct silofs_fuseq *fq = fcc->fq;
	const struct silofs_fuseq_conn_info *coni = &fq->fq_coni;

	fuseq_log_info("init: kern_proto_major=%u kern_proto_minor=%u",
	               coni->kern_proto_major, coni->kern_proto_minor);
	fuseq_log_info("init: kern_cap=0x%x", coni->kern_cap);
	fuseq_log_info("init: proto_major=%u proto_minor=%u",
	               coni->proto_major, coni->proto_minor);
	fuseq_log_info("init: want_cap=0x%x", coni->want_cap);
	fuseq_log_info("init: buffsize=%zu", coni->buffsize);
	fuseq_log_info("init: max_write=%u", coni->max_write);
	fuseq_log_info("init: max_read=%u", coni->max_read);
	fuseq_log_info("init: max_readahead=%u", coni->max_readahead);
	fuseq_log_info("init: max_background=%u", coni->max_background);
	fuseq_log_info("init: congestion_threshold=%u",
	               coni->congestion_threshold);
	fuseq_log_info("init: time_gran=%u", coni->time_gran);
	fuseq_log_info("init: max_pages=%u", coni->max_pages);
	fuseq_log_info("init: oper_mode=%s",
	               fuseq_may_splice(fq) ? "pipe-splice" : "buffer-copy");
}

static int do_init(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_conn_info *coni = &fcc->fq->fq_coni;
	const uint32_t in_major = fcc->in->u.init.arg.major;
	const uint32_t in_minor = fcc->in->u.init.arg.minor;
	const uint32_t in_flags = fcc->in->u.init.arg.flags;
	int err;
	int ret;

	fuseq_log_info("init: ino=%ld version=%d.%d flags=0x%x", fcc->ino,
	               in_major, in_minor, in_flags);

	err = fqs_check_init(fcc->fqs, &fcc->in->u.init.arg);
	if (!err) {
		coni->kern_proto_major = in_major;
		coni->kern_proto_minor = in_minor;
		do_init_capabilities(fcc);
		fcc->fq->fq_got_init = true;
	}

	do_init_log_conn_info(fcc);

	ret = fqs_reply_init(fcc->fqs, fcc->task, err);
	if (!err && !ret) {
		fcc->fq->fq_reply_init_ok = true;
		fuseq_log_info("init-ok: version=%d.%d", in_major, in_minor);
	} else {
		fuseq_log_info("init-failure: ret=%d err=%d", ret, err);
	}
	return err ? err : ret;
}

static int do_destroy(const struct silofs_fuseq_cmd_ctx *fcc)
{
	fuseq_lock_ctl(fcc->fq);
	fcc->fq->fq_got_destroy = true;
	fuseq_set_non_active(fcc->fq);
	fuseq_unlock_ctl(fcc->fq);

	return fqs_reply_status(fcc->fqs, fcc->task, 0);
}

static bool fuseq_has_cap(const struct silofs_fuseq *fq, uint32_t cap_mask)
{
	const uint32_t cap_want = fq->fq_coni.want_cap;

	return fq->fq_got_init && ((cap_want & cap_mask) == cap_mask);
}

static bool fuseq_is_normal(const struct silofs_fuseq *fq)
{
	return fq->fq_got_init && fq->fq_reply_init_ok &&
	       !fq->fq_got_destroy && (fq->fq_nopers > 1);
}

static bool fuseq_cap_splice(const struct silofs_fuseq *fq)
{
	return fuseq_has_cap(fq, FUSE_SPLICE_READ | FUSE_SPLICE_WRITE);
}

static bool fuseq_allowed_splice(const struct silofs_fuseq *fq)
{
	bool ret = false;

	if ((fq->fq_nopers > 2) && fuseq_is_normal(fq)) {
		ret = (fuseq_may_splice(fq) && fuseq_cap_splice(fq));
	}
	return ret;
}

static bool fuseq_has_nactive_disptch(const struct silofs_fuseq *fq)
{
	return (fq->fq_subs.fq_nsub_run == fq->fq_subs.fq_nsub_lim);
}

static void fuseq_update_nexecs(struct silofs_fuseq *fq, int n)
{
	fuseq_lock_ctl(fq);
	if (n > 0) {
		fq->fq_nopers += n;
		fq->fq_nexecs = silofs_max_i64(1, fq->fq_nexecs + n);
	} else if (n < 0) {
		fq->fq_nexecs = silofs_min_i64(fq->fq_subs.fq_nsub_run,
		                               fq->fq_nexecs + n);
	}
	fuseq_unlock_ctl(fq);
}

static bool fuseq_has_memory_pressure(const struct silofs_fuseq *fq)
{
	struct silofs_alloc_stat st;

	silofs_memstat(fq->fq_alloc, &st);
	return st.nbytes_use > (st.nbytes_max / 10);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_exec_op(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return exec_op(fcc->task, fcc->args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define FATTR_MASK                                                       \
	(FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE | FATTR_ATIME | \
	 FATTR_MTIME | FATTR_FH | FATTR_ATIME_NOW | FATTR_MTIME_NOW |    \
	 FATTR_LOCKOWNER | FATTR_CTIME | FATTR_KILL_SUIDGID)

#define FATTR_AMTIME_NOW (FATTR_ATIME_NOW | FATTR_MTIME_NOW)

#define FATTR_AMCTIME (FATTR_ATIME | FATTR_MTIME | FATTR_CTIME)

#define FATTR_NONTIME (FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE)

static bool testf(uint32_t flags, uint32_t mask)
{
	return (flags & mask) > 0;
}

static int
uid_gid_of(const struct stat *attr, uint32_t to_set, uid_t *uid, gid_t *gid)
{
	*uid = testf(to_set, FATTR_UID) ? attr->st_uid : (uid_t)(-1);
	*gid = testf(to_set, FATTR_GID) ? attr->st_gid : (gid_t)(-1);
	return 0; /* TODO: Check valid ranges */
}

static void utimens_of(const struct stat *st, unsigned to_set,
                       struct silofs_itimes *itimes)
{
	const uint32_t set_ctime_now = //
		FATTR_AMTIME_NOW | FATTR_AMCTIME | FATTR_MODE | FATTR_UID |
		FATTR_GID | FATTR_SIZE;

	silofs_ts_omit(&itimes->btime);
	silofs_ts_omit(&itimes->atime);
	silofs_ts_omit(&itimes->mtime);
	silofs_ts_omit(&itimes->ctime);

	if (testf(to_set, FATTR_ATIME)) {
		silofs_ts_copy(&itimes->atime, &st->st_atim);
	}
	if (testf(to_set, FATTR_MTIME)) {
		silofs_ts_copy(&itimes->mtime, &st->st_mtim);
	}
	if (testf(to_set, FATTR_CTIME)) {
		silofs_ts_copy(&itimes->ctime, &st->st_ctim);
	} else if (testf(to_set, set_ctime_now)) {
		itimes->ctime.tv_nsec = UTIME_NOW;
	}
}

static int do_setattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct stat attr = { .st_size = -1 };
	const unsigned to_set = fcc->in->u.setattr.arg.valid & FATTR_MASK;
	int err;

	silofs_memzero(&fcc->args->in.setattr, sizeof(fcc->args->in.setattr));
	fuse_setattr_to_stat(&fcc->in->u.setattr.arg, &attr);

	utimens_of(&attr, to_set, &fcc->args->in.setattr.itimes);

	if (testf(to_set, FATTR_UID | FATTR_GID)) {
		uid_gid_of(&attr, to_set, &fcc->args->in.setattr.uid,
		           &fcc->args->in.setattr.gid);
		fcc->args->in.setattr.set_uid_gid = true;
	}
	if (testf(to_set, FATTR_AMTIME_NOW)) {
		fcc->args->in.setattr.set_amtime_now = true;
	}
	if (testf(to_set, FATTR_MODE)) {
		fcc->args->in.setattr.mode = attr.st_mode;
		fcc->args->in.setattr.set_mode = true;
	}
	if (testf(to_set, FATTR_SIZE)) {
		fcc->args->in.setattr.size = attr.st_size;
		fcc->args->in.setattr.set_size = true;
	}
	if (testf(to_set, FATTR_AMCTIME)) {
		fcc->args->in.setattr.set_amctime = true;
	}
	if (testf(to_set, FATTR_NONTIME)) {
		fcc->args->in.setattr.set_nontime = true;
	}
	if (testf(to_set, FATTR_KILL_SUIDGID)) {
		fcc->args->in.setattr.kill_suidgid = true;
	}
	fcc->args->in.setattr.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqs_reply_attr(fcc->fqs, fcc->task, &fcc->args->out.setattr.st,
	                      err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_lookup(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.lookup.parent = fcc->ino;
	fcc->args->in.lookup.name = fcc->in->u.lookup.name;
	err = do_exec_op(fcc);
	return fqs_reply_lookup(fcc->fqs, fcc->task, &fcc->args->out.lookup.st,
	                        err);
}

static int do_forget(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.forget.ino = fcc->ino;
	fcc->args->in.forget.nlookup = fcc->in->u.forget.arg.nlookup;
	err = do_exec_op(fcc);
	unused(err);
	return fqs_reply_none(fcc->fqs);
}

static const struct silofs_forget_in *
as_forget_in(const struct fuse_forget_one *one)
{
	const void *ptr = one;
	const struct silofs_forget_in *ret = ptr;

	STATICASSERT_EQ(sizeof(*ret), sizeof(*one));
	STATICASSERT_EQ(offsetof(struct fuse_forget_one, nodeid),
	                offsetof(struct silofs_forget_in, ino));
	STATICASSERT_EQ(offsetof(struct fuse_forget_one, nlookup),
	                offsetof(struct silofs_forget_in, nlookup));

	return ret;
}

static int do_batch_forget(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.batch_forget.count = fcc->in->u.batch_forget.arg.count;
	fcc->args->in.batch_forget.one =
		as_forget_in(fcc->in->u.batch_forget.one);
	err = do_exec_op(fcc);
	unused(err);
	return fqs_reply_none(fcc->fqs);
}

static int do_getattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.getattr.arg.fh);
	fcc->args->in.getattr.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqs_reply_attr(fcc->fqs, fcc->task, &fcc->args->out.getattr.st,
	                      err);
}

static int do_statx(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.statx.arg.fh);
	fcc->args->in.statx.ino = fcc->ino;
	fcc->args->in.statx.sx_mask = fcc->in->u.statx.arg.sx_mask;
	err = do_exec_op(fcc);
	return fqs_reply_statx(fcc->fqs, fcc->task, &fcc->args->out.statx.st,
	                       err);
}

static int do_readlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_pathbuf *pab = &fcc->fqs->fqs_outb->u.pab;
	char *lnk = pab->path;
	int err;

	fcc->args->in.readlink.ino = fcc->ino;
	fcc->args->in.readlink.ptr = lnk;
	fcc->args->in.readlink.lim = sizeof(pab->path);
	fcc->args->out.readlink.len = 0;
	err = do_exec_op(fcc);
	return fqs_reply_readlink(fcc->fqs, fcc->task, lnk,
	                          fcc->args->out.readlink.len, err);
}

static int do_symlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.symlink.parent = fcc->ino;
	fcc->args->in.symlink.name = fcc->in->u.symlink.name_target;
	fcc->args->in.symlink.symval = after_name(fcc->args->in.symlink.name);
	err = do_exec_op(fcc);
	return fqs_reply_entry(fcc->fqs, fcc->task, &fcc->args->out.symlink.st,
	                       err);
}

static int do_mknod(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.mknod.parent = fcc->ino;
	fcc->args->in.mknod.name = fcc->in->u.mknod.name;
	fcc->args->in.mknod.rdev = (dev_t)fcc->in->u.mknod.arg.rdev;
	fcc->args->in.mknod.mode = (mode_t)fcc->in->u.mknod.arg.mode;
	fcc->args->in.mknod.umask = (mode_t)fcc->in->u.mknod.arg.umask;
	silofs_task_update_umask(fcc->task, fcc->args->in.mknod.umask);
	err = do_exec_op(fcc);
	return fqs_reply_entry(fcc->fqs, fcc->task, &fcc->args->out.mknod.st,
	                       err);
}

static int do_mkdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.mkdir.parent = fcc->ino;
	fcc->args->in.mkdir.name = fcc->in->u.mkdir.name;
	fcc->args->in.mkdir.mode = (mode_t)(fcc->in->u.mkdir.arg.mode);
	fcc->args->in.mkdir.mode |= S_IFDIR;
	fcc->args->in.mkdir.umask = (mode_t)fcc->in->u.mkdir.arg.umask;
	silofs_task_update_umask(fcc->task, fcc->args->in.mkdir.umask);
	err = do_exec_op(fcc);
	return fqs_reply_entry(fcc->fqs, fcc->task, &fcc->args->out.mkdir.st,
	                       err);
}

static int do_unlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.unlink.parent = fcc->ino;
	fcc->args->in.unlink.name = fcc->in->u.unlink.name;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_rmdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.rmdir.parent = fcc->ino;
	fcc->args->in.rmdir.name = fcc->in->u.rmdir.name;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_rename(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.rename.parent = fcc->ino;
	fcc->args->in.rename.name = fcc->in->u.rename.name_newname;
	fcc->args->in.rename.newparent = (ino_t)(fcc->in->u.rename.arg.newdir);
	fcc->args->in.rename.newname = after_name(fcc->args->in.rename.name);
	fcc->args->in.rename.flags = 0;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_link(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.link.ino = (ino_t)(fcc->in->u.link.arg.oldnodeid);
	fcc->args->in.link.parent = fcc->ino;
	fcc->args->in.link.name = fcc->in->u.link.name;
	err = do_exec_op(fcc);
	return fqs_reply_entry(fcc->fqs, fcc->task, &fcc->args->out.link.st,
	                       err);
}

static int do_open(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int noflush;
	int err;

	fcc->args->in.open.ino = fcc->ino;
	fcc->args->in.open.o_flags = (int)(fcc->in->u.open.arg.flags);
	fcc->args->in.open.kill_suidgid =
		testf(fcc->in->u.open.arg.open_flags, FUSE_OPEN_KILL_SUIDGID);
	noflush = (fcc->args->in.open.o_flags & O_ACCMODE) == O_RDONLY;
	fcc->args->in.open.noflush = noflush;
	err = do_exec_op(fcc);
	return fqs_reply_open(fcc->fqs, fcc->task, noflush > 0, err);
}

static int do_statfs(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.statfs.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqs_reply_statfs(fcc->fqs, fcc->task,
	                        &fcc->args->out.statfs.stv, err);
}

static int do_release(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.release.arg.fh);
	fcc->args->in.release.ino = fcc->ino;
	fcc->args->in.release.o_flags = (int)fcc->in->u.release.arg.flags;
	fcc->args->in.release.flush =
		(fcc->in->u.release.arg.flags & FUSE_RELEASE_FLUSH) > 0;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_fsync(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.fsync.arg.fh);
	fcc->args->in.fsync.ino = fcc->ino;
	fcc->args->in.fsync.datasync =
		(fcc->in->u.fsync.arg.fsync_flags & 1) != 0;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_setxattr1(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.setxattr.ino = fcc->ino;
	fcc->args->in.setxattr.name = fcc->in->u.setxattr1.name_value;
	fcc->args->in.setxattr.value =
		after_name(fcc->in->u.setxattr1.name_value);
	fcc->args->in.setxattr.size = fcc->in->u.setxattr1.arg.size;
	fcc->args->in.setxattr.flags = (int)(fcc->in->u.setxattr1.arg.flags);
	fcc->args->in.setxattr.kill_sgid = false;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_setxattr2(const struct silofs_fuseq_cmd_ctx *fcc)
{
	const int mask = FUSE_SETXATTR_ACL_KILL_SGID;
	int err;

	fcc->args->in.setxattr.ino = fcc->ino;
	fcc->args->in.setxattr.name = fcc->in->u.setxattr.name_value;
	fcc->args->in.setxattr.value =
		after_name(fcc->in->u.setxattr.name_value);
	fcc->args->in.setxattr.size = fcc->in->u.setxattr.arg.size;
	fcc->args->in.setxattr.flags = (int)(fcc->in->u.setxattr.arg.flags);
	fcc->args->in.setxattr.kill_sgid =
		(fcc->args->in.setxattr.flags & mask) > 0;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_setxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return (fcc->fq->fq_coni.kern_proto_minor <= 33) ? do_setxattr1(fcc) :
	                                                   do_setxattr2(fcc);
}

static int do_getxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_xattrbuf *xab = &fcc->fqs->fqs_outb->u.xab;
	int err;

	fcc->args->in.getxattr.ino = fcc->ino;
	fcc->args->in.getxattr.name = fcc->in->u.getxattr.name;
	fcc->args->in.getxattr.size =
		silofs_min(fcc->in->u.getxattr.arg.size, sizeof(xab->value));
	fcc->args->in.getxattr.buf = fcc->args->in.getxattr.size ? xab->value :
	                                                           nullptr;
	fcc->args->out.getxattr.size = 0;
	err = do_exec_op(fcc);
	return fqs_reply_xattr(fcc->fqs, fcc->task, fcc->args->in.getxattr.buf,
	                       fcc->args->out.getxattr.size, err);
}

static int do_listxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_xiter *xit = &fcc->fqs->fqs_outb->u.xit;
	int ret;
	int err;

	xiter_prep(xit, fcc->in->u.listxattr.arg.size);
	fcc->args->in.listxattr.ino = fcc->ino;
	fcc->args->in.listxattr.lxa_ctx = &xit->lxa;
	err = do_exec_op(fcc);
	ret = fqs_reply_xattr(fcc->fqs, fcc->task, xit->beg, xit->cnt, err);
	xiter_done(xit);
	return ret;
}

static int do_removexattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.removexattr.ino = fcc->ino;
	fcc->args->in.removexattr.name = fcc->in->u.removexattr.name;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_flush(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.flush.arg.fh);
	fcc->args->in.flush.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_opendir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.opendir.ino = fcc->ino;
	fcc->args->in.opendir.o_flags = (int)(fcc->in->u.opendir.arg.flags);
	err = do_exec_op(fcc);
	return fqs_reply_opendir(fcc->fqs, fcc->task, err);
}

static int do_readdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_diter *dit = &fcc->fqs->fqs_outb->u.dit;
	const size_t size = fcc->in->u.readdir.arg.size;
	const off_t off = (off_t)(fcc->in->u.readdir.arg.offset);
	int ret;
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 0);
	fcc->args->in.readdir.ino = fcc->ino;
	fcc->args->in.readdir.rd_ctx = &dit->rd_ctx;
	err = do_exec_op(fcc);
	ret = fqs_reply_readdir(fcc->fqs, fcc->task, dit, err);
	diter_done(dit);
	return ret;
}

static int do_readdirplus(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_diter *dit = &fcc->fqs->fqs_outb->u.dit;
	const size_t size = fcc->in->u.readdir.arg.size;
	const off_t off = (off_t)(fcc->in->u.readdir.arg.offset);
	int ret;
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 1);
	fcc->args->in.readdir.ino = fcc->ino;
	fcc->args->in.readdir.rd_ctx = &dit->rd_ctx;
	err = do_exec_op(fcc);
	ret = fqs_reply_readdir(fcc->fqs, fcc->task, dit, err);
	diter_done(dit);
	return ret;
}

static int do_releasedir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.releasedir.arg.fh);
	fcc->args->in.releasedir.ino = fcc->ino;
	fcc->args->in.releasedir.o_flags =
		(int)(fcc->in->u.releasedir.arg.flags);
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_fsyncdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.fsyncdir.arg.fh);
	fcc->args->in.fsyncdir.ino = fcc->ino;
	fcc->args->in.fsyncdir.datasync =
		(fcc->in->u.fsyncdir.arg.fsync_flags & 1) != 0;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_access(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.access.ino = fcc->ino;
	fcc->args->in.access.mask = (int)(fcc->in->u.access.arg.mask);
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_create(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.create.parent = fcc->ino;
	fcc->args->in.create.name = fcc->in->u.create.name;
	fcc->args->in.create.o_flags = (int)(fcc->in->u.create.arg.flags);
	fcc->args->in.create.mode = (mode_t)(fcc->in->u.create.arg.mode);
	fcc->args->in.create.umask = (mode_t)(fcc->in->u.create.arg.umask);
	fcc->args->in.create.kill_suidgid =
		testf(fcc->in->u.create.arg.open_flags,
	              FUSE_OPEN_KILL_SUIDGID);
	silofs_task_update_umask(fcc->task, fcc->args->in.create.umask);
	err = do_exec_op(fcc);
	return fqs_reply_create(fcc->fqs, fcc->task, &fcc->args->out.create.st,
	                        err);
}

static int do_fallocate(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.fallocate.arg.fh);
	fcc->args->in.fallocate.ino = fcc->ino;
	fcc->args->in.fallocate.mode = (int)(fcc->in->u.fallocate.arg.mode);
	fcc->args->in.fallocate.off = (off_t)(fcc->in->u.fallocate.arg.offset);
	fcc->args->in.fallocate.len = (off_t)(fcc->in->u.fallocate.arg.length);
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_rename2(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.rename.parent = fcc->ino;
	fcc->args->in.rename.newparent =
		(ino_t)(fcc->in->u.rename2.arg.newdir);
	fcc->args->in.rename.name = fcc->in->u.rename2.name_newname;
	fcc->args->in.rename.newname = after_name(fcc->args->in.rename.name);
	fcc->args->in.rename.flags = (int)(fcc->in->u.rename2.arg.flags);
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_lseek(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.lseek.arg.fh);
	fcc->args->in.lseek.ino = fcc->ino;
	fcc->args->in.lseek.off = (off_t)(fcc->in->u.lseek.arg.offset);
	fcc->args->in.lseek.whence = (int)(fcc->in->u.lseek.arg.whence);
	fcc->args->out.lseek.off = -1;
	err = do_exec_op(fcc);
	return fqs_reply_lseek(fcc->fqs, fcc->task, fcc->args->out.lseek.off,
	                       err);
}

static int do_copy_file_range(const struct silofs_fuseq_cmd_ctx *fcc)
{
	size_t len = 0;
	size_t ncp = 0;
	int err;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.copy_file_range.arg.fh_in);
	len = silofs_min(fcc->in->u.copy_file_range.arg.len,
	                 FUSEQ_COPY_FILE_RANGE_MAX);
	fcc->args->in.copy_file_range.ino_in = fcc->ino;
	fcc->args->in.copy_file_range.off_in =
		(off_t)fcc->in->u.copy_file_range.arg.off_in;
	fcc->args->in.copy_file_range.ino_out =
		(ino_t)fcc->in->u.copy_file_range.arg.nodeid_out;
	fcc->args->in.copy_file_range.off_out =
		(off_t)fcc->in->u.copy_file_range.arg.off_out;
	fcc->args->in.copy_file_range.len = len;
	fcc->args->in.copy_file_range.flags =
		(int)fcc->in->u.copy_file_range.arg.flags;
	fcc->args->out.copy_file_range.ncp = 0;
	err = do_exec_op(fcc);
	ncp = fcc->args->out.copy_file_range.ncp;
	return fqs_reply_copy_file_range(fcc->fqs, fcc->task, ncp, err);
}

static int do_syncfs(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.syncfs.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqs_reply_status(fcc->fqs, fcc->task, err);
}

static int do_interrupt(const struct silofs_fuseq_cmd_ctx *fcc)
{
	uint64_t unq;

	if (fcc->ino == 0) {
		unq = fcc->in->u.interrupt.arg.unique;
		fqs_interrupt_op(fcc->fqs, unq);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fuseq_rd_iter *
fq_rdi_of(const struct silofs_rwiter_ctx *rwi)
{
	const struct silofs_fuseq_rd_iter *fq_rdi =
		container_of2(rwi, struct silofs_fuseq_rd_iter, rwi);

	return unconst(fq_rdi);
}

static int
fq_rdi_actor(struct silofs_rwiter_ctx *rwi, const struct silofs_iovec *iovec)
{
	struct silofs_fuseq_rd_iter *fq_rdi = fq_rdi_of(rwi);

	if ((iovec->iov_fd > 0) && (iovec->iov_off < 0)) {
		return -SILOFS_EINVAL;
	}
	if (!(fq_rdi->cnt < ARRAY_SIZE(fq_rdi->iovec))) {
		return -SILOFS_EINVAL;
	}
	if ((fq_rdi->nrd + iovec->iov.iov_len) > fq_rdi->nrd_max) {
		return -SILOFS_EINVAL;
	}
	iovec_assign(&fq_rdi->iovec[fq_rdi->cnt++], iovec);
	fq_rdi->nrd += iovec->iov.iov_len;
	return 0;
}

static void
fqs_setup_rd_iter(struct silofs_fuseq_sub *fqs, struct silofs_task_ctx *task,
                  struct silofs_fuseq_rd_iter *fq_rdi, size_t len, off_t off)
{
	fq_rdi->fqs = fqs;
	fq_rdi->task = task;
	fq_rdi->cnt = 0;
	fq_rdi->ncp = 0;
	fq_rdi->nrd = 0;
	fq_rdi->nrd_max = len;
	fq_rdi->rwi.len = len;
	fq_rdi->rwi.off = off;
	fq_rdi->rwi.actor = fq_rdi_actor;
}

static int do_rdwr_post(struct silofs_task_ctx *task, int wr_mode,
                        const struct silofs_iovec *iov, size_t cnt)
{
	return silofs_exec_rdwr_post(task, wr_mode, iov, cnt);
}

static int do_read_iter(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_rd_iter *fq_rdi = &fcc->fqs->fqs_rwi->u.rdi;
	size_t len;
	int ret;
	int err;

	len = silofs_min(fcc->in->u.read.arg.size, fcc->fq->fq_coni.max_read);
	fcc->args->in.read.ino = fcc->ino;
	fcc->args->in.read.off = (off_t)(fcc->in->u.read.arg.offset);
	fcc->args->in.read.len = len;
	fcc->args->in.read.buf = nullptr;
	fcc->args->in.read.rwi_ctx = &fq_rdi->rwi;
	fcc->args->in.read.o_flags = (int)(fcc->in->u.read.arg.flags);
	fqs_setup_rd_iter(fcc->fqs, fcc->task, fq_rdi, len,
	                  fcc->args->in.read.off);
	err = do_exec_op(fcc);
	ret = fq_rdi_reply_read_iter(fq_rdi, err);
	do_rdwr_post(fcc->task, 0, fq_rdi->iovec, fq_rdi->cnt);
	return ret;
}

static int do_read_buf(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_databuf *dab = &fcc->fqs->fqs_outb->u.dab;
	size_t len;
	int err;

	len = silofs_min(fcc->in->u.read.arg.size, fcc->fq->fq_coni.max_read);
	fcc->args->in.read.ino = fcc->ino;
	fcc->args->in.read.off = (off_t)(fcc->in->u.read.arg.offset);
	fcc->args->in.read.len = len;
	fcc->args->in.read.buf = dab->buf;
	fcc->args->in.read.rwi_ctx = nullptr;
	fcc->args->in.read.o_flags = (int)(fcc->in->u.read.arg.flags);
	fcc->args->out.read.nrd = 0;
	err = do_exec_op(fcc);
	return fqs_reply_read_buf(fcc->fqs, fcc->task, dab->buf,
	                          fcc->args->out.read.nrd, err);
}

static bool fqs_may_read_iter(const struct silofs_fuseq_sub *fqs)
{
	return (fqs->fqs_pipe != nullptr) && fqs_has_large_read_in(fqs);
}

static int do_read(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int ret;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.read.arg.fh);
	if (fqs_may_read_iter(fcc->fqs)) {
		ret = do_read_iter(fcc);
	} else {
		ret = do_read_buf(fcc);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fuseq_wr_iter *
fq_wri_of(const struct silofs_rwiter_ctx *rwi)
{
	const struct silofs_fuseq_wr_iter *fq_wri =
		container_of2(rwi, struct silofs_fuseq_wr_iter, rwi);

	return unconst(fq_wri);
}

static int fqs_extract_from_pipe_by_fd(struct silofs_fuseq_sub *fqs,
                                       const struct silofs_iovec *iovec)
{
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);
	off_t off = iovec->iov_off;

	return silofs_pipe_splice_to_fd(pipe, iovec->iov_fd, &off,
	                                iovec->iov.iov_len,
	                                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
}

static int fqs_extract_from_pipe_by_iov(struct silofs_fuseq_sub *fqs,
                                        const struct silofs_iovec *iovec)
{
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);

	return silofs_pipe_vmsplice_to_iov(pipe, &iovec->iov, 1,
	                                   SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
}

static int fqs_extract_data_from_pipe(struct silofs_fuseq_sub *fqs,
                                      const struct silofs_iovec *iovec)
{
	int err;

	if (iovec->iov_fd > 0) {
		err = fqs_extract_from_pipe_by_fd(fqs, iovec);
	} else if (iovec->iov.iov_base != nullptr) {
		err = fqs_extract_from_pipe_by_iov(fqs, iovec);
	} else {
		fuseq_log_err("bad iovec entry: fd=%d off=%ld len=%lu",
		              iovec->iov_fd, iovec->iov_off,
		              iovec->iov.iov_len);
		err = -SILOFS_EINVAL;
	}
	return err;
}

static int fq_wri_check(const struct silofs_fuseq_wr_iter *fq_wri,
                        const struct silofs_iovec *iovec)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fq_wri->fqs);

	if (!fq->fq_active) {
		return -EROFS;
	}
	if (!(fq_wri->cnt < ARRAY_SIZE(fq_wri->iovec))) {
		return -SILOFS_EINVAL;
	}
	if (iovec->iov_off < 0) {
		return -SILOFS_EINVAL;
	}
	if ((iovec->iov_fd < 0) && (iovec->iov.iov_base == nullptr)) {
		return -SILOFS_EINVAL;
	}
	if ((fq_wri->nwr + iovec->iov.iov_len) > fq_wri->nwr_max) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int
fq_wri_actor(struct silofs_rwiter_ctx *rwi, const struct silofs_iovec *iovec)
{
	struct silofs_fuseq_wr_iter *fq_wri = fq_wri_of(rwi);
	int err;

	err = fq_wri_check(fq_wri, iovec);
	if (err) {
		return err;
	}
	err = fqs_extract_data_from_pipe(fq_wri->fqs, iovec);
	if (err) {
		return err;
	}
	iovec_assign(&fq_wri->iovec[fq_wri->cnt++], iovec);
	fq_wri->nwr += iovec->iov.iov_len;
	fq_wri->ncp++;
	return 0;
}

static int fq_wri_async_actor(struct silofs_rwiter_ctx *rwi,
                              const struct silofs_iovec *iov)
{
	struct silofs_fuseq_wr_iter *fq_wri = fq_wri_of(rwi);
	int err;

	err = fq_wri_check(fq_wri, iov);
	if (err) {
		return err;
	}
	iovec_assign(&fq_wri->iovec[fq_wri->cnt++], iov);
	return 0;
}

static int fq_wri_copy_iov(struct silofs_fuseq_wr_iter *fq_wri)
{
	struct silofs_iovec iovec;
	struct silofs_fuseq_sub *fqs = fq_wri->fqs;
	const struct silofs_iovec *itr = nullptr;
	size_t cur = 0;
	int err;

	while (fq_wri->ncp < fq_wri->cnt) {
		cur = 0;
		iovec_reset(&iovec);
		for (size_t i = fq_wri->ncp; i < fq_wri->cnt; ++i) {
			itr = &fq_wri->iovec[i];
			if (!cur) {
				iovec_assign(&iovec, itr);
			} else if (iovec_isfdseq(&iovec, itr)) {
				iovec_append_len(&iovec, itr);
			} else {
				break;
			}
			cur++;
		}
		err = fqs_extract_data_from_pipe(fqs, &iovec);
		if (err) {
			return err;
		}
		fq_wri->nwr += iovec.iov.iov_len;
		fq_wri->ncp += cur;
	}
	return 0;
}

static bool fqs_asyncwr_mode(const struct silofs_fuseq_sub *fqs)
{
	return fuseq_may(fqs_fuseq(fqs), SILOFS_F_ASYNCWR);
}

static void
fqs_setup_wr_iter(struct silofs_fuseq_sub *fqs,
                  struct silofs_fuseq_wr_iter *fq_rwi, size_t len, off_t off)
{
	fq_rwi->fqs = fqs;
	fq_rwi->nwr = 0;
	fq_rwi->cnt = 0;
	fq_rwi->ncp = 0;
	fq_rwi->nwr_max = len;
	fq_rwi->rwi.len = len;
	fq_rwi->rwi.off = off;
	fq_rwi->rwi.actor = fqs_asyncwr_mode(fqs) ? fq_wri_async_actor :
	                                            fq_wri_actor;
}

static void *tail_of(const struct silofs_fuseq_in *in, size_t head_len)
{
	const void *p = in;
	const uint8_t *t = (const uint8_t *)p + head_len;

	return unconst(t);
}

static int do_write_buf(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;
	int ret;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.write.arg.fh);
	fcc->args->in.write.ino = fcc->ino;
	fcc->args->in.write.len = fcc->in->u.write.arg.size;
	fcc->args->in.write.off = (off_t)(fcc->in->u.write.arg.offset);
	fcc->args->in.write.buf = tail_of(fcc->in, sizeof(fcc->in->u.write));
	fcc->args->in.write.rwi_ctx = nullptr;
	fcc->args->in.write.o_flags = (int)(fcc->in->u.write.arg.flags);
	fcc->args->in.write.kill_suidgid =
		testf(fcc->in->u.write.arg.write_flags,
	              FUSE_WRITE_KILL_SUIDGID);
	fcc->args->out.write.nwr = 0;
	err = do_exec_op(fcc);
	ret = fqs_reply_write(fcc->fqs, fcc->task, fcc->args->out.write.nwr,
	                      err);
	return ret;
}

static int do_write_iter(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_wr_iter *fq_wri = &fcc->fqs->fqs_rwi->u.wri;
	const size_t con_max_write = fcc->fq->fq_coni.max_write;
	size_t len = 0;
	int err1 = 0;
	int err2 = 0;
	int ret = 0;

	check_fh_of(fcc->task, fcc->ino, fcc->in->u.write.arg.fh);
	len = silofs_min(fcc->in->u.write.arg.size, con_max_write);
	fcc->args->in.write.ino = fcc->ino;
	fcc->args->in.write.len = len;
	fcc->args->in.write.off = (off_t)(fcc->in->u.write.arg.offset);
	fcc->args->in.write.buf = nullptr;
	fcc->args->in.write.rwi_ctx = &fq_wri->rwi;
	fcc->args->in.write.o_flags = (int)(fcc->in->u.write.arg.flags);
	fcc->args->in.write.kill_suidgid =
		testf(fcc->in->u.write.arg.write_flags,
	              FUSE_WRITE_KILL_SUIDGID);
	fcc->args->out.write.nwr = 0;
	fqs_setup_wr_iter(fcc->fqs, fq_wri, len, fcc->args->in.write.off);
	err1 = do_exec_op(fcc);
	if (!err1 || (err1 == -ENOSPC)) {
		err2 = fq_wri_copy_iov(fq_wri); /* unlocked */
	}
	do_rdwr_post(fcc->task, 1, fq_wri->iovec, fq_wri->cnt);
	ret = fqs_reply_write(fcc->fqs, fcc->task, fq_wri->nwr,
	                      err1 ? err1 : err2);
	return ret;
}

static bool fqs_may_write_iter(const struct silofs_fuseq_sub *fqs)
{
	return (fqs->fqs_pipe != nullptr) && fqs_has_large_write_in(fqs);
}

static void do_pre_write(const struct silofs_fuseq_cmd_ctx *fcc)
{
	if (fcc->in->u.write.arg.write_flags & FUSE_WRITE_CACHE) {
		fcc->task->t_kwrite = true;
	}
}

static int do_write(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int ret;

	do_pre_write(fcc);
	if (fqs_may_write_iter(fcc->fqs)) {
		ret = do_write_iter(fcc);
	} else {
		ret = do_write_buf(fcc);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_ioc_notimpl(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return fqs_reply_err(fcc->fqs, fcc->task, -ENOTTY);
}

static int do_ioc_getflags(const struct silofs_fuseq_cmd_ctx *fcc)
{
	const size_t out_bufsz = fcc->in->u.ioctl.arg.out_size;
	long attr = 0;
	int err;

	if (out_bufsz != sizeof(attr)) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	fcc->task->t_auth.opcode = FUSE_GETATTR;
	fcc->args->in.getattr.ino = fcc->ino;
	err = do_exec_op(fcc);
	if (err) {
		goto out;
	}
	/* TODO: proper impl */
	attr = (long)(FS_NOATIME_FL);
out:
	return fqs_reply_ioctl(fcc->fqs, fcc->task, 0, &attr, sizeof(attr),
	                       err);
}

static int do_ioc_query(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	const void *buf_in = fcc->in->u.ioctl.buf;
	const struct silofs_ioc_query *qry_in = &ioc_u.query;
	const size_t bsz_in = fcc->in->u.ioctl.arg.in_size;
	const size_t bsz_out = fcc->in->u.ioctl.arg.out_size;
	const int flags = (int)(fcc->in->u.ioctl.arg.flags);
	int err;

	if (bsz_in > sizeof(ioc_u)) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	memcpy(ioc_u.buf, buf_in, bsz_in);
	fcc->args->ioc_cmd = SILOFS_IOC_QUERY;
	fcc->args->in.query.ino = fcc->ino;
	fcc->args->in.query.qtype = (enum silofs_query_type)qry_in->qtype;

	if (!bsz_out && (flags & FUSE_IOCTL_RETRY)) {
		err = -SILOFS_ENOSYS;
		goto out;
	}
	if (bsz_out != sizeof(*qry_in)) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	if (bsz_in < sizeof(qry_in->qtype)) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	err = do_exec_op(fcc);
out:
	return fqs_reply_ioctl(fcc->fqs, fcc->task, 0,
	                       &fcc->args->out.query.qry,
	                       sizeof(fcc->args->out.query.qry), err);
}

static void assign_ioc_blobid(struct silofs_blobid *blobid,
                              const struct silofs_paddr *paddr)
{
	silofs_blobid_copyto(&paddr->blobid, blobid);
}

static int do_ioc_clone(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	const struct silofs_mbrefs *mbrefs = &fcc->args->out.clone.mbrefs;
	void *buf_out = fcc->fqs->fqs_outb->u.iob.b;
	struct silofs_ioc_forkfs *cl_out = &ioc_u.forkfs;
	const size_t bsz_in_min = 1;
	const size_t bsz_in_max = sizeof(*cl_out);
	const size_t bsz_out_min = sizeof(*cl_out);
	const size_t bsz_in = fcc->in->u.ioctl.arg.in_size;
	const size_t bsz_out = fcc->in->u.ioctl.arg.out_size;
	const int flags = (int)(fcc->in->u.ioctl.arg.flags);
	int err;

	if (!bsz_out && (flags & FUSE_IOCTL_RETRY)) {
		err = -SILOFS_ENOSYS;
		goto out;
	}
	if ((bsz_in < bsz_in_min) || (bsz_in > bsz_in_max)) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	if (bsz_out < bsz_out_min) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	fcc->args->ioc_cmd = SILOFS_IOC_FORKFS;
	fcc->args->in.clone.ino = fcc->ino;
	fcc->args->in.clone.flags = 0;
	err = do_exec_op(fcc);
	if (err) {
		goto out;
	}

	memset(cl_out, 0, sizeof(*cl_out));
	assign_ioc_blobid(&cl_out->base, &mbrefs->base);
	assign_ioc_blobid(&cl_out->main, &mbrefs->main);
	assign_ioc_blobid(&cl_out->fork, &mbrefs->fork);
	memcpy(buf_out, cl_out, sizeof(*cl_out));
out:
	return fqs_reply_ioctl(fcc->fqs, fcc->task, 0, cl_out, sizeof(*cl_out),
	                       err);
}

static int do_ioc_syncfs(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	const void *buf_in = fcc->in->u.ioctl.buf;
	const size_t bsz_in = fcc->in->u.ioctl.arg.in_size;
	const size_t bsz_out = fcc->in->u.ioctl.arg.out_size;
	int err;

	if ((bsz_in < sizeof(ioc_u.syncfs)) || (bsz_in > sizeof(ioc_u))) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	if (bsz_out > 0) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	memcpy(&ioc_u.syncfs, buf_in, sizeof(ioc_u.syncfs));
	fcc->args->ioc_cmd = SILOFS_IOC_SYNCFS;
	fcc->args->in.syncfs.ino = fcc->ino;
	fcc->args->in.syncfs.flags = (int)ioc_u.syncfs.flags;
	err = do_exec_op(fcc);
	if (err) {
		goto out;
	}
out:
	return fqs_reply_ioctl(fcc->fqs, fcc->task, 0, nullptr, 0, err);
}

static int do_ioc_tune(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	const void *buf_in = fcc->in->u.ioctl.buf;
	const size_t bsz_in = fcc->in->u.ioctl.arg.in_size;
	const size_t bsz_out = fcc->in->u.ioctl.arg.out_size;
	int err;

	if ((bsz_in < sizeof(ioc_u.tune)) || (bsz_in > sizeof(ioc_u))) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	if (bsz_out > 0) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	memcpy(&ioc_u.tune, buf_in, sizeof(ioc_u.tune));
	fcc->args->ioc_cmd = SILOFS_IOC_TUNE;
	fcc->args->in.tune.ino = fcc->ino;
	fcc->args->in.tune.iflags_want = (int)ioc_u.tune.iflags_want;
	fcc->args->in.tune.iflags_dont = (int)ioc_u.tune.iflags_dont;
	err = do_exec_op(fcc);
	if (err) {
		goto out;
	}
out:
	return fqs_reply_ioctl(fcc->fqs, fcc->task, 0, nullptr, 0, err);
}

static int fqs_check_ioctl_flags(struct silofs_fuseq_sub *fqs,
                                 const struct silofs_fuseq_in *in)
{
	const int flags = (int)(in->u.ioctl.arg.flags);

	if (flags & FUSE_IOCTL_COMPAT) {
		return -SILOFS_ENOSYS;
	}
	if ((flags & FUSE_IOCTL_DIR) && (flags & FUSE_IOCTL_UNRESTRICTED)) {
		return -SILOFS_ENOSYS;
	}
	unused(fqs);
	return 0;
}

static int fqs_check_ioctl_in_size(const struct silofs_fuseq_sub *fqs,
                                   const struct silofs_fuseq_in *in)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);
	const size_t in_size = in->u.ioctl.arg.in_size;
	const size_t bsz_max = fq->fq_coni.buffsize;

	return (in_size < bsz_max) ? 0 : -SILOFS_EINVAL;
}

static int do_ioctl(const struct silofs_fuseq_cmd_ctx *fcc)
{
	long ioc_cmd;
	int err;
	int ret;

	err = fqs_check_ioctl_flags(fcc->fqs, fcc->in);
	if (err) {
		ret = fqs_reply_err(fcc->fqs, fcc->task, err);
		goto out;
	}
	err = fqs_check_ioctl_in_size(fcc->fqs, fcc->in);
	if (err) {
		ret = fqs_reply_err(fcc->fqs, fcc->task, err);
		goto out;
	}
	ioc_cmd = (long)(fcc->in->u.ioctl.arg.cmd);
	switch (ioc_cmd) {
	case FS_IOC_GETFLAGS:
		ret = do_ioc_getflags(fcc);
		break;
	case SILOFS_IOC_QUERY:
		ret = do_ioc_query(fcc);
		break;
	case SILOFS_IOC_FORKFS:
		ret = do_ioc_clone(fcc);
		break;
	case SILOFS_IOC_SYNCFS:
		ret = do_ioc_syncfs(fcc);
		break;
	case SILOFS_IOC_TUNE:
		ret = do_ioc_tune(fcc);
		break;
	default:
		ret = do_ioc_notimpl(fcc);
		break;
	}
out:
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void fqt_init(struct silofs_fuseq_thread *fqt, struct silofs_fuseq *fq,
                     uint32_t idx)
{
	silofs_memzero(fqt, sizeof(*fqt));
	fqt->fq = fq;
	fqt->idx = idx;
	fqt->execed = false;
	fqt->joined = false;
}

static void fqt_fini(struct silofs_fuseq_thread *fqt)
{
	fqt->fq = nullptr;
	fqt->idx = UINT32_MAX;
}

static void fqt_make_thread_name(const struct silofs_fuseq_thread *fqt,
                                 struct silofs_strbuf *out_name)
{
	silofs_strbuf_reset(out_name);
	silofs_strbuf_sprintf(out_name, "silofs%u", fqt->idx + 1);
}

static int
fqt_exec_thread(struct silofs_fuseq_thread *fqt, silofs_threadexec_fn start_fn)
{
	struct silofs_strbuf name;
	int err;

	fqt_make_thread_name(fqt, &name);
	err = silofs_thread_create(&fqt->th, start_fn, nullptr, name.str);
	if (err) {
		fuseq_log_err("failed to create thread: name=%s err=%d",
		              name.str, err);
		return err;
	}
	fqt->execed = true;
	return 0;
}

static int fqt_block_thread_signals(const struct silofs_fuseq_thread *fqt)
{
	int err;

	err = silofs_thread_sigblock_common();
	if (err) {
		fuseq_log_warn("unable to block thread signals: "
		               "name=%s err=%d",
		               fqt->th.name, err);
	}
	return err;
}

static int fqt_join_thread(struct silofs_fuseq_thread *fqt)
{
	int err;

	err = silofs_thread_join(&fqt->th);
	if (err) {
		fuseq_log_err("failed to join thread: name=%s err=%d",
		              fqt->th.name, err);
		return err;
	}
	fqt->joined = true;
	return 0;
}

static void fqt_join_thread_now(struct silofs_fuseq_thread *fqt)
{
	int err;

	if (fqt->execed && !fqt->joined) {
		err = fqt_join_thread(fqt);
		if (err) {
			silofs_panic("failed to join thread: name=%s err=%d",
			             fqt->th.name, err);
		}
	}
}

static bool fqt_completed(const struct silofs_fuseq_thread *fqt)
{
	const time_t start_time = fqt->th.start_time;
	const time_t finish_time = fqt->th.finish_time;

	return (start_time > 0) && (finish_time >= start_time);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define FUSEQ_CMD(opcode_, hook_, rtime_) \
	[opcode_] = { hook_, SILOFS_STR(opcode_), opcode_, rtime_ }

static const struct silofs_fuseq_cmd_desc fuseq_cmd_tbl[] = {
	FUSEQ_CMD(FUSE_LOOKUP, do_lookup, 0),
	FUSEQ_CMD(FUSE_FORGET, do_forget, 0),
	FUSEQ_CMD(FUSE_GETATTR, do_getattr, 0),
	FUSEQ_CMD(FUSE_SETATTR, do_setattr, 1),
	FUSEQ_CMD(FUSE_READLINK, do_readlink, 0),
	FUSEQ_CMD(FUSE_SYMLINK, do_symlink, 1),
	FUSEQ_CMD(FUSE_MKNOD, do_mknod, 1),
	FUSEQ_CMD(FUSE_MKDIR, do_mkdir, 1),
	FUSEQ_CMD(FUSE_UNLINK, do_unlink, 1),
	FUSEQ_CMD(FUSE_RMDIR, do_rmdir, 1),
	FUSEQ_CMD(FUSE_RENAME, do_rename, 1),
	FUSEQ_CMD(FUSE_LINK, do_link, 1),
	FUSEQ_CMD(FUSE_OPEN, do_open, 1),
	FUSEQ_CMD(FUSE_READ, do_read, 0),
	FUSEQ_CMD(FUSE_WRITE, do_write, 1),
	FUSEQ_CMD(FUSE_STATFS, do_statfs, 0),
	FUSEQ_CMD(FUSE_RELEASE, do_release, 0),
	FUSEQ_CMD(FUSE_FSYNC, do_fsync, 0),
	FUSEQ_CMD(FUSE_SETXATTR, do_setxattr, 1),
	FUSEQ_CMD(FUSE_GETXATTR, do_getxattr, 0),
	FUSEQ_CMD(FUSE_LISTXATTR, do_listxattr, 0),
	FUSEQ_CMD(FUSE_REMOVEXATTR, do_removexattr, 1),
	FUSEQ_CMD(FUSE_FLUSH, do_flush, 0),
	FUSEQ_CMD(FUSE_INIT, do_init, 1),
	FUSEQ_CMD(FUSE_OPENDIR, do_opendir, 1),
	FUSEQ_CMD(FUSE_READDIR, do_readdir, 1),
	FUSEQ_CMD(FUSE_RELEASEDIR, do_releasedir, 1),
	FUSEQ_CMD(FUSE_FSYNCDIR, do_fsyncdir, 1),
	FUSEQ_CMD(FUSE_GETLK, nullptr, 0),
	FUSEQ_CMD(FUSE_SETLKW, nullptr, 0),
	FUSEQ_CMD(FUSE_ACCESS, do_access, 0),
	FUSEQ_CMD(FUSE_CREATE, do_create, 1),
	FUSEQ_CMD(FUSE_INTERRUPT, nullptr, 0),
	FUSEQ_CMD(FUSE_BMAP, nullptr, 0),
	FUSEQ_CMD(FUSE_DESTROY, do_destroy, 1),
	FUSEQ_CMD(FUSE_IOCTL, do_ioctl, 1),
	FUSEQ_CMD(FUSE_POLL, nullptr, 0),
	FUSEQ_CMD(FUSE_NOTIFY_REPLY, nullptr, 0),
	FUSEQ_CMD(FUSE_BATCH_FORGET, do_batch_forget, 0),
	FUSEQ_CMD(FUSE_FALLOCATE, do_fallocate, 1),
	FUSEQ_CMD(FUSE_READDIRPLUS, do_readdirplus, 0),
	FUSEQ_CMD(FUSE_RENAME2, do_rename2, 1),
	FUSEQ_CMD(FUSE_LSEEK, do_lseek, 0),
	FUSEQ_CMD(FUSE_COPY_FILE_RANGE, do_copy_file_range, 1),
	FUSEQ_CMD(FUSE_SETUPMAPPING, nullptr, 0),
	FUSEQ_CMD(FUSE_REMOVEMAPPING, nullptr, 0),
	FUSEQ_CMD(FUSE_SYNCFS, do_syncfs, 1),
	FUSEQ_CMD(FUSE_STATX, do_statx, 0),
};

static const struct silofs_fuseq_cmd_desc *cmd_desc_of(uint32_t opc)
{
	const struct silofs_fuseq_cmd_desc *cmd = nullptr;

	STATICASSERT_LE(ARRAY_SIZE(fuseq_cmd_tbl), FUSEQ_CMD_MAX);

	if (opc && (opc < ARRAY_SIZE(fuseq_cmd_tbl))) {
		cmd = &fuseq_cmd_tbl[opc];
	}
	return cmd;
}

static const char *fqs_thread_name(const struct silofs_fuseq_sub *fqs)
{
	return fqs->fqs_th.th.name;
}

static struct silofs_fuseq_in *fqs_in_of(struct silofs_fuseq_sub *fqs)
{
	return &fqs->fqs_inb->u.in;
}

static const struct silofs_fuseq_in *
fqs_in_of2(const struct silofs_fuseq_sub *fqs)
{
	return &fqs->fqs_inb->u.in;
}

static uint32_t fqs_in_opcode(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq_in *in = fqs_in_of2(fqs);

	return in->u.hdr.hdr.opcode;
}

static uint64_t fqs_in_ioctl_cmd(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq_in *in = fqs_in_of2(fqs);
	uint64_t ioc_cmd = 0;
	uint32_t opcode;

	opcode = fqs_in_opcode(fqs);
	if (opcode == FUSE_IOCTL) {
		ioc_cmd = in->u.ioctl.arg.cmd;
	}
	return ioc_cmd;
}

static bool fqs_has_exclusive_cmd(const struct silofs_fuseq_sub *fqs)
{
	const uint64_t ioc_cmd = fqs_in_ioctl_cmd(fqs);

	return (ioc_cmd == SILOFS_IOC_FORKFS) ||
	       (ioc_cmd == SILOFS_IOC_SYNCFS);
}

static int
fqs_check_opcode(const struct silofs_fuseq_sub *fqs, uint32_t op_code)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);
	const struct silofs_fuseq_cmd_desc *cmd_desc = cmd_desc_of(op_code);

	if ((cmd_desc == nullptr) || (cmd_desc->hook == nullptr)) {
		/* TODO: handle cases of FUSE_INTERUPT properly */
		return -SILOFS_ENOSYS;
	}
	if (!fq->fq_got_init && (cmd_desc->code != FUSE_INIT)) {
		return -SILOFS_EIO;
	}
	if (fq->fq_got_init && (cmd_desc->code == FUSE_INIT)) {
		return -SILOFS_EIO;
	}
	return 0;
}

static int fqs_check_perm(const struct silofs_fuseq_sub *fqs, uid_t op_uid,
                          uint32_t op_code)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	if (!fq->fq_deny_others) {
		return 0;
	}
	if ((op_uid == 0) || (op_uid == fq->fq_fs_owner)) {
		return 0;
	}
	switch (op_code) {
	case FUSE_INIT:
	case FUSE_READ:
	case FUSE_WRITE:
	case FUSE_FSYNC:
	case FUSE_RELEASE:
	case FUSE_READDIR:
	case FUSE_FSYNCDIR:
	case FUSE_RELEASEDIR:
	case FUSE_NOTIFY_REPLY:
	case FUSE_READDIRPLUS:
		return 0;
	default:
		break;
	}
	return -EACCES;
}

static bool is_large_io(off_t off, size_t size)
{
	off_t end;

	if (size <= SILOFS_PAGE_SIZE_MIN) {
		return false;
	}
	end = silofs_off_end(off, size);
	if (end <= SILOFS_LBK_SIZE) {
		return false;
	}
	return true;
}

static bool fqs_has_large_write_in(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq_in *in = nullptr;
	const uint32_t opcode = fqs_in_opcode(fqs);
	off_t off = 0;
	bool ret = false;

	if (opcode == FUSE_WRITE) {
		in = fqs_in_of2(fqs);
		off = (off_t)in->u.write.arg.offset;
		ret = is_large_io(off, in->u.write.arg.size);
	}
	return ret;
}

static bool fqs_has_large_read_in(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq_in *in = nullptr;
	const uint32_t opcode = fqs_in_opcode(fqs);
	off_t off = 0;
	bool ret = false;

	if (opcode == FUSE_READ) {
		in = fqs_in_of2(fqs);
		off = (off_t)in->u.read.arg.offset;
		ret = is_large_io(off, in->u.read.arg.size);
	}
	return ret;
}

static void fqs_update_task(const struct silofs_fuseq_sub *fqs,
                            struct silofs_task_ctx *task)
{
	const struct silofs_fuseq_in *in = fqs_in_of2(fqs);
	const struct fuse_in_header *hdr = &in->u.hdr.hdr;

	silofs_task_set_creds(task, hdr->uid, hdr->gid, 0);
	task->t_auth.pid = (pid_t)hdr->pid;
	task->t_auth.unique = hdr->unique;
	task->t_auth.opcode = fqs_in_opcode(fqs);
	task->t_exclusive = fqs_has_exclusive_cmd(fqs);
}

static void fqs_setup_task(const struct silofs_fuseq_sub *fqs,
                           struct silofs_task_ctx *task)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	silofs_task_init(task, fq->fq_env);
	fqs_update_task(fqs, task);
}

static void fqs_finish_task(const struct silofs_fuseq_sub *fqs,
                            struct silofs_task_ctx *task)
{
	silofs_task_fini(task);
	silofs_unused(fqs);
}

static int fqs_check_task(struct silofs_fuseq_sub *fqs,
                          const struct silofs_task_ctx *task)
{
	const unsigned int op_code = task->t_auth.opcode;
	const uid_t uid = task->t_auth.creds.host_cred.uid;
	int err;

	err = fqs_check_opcode(fqs, op_code);
	if (err) {
		return err;
	}
	err = fqs_check_perm(fqs, uid, op_code);
	if (err) {
		return err;
	}
	return 0;
}

static void fqs_pre_exec_request(struct silofs_fuseq_sub *fqs)
{
	fuseq_update_nexecs(fqs_fuseq2(fqs), 1);
}

static void
fqs_enq_active_op(struct silofs_fuseq_sub *fqs, struct silofs_task_ctx *task)
{
	struct silofs_fuseq *fq = fqs_fuseq2(fqs);

	fuseq_lock_op(fq);
	listq_push_front(&fq->fq_curr_opers, &fqs->fqs_lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fq);
}

static void
fqs_dec_active_op(struct silofs_fuseq_sub *fqs, struct silofs_task_ctx *task)
{
	struct silofs_fuseq *fq = fqs_fuseq2(fqs);

	fuseq_lock_op(fq);
	listq_remove(&fq->fq_curr_opers, &fqs->fqs_lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fq);
}

static void fqs_interrupt_op(struct silofs_fuseq_sub *fqs, uint64_t unq)
{
	/*
	 * TODO-0026: Re-anble FUSEINTERRUPT hook
	 *
	 * Using list of active operations turned out as buggy; for example, it
	 * breaks postgresql unit-test. Need to read carefully Kernel side code
	 * and see what can be done. Also, try to understand what the warding
	 * in kernel's Documentation:
	 *   fuse.rst:#interrupting-filesystem-operations
	 */
	if (unq > 0) {
		struct silofs_fuseq *fq = fqs_fuseq2(fqs);

		fuseq_lock_op(fq);
		/* interrupt code comes here... */
		fuseq_unlock_op(fq);
	}
	silofs_unused(do_interrupt);
}

static int call_oper_of(const struct silofs_fuseq_cmd_ctx *fcc,
                        const struct silofs_fuseq_cmd_desc *cmd_desc)
{
	return cmd_desc->hook(fcc);
}

static int
fqs_call_oper(struct silofs_fuseq_sub *fqs, struct silofs_task_ctx *task)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc = nullptr;
	const struct silofs_fuseq_in *in = fqs_in_of(fqs);
	const struct silofs_fuseq_cmd_ctx fcc = {
		.fq = fqs_fuseq2(fqs),
		.fqs = fqs,
		.task = task,
		.args = &fqs->fqs_args,
		.in = in,
		.ino = in->u.hdr.hdr.nodeid,
	};
	int err = -SILOFS_ENOSYS;

	cmd_desc = cmd_desc_of(task->t_auth.opcode);
	if (likely(cmd_desc != nullptr)) {
		fqs_enq_active_op(fqs, task);
		err = call_oper_of(&fcc, cmd_desc);
		fqs_dec_active_op(fqs, task);
	}
	return err;
}

static int
fqs_submit_by(const struct silofs_fuseq_sub *fqs, struct silofs_task_ctx *task)
{
	silofs_unused(fqs);
	return silofs_task_submit(task, false);
}

static int
fqs_do_exec_request(struct silofs_fuseq_sub *fqs, struct silofs_task_ctx *task)
{
	int err1;
	int err2;

	fqs_pre_exec_request(fqs);
	silofs_rwlock_fs_by(task);
	err1 = fqs_call_oper(fqs, task);
	err2 = fqs_submit_by(fqs, task);
	silofs_rwunlock_fs_by(task);

	return err1 ? err1 : err2;
}

static void fqs_refresh_task_by_cmd(const struct silofs_fuseq_sub *fqs,
                                    struct silofs_task_ctx *task)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc;

	cmd_desc = cmd_desc_of(task->t_auth.opcode);
	silofs_task_set_ts(task, cmd_desc && (cmd_desc->realtime > 0));
	silofs_unused(fqs);
}

static int fqs_exec_request(struct silofs_fuseq_sub *fqs)
{
	struct silofs_task_ctx task;
	int err;

	fqs_setup_task(fqs, &task);
	err = fqs_check_task(fqs, &task);
	if (unlikely(err)) {
		err = fqs_reply_err(fqs, &task, err);
	} else {
		fqs_refresh_task_by_cmd(fqs, &task);
		err = fqs_do_exec_request(fqs, &task);
	}
	fqs_finish_task(fqs, &task);
	return err;
}

static void fqs_reset_inhdr(struct silofs_fuseq_sub *fqs)
{
	struct silofs_fuseq_in *in = fqs_in_of(fqs);
	struct silofs_fuseq_hdr_in *hdr = &in->u.hdr;

	memset(hdr, 0, sizeof(*hdr));
}

static size_t fqs_max_inlen(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);
	const struct silofs_fuseq_in *in = fqs_in_of2(fqs);
	const size_t len_max = fq->fq_coni.buffsize;

	silofs_assert_gt(len_max, FUSE_BUFFER_HEADER_SIZE);
	silofs_assert_le(len_max, sizeof(*in));
	silofs_unused(in); /* make clangscan happy */

	return len_max;
}

static int
fqs_check_inhdr(const struct silofs_fuseq_sub *fqs, size_t nrd, bool full)
{
	const struct silofs_fuseq_in *in = fqs_in_of2(fqs);
	const struct silofs_fuseq_hdr_in *hdr = &in->u.hdr;
	const size_t len = hdr->hdr.len;
	const size_t len_min = sizeof(*hdr);
	const size_t len_max = fqs_max_inlen(fqs);

	if (unlikely(nrd < len_min)) {
		fuseq_log_err("illegal in-length: "
		              "nrd=%lu len_min=%lu ",
		              nrd, len_min);
		return -SILOFS_EPROTO;
	}
	if (unlikely(len > len_max)) {
		fuseq_log_err("illegal header: opcode=%d len=%lu len_max=%lu",
		              fqs_in_opcode(fqs), len, len_max);
		return -SILOFS_EPROTO;
	}
	if (unlikely(full && (len != nrd))) {
		fuseq_log_err("header length mismatch: "
		              "opcode=%d nrd=%lu len=%lu ",
		              fqs_in_opcode(fqs), nrd, len);
		return -SILOFS_EIO;
	}
	return 0;
}

static int fqs_wait_request(const struct silofs_fuseq_sub *fqs)
{
	const int fuse_fd = fqs_fuse_fd(fqs);
	const int timout_millisec = 300 + (int)(fqs->fqs_th.idx);

	return silofs_sys_pollin_rfd(fuse_fd, timout_millisec);
}

static int fqs_recv_buf(const struct silofs_fuseq_sub *fqs, void *buf,
                        size_t cnt, size_t *out_sz)
{
	const int fuse_fd = fqs_fuse_fd(fqs);

	*out_sz = 0;
	return cnt ? silofs_sys_read(fuse_fd, buf, cnt, out_sz) : 0;
}

static int fqs_recv_in_all(struct silofs_fuseq_sub *fqs, size_t *out_sz)
{
	struct silofs_fuseq_in *in = fqs_in_of(fqs);

	return fqs_recv_buf(fqs, in, fqs_max_inlen(fqs), out_sz);
}

static int fqs_recv_copy_in(struct silofs_fuseq_sub *fqs)
{
	size_t len = 0;
	int err;

	err = fqs_recv_in_all(fqs, &len);
	if (err == -ETIMEDOUT) {
		return err;
	}
	if (unlikely(err)) {
		fuseq_log_err("read fuse-to-buff failed: fuse_fd=%d err=%d",
		              fqs_fuse_fd(fqs), err);
		return err;
	}
	if (unlikely(len < sizeof(struct fuse_in_header))) {
		fuseq_log_err("fuse read-in too-short: len=%lu", len);
		return -SILOFS_EIO;
	}
	return fqs_check_inhdr(fqs, len, true);
}

static int fqs_splice_into_pipe(struct silofs_fuseq_sub *fqs, size_t cnt)
{
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);
	const int fuse_fd = fqs_fuse_fd(fqs);
	int err;

	silofs_assert_eq(pipe->pend, 0);
	silofs_assert_gt(cnt, 0);
	silofs_assert_le(cnt, pipe->size);

	err = silofs_pipe_splice_from_fd(pipe, fuse_fd, nullptr, cnt,
	                                 SPLICE_F_MOVE);
	if (unlikely(err)) {
		if (err == -ENODEV) {
			fuseq_log_dbg("fuse splice-in nodev-error: "
			              "fuse_fd=%d cnt=%lu",
			              fuse_fd, cnt);
		} else {
			fuseq_log_err("fuse splice-in failed: fuse_fd=%d "
			              "cnt=%lu err=%d",
			              fuse_fd, cnt, err);
		}
	}
	return err;
}

static int fqs_copy_from_pipe_in(struct silofs_fuseq_sub *fqs, size_t head_sz,
                                 size_t cnt, size_t *out_ncp)
{
	struct silofs_fuseq_in *in = fqs_in_of(fqs);
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);
	const int pre = pipe->pend;
	int err;

	err = silofs_pipe_copy_to_buf(pipe, tail_of(in, head_sz), cnt);
	if (unlikely(err)) {
		return err;
	}
	*out_ncp = (size_t)(pre - pipe->pend);
	return 0;
}

/*
 * fuse.ko requires user-space to transfer the entire message (header +
 * sub-command control + data payload) into user-space owned buffer: either
 * as in-memory buffer or via in-kernel pipe (splice-mode). When trying to
 * copy in smaller chunks, we get -EINVAL.
 *
 * Do a two phase operation: first copy from common fuse-fd into thread-private
 * pipe under channel-lock, then release the lock and copy from private pipe
 * into internal buffer. Note that for the special case of long-write
 * operation, data remains in pipe until it is consumed by write_iter.
 */
static int fqs_recv_splice_in(struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	return fqs_splice_into_pipe(fqs, fq->fq_coni.buffsize);
}

/*
 * TODO-0056: Copy into in-buffer with offset to make I/O page-aligned
 *
 * When doing FUSE_WRITE in non-large mode, copy data into in buffer with
 * proper initial skip to make each sub-io copy operation touch only a single
 * memory page. Check that it improves performance.
 */
static int fqs_copy_pipe_in(struct silofs_fuseq_sub *fqs)
{
	struct silofs_fuseq_in *in = fqs_in_of(fqs);
	struct silofs_fuseq_hdr_in *hdr_in = &in->u.hdr;
	struct silofs_pipe *pipe = fqs_cur_pipe(fqs);
	const size_t nsp = (size_t)(pipe->pend);
	const size_t cnt = silofs_min(sizeof(in->u.write), nsp);
	size_t ncp1 = 0;
	size_t ncp2 = 0;
	size_t rem;
	int err;

	err = fqs_copy_from_pipe_in(fqs, 0, cnt, &ncp1);
	if (err) {
		return err;
	}
	rem = (size_t)hdr_in->hdr.len - ncp1;
	err = fqs_check_inhdr(fqs, ncp1, rem == 0);
	if (unlikely(err)) {
		return err;
	}
	if (!rem || fqs_has_large_write_in(fqs)) {
		return 0;
	}
	err = fqs_copy_from_pipe_in(fqs, ncp1, rem, &ncp2);
	if (unlikely(err)) {
		return err;
	}
	err = fqs_check_inhdr(fqs, ncp1 + ncp2, true);
	if (unlikely(err)) {
		return err;
	}
	return 0;
}

static bool fqs_has_exec_mode(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	return fuseq_is_active(fq) || fuseq_has_live_opers(fq);
}

static int fqs_copy_or_splice_in(struct silofs_fuseq_sub *fqs)
{
	int ret;

	if (fqs->fqs_pipe != nullptr) {
		ret = fqs_recv_splice_in(fqs);
	} else {
		ret = fqs_recv_copy_in(fqs);
	}
	return ret;
}

static int fqs_do_recv_in(struct silofs_fuseq_sub *fqs)
{
	int err = -SILOFS_ENORX;

	if (fqs_has_exec_mode(fqs)) {
		err = fqs_wait_request(fqs);
		if (!err) {
			err = fqs_copy_or_splice_in(fqs);
		}
	}
	return err;
}

static int fqs_check_pipe_pre(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);
	const size_t buffsize = fq->fq_coni.buffsize;
	int pipesize, pipepend;

	if (fqs->fqs_pipe == nullptr) {
		return 0;
	}
	pipesize = fqs->fqs_pipe->pp.size;
	if (unlikely((int)buffsize < pipesize)) {
		fuseq_log_err("pipe-fuse mismatch: pipesize=%d buffsize=%zu ",
		              pipesize, buffsize);
		return -SILOFS_EIO;
	}
	pipepend = fqs->fqs_pipe->pp.pend;
	if (unlikely(pipepend != 0)) {
		fuseq_log_err("pipe not empty: pend=%d fuse_fd=%d", pipepend,
		              fq->fq_fuse_fd);
		return -SILOFS_EIO;
	}
	return 0;
}

static int fqs_acquire_pipe(struct silofs_fuseq_sub *fqs)
{
	struct silofs_fuseq *fq = fqs_fuseq2(fqs);
	int err;

	silofs_assert_null(fqs->fqs_pipe);

	fqs->fqs_pipe = fuseq_pop_pipe(fq);
	if (fqs->fqs_pipe == nullptr) {
		return 0; /* OK, fallback to buffer-only mode */
	}
	err = fqp_dispose(fqs->fqs_pipe, &fq->fq_nilfd);
	if (err) {
		return err; /* should never happen */
	}
	return fqs_check_pipe_pre(fqs);
}

static bool fqs_allowed_splice(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	return fuseq_allowed_splice(fq);
}

static int fqs_try_acquire_pipe(struct silofs_fuseq_sub *fqs)
{
	int ret = 0;

	if (fqs_allowed_splice(fqs)) {
		ret = fqs_acquire_pipe(fqs);
	}
	return ret;
}

static void fqs_release_pipe(struct silofs_fuseq_sub *fqs)
{
	if (fqs->fqs_pipe != nullptr) {
		fuseq_push_pipe(fqs_fuseq2(fqs), fqs->fqs_pipe);
		fqs->fqs_pipe = nullptr;
	}
}

static bool fqs_want_keep_pipe(const struct silofs_fuseq_sub *fqs)
{
	return fqs_has_large_write_in(fqs) || fqs_has_large_read_in(fqs);
}

static void fqs_deactivate_fuseq(struct silofs_fuseq_sub *fqs)
{
	struct silofs_fuseq *fq = fqs_fuseq2(fqs);

	if (fq->fq_active) {
		fuseq_set_non_active(fq);
		fuseq_log_info("deactivated by: %s", fqs_thread_name(fqs));
	}
}

static void fqs_post_recv_in_locked(struct silofs_fuseq_sub *fqs, int status)
{
	if ((status != 0) && (fqs->fqs_pipe != nullptr)) {
		fqs_release_pipe(fqs);
	}

	if (status == -SILOFS_EINVAL) {
		fuseq_log_err("unexpected input error: fuse_fd=%d err=%d",
		              fqs_fuse_fd(fqs), status);
		fqs_deactivate_fuseq(fqs);
	} else if (status == -ENODEV) {
		/* umount case: set non-active under channel-lock */
		fuseq_log_info("input status: err=%d", status);
		fqs_deactivate_fuseq(fqs);
	}
}

static int fqs_recv_in_locked(struct silofs_fuseq_sub *fqs)
{
	struct silofs_fuseq *fq = fqs_fuseq2(fqs);
	int err = 0;

	fuseq_lock_ch(fq);
	err = fqs_try_acquire_pipe(fqs);
	if (!err) {
		err = fqs_do_recv_in(fqs);
		fqs_post_recv_in_locked(fqs, err);
	}
	fuseq_unlock_ch(fq);
	return err;
}

static int fqs_splice_request_tail(struct silofs_fuseq_sub *fqs)
{
	int err = 0;

	if (fqs->fqs_pipe != nullptr) {
		/* copy from pipe to buffer outside of channel-lock */
		err = fqs_copy_pipe_in(fqs);
		if (err || !fqs_want_keep_pipe(fqs)) {
			fqs_release_pipe(fqs);
		}
	}
	return err;
}

static int fqs_recv_request_in(struct silofs_fuseq_sub *fqs)
{
	int err;

	err = fqs_recv_in_locked(fqs);
	if ((err == -ETIMEDOUT) || (err == -SILOFS_ENORX)) {
		return err;
	}
	if (err == -ENOENT) {
		/* hmmm... ok, but why? */
		return -SILOFS_ENORX;
	}
	if ((err == -EINTR) || (err == -EAGAIN)) {
		log_dbg("fuse no-read: err=%d", err);
		return -SILOFS_ENORX;
	}
	if (err == -ENODEV) {
		/* unmount or connection aborted */
		fuseq_log_info("fuse connection aborted: err=%d", err);
		return err;
	}
	if (err) {
		fuseq_log_err("fuse recv-request: err=%d", err);
		return err;
	}
	return fqs_splice_request_tail(fqs);
}

static int fqs_recv_request(struct silofs_fuseq_sub *fqs)
{
	int err;

	fqs_reset_inhdr(fqs);
	err = fqs_recv_request_in(fqs);
	if (!err) {
		fqs->fqs_req_count++;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *iob_new(struct silofs_alloc *alloc, size_t len)
{
	void *iob;

	silofs_assert_le(len, 2 * SILOFS_MEGA);
	silofs_assert_ge(len, SILOFS_LBK_SIZE);

	iob = silofs_memalloc(alloc, len, 0);
	return iob;
}

static void iob_del(struct silofs_alloc *alloc, void *iob, size_t len)
{
	silofs_memfree(alloc, iob, len, SILOFS_ALLOCF_TRYPUNCH);
}

static struct silofs_fuseq_inb *inb_new(struct silofs_alloc *alloc)
{
	struct silofs_fuseq_inb *inb;

	STATICASSERT_EQ(sizeof(*inb), 2 * SILOFS_MEGA);

	inb = iob_new(alloc, sizeof(*inb));
	return inb;
}

static void inb_del(struct silofs_fuseq_inb *inb, struct silofs_alloc *alloc)
{
	iob_del(alloc, inb, sizeof(*inb));
}

static struct silofs_fuseq_outb *outb_new(struct silofs_alloc *alloc)
{
	struct silofs_fuseq_outb *outb;

	STATICASSERT_EQ(sizeof(*outb), 2 * SILOFS_MEGA);

	outb = iob_new(alloc, sizeof(*outb));
	return outb;
}

static void
outb_del(struct silofs_fuseq_outb *outb, struct silofs_alloc *alloc)
{
	iob_del(alloc, outb, sizeof(*outb));
}

static struct silofs_fuseq_rw_iter *rwi_new(struct silofs_alloc *alloc)
{
	struct silofs_fuseq_rw_iter *rwi;

	rwi = silofs_memalloc(alloc, sizeof(*rwi), 0);
	if (rwi != nullptr) {
		silofs_memzero(rwi, sizeof(*rwi));
	}
	return rwi;
}

static void
rwi_del(struct silofs_fuseq_rw_iter *rwi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, rwi, sizeof(*rwi), 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_alloc *fqs_alloc(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	return fq->fq_alloc;
}

static int fqs_init_bufs(struct silofs_fuseq_sub *fqs)
{
	struct silofs_alloc *alloc = fqs_alloc(fqs);

	fqs->fqs_inb = inb_new(alloc);
	if (fqs->fqs_inb == nullptr) {
		return -SILOFS_ENOMEM;
	}
	fqs->fqs_outb = outb_new(alloc);
	if (fqs->fqs_outb == nullptr) {
		inb_del(fqs->fqs_inb, alloc);
		fqs->fqs_inb = nullptr;
		return -SILOFS_ENOMEM;
	}
	return 0;
}

static void fqs_fini_bufs(struct silofs_fuseq_sub *fqs)
{
	struct silofs_alloc *alloc = fqs_alloc(fqs);

	if (fqs->fqs_outb != nullptr) {
		outb_del(fqs->fqs_outb, alloc);
		fqs->fqs_outb = nullptr;
	}
	if (fqs->fqs_inb != nullptr) {
		inb_del(fqs->fqs_inb, alloc);
		fqs->fqs_inb = nullptr;
	}
}

static int fqs_renew_bufs(struct silofs_fuseq_sub *fqs)
{
	struct silofs_alloc *alloc = fqs_alloc(fqs);
	struct silofs_fuseq_inb *inb = nullptr;
	struct silofs_fuseq_outb *outb = nullptr;

	inb = inb_new(alloc);
	if (inb == nullptr) {
		return -SILOFS_ENOMEM;
	}
	if (fqs->fqs_inb != nullptr) {
		inb_del(fqs->fqs_inb, alloc);
	}
	fqs->fqs_inb = inb;

	outb = outb_new(alloc);
	if (outb == nullptr) {
		return -SILOFS_ENOMEM;
	}
	if (fqs->fqs_outb != nullptr) {
		outb_del(fqs->fqs_outb, alloc);
	}
	fqs->fqs_outb = outb;
	return 0;
}

static int fqs_init_rwi(struct silofs_fuseq_sub *fqs)
{
	fqs->fqs_rwi = rwi_new(fqs_alloc(fqs));
	return (fqs->fqs_rwi != nullptr) ? 0 : -SILOFS_ENOMEM;
}

static void fqs_fini_rwi(struct silofs_fuseq_sub *fqs)
{
	if (fqs->fqs_rwi != nullptr) {
		rwi_del(fqs->fqs_rwi, fqs_alloc(fqs));
		fqs->fqs_rwi = nullptr;
	}
}

static int fqs_init_op_args(struct silofs_fuseq_sub *fqs)
{
	struct silofs_call_args *op_args = &fqs->fqs_args;

	silofs_memzero(op_args, sizeof(*op_args));
	return 0;
}

static void fqs_fini_op_args(struct silofs_fuseq_sub *fqs)
{
	struct silofs_call_args *op_args = &fqs->fqs_args;

	silofs_memffff(op_args, sizeof(*op_args));
}

static int
fqs_init(struct silofs_fuseq_sub *fqs, struct silofs_fuseq *fq, uint32_t idx)
{
	int err;

	STATICASSERT_LE(sizeof(*fqs), 4096);

	silofs_memzero(fqs, sizeof(*fqs));
	fqt_init(&fqs->fqs_th, fq, idx);
	list_head_init(&fqs->fqs_lh);
	fqs->fqs_pipe = nullptr;
	fqs->fqs_inb = nullptr;
	fqs->fqs_outb = nullptr;
	fqs->fqs_req_count = 0;
	fqs->fqs_init_ok = false;
	fqs->fqs_exec_ok = false;

	err = fqs_init_bufs(fqs);
	if (err) {
		goto out_err;
	}
	err = fqs_init_rwi(fqs);
	if (err) {
		goto out_err;
	}
	err = fqs_init_op_args(fqs);
	if (err) {
		goto out_err;
	}
	fqs->fqs_init_ok = true;
	return 0;
out_err:
	fqs_fini_op_args(fqs);
	fqs_fini_rwi(fqs);
	fqs_fini_bufs(fqs);
	return err;
}

static void fqs_fini(struct silofs_fuseq_sub *fqs)
{
	list_head_fini(&fqs->fqs_lh);
	fqs_fini_op_args(fqs);
	fqs_fini_rwi(fqs);
	fqs_fini_bufs(fqs);
	fqt_fini(&fqs->fqs_th);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fqs_check_input(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq_in *in = fqs_in_of2(fqs);
	const uint32_t in_len = in->u.hdr.hdr.len;
	const uint32_t opcode = in->u.hdr.hdr.opcode;

	if (!in_len || !opcode) {
		fuseq_log_warn("bad fuse input: in_len=%u opcode=%u", in_len,
		               opcode);
		return -SILOFS_ENORX;
	}
	return 0;
}

static void fqs_recv_done_request(struct silofs_fuseq_sub *fqs)
{
	if (fqs->fqs_pipe != nullptr) {
		fqs_release_pipe(fqs);
	}
}

static int fqs_recv_exec_request(struct silofs_fuseq_sub *fqs)
{
	int err = -SILOFS_ENORX;

	if (!fqs_has_exec_mode(fqs)) {
		goto out;
	}
	err = fqs_recv_request(fqs);
	if (err) {
		goto out;
	}
	err = fqs_check_input(fqs);
	if (err) {
		goto out;
	}
	err = fqs_exec_request(fqs);
	if (err == -ENOENT) {
		/* probably due to FR_ABORTED on FUSE side (ENOENT means the
		 * operation was interrupted). */
		err = -SILOFS_ENOTX;
	}
out:
	fqs_recv_done_request(fqs);
	fqs->fqs_exec_ok = (err == 0);
	return err;
}

static void fqs_post_timedout(struct silofs_fuseq_sub *fqs)
{
	if (fqs->fqs_req_count > 0) {
		/* renew base state */
		fqs_renew_bufs(fqs);
		fqs->fqs_req_count = 0;
	}
}

static int fqs_exec_timedout(struct silofs_fuseq_sub *fqs)
{
	struct silofs_fuseq *fq = fqs_fuseq2(fqs);

	if (fuseq_is_normal(fq)) {
		fuseq_update_nexecs(fq, -1);
		fqs_post_timedout(fqs);
	}
	return 0;
}

static void fqs_suspend(const struct silofs_fuseq_sub *fqs)
{
	silofs_unused(fqs);
	silofs_suspend_nsecs(1);
}

static bool fqs_is_leader(const struct silofs_fuseq_sub *fqs)
{
	return (fqs->fqs_th.idx == 0);
}

static bool fqs_allowed_exec(const struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);

	/* bootstrap case-1: not all worker-threads to started */
	if (!fuseq_has_nactive_disptch(fq)) {
		return false;
	}
	/* bootstrap case-2: only first (leader) may operate */
	if (!fqs_is_leader(fqs) && !fuseq_is_normal(fq)) {
		return false;
	}
	return true;
}

static struct silofs_fuseq_thread *fqt_from_th(struct silofs_thread *th)
{
	return container_of(th, struct silofs_fuseq_thread, th);
}

static struct silofs_fuseq_sub *fqs_from_th(struct silofs_thread *th)
{
	struct silofs_fuseq_thread *fqt = fqt_from_th(th);

	return container_of(fqt, struct silofs_fuseq_sub, fqs_th);
}

static int fqs_post_exec_once(struct silofs_fuseq_sub *fqs, int status)
{
	const int err = -abs(status);

	/* normal case */
	if (!err) {
		return 0;
	}
	/* umount case */
	if (err == -ENODEV) {
		fqs_deactivate_fuseq(fqs);
		return err;
	}
	/* no-lock & interrupt cases */
	if ((err == -SILOFS_ENORX) || (err == -SILOFS_ENOTX)) {
		fqs_suspend(fqs);
		return 0;
	}
	/* termination case */
	if (err == -ENOENT) {
		fqs_suspend(fqs);
		return err;
	}
	/* abnormal failure */
	fuseq_log_err("abnormal error: %s err=%d", fqs_thread_name(fqs), err);
	return err;
}

static int fqs_exec_once(struct silofs_fuseq_sub *fqs)
{
	int err = 0;

	/* allow only single worker on bootstrap */
	if (!fqs_allowed_exec(fqs)) {
		fqs_suspend(fqs);
		return 0;
	}
	/* serve single in-comming request */
	err = fqs_recv_exec_request(fqs);

	/* timeout case */
	if (err == -ETIMEDOUT) {
		fqs_exec_timedout(fqs);
		return 0;
	}

	/* post-execution action based on status code */
	return fqs_post_exec_once(fqs, err);
}

static void fqs_setup_self_task(const struct silofs_fuseq_sub *fqs,
                                struct silofs_task_ctx *task)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);
	const struct silofs_env_args *args = fq->fq_env->base.args;

	silofs_task_init(task, fq->fq_env);
	silofs_task_set_creds(task, args->uid, args->gid, args->umask);
	silofs_task_set_ts(task, false);
	task->t_auth.pid = args->pid;
	task->t_exclusive = false;
}

static int fqs_do_exec_maintain(struct silofs_fuseq_sub *fqs,
                                struct silofs_task_ctx *task, int flags)
{
	int err1 = 0;
	int err2 = 0;

	silofs_rwlock_fs_by(task);
	err1 = silofs_exec_maintain(task, flags);
	err2 = fqs_submit_by(fqs, task);
	silofs_rwunlock_fs_by(task);

	return err1 ? err1 : err2;
}

static int fqs_exec_maintain(struct silofs_fuseq_sub *fqs, int flags)
{
	struct silofs_task_ctx task;
	int err;

	fqs_setup_self_task(fqs, &task);
	err = fqs_do_exec_maintain(fqs, &task, flags);
	fqs_finish_task(fqs, &task);
	return err;
}

static int fqs_exec_maintain_once(struct silofs_fuseq_sub *fqs)
{
	const struct silofs_fuseq *fq = fqs_fuseq(fqs);
	int ret = 0;

	if (!fuseq_is_normal(fq)) {
		/* yield to let other have a chance to do some work */
		silofs_sys_sched_yield();
	} else if (!fqs->fqs_exec_ok) {
		/* do flush-and-relax in idle mode */
		ret = fqs_exec_maintain(fqs, SILOFS_CTLF_IDLE);
	} else if (fuseq_has_memory_pressure(fq)) {
		/* do flush-and-relax along-side other threads */
		ret = fqs_exec_maintain(fqs, SILOFS_CTLF_INTERN);
	}
	return ret;
}

static int fqs_exec_loop(struct silofs_fuseq_sub *fqs)
{
	const uint32_t idx = fqs->fqs_th.idx;
	int err = 0;

	while (fqs_has_exec_mode(fqs)) {
		err = fqs_exec_once(fqs);
		if (err) {
			break;
		}
		err = fqs_exec_maintain_once(fqs);
		if (err) {
			break;
		}
	}
	if (err && (err != -ENODEV)) {
		fuseq_log_warn("sub-thread done: idx=%u err=%d", idx, err);
	}
	return err;
}

static int fqs_start(struct silofs_thread *th)
{
	struct silofs_fuseq_sub *fqs = fqs_from_th(th);
	int err;

	fuseq_log_info("start: %s", th->name);
	err = fqt_block_thread_signals(&fqs->fqs_th);
	if (!err) {
		err = fqs_exec_loop(fqs);
	}
	fuseq_log_info("finish: %s", th->name);
	return err;
}

static int fqs_exec_thread(struct silofs_fuseq_sub *fqs)
{
	return fqt_exec_thread(&fqs->fqs_th, fqs_start);
}

static bool fqs_try_join_thread(struct silofs_fuseq_sub *fqs)
{
	struct silofs_fuseq_thread *fqt = &fqs->fqs_th;

	if (fqt->joined) {
		return false;
	}
	if (!fqt_completed(fqt)) {
		return false;
	}
	fqt_join_thread_now(fqt);
	return true;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint32_t clamp(uint32_t v, uint32_t lo, uint32_t hi)
{
	return silofs_clamp_u32(v, lo, hi);
}

static bool fuseq_has_live_opers(const struct silofs_fuseq *fq)
{
	return (fq->fq_curr_opers.sz > 0);
}

static bool fuseq_is_active(const struct silofs_fuseq *fq)
{
	return (fq->fq_active > 0);
}

static void fuseq_set_active(struct silofs_fuseq *fq)
{
	if (fq->fq_active <= 0) {
		fq->fq_active = 1;
	}
}

static void fuseq_set_non_active(struct silofs_fuseq *fq)
{
	if (fq->fq_active > 0) {
		fq->fq_active = 0;
		silofs_sem_post(&fq->fq_sem);
	}
}

static int fuseq_update_pipes(struct silofs_fuseq *fq)
{
	int mode_flags = (int)(fq->fq_mode_flags);
	int err = 0;

	if (fuseq_may_splice(fq) && fuseq_cap_splice(fq)) {
		err = fuseq_open_pipes(fq);
		if (err) {
			fuseq_log_warn("failed to open pipes: err=%d", err);
			mode_flags &= ~SILOFS_F_MAYSPLICE;
		}
	}
	fq->fq_mode_flags = (enum silofs_flags)mode_flags;
	return err;
}

static int fuseq_init_nilfd(struct silofs_fuseq *fq)
{
	silofs_nilfd_init(&fq->fq_nilfd);
	return silofs_nilfd_open(&fq->fq_nilfd);
}

static void fuseq_fini_nilfd(struct silofs_fuseq *fq)
{
	silofs_nilfd_close(&fq->fq_nilfd);
	silofs_nilfd_fini(&fq->fq_nilfd);
}

static int fuseq_init_pipes(struct silofs_fuseq *fq)
{
	silofs_listq_init(&fq->fq_pipes_freeq);
	for (size_t i = 0; i < ARRAY_SIZE(fq->fq_pipes); ++i) {
		fqp_init(&fq->fq_pipes[i]);
	}
	fq->fq_init_pipes = true;
	return 0;
}

static void fuseq_fini_pipes(struct silofs_fuseq *fq)
{
	if (fq->fq_init_pipes) {
		for (size_t i = 0; i < ARRAY_SIZE(fq->fq_pipes); ++i) {
			fqp_fini(&fq->fq_pipes[i]);
		}
		silofs_listq_fini(&fq->fq_pipes_freeq);
	}
}

static int fuseq_init_locks(struct silofs_fuseq *fq)
{
	int err;

	err = silofs_sem_init(&fq->fq_sem);
	if (err) {
		return err;
	}
	err = silofs_mutex_init(&fq->fq_ps_lock);
	if (err) {
		goto out_err1;
	}
	err = silofs_mutex_init(&fq->fq_ch_lock);
	if (err) {
		goto out_err2;
	}
	err = silofs_mutex_init(&fq->fq_op_lock);
	if (err) {
		goto out_err3;
	}
	err = silofs_mutex_init(&fq->fq_ctl_lock);
	if (err) {
		goto out_err4;
	}
	fq->fq_init_locks = true;
	return 0;

out_err4:
	silofs_mutex_fini(&fq->fq_op_lock);
out_err3:
	silofs_mutex_fini(&fq->fq_ch_lock);
out_err2:
	silofs_mutex_fini(&fq->fq_ps_lock);
out_err1:
	silofs_sem_fini(&fq->fq_sem);
	return err;
}

static void fuseq_fini_locks(struct silofs_fuseq *fq)
{
	if (fq->fq_init_locks) {
		silofs_mutex_fini(&fq->fq_ctl_lock);
		silofs_mutex_fini(&fq->fq_op_lock);
		silofs_mutex_fini(&fq->fq_ch_lock);
		silofs_mutex_fini(&fq->fq_ps_lock);
		silofs_sem_fini(&fq->fq_sem);
	}
}

static void
fuseq_init_common(struct silofs_fuseq *fq, struct silofs_alloc *alloc,
                  const struct silofs_fuseq_subs *subx)
{
	memcpy(&fq->fq_subs, subx, sizeof(fq->fq_subs));
	fq->fq_subs.fq_nsub_run = 0;
	listq_init(&fq->fq_curr_opers);
	fq->fq_env = nullptr;
	fq->fq_pagesize = (uint32_t)silofs_sc_page_size();
	fq->fq_nprocs = (uint32_t)silofs_sc_nproc_onln();
	fq->fq_alloc = alloc;
	fq->fq_nopers = 0;
	fq->fq_nexecs = 0;
	fq->fq_active = 0;
	fq->fq_fuse_fd = -1;
	fq->fq_got_init = false;
	fq->fq_reply_init_ok = false;
	fq->fq_got_destroy = false;
	fq->fq_deny_others = false;
	fq->fq_mount = false;
	fq->fq_umount = false;
	fq->fq_fs_owner = (uid_t)(-1);
	fq->fq_mode_flags = SILOFS_F_MAYSPLICE;
}

static int fuseq_init_subs(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_sub *fqs = nullptr;
	int err;

	for (uint32_t i = 0; i < fq->fq_subs.fq_nsub_lim; ++i) {
		fqs = &fq->fq_subs.fq_subs[i];
		err = fqs_init(fqs, fq, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static void fuseq_fini_subs(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_sub *fqs = nullptr;

	for (uint32_t i = 0; i < fq->fq_subs.fq_nsub_lim; ++i) {
		fqs = &fq->fq_subs.fq_subs[i];
		fqs_fini(fqs);
	}
}

static bool fuseq_may(const struct silofs_fuseq *fq, enum silofs_flags mode)
{
	return (fq->fq_mode_flags & mode) == mode;
}

static bool fuseq_may_splice(const struct silofs_fuseq *fq)
{
	return fuseq_may(fq, SILOFS_F_MAYSPLICE);
}

static size_t fuseq_bufsize_max(const struct silofs_fuseq *fq)
{
	const struct silofs_fuseq_sub *fqs = &fq->fq_subs.fq_subs[0];
	const size_t inbuf_max = sizeof(*fqs->fqs_inb);
	const size_t outbuf_max = sizeof(*fqs->fqs_outb);

	unused(fqs); /* make clangscan happy */
	return silofs_max(inbuf_max, outbuf_max);
}

static int
fuseq_resolve_bufsize(const struct silofs_fuseq *fq, size_t *out_bufsize)
{
	const size_t pgsz = fq->fq_pagesize;
	size_t bufsize_min;
	size_t bufsize_max;
	size_t bufsize_may;
	size_t bufsize;

	STATICASSERT_GE(FUSE_MIN_READ_BUFFER, 2 * FUSE_BUFFER_HEADER_SIZE);

	bufsize_min = silofs_min(FUSE_MIN_READ_BUFFER, 2 * SILOFS_LBK_SIZE);
	bufsize_max = fuseq_bufsize_max(fq);
	if (fuseq_may_splice(fq)) {
		bufsize_may = silofs_pipe_size_of(bufsize_max);
	} else {
		bufsize_may = bufsize_max;
	}
	bufsize = (silofs_min(bufsize_may, bufsize_max) / pgsz) * pgsz;
	if ((bufsize < bufsize_min) || (bufsize > bufsize_max)) {
		fuseq_log_err("can not creat channel: bufsize=%zu "
		              "bufsize_max=%zu bufsize_min=%zu ",
		              bufsize, bufsize_max, bufsize_min);
		return -SILOFS_EPROTO;
	}
	fuseq_log_dbg("channel params: bufsize=%zu bufsize_max=%zu "
	              "bufsize_min=%zu ",
	              bufsize, bufsize_max, bufsize_min);
	*out_bufsize = bufsize;
	return 0;
}

/*
 * From Linux kerenl fs/fuse/dec.c:
 *
 *     Require sane minimum read buffer - that has capacity for fixed part
 *     of any request header + negotiated max_write room for data...
 */
static int fuseq_calc_max_write(const struct silofs_fuseq *fq, size_t bufsize,
                                size_t *out_max_write)
{
	const size_t page_size = fq->fq_pagesize;
	const size_t hdr_size = sizeof(struct fuse_in_header);
	const size_t write_in_size = sizeof(struct fuse_write_in);
	size_t data_size;
	size_t max_write;

	if (bufsize < (hdr_size + write_in_size + page_size)) {
		fuseq_log_err("short buffer: bufsize=%zu hdr_size=%zu "
		              "write_in_size=%zu ",
		              bufsize, hdr_size, write_in_size);
		return -SILOFS_EPROTO;
	}
	data_size = bufsize - hdr_size - write_in_size;
	max_write = (data_size / page_size) * page_size;
	if (max_write < silofs_max(2 * page_size, FUSE_MIN_READ_BUFFER)) {
		fuseq_log_err("short buffer: data_size=%zu max_write=%zu ",
		              data_size, max_write);
		return -SILOFS_EPROTO;
	}
	*out_max_write = max_write;
	return 0;
}

static int fuseq_update_conn_info(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_conn_info *coni = &fq->fq_coni;
	size_t bufsize = 0;
	size_t max_write = 0;
	size_t max_pages = 0;
	int err;

	err = fuseq_resolve_bufsize(fq, &bufsize);
	if (err) {
		return err;
	}
	err = fuseq_calc_max_write(fq, bufsize, &max_write);
	if (err) {
		return err;
	}
	coni->buffsize = bufsize;
	coni->max_write = (uint32_t)max_write;
	coni->max_read = (uint32_t)max_write;
	coni->max_readahead = (uint32_t)(bufsize - fq->fq_pagesize);

	/* logic from libfuse::fuse_lowlevel.c -- is it correct? */
	max_pages = ((coni->max_write - 1) / fq->fq_pagesize) + 1;
	coni->max_pages = (uint32_t)silofs_min(max_pages, UINT16_MAX);

	return 0;
}

/*
 * Libfuse uses by default max_background of = 1 << 16) - 1 and
 * congestion_threshold = max_background * 3 / 4 (libfuse:lib/fuse_lowlevel.c).
 *
 * It is not clear from the code of libfuse or fuse.ko why those values.
 * Documentation is minimal, needs further investigation.
 *
 * See also:
 * https://lore.kernel.org/linux-fsdevel/aEi2oPUdTUiRkzSl@archie.me/T/#t
 */
static uint32_t fuseq_calc_max_background(const struct silofs_fuseq *fq)
{
	const uint32_t max_background_lim = (1 << 16) - 1;
	const uint32_t max_background_want = fq->fq_nprocs * 1024;

	return silofs_min_u32(max_background_lim, max_background_want);
}

static void fuseq_init_conn_info(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_conn_info *coni = &fq->fq_coni;

	memset(coni, 0, sizeof(*coni));
	coni->proto_major = FUSE_KERNEL_VERSION;
	coni->proto_minor = FUSE_KERNEL_MINOR_VERSION;
	coni->time_gran = 1;
	coni->max_background = fuseq_calc_max_background(fq);
	coni->congestion_threshold = coni->max_background / 2;
}

static int fuseq_init(struct silofs_fuseq *fq, struct silofs_alloc *alloc,
                      const struct silofs_fuseq_subs *subx)
{
	int err;

	fuseq_init_common(fq, alloc, subx);
	fuseq_init_conn_info(fq);

	err = fuseq_init_nilfd(fq);
	if (err) {
		return err;
	}
	err = fuseq_init_pipes(fq);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_locks(fq);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_subs(fq);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	fuseq_fini_subs(fq);
	fuseq_fini_locks(fq);
	fuseq_fini_pipes(fq);
	fuseq_fini_nilfd(fq);
	return err;
}

static void fuseq_fini_fuse_fd(struct silofs_fuseq *fq)
{
	if (fq->fq_fuse_fd > 0) {
		silofs_sys_close(fq->fq_fuse_fd);
		fq->fq_fuse_fd = -1;
	}
}

static void fuseq_fini(struct silofs_fuseq *fq)
{
	silofs_assert_eq(fq->fq_curr_opers.sz, 0);

	fuseq_fini_fuse_fd(fq);
	fuseq_fini_subs(fq);
	fuseq_fini_locks(fq);
	fuseq_fini_pipes(fq);
	fuseq_fini_nilfd(fq);
	silofs_listq_fini(&fq->fq_curr_opers);
	fq->fq_alloc = nullptr;
	fq->fq_env = nullptr;
}

int silofs_fuseq_update(struct silofs_fuseq *fq)
{
	int err;

	err = fuseq_update_conn_info(fq);
	if (err) {
		goto out;
	}
	err = fuseq_update_pipes(fq);
	if (!err) {
		goto out; /* OK */
	}
	/*
	 * Special case: fallback from pipe-splice mode to buffer-copy mode due
	 * to insufficient resources to create big-enough pipes. Need to update
	 * connection-info settings.
	 */
	err = fuseq_update_conn_info(fq);
out:
	return err;
}

int silofs_fuseq_mount(struct silofs_fuseq *fq, struct silofs_env *env,
                       const char *path)
{
	const size_t max_read = fq->fq_coni.max_read;
	const char *sock = SILOFS_MNTSOCK_NAME;
	uint64_t ms_flags;
	uid_t uid;
	gid_t gid;
	int fd = -1;
	int err;
	bool allow_other;

	uid = env->owner_cred.uid;
	gid = env->owner_cred.gid;
	ms_flags = env->ms_flags;
	allow_other = fuseq_may(fq, SILOFS_F_ALLOWOTHER);

	err = silofs_mntrpc_handshake(uid, gid);
	if (err) {
		fuseq_log_err("handshake with mountd failed: "
		              "sock=@%s err=%d",
		              sock, err);
		return err;
	}
	err = silofs_mntrpc_mount(path, uid, gid, max_read, ms_flags,
	                          allow_other, false, &fd);
	if (err) {
		fuseq_log_err("mount failed: path=%s max_read=%lu "
		              "ms_flags=0x%lx allow_other=%d err=%d",
		              path, max_read, ms_flags, (int)allow_other, err);
		return err;
	}

	fq->fq_fs_owner = env->owner_cred.uid;
	fq->fq_fuse_fd = fd;
	fq->fq_mount = true;
	fq->fq_env = env;

	/* TODO: Looks like kernel needs time. why? */
	silofs_suspend_nsecs(1);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_start_subs(struct silofs_fuseq *fq)
{
	const size_t nsub_lim = fq->fq_subs.fq_nsub_lim;
	int err;

	fuseq_log_dbg("start dispatchers: lim=%zu", nsub_lim);
	fq->fq_subs.fq_nsub_run = 0;
	for (size_t i = 0; i < nsub_lim; ++i) {
		err = fqs_exec_thread(&fq->fq_subs.fq_subs[i]);
		if (err) {
			return err;
		}
		silofs_sys_sched_yield();
		fq->fq_subs.fq_nsub_run++;
	}
	return 0;
}

static bool fuseq_join_subs(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_sub *fqs = nullptr;
	size_t njoined = 0;

	for (size_t i = 0; i < fq->fq_subs.fq_nsub_run; ++i) {
		fqs = &fq->fq_subs.fq_subs[i];
		if (fqs->fqs_th.joined || fqs_try_join_thread(fqs)) {
			njoined++;
		}
		silofs_sys_sched_yield();
	}
	return (njoined == fq->fq_subs.fq_nsub_run);
}

static void fuseq_finish_subs(struct silofs_fuseq *fq)
{
	const size_t nsub_run = fq->fq_subs.fq_nsub_run;
	int retry = 30;

	fuseq_log_dbg("finish sub-threads: nsub_run=%zu", nsub_run);
	while (--retry > 0) {
		if (fuseq_join_subs(fq)) {
			break;
		}
		silofs_suspend_nsecs(1);
	}
	if (retry == 0) {
		silofs_panic("failed to join all sub-threads: nsub_run=%zu",
		             nsub_run);
	}
	fq->fq_subs.fq_nsub_run = 0;
}

static int fuseq_start_exec_threads(struct silofs_fuseq *fq)
{
	fuseq_set_active(fq);
	return fuseq_start_subs(fq);
}

static void fuseq_finish_exec_threads(struct silofs_fuseq *fq)
{
	fuseq_set_non_active(fq);
	fuseq_finish_subs(fq);
}

static bool fuseq_ntimedwait(struct silofs_fuseq *fq, time_t nsecs)
{
	return silofs_sem_ntimedwait(&fq->fq_sem, nsecs);
}

static void fuseq_suspend_while_active(struct silofs_fuseq *fq)
{
	bool active = fuseq_is_active(fq);

	while (active || fuseq_has_live_opers(fq)) {
		if (!active || !fuseq_ntimedwait(fq, 10)) {
			silofs_suspend_nsecs(1);
		}
		active = fuseq_is_active(fq);
	}
}

int silofs_fuseq_exec(struct silofs_fuseq *fq)
{
	int err;

	err = fuseq_start_exec_threads(fq);
	if (!err) {
		fuseq_suspend_while_active(fq);
	}
	fuseq_finish_exec_threads(fq);
	return err;
}

void silofs_fuseq_term(struct silofs_fuseq *fq)
{
	fuseq_fini_fuse_fd(fq);
	fq->fq_env = nullptr;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const silofs_call_fn silofs_call_tbl[] = {
	[FUSE_LOOKUP] = silofs_call_lookup,
	[FUSE_FORGET] = silofs_call_forget,
	[FUSE_GETATTR] = silofs_call_getattr,
	[FUSE_SETATTR] = silofs_call_setattr,
	[FUSE_READLINK] = silofs_call_readlink,
	[FUSE_SYMLINK] = silofs_call_symlink,
	[FUSE_MKNOD] = silofs_call_mknod,
	[FUSE_MKDIR] = silofs_call_mkdir,
	[FUSE_UNLINK] = silofs_call_unlink,
	[FUSE_RMDIR] = silofs_call_rmdir,
	[FUSE_RENAME] = silofs_call_rename,
	[FUSE_LINK] = silofs_call_link,
	[FUSE_OPEN] = silofs_call_open,
	[FUSE_READ] = silofs_call_read,
	[FUSE_WRITE] = silofs_call_write,
	[FUSE_STATFS] = silofs_call_statfs,
	[FUSE_RELEASE] = silofs_call_release,
	[FUSE_FSYNC] = silofs_call_fsync,
	[FUSE_SETXATTR] = silofs_call_setxattr,
	[FUSE_GETXATTR] = silofs_call_getxattr,
	[FUSE_LISTXATTR] = silofs_call_listxattr,
	[FUSE_REMOVEXATTR] = silofs_call_removexattr,
	[FUSE_FLUSH] = silofs_call_flush,
	[FUSE_OPENDIR] = silofs_call_opendir,
	[FUSE_READDIR] = silofs_call_readdir,
	[FUSE_RELEASEDIR] = silofs_call_releasedir,
	[FUSE_FSYNCDIR] = silofs_call_fsyncdir,
	[FUSE_ACCESS] = silofs_call_access,
	[FUSE_CREATE] = silofs_call_create,
	[FUSE_BATCH_FORGET] = silofs_call_batch_forget,
	[FUSE_FALLOCATE] = silofs_call_fallocate,
	[FUSE_READDIRPLUS] = silofs_call_readdirplus,
	[FUSE_RENAME2] = silofs_call_rename,
	[FUSE_LSEEK] = silofs_call_lseek,
	[FUSE_COPY_FILE_RANGE] = silofs_call_copy_file_range,
	[FUSE_SYNCFS] = silofs_call_syncfs,
	[FUSE_IOCTL] = silofs_call_ioctl,
	[FUSE_STATX] = silofs_call_statx,
};

static silofs_call_fn hook_of(uint32_t op_code)
{
	silofs_call_fn hook = nullptr;

	STATICASSERT_LE(ARRAY_SIZE(silofs_call_tbl), FUSEQ_CMD_MAX);

	if (op_code && (op_code < ARRAY_SIZE(silofs_call_tbl))) {
		hook = silofs_call_tbl[op_code];
	}
	return hook;
}

static int exec_op(struct silofs_task_ctx *task, struct silofs_call_args *args)
{
	silofs_call_fn hook = hook_of(task->t_auth.opcode);

	return likely(hook != nullptr) ? hook(task, args) : -SILOFS_ENOSYS;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void *address_at(void *ptr, ptrdiff_t dif)
{
	return (int8_t *)ptr + dif;
}

static uint32_t calc_nsub_lim(void)
{
	const uint32_t nproc = (uint32_t)silofs_sc_nproc_onln();

	return clamp(nproc, 2, 16);
}

static size_t fuseq_calc_selfsize(const struct silofs_fuseq *fq,
                                  const struct silofs_fuseq_subs *subx)
{
	const size_t pgsz = (size_t)silofs_sc_page_size();
	const size_t dsz = sizeof(subx->fq_subs[0]);
	size_t sz;

	sz = sizeof(*fq);
	sz += (subx->fq_nsub_lim * dsz);
	sz = silofs_div_round_up(sz, pgsz) * pgsz;
	return sz;
}

static void
fuseq_resolve_subx(struct silofs_fuseq *fq, struct silofs_fuseq_subs *subx)
{
	subx->fq_subs = address_at(fq, sizeof(*fq));
}

struct silofs_fuseq *
silofs_fuseq_new(struct silofs_alloc *alloc, enum silofs_flags mode_flags)
{
	struct silofs_fuseq *fq = nullptr;
	struct silofs_fuseq_subs fq_subs = {
		.fq_subs = nullptr,
		.fq_nsub_lim = calc_nsub_lim(),
		.fq_nsub_run = 0,
	};
	size_t fq_msz = 0;
	void *fq_mem = nullptr;
	int err;

	fq_msz = fuseq_calc_selfsize(fq, &fq_subs);
	fq_mem = silofs_memalloc(alloc, fq_msz, SILOFS_ALLOCF_BZERO);
	if (fq_mem == nullptr) {
		return nullptr;
	}

	fq = fq_mem;
	fuseq_resolve_subx(fq, &fq_subs);
	err = fuseq_init(fq, alloc, &fq_subs);
	if (err) {
		silofs_memfree(alloc, fq_mem, fq_msz, 0);
		return nullptr;
	}
	fq->fq_selfsize = (uint32_t)fq_msz;
	fq->fq_mode_flags = mode_flags;
	return fq;
}

void silofs_fuseq_del(struct silofs_fuseq *fq, struct silofs_alloc *alloc)
{
	const size_t fq_msz = fq->fq_selfsize;
	void *fq_mem = fq;

	fuseq_fini(fq);
	silofs_memfree(alloc, fq_mem, fq_msz, SILOFS_ALLOCF_TRYPUNCH);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define FUSEQ_HDR_IN_SIZE (40)

#define REQUIRE_SIZEOF(type, size) \
	SILOFS_STATICASSERT(((sizeof(type) == (size)) && ((size) % 8) == 0))

#define REQUIRE_OFFSET(type, member, offset) \
	SILOFS_STATICASSERT_EQ(offsetof(type, member), offset)

#define REQUIRE_BASEOF(type, member) \
	REQUIRE_OFFSET(type, member, FUSEQ_HDR_IN_SIZE)

void silofs_guarantee_fuse_proto(void)
{
	REQUIRE_SIZEOF(struct fuse_in_header, 40);
	REQUIRE_SIZEOF(struct fuse_rename_in, 8);
	REQUIRE_SIZEOF(struct fuse_rename2_in, 16);
	REQUIRE_SIZEOF(struct fuse_setxattr1_in, FUSE_COMPAT_SETXATTR_IN_SIZE);
	REQUIRE_SIZEOF(struct silofs_fuseq_hdr_in, FUSEQ_HDR_IN_SIZE);
	REQUIRE_OFFSET(struct silofs_fuseq_hdr_in, hdr, 0);
	REQUIRE_SIZEOF(struct silofs_fuseq_init_in, 104);
	REQUIRE_BASEOF(struct silofs_fuseq_init_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_setattr_in, 128);
	REQUIRE_BASEOF(struct silofs_fuseq_setattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_lookup_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_lookup_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_forget_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_forget_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_getattr_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_getattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_symlink_in, 4648);
	REQUIRE_BASEOF(struct silofs_fuseq_symlink_in, name_target);
	REQUIRE_SIZEOF(struct silofs_fuseq_mknod_in, 568);
	REQUIRE_BASEOF(struct silofs_fuseq_mknod_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_mkdir_in, 560);
	REQUIRE_BASEOF(struct silofs_fuseq_mkdir_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_mkdir_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_unlink_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_unlink_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_rmdir_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_rmdir_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_rename_in, 1072);
	REQUIRE_BASEOF(struct silofs_fuseq_rename_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_rename_in, name_newname, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_link_in, 560);
	REQUIRE_BASEOF(struct silofs_fuseq_link_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_link_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_open_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_open_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_release_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_release_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_fsync_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_fsync_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_fsync_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_fsync_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_setxattr1_in, 2608);
	REQUIRE_BASEOF(struct silofs_fuseq_setxattr1_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_setxattr1_in, name_value, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_setxattr_in, 2616);
	REQUIRE_BASEOF(struct silofs_fuseq_setxattr_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_setxattr_in, name_value, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_getxattr_in, 560);
	REQUIRE_BASEOF(struct silofs_fuseq_getxattr_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_getxattr_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_listxattr_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_listxattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_removexattr_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_removexattr_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_flush_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_flush_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_opendir_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_opendir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_readdir_in, 80);
	REQUIRE_BASEOF(struct silofs_fuseq_readdir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_releasedir_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_releasedir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_fsyncdir_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_fsyncdir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_access_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_access_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_create_in, 568);
	REQUIRE_BASEOF(struct silofs_fuseq_create_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_create_in, name, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_interrupt_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_interrupt_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_interrupt_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_interrupt_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_ioctl_in, 4168);
	REQUIRE_BASEOF(struct silofs_fuseq_ioctl_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_ioctl_in, buf, 72);
	REQUIRE_SIZEOF(struct silofs_fuseq_rename2_in, 1080);
	REQUIRE_BASEOF(struct silofs_fuseq_rename2_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_rename2_in, name_newname, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_lseek_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_lseek_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_read_in, 80);
	REQUIRE_BASEOF(struct silofs_fuseq_read_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_copy_file_range_in, 96);
	REQUIRE_BASEOF(struct silofs_fuseq_copy_file_range_in, arg);
}
