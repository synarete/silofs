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
#include <silofs/fs.h>
#include <silofs/ioctls.h>
#include <silofs/fuseq.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/sysinfo.h>
#include <linux/fs.h>
#include <linux/fuse7.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <time.h>


#if FUSE_KERNEL_VERSION != 7
#error "wrong FUSE_KERNEL_VERSION"
#endif
#if FUSE_KERNEL_MINOR_VERSION < 34
#error "wrong FUSE_KERNEL_MINOR_VERSION"
#endif

#if FUSE_KERNEL_MINOR_VERSION >= 100
#define SILOFS_FUSE_STATX 1
#else
#define SILOFS_FUSE_STATX 0
#endif

#define fuseq_log_info(fmt, ...) silofs_log_info("fuseq: " fmt, __VA_ARGS__)
#define fuseq_log_warn(fmt, ...) silofs_log_warn("fuseq: " fmt, __VA_ARGS__)
#define fuseq_log_err(fmt, ...)  silofs_log_error("fuseq: " fmt, __VA_ARGS__)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define SILOFS_CMD_TAIL_MAX \
	(SILOFS_IO_SIZE_MAX - sizeof(struct fuse_in_header))
#define SILOFS_CMD_FORGET_ONE_MAX \
	(SILOFS_CMD_TAIL_MAX / sizeof(struct fuse_forget_one))

/* max size for read/write I/O copy-buffer in splice-pipe mode */
#define FUSEQ_IOBUF_MAX SILOFS_PAGE_SIZE_MIN

/* splice-mode flags */
#define FUSEQ_SPLICE_FLAGS      (SPLICE_F_MOVE | SPLICE_F_NONBLOCK)

/* local functions */
static void fuseq_lock_ch(struct silofs_fuseq *fq);
static void fuseq_unlock_ch(struct silofs_fuseq *fq);
static void fuseq_lock_fs(struct silofs_fuseq *fq);
static void fuseq_unlock_fs(struct silofs_fuseq *fq);
static void fuseq_lock_op(struct silofs_fuseq *fq);
static void fuseq_unlock_op(struct silofs_fuseq *fq);
static void fuseq_interrupt_op(struct silofs_fuseq_worker *fqw, uint64_t unq);
static int fuseq_exec_op(struct silofs_fuseq *fq, struct silofs_oper_ctx *opc);
static size_t fuseq_bufsize_max(const struct silofs_fuseq *fq);

/* FUSE types per 7.34 */
struct fuse_setxattr1_in {
	uint32_t        size;
	uint32_t        flags;
};

/* local types */
struct silofs_fuseq_hdr_in {
	struct fuse_in_header   hdr;
};

struct silofs_fuseq_cmd_in {
	struct fuse_in_header   hdr;
	uint8_t cmd[SILOFS_IO_SIZE_MAX];
	uint8_t tail[SILOFS_BK_SIZE - sizeof(struct fuse_in_header)];
};

struct silofs_fuseq_init_in {
	struct fuse_in_header   hdr;
	struct fuse_init_in     arg;
};

struct silofs_fuseq_setattr_in {
	struct fuse_in_header   hdr;
	struct fuse_setattr_in  arg;
};

struct silofs_fuseq_lookup_in {
	struct fuse_in_header   hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_forget_in {
	struct fuse_in_header   hdr;
	struct fuse_forget_in   arg;
};

struct silofs_fuseq_batch_forget_in {
	struct fuse_in_header   hdr;
	struct fuse_batch_forget_in arg;
	struct fuse_forget_one  one[SILOFS_CMD_FORGET_ONE_MAX];
};

struct silofs_fuseq_getattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getattr_in  arg;
};

struct silofs_fuseq_symlink_in {
	struct fuse_in_header   hdr;
	char name_target[SILOFS_NAME_MAX + 1 + SILOFS_SYMLNK_MAX];
};

struct silofs_fuseq_mknod_in {
	struct fuse_in_header   hdr;
	struct fuse_mknod_in    arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_mkdir_in {
	struct fuse_in_header   hdr;
	struct fuse_mkdir_in    arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_unlink_in {
	struct fuse_in_header   hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_rmdir_in {
	struct fuse_in_header   hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_rename_in {
	struct fuse_in_header   hdr;
	struct fuse_rename_in   arg;
	char name_newname[2 * (SILOFS_NAME_MAX + 1)];
};

struct silofs_fuseq_link_in {
	struct fuse_in_header   hdr;
	struct fuse_link_in     arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_open_in {
	struct fuse_in_header   hdr;
	struct fuse_open_in     arg;
};

struct silofs_fuseq_release_in {
	struct fuse_in_header   hdr;
	struct fuse_release_in  arg;
};

struct silofs_fuseq_fsync_in {
	struct fuse_in_header   hdr;
	struct fuse_fsync_in    arg;
};

struct silofs_fuseq_setxattr1_in {
	struct fuse_in_header   hdr;
	struct fuse_setxattr1_in arg;
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_SYMLNK_MAX];
};

struct silofs_fuseq_setxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_setxattr_in arg;
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_SYMLNK_MAX];
};

struct silofs_fuseq_getxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getxattr_in arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_listxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getxattr_in arg;
};

struct silofs_fuseq_removexattr_in {
	struct fuse_in_header   hdr;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_flush_in {
	struct fuse_in_header   hdr;
	struct fuse_flush_in    arg;
};

struct silofs_fuseq_opendir_in {
	struct fuse_in_header   hdr;
	struct fuse_open_in     arg;
};

struct silofs_fuseq_readdir_in {
	struct fuse_in_header   hdr;
	struct fuse_read_in     arg;
};

struct silofs_fuseq_releasedir_in {
	struct fuse_in_header   hdr;
	struct fuse_release_in  arg;
};

struct silofs_fuseq_fsyncdir_in {
	struct fuse_in_header   hdr;
	struct fuse_fsync_in    arg;
};

struct silofs_fuseq_access_in {
	struct fuse_in_header   hdr;
	struct fuse_access_in   arg;
};

struct silofs_fuseq_create_in {
	struct fuse_in_header   hdr;
	struct fuse_create_in   arg;
	char name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_interrupt_in {
	struct fuse_in_header   hdr;
	struct fuse_interrupt_in arg;
};

struct silofs_fuseq_ioctl_in {
	struct fuse_in_header   hdr;
	struct fuse_ioctl_in    arg;
	char buf[SILOFS_PAGE_SIZE_MIN];
};

struct silofs_fuseq_fallocate_in {
	struct fuse_in_header   hdr;
	struct fuse_fallocate_in arg;
};

struct silofs_fuseq_rename2_in {
	struct fuse_in_header   hdr;
	struct fuse_rename2_in  arg;
	char name_newname[2 * (SILOFS_NAME_MAX + 1)];
};

struct silofs_fuseq_lseek_in {
	struct fuse_in_header   hdr;
	struct fuse_lseek_in    arg;
};

struct silofs_fuseq_read_in {
	struct fuse_in_header   hdr;
	struct fuse_read_in     arg;
};

struct silofs_fuseq_write_in {
	struct fuse_in_header   hdr;
	struct fuse_write_in    arg;
};

struct silofs_fuseq_copy_file_range_in {
	struct fuse_in_header   hdr;
	struct fuse_copy_file_range_in arg;
};

struct silofs_fuseq_syncfs_in {
	struct fuse_in_header   hdr;
	struct fuse_syncfs_in   arg;
};


#if SILOFS_FUSE_STATX
struct silofs_fuseq_statx_in {
	struct fuse_in_header   hdr;
	struct fuse_statx_in    arg;
};
#endif

union silofs_fuseq_in_u {
	struct silofs_fuseq_hdr_in              hdr;
	struct silofs_fuseq_cmd_in              cmd;
	struct silofs_fuseq_init_in             init;
	struct silofs_fuseq_setattr_in          setattr;
	struct silofs_fuseq_lookup_in           lookup;
	struct silofs_fuseq_forget_in           forget;
	struct silofs_fuseq_batch_forget_in     batch_forget;
	struct silofs_fuseq_getattr_in          getattr;
	struct silofs_fuseq_symlink_in          symlink;
	struct silofs_fuseq_mknod_in            mknod;
	struct silofs_fuseq_mkdir_in            mkdir;
	struct silofs_fuseq_unlink_in           unlink;
	struct silofs_fuseq_rmdir_in            rmdir;
	struct silofs_fuseq_rename_in           rename;
	struct silofs_fuseq_link_in             link;
	struct silofs_fuseq_open_in             open;
	struct silofs_fuseq_release_in          release;
	struct silofs_fuseq_fsync_in            fsync;
	struct silofs_fuseq_setxattr1_in        setxattr1;
	struct silofs_fuseq_setxattr_in         setxattr;
	struct silofs_fuseq_getxattr_in         getxattr;
	struct silofs_fuseq_listxattr_in        listxattr;
	struct silofs_fuseq_removexattr_in      removexattr;
	struct silofs_fuseq_flush_in            flush;
	struct silofs_fuseq_opendir_in          opendir;
	struct silofs_fuseq_readdir_in          readdir;
	struct silofs_fuseq_releasedir_in       releasedir;
	struct silofs_fuseq_fsyncdir_in         fsyncdir;
	struct silofs_fuseq_access_in           access;
	struct silofs_fuseq_create_in           create;
	struct silofs_fuseq_interrupt_in        interrupt;
	struct silofs_fuseq_ioctl_in            ioctl;
	struct silofs_fuseq_fallocate_in        fallocate;
	struct silofs_fuseq_rename2_in          rename2;
	struct silofs_fuseq_lseek_in            lseek;
	struct silofs_fuseq_read_in             read;
	struct silofs_fuseq_write_in            write;
	struct silofs_fuseq_copy_file_range_in  copy_file_range;
	struct silofs_fuseq_syncfs_in           syncfs;
#if SILOFS_FUSE_STATX
	struct silofs_fuseq_statx_in            statx;
#endif
};

struct silofs_fuseq_in {
	union silofs_fuseq_in_u u;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_fuseq_diter {
	char   buf[8 * SILOFS_UKILO];
	struct silofs_namebuf de_name;
	struct silofs_readdir_ctx rd_ctx;
	size_t bsz;
	size_t len;
	size_t ndes;
	struct stat de_attr;
	loff_t de_off;
	size_t de_nlen;
	ino_t  de_ino;
	mode_t de_dt;
	int    plus;
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
	struct silofs_iovec iov[SILOFS_FILE_NITER_MAX];
	struct silofs_rwiter_ctx rwi;
	struct silofs_fuseq_worker *fqw;
	size_t cnt;
	size_t ncp;
	size_t nwr;
	size_t nwr_max;
};

struct silofs_fuseq_rd_iter {
	struct silofs_iovec iov[SILOFS_FILE_NITER_MAX];
	struct silofs_rwiter_ctx rwi;
	struct silofs_fuseq_worker *fqw;
	size_t cnt;
	size_t ncp;
	size_t nrd;
	size_t nrd_max;
};

struct silofs_fuseq_iob {
	uint8_t b[SILOFS_BK_SIZE + SILOFS_IO_SIZE_MAX];
};

union silofs_fuseq_inb_u {
	struct silofs_fuseq_in  in;
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
	struct silofs_fuseq_databuf     dab;
	struct silofs_fuseq_pathbuf     pab;
	struct silofs_fuseq_xattrbuf    xab;
	struct silofs_fuseq_xiter       xit;
	struct silofs_fuseq_diter       dit;
	struct silofs_fuseq_iob         iob;
};

struct silofs_fuseq_outb {
	union silofs_fuseq_outb_u u;
};

union silofs_fuseq_rw_iter_u {
	struct silofs_fuseq_wr_iter     wri;
	struct silofs_fuseq_rd_iter     rdi;
};

struct silofs_fuseq_rw_iter {
	union silofs_fuseq_rw_iter_u u;
};

typedef int (*silofs_fuseq_hook)(struct silofs_fuseq_worker *, ino_t,
                                 const struct silofs_fuseq_in *);

struct silofs_fuseq_cmd {
	silofs_fuseq_hook hook;
	const char *name;
	int code;
	int realtime;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const void *after_name(const char *name)
{
	return name + strlen(name) + 1;
}

static void ts_to_fuse_attr(const struct timespec *ts,
                            uint64_t *sec, uint32_t *nsec)
{
	*sec = (uint64_t)ts->tv_sec;
	*nsec = (uint32_t)ts->tv_nsec;
}

static void fuse_attr_to_timespec(uint64_t sec, uint32_t nsec,
                                  struct timespec *ts)
{
	ts->tv_sec = (time_t)sec;
	ts->tv_nsec = (long)nsec;
}

static void stat_to_fuse_attr(const struct stat *st, struct fuse_attr *attr)
{
	attr->ino = st->st_ino;
	attr->mode = st->st_mode;
	attr->nlink = (uint32_t)st->st_nlink;
	attr->uid = st->st_uid;
	attr->gid = st->st_gid;
	attr->rdev = (uint32_t)st->st_rdev;
	attr->size = (uint64_t)st->st_size;
	attr->blksize = (uint32_t)st->st_blksize;
	attr->blocks = (uint64_t)st->st_blocks;
	ts_to_fuse_attr(&st->st_atim, &attr->atime, &attr->atimensec);
	ts_to_fuse_attr(&st->st_mtim, &attr->mtime, &attr->mtimensec);
	ts_to_fuse_attr(&st->st_ctim, &attr->ctime, &attr->ctimensec);
}

#if SILOFS_FUSE_STATX
static void xts_to_fuse_timestamp(const struct statx_timestamp *xts,
                                  struct fuse_statx_timestamp *fts)
{
	fts->sec = xts->tv_sec;
	fts->nsec = xts->tv_nsec;
}

static void statx_to_fuse_attr(const struct statx *stx,
                               struct fuse_statx *attr)
{
	attr->mask = stx->stx_mask;
	attr->blksize = stx->stx_blksize;
	attr->attributes = stx->stx_attributes;
	attr->nlink = stx->stx_nlink;
	attr->uid = stx->stx_uid;
	attr->gid = stx->stx_gid;
	attr->mask = stx->stx_mode;
	attr->ino = stx->stx_ino;
	attr->size = stx->stx_size;
	attr->blocks = stx->stx_blocks;
	attr->attributes_mask = stx->stx_attributes_mask;
	xts_to_fuse_timestamp(&stx->stx_atime, &attr->atime);
	xts_to_fuse_timestamp(&stx->stx_btime, &attr->btime);
	xts_to_fuse_timestamp(&stx->stx_ctime, &attr->ctime);
	xts_to_fuse_timestamp(&stx->stx_mtime, &attr->mtime);
	attr->rdev_major = stx->stx_rdev_major;
	attr->rdev_minor = stx->stx_rdev_minor;
}
#endif

static void
fuse_setattr_to_stat(const struct fuse_setattr_in *attr, struct stat *st)
{
	memset(st, 0, sizeof(*st));
	st->st_mode = attr->mode;
	st->st_uid = attr->uid;
	st->st_gid = attr->gid;
	st->st_size = (loff_t)attr->size;
	fuse_attr_to_timespec(attr->atime, attr->atimensec, &st->st_atim);
	fuse_attr_to_timespec(attr->mtime, attr->mtimensec, &st->st_mtim);
	fuse_attr_to_timespec(attr->ctime, attr->ctimensec, &st->st_ctim);
}

static void
statfs_to_fuse_kstatfs(const struct statvfs *stv, struct fuse_kstatfs *kstfs)
{
	kstfs->bsize = (uint32_t)stv->f_bsize;
	kstfs->frsize = (uint32_t)stv->f_frsize;
	kstfs->blocks = stv->f_blocks;
	kstfs->bfree = stv->f_bfree;
	kstfs->bavail = stv->f_bavail;
	kstfs->files = stv->f_files;
	kstfs->ffree = stv->f_ffree;
	kstfs->namelen = (uint32_t)stv->f_namemax;
}

static void fill_fuse_entry(struct fuse_entry_out *ent, const struct stat *st)
{
	memset(ent, 0, sizeof(*ent));
	ent->nodeid = st->st_ino;
	ent->generation = 0;
	ent->entry_valid = UINT_MAX;
	ent->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &ent->attr);
}

static void fill_fuse_attr(struct fuse_attr_out *attr, const struct stat *st)
{
	memset(attr, 0, sizeof(*attr));
	attr->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &attr->attr);
}

#if SILOFS_FUSE_STATX
static void fill_fuse_statx(struct fuse_statx_out *attr,
                            const struct statx *stx)
{
	STATICASSERT_EQ(sizeof(*stx), 256);
	STATICASSERT_EQ(sizeof(attr->attr), 240);
	STATICASSERT_EQ(sizeof(*attr), 256);
	STATICASSERT_EQ(sizeof(struct fuse_out_header) + sizeof(*attr), 272);
	STATICASSERT_EQ(sizeof(struct fuse_attr), 88);

	memset(attr, 0, sizeof(*attr));
	attr->attr_valid = UINT_MAX;
	statx_to_fuse_attr(stx, &attr->attr);
}
#endif

static void fill_fuse_open(struct fuse_open_out *open, int noflush)
{
	memset(open, 0, sizeof(*open));
	open->open_flags = FOPEN_KEEP_CACHE | FOPEN_CACHE_DIR;
	if (noflush) {
		open->open_flags |= FOPEN_NOFLUSH;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fs_uber *uber_of(const struct silofs_fuseq_worker *fqw)
{
	return fqw->fq->fq_uber;
}

static struct silofs_oper_ctx *op_ctx_of(const struct silofs_fuseq_worker *fqw)
{
	return fqw->opc;
}

static void op_ctx_set_umask(struct silofs_oper_ctx *opc, mode_t umask)
{
	opc->opc_task.t_oper.op_creds.xcred.umask = umask;
	opc->opc_task.t_oper.op_creds.icred.umask = umask;
}

static struct silofs_task *task_of(const struct silofs_fuseq_worker *fqw)
{
	return &fqw->opc->opc_task;
}

static struct silofs_task *task_self(const struct silofs_fuseq_worker *fqw)
{
	struct silofs_task *task = task_of(fqw);
	struct silofs_fs_uber *uber = uber_of(fqw);
	struct silofs_creds *creds = &task->t_oper.op_creds;

	task->t_uber = uber;
	task->t_interrupt = 0;
	creds->xcred.uid = uber->ub_args->uid;
	creds->xcred.gid = uber->ub_args->gid;
	creds->xcred.pid = getpid();
	creds->xcred.umask = uber->ub_args->umask;
	creds->icred.uid = uber->ub_args->uid;
	creds->icred.gid = uber->ub_args->gid;
	creds->icred.pid = getpid();
	creds->icred.umask = uber->ub_args->umask;
	creds->ts.tv_sec = silofs_time_now();
	creds->ts.tv_nsec = 0;
	task->t_oper.op_unique = 0;
	task->t_oper.op_code = 0;

	return task;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fuseq_check_fh(const struct silofs_fuseq_worker *fqw,
                           ino_t ino, uint64_t fh)
{
	if (fh != 0) {
		fuseq_log_warn("op=%s ino=%lu fh=0x%lx",
		               fqw->cmd->name, ino, fh);
	}
}

static void fuseq_fill_out_header(struct silofs_fuseq_worker *fqw,
                                  struct fuse_out_header *out_hdr,
                                  size_t len, int err)
{
	const struct silofs_task *task = task_of(fqw);

	out_hdr->len = (uint32_t)len;
	out_hdr->error = -abs(err);
	out_hdr->unique = task->t_oper.op_unique;
}

static int fuseq_send_msg(struct silofs_fuseq_worker *fqw,
                          const struct iovec *iov, size_t iovcnt)
{
	int err;
	size_t nwr = 0;
	const int fuse_fd = fqw->fq->fq_fuse_fd;

	err = silofs_sys_writev(fuse_fd, iov, (int)iovcnt, &nwr);
	if (err && (err != -ENOENT)) {
		fuseq_log_warn("send-to-fuse failed: fuse_fd=%d "\
		               "iovcnt=%lu err=%d", fuse_fd, iovcnt, err);
	}
	return err;
}

static int fuseq_reply_arg(struct silofs_fuseq_worker *fqw,
                           const void *arg, size_t argsz)
{
	struct fuse_out_header hdr;
	struct iovec iov[2];
	const size_t hdrsz = sizeof(hdr);
	size_t cnt = 1;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsz;
	if (argsz) {
		iov[1].iov_base = unconst(arg);
		iov[1].iov_len = argsz;
		cnt = 2;
	}
	fuseq_fill_out_header(fqw, &hdr, hdrsz + argsz, 0);
	return fuseq_send_msg(fqw, iov, cnt);
}

static int fuseq_reply_arg2(struct silofs_fuseq_worker *fqw,
                            const void *arg, size_t argsz,
                            const void *buf, size_t bufsz)
{
	struct fuse_out_header hdr;
	struct iovec iov[3];
	const size_t hdrsz = sizeof(hdr);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsz;
	iov[1].iov_base = unconst(arg);
	iov[1].iov_len = argsz;
	iov[2].iov_base = unconst(buf);
	iov[2].iov_len = bufsz;

	fuseq_fill_out_header(fqw, &hdr, hdrsz + argsz + bufsz, 0);
	return fuseq_send_msg(fqw, iov, 3);
}

static int fuseq_reply_buf(struct silofs_fuseq_worker *fqw,
                           const void *buf, size_t bsz)
{
	return fuseq_reply_arg(fqw, buf, bsz);
}

static int fuseq_reply_err(struct silofs_fuseq_worker *fqw, int err)
{
	struct fuse_out_header hdr;
	struct iovec iov[1];
	const size_t hdrsz = sizeof(hdr);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsz;

	fuseq_fill_out_header(fqw, &hdr, hdrsz, err);
	return fuseq_send_msg(fqw, iov, 1);
}

static int fuseq_reply_intr(struct silofs_fuseq_worker *fqw)
{
	return fuseq_reply_err(fqw, -EINTR);
}

static int fuseq_reply_status(struct silofs_fuseq_worker *fqw, int status)
{
	return fuseq_reply_err(fqw, status);
}

static int fuseq_reply_none(struct silofs_fuseq_worker *fqw)
{
	struct silofs_task *task = task_of(fqw);

	task->t_oper.op_unique = 0;
	return 0;
}

static int fuseq_reply_entry_ok(struct silofs_fuseq_worker *fqw,
                                const struct stat *st)
{
	struct fuse_entry_out arg;

	fill_fuse_entry(&arg, st);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_create_ok(struct silofs_fuseq_worker *fqw,
                                 const struct stat *st)
{
	struct fuseq_create_out {
		struct fuse_entry_out ent;
		struct fuse_open_out  open;
	} silofs_packed_aligned16 arg;

	fill_fuse_entry(&arg.ent, st);
	fill_fuse_open(&arg.open, 0);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_attr_ok(struct silofs_fuseq_worker *fqw,
                               const struct stat *st)
{
	struct fuse_attr_out arg;

	fill_fuse_attr(&arg, st);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

#if SILOFS_FUSE_STATX
static int fuseq_reply_statx_ok(struct silofs_fuseq_worker *fqw,
                                const struct statx *stx)
{
	struct fuse_statx_out arg;

	fill_fuse_statx(&arg, stx);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}
#endif

static int fuseq_reply_statfs_ok(struct silofs_fuseq_worker *fqw,
                                 const struct statvfs *stv)
{
	struct fuse_statfs_out arg;

	statfs_to_fuse_kstatfs(stv, &arg.st);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_buf_ok(struct silofs_fuseq_worker *fqw,
                              const char *buf, size_t bsz)
{
	return fuseq_reply_arg(fqw, buf, bsz);
}

static int fuseq_reply_readlink_ok(struct silofs_fuseq_worker *fqw,
                                   const char *lnk, size_t len)
{
	return fuseq_reply_buf_ok(fqw, lnk, len);
}

static int fuseq_reply_open_ok(struct silofs_fuseq_worker *fqw, int noflush)
{
	struct fuse_open_out arg;

	fill_fuse_open(&arg, noflush);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_opendir_ok(struct silofs_fuseq_worker *fqw)
{
	return fuseq_reply_open_ok(fqw, 0);
}

static int fuseq_reply_write_ok(struct silofs_fuseq_worker *fqw, size_t cnt)
{
	struct fuse_write_out arg = {
		.size = (uint32_t)cnt
	};

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_lseek_ok(struct silofs_fuseq_worker *fqw, loff_t off)
{
	struct fuse_lseek_out arg = {
		.offset = (uint64_t)off
	};

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_xattr_len(struct silofs_fuseq_worker *fqw, size_t len)
{
	struct fuse_getxattr_out arg = {
		.size = (uint32_t)len
	};

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_xattr_buf(struct silofs_fuseq_worker *fqw,
                                 const void *buf, size_t len)
{
	return fuseq_reply_buf(fqw, buf, len);
}

static int fuseq_reply_init_ok(struct silofs_fuseq_worker *fqw,
                               const struct silofs_fuseq_conn_info *coni)
{
	const size_t max_pages = ((coni->max_write - 1) / coni->pagesize) + 1;
	struct fuse_init_out arg = {
		.major = FUSE_KERNEL_VERSION,
		.minor = FUSE_KERNEL_MINOR_VERSION,
		.flags = 0
	};

	if (coni->cap_kern & FUSE_MAX_PAGES) {
		arg.flags |= FUSE_MAX_PAGES;
		arg.max_pages = (uint16_t)min(max_pages, UINT16_MAX);
	}
	arg.flags |= FUSE_BIG_WRITES;
	arg.flags |= (uint32_t)coni->cap_want;
	arg.max_readahead = (uint32_t)coni->max_readahead;
	arg.max_write = (uint32_t)coni->max_write;
	arg.max_background = (uint16_t)coni->max_background;
	arg.congestion_threshold = (uint16_t)coni->congestion_threshold;
	arg.time_gran = (uint32_t)coni->time_gran;

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_ioctl_ok(struct silofs_fuseq_worker *fqw, int result,
                                const void *buf, size_t size)
{
	struct fuse_ioctl_out arg;
	int ret;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;

	if (size && buf) {
		ret = fuseq_reply_arg2(fqw, &arg, sizeof(arg), buf, size);
	} else {
		ret = fuseq_reply_arg(fqw, &arg, sizeof(arg));
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool fuseq_interrupted(const struct silofs_fuseq_worker *fqw)
{
	const struct silofs_task *task = task_of(fqw);

	return task->t_interrupt > 0;
}

static int fuseq_reply_attr(struct silofs_fuseq_worker *fqw,
                            const struct stat *st, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_attr_ok(fqw, st);
	}
	return ret;
}

static int fuseq_reply_entry(struct silofs_fuseq_worker *fqw,
                             const struct stat *st, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_entry_ok(fqw, st);
	}
	return ret;
}

static int fuseq_reply_create(struct silofs_fuseq_worker *fqw,
                              const struct stat *st, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_create_ok(fqw, st);
	}
	return ret;
}

static int fuseq_reply_readlink(struct silofs_fuseq_worker *fqw,
                                const char *lnk, size_t len, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_readlink_ok(fqw, lnk, len);
	}
	return ret;
}

static int fuseq_reply_statfs(struct silofs_fuseq_worker *fqw,
                              const struct statvfs *stv, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_statfs_ok(fqw, stv);
	}
	return ret;
}

static int fuseq_reply_open(struct silofs_fuseq_worker *fqw,
                            int noflush, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_open_ok(fqw, noflush);
	}
	return ret;
}

static int fuseq_reply_xattr(struct silofs_fuseq_worker *fqw,
                             const void *buf, size_t len, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else if (buf == NULL) {
		ret = fuseq_reply_xattr_len(fqw, len);
	} else {
		ret = fuseq_reply_xattr_buf(fqw, buf, len);
	}
	return ret;
}

static int fuseq_reply_opendir(struct silofs_fuseq_worker *fqw, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_opendir_ok(fqw);
	}
	return ret;
}

static int fuseq_reply_readdir(struct silofs_fuseq_worker *fqw,
                               const struct silofs_fuseq_diter *di, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_buf(fqw, di->buf, di->len);
	}
	return ret;
}

static int fuseq_reply_lseek(struct silofs_fuseq_worker *fqw,
                             loff_t off, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_lseek_ok(fqw, off);
	}
	return ret;
}

static int fuseq_reply_copy_file_range(struct silofs_fuseq_worker *fqw,
                                       size_t cnt, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_write_ok(fqw, cnt);
	}
	return ret;
}

#if SILOFS_FUSE_STATX
static int fuseq_reply_statx(struct silofs_fuseq_worker *fqw,
                             const struct statx *stx, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_statx_ok(fqw, stx);
	}
	return ret;
}
#endif

static int fuseq_reply_init(struct silofs_fuseq_worker *fqw, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_init_ok(fqw, &fqw->fq->fq_coni);
	}
	return ret;
}

static int fuseq_reply_ioctl(struct silofs_fuseq_worker *fqw, int result,
                             const void *buf, size_t size, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_ioctl_ok(fqw, result, buf, size);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_reply_write(struct silofs_fuseq_worker *fqw,
                             size_t cnt, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_write_ok(fqw, cnt);
	}
	return ret;
}

static int fuseq_reply_read_buf(struct silofs_fuseq_worker *fqw,
                                const void *dat, size_t len, int err)
{
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_buf_ok(fqw, dat, len);
	}
	return ret;
}

static int fuseq_rdwr_post(const struct silofs_fuseq_worker *fqw,
                           const struct silofs_iovec *iov, size_t cnt)
{
	return silofs_fs_rdwr_post(task_of(fqw), iov, cnt);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void iovec_reset(struct silofs_iovec *iov)
{
	memset(iov, 0, sizeof(*iov));
	iov->iov_fd = -1;
}

static void iovec_assign(struct silofs_iovec *iov,
                         const struct silofs_iovec *other)
{
	memcpy(iov, other, sizeof(*iov));
}

static bool iovec_isfdseq(const struct silofs_iovec *iov1,
                          const struct silofs_iovec *iov2)
{
	const loff_t end1 = off_end(iov1->iov_off, iov1->iov_len);
	const loff_t beg2 = iov2->iov_off;
	const int fd1 = iov1->iov_fd;
	const int fd2 = iov2->iov_fd;

	return (fd1 > 0) && (fd2 > 0) && (fd1 == fd2) && (end1 == beg2);
}

static void iovec_append_len(struct silofs_iovec *iov,
                             const struct silofs_iovec *other)
{
	iov->iov_len += other->iov_len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
fuseq_append_hdr_to_pipe(struct silofs_fuseq_worker *fqw, size_t len)
{
	struct fuse_out_header hdr;
	struct silofs_pipe *pipe = &fqw->piper.pipe;

	fuseq_fill_out_header(fqw, &hdr,  sizeof(hdr) + len, 0);
	return silofs_pipe_append_from_buf(pipe, &hdr, sizeof(hdr));
}

static int fuseq_append_to_pipe_by_fd(struct silofs_fuseq_worker *fqw,
                                      const struct silofs_iovec *iov)
{
	struct silofs_pipe *pipe = &fqw->piper.pipe;
	size_t len = iov->iov_len;
	loff_t off = iov->iov_off;

	return silofs_pipe_splice_from_fd(pipe, iov->iov_fd,
	                                  &off, len, FUSEQ_SPLICE_FLAGS);
}

static int fuseq_append_to_pipe_by_iov(struct silofs_fuseq_worker *fqw,
                                       const struct silofs_iovec *siov)
{
	struct iovec iov = {
		.iov_base = siov->iov_base,
		.iov_len = siov->iov_len
	};

	return silofs_pipe_vmsplice_from_iov(&fqw->piper.pipe,
	                                     &iov, 1, FUSEQ_SPLICE_FLAGS);
}

static int
fuseq_append_data_to_pipe(struct silofs_fuseq_worker *fqw,
                          const struct silofs_iovec *iov_arr, size_t cnt)
{
	const struct silofs_iovec *iov;
	int err = 0;

	for (size_t i = 0; (i < cnt) && !err; ++i) {
		iov = &iov_arr[i];
		if (iov->iov_fd > 0) {
			err = fuseq_append_to_pipe_by_fd(fqw, iov);
		} else if (iov->iov_base != NULL) {
			err = fuseq_append_to_pipe_by_iov(fqw, iov);
		} else {
			fuseq_log_err("bad iovec entry: "\
			              "fd=%d off=%ld len=%lu",
			              iov->iov_fd, iov->iov_off,
			              iov->iov_len);
			err = -EINVAL;
		}
	}
	return err;
}

static int fuseq_send_pipe(struct silofs_fuseq_worker *fqw)
{
	struct silofs_pipe *pipe = &fqw->piper.pipe;

	return silofs_pipe_flush_to_fd(pipe, fqw->fq->fq_fuse_fd);
}

static int fuseq_reply_read_data(struct silofs_fuseq_worker *fqw, size_t nrd,
                                 const struct silofs_iovec *iov)
{
	return fuseq_reply_arg(fqw, iov->iov_base, nrd);
}

static int fuseq_reply_read_iov(struct silofs_fuseq_rd_iter *fq_rdi)
{
	struct silofs_iovec iov;
	struct silofs_fuseq_worker *fqw = fq_rdi->fqw;
	const struct silofs_iovec *itr = NULL;
	size_t cur = 0;
	int err = 0;
	int ret = 0;

	err = fuseq_append_hdr_to_pipe(fqw, fq_rdi->nrd);
	if (err) {
		goto out;
	}
	while (fq_rdi->ncp < fq_rdi->cnt) {
		cur = 0;
		iovec_reset(&iov);
		for (size_t i = fq_rdi->ncp; i < fq_rdi->cnt; ++i) {
			itr = &fq_rdi->iov[i];
			if (!cur) {
				iovec_assign(&iov, itr);
			} else if (iovec_isfdseq(&iov, itr)) {
				iovec_append_len(&iov, itr);
			} else {
				break;
			}
			cur++;
		}
		err = fuseq_append_data_to_pipe(fqw, &iov, 1);
		if (err) {
			goto out;
		}
		fq_rdi->ncp += cur;
	}
out:
	if (err) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_send_pipe(fqw);
	}
	return ret ? ret : err;
}

static int fuseq_reply_read_ok(struct silofs_fuseq_rd_iter *fq_rdi)
{
	struct silofs_fuseq_worker *fqw = fq_rdi->fqw;
	int ret;

	if ((fq_rdi->cnt <= 1) && (fq_rdi->iov[0].iov_fd < 0)) {
		ret = fuseq_reply_read_data(fqw, fq_rdi->nrd, fq_rdi->iov);
	} else {
		ret = fuseq_reply_read_iov(fq_rdi);
	}
	return ret;
}

static int fuseq_reply_read_iter(struct silofs_fuseq_rd_iter *fq_rdi, int err)
{
	struct silofs_fuseq_worker *fqw = fq_rdi->fqw;
	int ret;

	if (fuseq_interrupted(fqw)) {
		ret = fuseq_reply_intr(fqw);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_read_ok(fq_rdi);
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

static int fillxent(struct silofs_listxattr_ctx *lsx,
                    const char *name, size_t nlen)
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
		xi->end = xi->beg + min(size, sizeof(xi->buf));
		xi->cur = xi->buf;
	} else {
		xi->beg = NULL;
		xi->end = NULL;
		xi->cur = NULL;
	}
}

static void xiter_done(struct silofs_fuseq_xiter *xi)
{
	xi->lxa.actor = NULL;
	xi->cnt = 0;
	xi->beg = NULL;
	xi->end = NULL;
	xi->cur = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
emit_direntonly(void *buf, size_t bsz, const char *name, size_t nlen,
                ino_t ino, mode_t dt, loff_t off, size_t *out_sz)
{
	size_t entlen;
	size_t entlen_padded;
	struct fuse_dirent *fde = buf;

	entlen = FUSE_NAME_OFFSET + nlen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if (entlen_padded > bsz) {
		return -EINVAL;
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
                const struct stat *attr, loff_t off, size_t *out_sz)
{
	size_t entlen;
	size_t entlen_padded;
	struct fuse_direntplus *fdp = buf;
	struct fuse_dirent *fde = &fdp->dirent;

	entlen = FUSE_NAME_OFFSET_DIRENTPLUS + nlen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if (entlen_padded > bsz) {
		return -EINVAL;
	}

	memset(&fdp->entry_out, 0, sizeof(fdp->entry_out));
	fill_fuse_entry(&fdp->entry_out, attr);

	fde->ino = attr->st_ino;
	fde->off = (uint64_t)off;
	fde->namelen = (uint32_t)nlen;
	fde->type =  IFTODT(attr->st_mode);
	memcpy(fde->name, name, nlen);
	memset(fde->name + nlen, 0, entlen_padded - entlen);

	*out_sz = entlen_padded;
	return 0;
}

static int emit_dirent(struct silofs_fuseq_diter *di, loff_t off)
{
	char *buf = di->buf + di->len;
	const size_t rem = di->bsz - di->len;
	const ino_t ino = di->de_ino;
	const size_t nlen = di->de_nlen;
	const char *name = di->de_name.name;
	size_t cnt = 0;
	int err;

	if (rem <= di->de_nlen) {
		return -EINVAL;
	}
	err = likely(di->plus) ?
	      emit_direntplus(buf, rem, name, nlen, &di->de_attr, off, &cnt) :
	      emit_direntonly(buf, rem, name, nlen, ino, di->de_dt, off, &cnt);
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
	const size_t namebuf_sz = sizeof(di->de_name.name);

	di->de_off = rdi->off;
	di->de_ino = rdi->ino;
	di->de_dt = rdi->dt;
	di->de_nlen = min(rdi->namelen, namebuf_sz - 1);
	memcpy(di->de_name.name, rdi->name, di->de_nlen);
	memset(di->de_name.name + di->de_nlen, 0, namebuf_sz - di->de_nlen);
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

static void diter_prep(struct silofs_fuseq_diter *di,
                       size_t bsz, loff_t pos, int plus)
{
	di->ndes = 0;
	di->de_off = 0;
	di->de_nlen = 0;
	di->de_ino = 0;
	di->de_dt = 0;
	di->de_name.name[0] = '\0';
	di->bsz = min(bsz, sizeof(di->buf));
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
	di->rd_ctx.actor = NULL;
	di->rd_ctx.pos = 0;
	di->plus = 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void setup_cap_want(struct silofs_fuseq_conn_info *coni, int cap)
{
	if (coni->cap_kern & cap) {
		coni->cap_want |= cap;
	}
}

static int check_init(const struct silofs_fuseq_worker *fqw,
                      const struct fuse_init_in *arg)
{
	const unsigned int u_major = FUSE_KERNEL_VERSION;
	const unsigned int u_minor = FUSE_KERNEL_MINOR_VERSION;

	unused(fqw);
	if ((arg->major != u_major) || (arg->minor < u_minor)) {
		fuseq_log_warn("version mismatch: "\
		               "kernel=%u.%u userspace=%u.%u",
		               arg->major, arg->minor, u_major, u_minor);
	}
	/*
	 * XXX minor __should__ be 34, but allow 31 due to fuse version on
	 * github's ubuntu-20.04 runners (fuse7.33) and RHEL8 (fuse7.31).
	 */
	if ((arg->major != 7) || (arg->minor < 31)) {
		fuseq_log_err("unsupported fuse-protocol version: %u.%u",
		              arg->major, arg->minor);
		return -EPROTO;
	}
	return 0;
}

static int do_init(struct silofs_fuseq_worker *fqw, ino_t ino,
                   const struct silofs_fuseq_in *in)
{
	struct silofs_fuseq_conn_info *coni = &fqw->fq->fq_coni;
	const int in_major = (int)(in->u.init.arg.major);
	const int in_minor = (int)(in->u.init.arg.minor);
	const int in_flags = (int)(in->u.init.arg.flags);
	int err = 0;
	int ret;

	fuseq_log_info("init: ino=%ld version=%d.%d flags=0x%x",
	               ino, in_major, in_minor, in_flags);

	err = check_init(fqw, &in->u.init.arg);
	if (err) {
		goto out;
	}

	fqw->fq->fq_got_init = true;
	coni->proto_major = in_major;
	coni->proto_minor = in_minor;
	coni->cap_kern = in_flags;
	coni->cap_want = 0;

	/*
	 * TODO-0018: Enable more capabilities
	 *
	 * XXX: When enabling FUSE_WRITEBACK_CACHE fstests fails with
	 * metadata (st_ctime,st_blocks) issues. Also, bugs in
	 * 'test_truncate_zero'. Needs further investigation.
	 */
	setup_cap_want(coni, FUSE_ATOMIC_O_TRUNC);
	setup_cap_want(coni, FUSE_EXPORT_SUPPORT);
	setup_cap_want(coni, FUSE_HANDLE_KILLPRIV);
	setup_cap_want(coni, FUSE_CACHE_SYMLINKS);
	setup_cap_want(coni, FUSE_DO_READDIRPLUS);
	setup_cap_want(coni, FUSE_SPLICE_READ);
	setup_cap_want(coni, FUSE_SPLICE_WRITE);
	setup_cap_want(coni, FUSE_SETXATTR_EXT);
	if (fqw->fq->fq_writeback_cache) {
		setup_cap_want(coni, FUSE_WRITEBACK_CACHE);
	}

	/*
	 * TODO-0025: Have support for ACLs
	 *
	 * Enable FUSE_POSIX_ACL (plus, "system." prefix in xattr)
	 */
	/* setup_cap_want(coni, FUSE_POSIX_ACL); */

out:
	ret = fuseq_reply_init(fqw, err);
	if (!err && !ret) {
		fqw->fq->fq_reply_init_ok = true;
	}
	return err ? err : ret;
}

static int do_destroy(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	unused(ino);
	unused(in);

	fuseq_lock_fs(fqw->fq);
	fqw->fq->fq_got_destroy = true;
	fqw->fq->fq_active = 0;
	fuseq_unlock_fs(fqw->fq);

	return fuseq_reply_status(fqw, 0);
}

static bool fuseq_has_cap(const struct silofs_fuseq *fq, int cap_mask)
{
	const int cap_want = fq->fq_coni.cap_want;

	return fq->fq_got_init && ((cap_want & cap_mask) == cap_mask);
}

static bool fuseq_is_normal(const struct silofs_fuseq *fq)
{
	return fq->fq_got_init && fq->fq_reply_init_ok &&
	       !fq->fq_got_destroy && (fq->fq_nopers > 1);
}

static bool fuseq_may_splice(const struct silofs_fuseq *fq)
{
	return fuseq_is_normal(fq) && (fq->fq_nopers > 2);
}

static bool fuseq_cap_splice_read(const struct silofs_fuseq *fq)
{
	return fuseq_may_splice(fq) && fuseq_has_cap(fq, FUSE_SPLICE_READ);
}

static bool fuseq_cap_splice_write(const struct silofs_fuseq *fq)
{
	return fuseq_may_splice(fq) && fuseq_has_cap(fq, FUSE_SPLICE_WRITE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define FATTR_MASK \
	(FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE | \
	 FATTR_ATIME | FATTR_MTIME | FATTR_FH | FATTR_ATIME_NOW | \
	 FATTR_MTIME_NOW | FATTR_LOCKOWNER | FATTR_CTIME)

#define FATTR_AMTIME_NOW \
	(FATTR_ATIME_NOW | FATTR_MTIME_NOW)

#define FATTR_AMCTIME \
	(FATTR_ATIME | FATTR_MTIME | FATTR_CTIME)

#define FATTR_NONTIME \
	(FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE)


static int
uid_gid_of(const struct stat *attr, int to_set, uid_t *uid, gid_t *gid)
{
	*uid = (to_set & FATTR_UID) ? attr->st_uid : (uid_t)(-1);
	*gid = (to_set & FATTR_GID) ? attr->st_gid : (gid_t)(-1);
	return 0; /* TODO: Check valid ranges */
}

static void utimens_of(const struct stat *st, int to_set, struct stat *times)
{
	const int set_ctime_now =
	        FATTR_AMTIME_NOW | FATTR_AMCTIME | FATTR_MODE |
	        FATTR_UID | FATTR_GID | FATTR_SIZE;

	silofs_memzero(times, sizeof(*times));
	times->st_atim.tv_nsec = UTIME_OMIT;
	times->st_mtim.tv_nsec = UTIME_OMIT;
	times->st_ctim.tv_nsec = UTIME_OMIT;

	if (to_set & FATTR_ATIME) {
		silofs_ts_copy(&times->st_atim, &st->st_atim);
	}
	if (to_set & FATTR_MTIME) {
		silofs_ts_copy(&times->st_mtim, &st->st_mtim);
	}
	if (to_set & FATTR_CTIME) {
		silofs_ts_copy(&times->st_ctim, &st->st_ctim);
	} else if (to_set & set_ctime_now) {
		times->st_ctim.tv_nsec = UTIME_NOW;
	}
}

static int do_setattr(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	struct stat attr = { .st_size = -1 };
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	const int to_set = (int)(in->u.setattr.arg.valid & FATTR_MASK);
	int err;

	silofs_memzero(&opc->opc_in.setattr, sizeof(opc->opc_in.setattr));
	fuse_setattr_to_stat(&in->u.setattr.arg, &attr);

	utimens_of(&attr, to_set, &opc->opc_in.setattr.tims);
	if (to_set & (FATTR_UID | FATTR_GID)) {
		uid_gid_of(&attr, to_set, &opc->opc_in.setattr.uid,
		           &opc->opc_in.setattr.gid);
		opc->opc_in.setattr.set_uid_gid = true;
	}
	if (to_set & FATTR_AMTIME_NOW) {
		opc->opc_in.setattr.set_amtime_now = true;
	}
	if (to_set & FATTR_MODE) {
		opc->opc_in.setattr.mode = attr.st_mode;
		opc->opc_in.setattr.set_mode = true;
	}
	if (to_set & FATTR_SIZE) {
		opc->opc_in.setattr.size = attr.st_size;
		opc->opc_in.setattr.set_size = true;
	}
	if (to_set & FATTR_AMCTIME) {
		opc->opc_in.setattr.set_amctime = true;
	}
	if (to_set & FATTR_NONTIME) {
		opc->opc_in.setattr.set_nontime = true;
	}
	opc->opc_in.setattr.ino = ino;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_attr(fqw, &opc->opc_out.setattr.st, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_lookup(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.lookup.parent = ino;
	opc->opc_in.lookup.name = in->u.lookup.name;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_entry(fqw, &opc->opc_out.lookup.st, err);
}

static int do_forget(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.forget.ino = ino;
	opc->opc_in.forget.nlookup = in->u.forget.arg.nlookup;

	err = fuseq_exec_op(fqw->fq, opc);
	unused(err);
	return fuseq_reply_none(fqw);
}

static int do_batch_forget(struct silofs_fuseq_worker *fqw, ino_t unused_ino,
                           const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.batch_forget.count = in->u.batch_forget.arg.count;
	opc->opc_in.batch_forget.one = in->u.batch_forget.one;

	err = fuseq_exec_op(fqw->fq, opc);
	unused(err);
	unused(unused_ino);
	return fuseq_reply_none(fqw);
}

static int do_getattr(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.getattr.arg.fh);
	opc->opc_in.getattr.ino = ino;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_attr(fqw, &opc->opc_out.getattr.st, err);
}

static int do_readlink(struct silofs_fuseq_worker *fqw, ino_t ino,
                       const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_pathbuf *pab = &fqw->outb->u.pab;
	char *lnk = pab->path;
	int err;

	unused(in);
	opc->opc_in.readlink.ino = ino;
	opc->opc_in.readlink.ptr = lnk;
	opc->opc_in.readlink.lim = sizeof(pab->path);
	opc->opc_out.readlink.len = 0;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_readlink(fqw, lnk, opc->opc_out.readlink.len, err);
}

static int do_symlink(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.symlink.parent = ino;
	opc->opc_in.symlink.name = in->u.symlink.name_target;
	opc->opc_in.symlink.symval = after_name(opc->opc_in.symlink.name);

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_entry(fqw, &opc->opc_out.symlink.st, err);
}

static int do_mknod(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.mknod.parent = ino;
	opc->opc_in.mknod.name = in->u.mknod.name;
	opc->opc_in.mknod.rdev = (dev_t)in->u.mknod.arg.rdev;
	opc->opc_in.mknod.mode = (mode_t)in->u.mknod.arg.mode;
	opc->opc_in.mknod.umask = (mode_t)in->u.mknod.arg.umask;
	op_ctx_set_umask(opc, opc->opc_in.mknod.umask);

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_entry(fqw, &opc->opc_out.mknod.st, err);
}

static int do_mkdir(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.mkdir.parent = ino;
	opc->opc_in.mkdir.name = in->u.mkdir.name;
	opc->opc_in.mkdir.mode = (mode_t)(in->u.mkdir.arg.mode | S_IFDIR);
	opc->opc_in.mkdir.umask = (mode_t)in->u.mkdir.arg.umask;
	op_ctx_set_umask(opc, opc->opc_in.mkdir.umask);

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_entry(fqw, &opc->opc_out.mkdir.st, err);
}

static int do_unlink(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.unlink.parent = ino;
	opc->opc_in.unlink.name = in->u.unlink.name;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_rmdir(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.rmdir.parent = ino;
	opc->opc_in.rmdir.name = in->u.rmdir.name;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_rename(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.rename.parent = ino;
	opc->opc_in.rename.name = in->u.rename.name_newname;
	opc->opc_in.rename.newparent = (ino_t)(in->u.rename.arg.newdir);
	opc->opc_in.rename.newname = after_name(opc->opc_in.rename.name);
	opc->opc_in.rename.flags = 0;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_link(struct silofs_fuseq_worker *fqw, ino_t ino,
                   const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.link.ino = (ino_t)(in->u.link.arg.oldnodeid);
	opc->opc_in.link.parent = ino;
	opc->opc_in.link.name = in->u.link.name;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_entry(fqw, &opc->opc_out.link.st, err);
}

static int do_open(struct silofs_fuseq_worker *fqw, ino_t ino,
                   const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.open.ino = ino;
	opc->opc_in.open.o_flags = (int)(in->u.open.arg.flags);
	opc->opc_in.open.noflush =
	        (opc->opc_in.open.o_flags & O_ACCMODE) == O_RDONLY;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_open(fqw, opc->opc_in.open.noflush, err);
}

static int do_statfs(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.statfs.ino = ino;

	unused(in);
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_statfs(fqw, &opc->opc_out.statfs.stv, err);
}

static int do_release(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.release.arg.fh);
	opc->opc_in.release.ino = ino;
	opc->opc_in.release.o_flags = (int)in->u.release.arg.flags;
	opc->opc_in.release.flush =
	        (in->u.release.arg.flags & FUSE_RELEASE_FLUSH) > 0;

	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_fsync(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.fsync.arg.fh);
	opc->opc_in.fsync.ino = ino;
	opc->opc_in.fsync.datasync = (in->u.fsync.arg.fsync_flags & 1) != 0;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_setxattr1(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.setxattr.ino = ino;
	opc->opc_in.setxattr.name = in->u.setxattr1.name_value;
	opc->opc_in.setxattr.value = after_name(in->u.setxattr1.name_value);
	opc->opc_in.setxattr.size = in->u.setxattr1.arg.size;
	opc->opc_in.setxattr.flags = (int)(in->u.setxattr1.arg.flags);
	opc->opc_in.setxattr.kill_sgid = false;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_setxattr2(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.setxattr.ino = ino;
	opc->opc_in.setxattr.name = in->u.setxattr.name_value;
	opc->opc_in.setxattr.value = after_name(in->u.setxattr.name_value);
	opc->opc_in.setxattr.size = in->u.setxattr.arg.size;
	opc->opc_in.setxattr.flags = (int)(in->u.setxattr.arg.flags);
	opc->opc_in.setxattr.kill_sgid =
	        (opc->opc_in.setxattr.flags & FUSE_SETXATTR_ACL_KILL_SGID) > 0;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_setxattr(struct silofs_fuseq_worker *fqw, ino_t ino,
                       const struct silofs_fuseq_in *in)
{
	return (fqw->fq->fq_coni.proto_minor <= 33) ?
	       do_setxattr1(fqw, ino, in) : do_setxattr2(fqw, ino, in);
}

static int do_getxattr(struct silofs_fuseq_worker *fqw, ino_t ino,
                       const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_xattrbuf *xab = &fqw->outb->u.xab;
	int err;

	opc->opc_in.getxattr.ino = ino;
	opc->opc_in.getxattr.name = in->u.getxattr.name;
	opc->opc_in.getxattr.size =
	        min(in->u.getxattr.arg.size, sizeof(xab->value));
	opc->opc_in.getxattr.buf =
	        opc->opc_in.getxattr.size ? xab->value : NULL;
	opc->opc_out.getxattr.size = 0;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_xattr(fqw, opc->opc_in.getxattr.buf,
	                         opc->opc_out.getxattr.size, err);
}

static int do_listxattr(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_xiter *xit = &fqw->outb->u.xit;
	int ret;
	int err;

	xiter_prep(xit, in->u.listxattr.arg.size);
	opc->opc_in.listxattr.ino = ino;
	opc->opc_in.listxattr.lxa_ctx = &xit->lxa;
	err = fuseq_exec_op(fqw->fq, opc);
	ret = fuseq_reply_xattr(fqw, xit->beg, xit->cnt, err);
	xiter_done(xit);
	return ret;
}

static int do_removexattr(struct silofs_fuseq_worker *fqw, ino_t ino,
                          const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.removexattr.ino = ino;
	opc->opc_in.removexattr.name = in->u.removexattr.name;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_flush(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.flush.arg.fh);
	opc->opc_in.flush.ino = ino;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_opendir(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	/* TODO: use OPENDIR's o_flags */
	opc->opc_in.opendir.ino = ino;
	opc->opc_in.opendir.o_flags = (int)(in->u.opendir.arg.flags);
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_opendir(fqw, err);
}

static int do_readdir(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_diter *dit = &fqw->outb->u.dit;
	const size_t size = in->u.readdir.arg.size;
	const loff_t off = (loff_t)(in->u.readdir.arg.offset);
	int ret;
	int err;

	fuseq_check_fh(fqw, ino, in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 0);
	opc->opc_in.readdir.ino = ino;
	opc->opc_in.readdir.rd_ctx = &dit->rd_ctx;
	err = fuseq_exec_op(fqw->fq, opc);
	ret = fuseq_reply_readdir(fqw, dit, err);
	diter_done(dit);
	return ret;
}

static int do_readdirplus(struct silofs_fuseq_worker *fqw, ino_t ino,
                          const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_diter *dit = &fqw->outb->u.dit;
	const size_t size = in->u.readdir.arg.size;
	const loff_t off = (loff_t)(in->u.readdir.arg.offset);
	int ret;
	int err;

	fuseq_check_fh(fqw, ino, in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 1);
	opc->opc_in.readdir.ino = ino;
	opc->opc_in.readdir.rd_ctx = &dit->rd_ctx;
	err = fuseq_exec_op(fqw->fq, opc);
	ret = fuseq_reply_readdir(fqw, dit, err);
	diter_done(dit);
	return ret;
}

static int do_releasedir(struct silofs_fuseq_worker *fqw, ino_t ino,
                         const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.releasedir.arg.fh);
	opc->opc_in.releasedir.ino = ino;
	opc->opc_in.releasedir.o_flags = (int)(in->u.releasedir.arg.flags);
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_fsyncdir(struct silofs_fuseq_worker *fqw, ino_t ino,
                       const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.fsyncdir.arg.fh);

	opc->opc_in.fsyncdir.ino = ino;
	opc->opc_in.fsyncdir.datasync =
	        (in->u.fsyncdir.arg.fsync_flags & 1) != 0;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_access(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.access.ino = ino;
	opc->opc_in.access.mask = (int)(in->u.access.arg.mask);
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_create(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.create.parent = ino;
	opc->opc_in.create.name = in->u.create.name;
	opc->opc_in.create.o_flags = (int)(in->u.create.arg.flags);
	opc->opc_in.create.mode = (mode_t)(in->u.create.arg.mode);
	opc->opc_in.create.umask = (mode_t)(in->u.create.arg.umask);
	op_ctx_set_umask(opc, opc->opc_in.create.umask);
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_create(fqw, &opc->opc_out.create.st, err);
}

static int do_fallocate(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.fallocate.arg.fh);
	opc->opc_in.fallocate.ino = ino;
	opc->opc_in.fallocate.mode = (int)(in->u.fallocate.arg.mode);
	opc->opc_in.fallocate.off = (loff_t)(in->u.fallocate.arg.offset);
	opc->opc_in.fallocate.len = (loff_t)(in->u.fallocate.arg.length);
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_rename2(struct silofs_fuseq_worker *fqw, ino_t ino,
                      const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	opc->opc_in.rename.parent = ino;
	opc->opc_in.rename.newparent = (ino_t)(in->u.rename2.arg.newdir);
	opc->opc_in.rename.name = in->u.rename2.name_newname;
	opc->opc_in.rename.newname = after_name(opc->opc_in.rename.name);
	opc->opc_in.rename.flags = (int)(in->u.rename2.arg.flags);
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

static int do_lseek(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	fuseq_check_fh(fqw, ino, in->u.lseek.arg.fh);
	opc->opc_in.lseek.ino = ino;
	opc->opc_in.lseek.off = (loff_t)(in->u.lseek.arg.offset);
	opc->opc_in.lseek.whence = (int)(in->u.lseek.arg.whence);
	opc->opc_out.lseek.off = -1;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_lseek(fqw, opc->opc_out.lseek.off, err);
}


static int do_copy_file_range(struct silofs_fuseq_worker *fqw, ino_t ino_in,
                              const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	size_t ncp = 0;
	int err;

	fuseq_check_fh(fqw, ino_in, in->u.copy_file_range.arg.fh_in);

	opc->opc_in.copy_file_range.ino_in = ino_in;
	opc->opc_in.copy_file_range.off_in =
	        (loff_t)in->u.copy_file_range.arg.off_in;
	opc->opc_in.copy_file_range.ino_out =
	        (ino_t)in->u.copy_file_range.arg.nodeid_out;
	opc->opc_in.copy_file_range.off_out =
	        (loff_t)in->u.copy_file_range.arg.off_out;
	opc->opc_in.copy_file_range.len = in->u.copy_file_range.arg.len;
	opc->opc_in.copy_file_range.flags =
	        (int)in->u.copy_file_range.arg.flags;
	opc->opc_out.copy_file_range.ncp = 0;
	err = fuseq_exec_op(fqw->fq, opc);
	ncp = opc->opc_out.copy_file_range.ncp;
	return fuseq_reply_copy_file_range(fqw, ncp, err);
}

static int do_syncfs(struct silofs_fuseq_worker *fqw, ino_t ino,
                     const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;

	unused(in);
	opc->opc_in.syncfs.ino = ino;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_status(fqw, err);
}

#if SILOFS_FUSE_STATX
static int do_statx(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	int err;
	const unsigned int request_mask = (loff_t)in->u.statx.arg.mask;
	struct statx stx = { .stx_mask = 0 };

	fuseq_lock_fs(fqw);
	err = silofs_fs_statx(uber_of(fqw), task_of(fqw),
	                      ino, request_mask, &stx);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_statx(fqw, &stx, err);
}
#endif

static int do_interrupt(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	const uint64_t unq = in->u.interrupt.arg.unique;

	if (ino == 0) {
		fuseq_interrupt_op(fqw, unq);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fuseq_rd_iter *
fuseq_rd_iter_of(const struct silofs_rwiter_ctx *rwi)
{
	const struct silofs_fuseq_rd_iter *fq_rdi =
	        container_of2(rwi, struct silofs_fuseq_rd_iter, rwi);

	return unconst(fq_rdi);
}

static int fuseq_rd_iter_actor(struct silofs_rwiter_ctx *rwi,
                               const struct silofs_iovec *iov)
{
	struct silofs_fuseq_rd_iter *fq_rdi;

	fq_rdi = fuseq_rd_iter_of(rwi);
	if ((iov->iov_fd > 0) && (iov->iov_off < 0)) {
		return -EINVAL;
	}
	if (!(fq_rdi->cnt < ARRAY_SIZE(fq_rdi->iov))) {
		return -EINVAL;
	}
	if ((fq_rdi->nrd + iov->iov_len) > fq_rdi->nrd_max) {
		return -EINVAL;
	}
	iovec_assign(&fq_rdi->iov[fq_rdi->cnt++], iov);
	fq_rdi->nrd += iov->iov_len;
	return 0;
}

static void fuseq_setup_rd_iter(struct silofs_fuseq_worker *fqw,
                                struct silofs_fuseq_rd_iter *fq_rdi,
                                size_t len, loff_t off)
{
	fq_rdi->fqw = fqw;
	fq_rdi->cnt = 0;
	fq_rdi->ncp = 0;
	fq_rdi->nrd = 0;
	fq_rdi->nrd_max = len;
	fq_rdi->rwi.len = len;
	fq_rdi->rwi.off = off;
	fq_rdi->rwi.actor = fuseq_rd_iter_actor;
}

static int do_read_iter(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_rd_iter *fq_rdi = &fqw->rwi->u.rdi;
	const size_t len = min(in->u.read.arg.size, fqw->fq->fq_coni.max_read);
	int ret;
	int err;

	opc->opc_in.read.ino = ino;
	opc->opc_in.read.buf = NULL;
	opc->opc_in.read.off = (loff_t)(in->u.read.arg.offset);
	opc->opc_in.read.len = len;
	opc->opc_in.read.rwi_ctx = &fq_rdi->rwi;
	fuseq_setup_rd_iter(fqw, fq_rdi, len, opc->opc_in.read.off);
	err = fuseq_exec_op(fqw->fq, opc);
	ret = fuseq_reply_read_iter(fq_rdi, err);
	fuseq_rdwr_post(fqw, fq_rdi->iov, fq_rdi->cnt);
	return ret;
}

static int do_read_buf(struct silofs_fuseq_worker *fqw, ino_t ino,
                       const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_databuf *dab = &fqw->outb->u.dab;
	const size_t len = min(in->u.read.arg.size, fqw->fq->fq_coni.max_read);
	int err;

	opc->opc_in.read.ino = ino;
	opc->opc_in.read.buf = dab->buf;
	opc->opc_in.read.off = (loff_t)(in->u.read.arg.offset);
	opc->opc_in.read.len = len;
	opc->opc_in.read.rwi_ctx = NULL;
	opc->opc_out.read.nrd = 0;
	err = fuseq_exec_op(fqw->fq, opc);
	return fuseq_reply_read_buf(fqw, dab->buf, opc->opc_out.read.nrd, err);
}

static bool fuseq_cap_splice_out(const struct silofs_fuseq_worker *fqw)
{
	return fuseq_cap_splice_write(fqw->fq);
}

static int do_read(struct silofs_fuseq_worker *fqw, ino_t ino,
                   const struct silofs_fuseq_in *in)
{
	const size_t rd_size = in->u.read.arg.size;
	int ret;

	fuseq_check_fh(fqw, ino, in->u.read.arg.fh);

	if ((rd_size > FUSEQ_IOBUF_MAX) && fuseq_cap_splice_out(fqw)) {
		ret = do_read_iter(fqw, ino, in);
	} else {
		ret = do_read_buf(fqw, ino, in);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fuseq_wr_iter *
fuseq_wr_iter_of(const struct silofs_rwiter_ctx *rwi)
{
	const struct silofs_fuseq_wr_iter *fq_wri =
	        container_of2(rwi, struct silofs_fuseq_wr_iter, rwi);

	return unconst(fq_wri);
}

static int
fuseq_extract_from_pipe_by_fd(struct silofs_fuseq_worker *fqw,
                              const struct silofs_iovec *iov)
{
	struct silofs_pipe *pipe = &fqw->piper.pipe;
	loff_t off = iov->iov_off;
	size_t len = iov->iov_len;

	return silofs_pipe_splice_to_fd(pipe, iov->iov_fd,
	                                &off, len, FUSEQ_SPLICE_FLAGS);
}

static int
fuseq_extract_from_pipe_by_iov(struct silofs_fuseq_worker *fqw,
                               const struct silofs_iovec *siov)
{
	struct iovec iov = {
		.iov_base = siov->iov_base,
		.iov_len = siov->iov_len
	};

	return silofs_pipe_vmsplice_to_iov(&fqw->piper.pipe, &iov, 1,
	                                   FUSEQ_SPLICE_FLAGS);
}

static int
fuseq_extract_data_from_pipe(struct silofs_fuseq_worker *fqw,
                             const struct silofs_iovec *iov)
{
	int err;

	if (iov->iov_fd > 0) {
		err = fuseq_extract_from_pipe_by_fd(fqw, iov);
	} else if (iov->iov_base != NULL) {
		err = fuseq_extract_from_pipe_by_iov(fqw, iov);
	} else {
		fuseq_log_err("bad iovec entry: fd=%d off=%ld len=%lu",
		              iov->iov_fd, iov->iov_off, iov->iov_len);
		err = -EINVAL;
	}
	return err;
}

static int fuseq_wr_iter_check(const struct silofs_fuseq_wr_iter *fq_wri,
                               const struct silofs_iovec *iov)
{
	if (!fq_wri->fqw->fq->fq_active) {
		return -EROFS;
	}
	if (!(fq_wri->cnt < ARRAY_SIZE(fq_wri->iov))) {
		return -EINVAL;
	}
	if ((iov->iov_fd < 0) || (iov->iov_off < 0)) {
		return -EINVAL;
	}
	if ((fq_wri->nwr + iov->iov_len) > fq_wri->nwr_max) {
		return -EINVAL;
	}
	return 0;
}

static int fuseq_wr_iter_actor(struct silofs_rwiter_ctx *rwi,
                               const struct silofs_iovec *iov)
{
	struct silofs_fuseq_wr_iter *fq_wri = fuseq_wr_iter_of(rwi);
	int err;

	err = fuseq_wr_iter_check(fq_wri, iov);
	if (err) {
		return err;
	}
	err = fuseq_extract_data_from_pipe(fq_wri->fqw, iov);
	if (err) {
		return err;
	}
	iovec_assign(&fq_wri->iov[fq_wri->cnt++], iov);
	fq_wri->nwr += iov->iov_len;
	fq_wri->ncp++;
	return 0;
}

static int fuseq_wr_iter_concp_actor(struct silofs_rwiter_ctx *rwi,
                                     const struct silofs_iovec *iov)
{
	struct silofs_fuseq_wr_iter *fq_wri = fuseq_wr_iter_of(rwi);
	int err;

	err = fuseq_wr_iter_check(fq_wri, iov);
	if (err) {
		return err;
	}
	iovec_assign(&fq_wri->iov[fq_wri->cnt++], iov);
	return 0;
}

static int fuseq_wr_iter_copy_iov(struct silofs_fuseq_wr_iter *fq_wri)
{
	struct silofs_iovec iov;
	struct silofs_fuseq_worker *fqw = fq_wri->fqw;
	const struct silofs_iovec *itr = NULL;
	size_t cur = 0;
	int err;

	while (fq_wri->ncp < fq_wri->cnt) {
		cur = 0;
		iovec_reset(&iov);
		for (size_t i = fq_wri->ncp; i < fq_wri->cnt; ++i) {
			itr = &fq_wri->iov[i];
			if (!cur) {
				iovec_assign(&iov, itr);
			} else if (iovec_isfdseq(&iov, itr)) {
				iovec_append_len(&iov, itr);
			} else {
				break;
			}
			cur++;
		}
		err = fuseq_extract_data_from_pipe(fqw, &iov);
		if (err) {
			return err;
		}
		fq_wri->nwr += iov.iov_len;
		fq_wri->ncp += cur;
	}
	return 0;
}

static void fuseq_setup_wr_iter(struct silofs_fuseq_worker *fqw,
                                struct silofs_fuseq_wr_iter *fq_rwi,
                                size_t len, loff_t off)
{
	const struct silofs_fs_uber *uber = uber_of(fqw);
	const bool concp = uber->ub_args->concp;

	fq_rwi->fqw = fqw;
	fq_rwi->nwr = 0;
	fq_rwi->cnt = 0;
	fq_rwi->ncp = 0;
	fq_rwi->nwr_max = len;
	fq_rwi->rwi.len = len;
	fq_rwi->rwi.off = off;
	fq_rwi->rwi.actor =
	        concp ? fuseq_wr_iter_concp_actor : fuseq_wr_iter_actor;
}

static void *tail_of(const struct silofs_fuseq_in *in, size_t head_len)
{
	const void *p = in;
	const uint8_t *t = (const uint8_t *)p + head_len;

	return unconst(t);
}

static int do_write_buf(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	int err;
	int ret;

	fuseq_check_fh(fqw, ino, in->u.write.arg.fh);
	opc->opc_in.write.ino = ino;
	opc->opc_in.write.buf = tail_of(in, sizeof(in->u.write));
	opc->opc_in.write.len = in->u.write.arg.size;
	opc->opc_in.write.off = (loff_t)(in->u.write.arg.offset);
	opc->opc_in.write.rwi_ctx = NULL;
	opc->opc_out.write.nwr = 0;
	err = fuseq_exec_op(fqw->fq, opc);
	ret = fuseq_reply_write(fqw, opc->opc_out.write.nwr, err);
	return ret;
}

static int do_write_iter(struct silofs_fuseq_worker *fqw, ino_t ino,
                         const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	struct silofs_fuseq_wr_iter *fq_wri = &fqw->rwi->u.wri;
	size_t len = min(in->u.write.arg.size, fqw->fq->fq_coni.max_write);
	int err1 = 0;
	int err2 = 0;
	int ret = 0;

	fuseq_check_fh(fqw, ino, in->u.write.arg.fh);
	opc->opc_in.write.ino = ino;
	opc->opc_in.write.buf = NULL;
	opc->opc_in.write.len = len;
	opc->opc_in.write.off = (loff_t)(in->u.write.arg.offset);
	opc->opc_in.write.rwi_ctx = &fq_wri->rwi;
	opc->opc_out.write.nwr = 0;
	fuseq_setup_wr_iter(fqw, fq_wri, len, opc->opc_in.write.off);
	err1 = fuseq_exec_op(fqw->fq, opc);
	if (!err1 || (err1 == -ENOSPC)) {
		err2 = fuseq_wr_iter_copy_iov(fq_wri); /* unlocked */
	}
	ret = fuseq_reply_write(fqw, fq_wri->nwr, err1 ? err1 : err2);
	fuseq_rdwr_post(fqw, fq_wri->iov, fq_wri->cnt);
	return ret;
}

static int do_write(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	const size_t wsz = in->u.write.arg.size;

	return (wsz <= FUSEQ_IOBUF_MAX) ?
	       do_write_buf(fqw, ino, in) : do_write_iter(fqw, ino, in);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_ioc_notimpl(struct silofs_fuseq_worker *fqw, ino_t ino,
                          const struct silofs_fuseq_in *in)
{
	unused(ino);
	unused(in);

	return fuseq_reply_err(fqw, -ENOTTY);
}

static int do_ioc_getflags(struct silofs_fuseq_worker *fqw, ino_t ino,
                           const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	const size_t out_bufsz = in->u.ioctl.arg.out_size;
	long attr = 0;
	int err;

	if (out_bufsz != sizeof(attr)) {
		err = -EINVAL;
		goto out;
	}
	opc->opc_task.t_oper.op_code = FUSE_GETATTR;
	opc->opc_in.getattr.ino = ino;
	err = fuseq_exec_op(fqw->fq, opc);
	if (err) {
		goto out;
	}
	/* TODO: proper impl */
	attr = (long)(FS_NOATIME_FL);
out:
	return fuseq_reply_ioctl(fqw, 0, &attr, sizeof(attr), err);
}

static int do_ioc_query(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	const void *buf_in = in->u.ioctl.buf;
	const struct silofs_ioc_query *qry_in = buf_in;
	const size_t bsz_in = in->u.ioctl.arg.in_size;
	const size_t bsz_out = in->u.ioctl.arg.out_size;
	const int flags = (int)(in->u.ioctl.arg.flags);
	int err;

	opc->opc_ioc_cmd = SILOFS_FS_IOC_QUERY;
	opc->opc_in.query.ino = ino;
	opc->opc_in.query.qtype = (enum silofs_query_type)qry_in->qtype;

	if (!bsz_out && (flags | FUSE_IOCTL_RETRY)) {
		err = -ENOSYS;
		goto out;
	}
	if (bsz_out != sizeof(*qry_in)) {
		err = -EINVAL;
		goto out;
	}
	if (bsz_in < sizeof(qry_in->qtype)) {
		err = -EINVAL;
		goto out;
	}
	err = fuseq_exec_op(fqw->fq, opc);
out:
	return fuseq_reply_ioctl(fqw, 0, &opc->opc_out.query.qry,
	                         sizeof(opc->opc_out.query.qry), err);
}

static void uuid_of(const struct silofs_bootsecs *bsecs,
                    size_t idx, struct silofs_uuid *out_uuid)
{
	silofs_bootsec_uuid(&bsecs->bsec[idx], out_uuid);
}

static int do_ioc_clone(struct silofs_fuseq_worker *fqw, ino_t ino,
                        const struct silofs_fuseq_in *in)
{
	struct silofs_oper_ctx *opc = op_ctx_of(fqw);
	void *buf_out = fqw->outb->u.iob.b;
	struct silofs_ioc_clone *clone_out = buf_out;
	const size_t bsz_in_min = 1;
	const size_t bsz_in_max = sizeof(*clone_out);
	const size_t bsz_out_min = sizeof(*clone_out);
	const size_t bsz_in = in->u.ioctl.arg.in_size;
	const size_t bsz_out = in->u.ioctl.arg.out_size;
	const int flags = (int)(in->u.ioctl.arg.flags);
	int err;

	if (!bsz_out && (flags | FUSE_IOCTL_RETRY)) {
		err = -ENOSYS;
		goto out;
	}
	if ((bsz_in < bsz_in_min) || (bsz_in > bsz_in_max)) {
		err = -EINVAL;
		goto out;
	}
	if (bsz_out < bsz_out_min) {
		err = -EINVAL;
		goto out;
	}
	opc->opc_ioc_cmd = SILOFS_FS_IOC_CLONE;
	opc->opc_in.clone.ino = ino;
	opc->opc_in.clone.flags = 0;
	err = fuseq_exec_op(fqw->fq, opc);
	if (err) {
		goto out;
	}
	uuid_of(&opc->opc_out.clone.bsecs, 0, &clone_out->uuid_new);
	uuid_of(&opc->opc_out.clone.bsecs, 1, &clone_out->uuid_alt);
out:
	return fuseq_reply_ioctl(fqw, 0, clone_out, sizeof(*clone_out), err);
}

static int fuseq_check_ioctl_flags(struct silofs_fuseq_worker *fqw,
                                   const struct silofs_fuseq_in *in)
{
	const int flags = (int)(in->u.ioctl.arg.flags);

	if (flags & FUSE_IOCTL_COMPAT) {
		return -ENOSYS;
	}
	if ((flags & FUSE_IOCTL_DIR) && (flags & FUSE_IOCTL_UNRESTRICTED)) {
		return -ENOTTY;
	}
	unused(fqw);
	return 0;
}

static int fuseq_check_ioctl_in_size(struct silofs_fuseq_worker *fqw,
                                     const struct silofs_fuseq_in *in)
{
	const size_t in_size = in->u.ioctl.arg.in_size;
	const size_t bsz_max = fuseq_bufsize_max(fqw->fq);

	return (in_size < bsz_max) ? 0 : -EINVAL;
}

static int do_ioctl(struct silofs_fuseq_worker *fqw, ino_t ino,
                    const struct silofs_fuseq_in *in)
{
	long cmd;
	int err;
	int ret;

	err = fuseq_check_ioctl_flags(fqw, in);
	if (err) {
		ret = fuseq_reply_err(fqw, err);
		goto out;
	}
	err = fuseq_check_ioctl_in_size(fqw, in);
	if (err) {
		ret = fuseq_reply_err(fqw, err);
		goto out;
	}
	cmd = (long)(in->u.ioctl.arg.cmd);
	switch (cmd) {
	case FS_IOC_GETFLAGS:
		ret = do_ioc_getflags(fqw, ino, in);
		break;
	case SILOFS_FS_IOC_QUERY:
		ret = do_ioc_query(fqw, ino, in);
		break;
	case SILOFS_FS_IOC_CLONE:
		ret = do_ioc_clone(fqw, ino, in);
		break;
	default:
		ret = do_ioc_notimpl(fqw, ino, in);
		break;
	}
out:
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define FUSEQ_CMD(opcode_, hook_, rtime_) \
	[opcode_] = { hook_, SILOFS_STR(opcode_), opcode_, rtime_ }

static const struct silofs_fuseq_cmd fuseq_cmd_tbl[] = {
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
	FUSEQ_CMD(FUSE_GETLK, NULL, 0),
	FUSEQ_CMD(FUSE_SETLKW, NULL, 0),
	FUSEQ_CMD(FUSE_ACCESS, do_access, 0),
	FUSEQ_CMD(FUSE_CREATE, do_create, 1),
	FUSEQ_CMD(FUSE_INTERRUPT, NULL, 0),
	FUSEQ_CMD(FUSE_BMAP, NULL, 0),
	FUSEQ_CMD(FUSE_DESTROY, do_destroy, 1),
	FUSEQ_CMD(FUSE_IOCTL, do_ioctl, 1),
	FUSEQ_CMD(FUSE_POLL, NULL, 0),
	FUSEQ_CMD(FUSE_NOTIFY_REPLY, NULL, 0),
	FUSEQ_CMD(FUSE_BATCH_FORGET, do_batch_forget, 0),
	FUSEQ_CMD(FUSE_FALLOCATE, do_fallocate, 1),
	FUSEQ_CMD(FUSE_READDIRPLUS, do_readdirplus, 0),
	FUSEQ_CMD(FUSE_RENAME2, do_rename2, 1),
	FUSEQ_CMD(FUSE_LSEEK, do_lseek, 0),
	FUSEQ_CMD(FUSE_COPY_FILE_RANGE, do_copy_file_range, 1),
	FUSEQ_CMD(FUSE_SETUPMAPPING, NULL, 0),
	FUSEQ_CMD(FUSE_REMOVEMAPPING, NULL, 0),
	FUSEQ_CMD(FUSE_SYNCFS, do_syncfs, 1),
#if SILOFS_FUSE_STATX
	FUSEQ_CMD(FUSE_STATX, do_statx, 0),
#endif
};

static const struct silofs_fuseq_cmd *cmd_of(unsigned int opc)
{
	const struct silofs_fuseq_cmd *cmd = NULL;

	if (opc && (opc < ARRAY_SIZE(fuseq_cmd_tbl))) {
		cmd = &fuseq_cmd_tbl[opc];
	}
	return cmd;
}

static int fuseq_resolve_cmd(struct silofs_fuseq_worker *fqw, unsigned int opc)
{
	const struct silofs_fuseq_cmd *cmd = cmd_of(opc);

	if ((cmd == NULL) || (cmd->hook == NULL)) {
		/* TODO: handle cases of FUSE_INTERUPT properly */
		return -ENOSYS;
	}
	if (!fqw->fq->fq_got_init && (cmd->code != FUSE_INIT)) {
		return -EIO;
	}
	if (fqw->fq->fq_got_init && (cmd->code == FUSE_INIT)) {
		return -EIO;
	}
	fqw->cmd = cmd;
	return 0;
}

static int fuseq_check_perm(const struct silofs_fuseq_worker *fqw, uid_t opuid)
{
	const struct silofs_task *task = NULL;

	if (!fqw->fq->fq_deny_others) {
		return 0;
	}
	if ((opuid == 0) || (opuid == fqw->fq->fq_fs_owner)) {
		return 0;
	}

	task = task_of(fqw);
	switch (task->t_oper.op_code) {
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

static void fuseq_assign_curr_oper(struct silofs_fuseq_worker *fqw,
                                   const struct fuse_in_header *hdr)
{
	struct silofs_task *fsc = task_of(fqw);

	fsc->t_uber = fqw->fq->fq_uber;
	fsc->t_oper.op_creds.xcred.uid = (uid_t)(hdr->uid);
	fsc->t_oper.op_creds.xcred.gid = (gid_t)(hdr->gid);
	fsc->t_oper.op_creds.xcred.pid = (pid_t)(hdr->pid);
	fsc->t_oper.op_creds.xcred.umask = 0;
	fsc->t_oper.op_unique = hdr->unique;
	fsc->t_oper.op_code = (int)hdr->opcode;
	fsc->t_interrupt = 0;
}

static int fuseq_assign_curr_xtime(struct silofs_fuseq_worker *fqw)
{
	struct silofs_task *task = task_of(fqw);
	struct silofs_creds *creds = &task->t_oper.op_creds;
	const bool is_realtime = (fqw->cmd->realtime > 0);

	return silofs_ts_gettime(&creds->ts, is_realtime);
}

static struct silofs_fuseq_in *
fuseq_in_of(const struct silofs_fuseq_worker *fqw)
{
	const struct silofs_fuseq_in *in = &fqw->inb->u.in;

	return unconst(in);
}

static int fuseq_process_hdr(struct silofs_fuseq_worker *fqw)
{
	int err;
	const struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	const struct fuse_in_header *hdr = &in->u.hdr.hdr;

	fuseq_assign_curr_oper(fqw, hdr);
	err = fuseq_resolve_cmd(fqw, hdr->opcode);
	if (err) {
		return err;
	}
	err = fuseq_check_perm(fqw, hdr->uid);
	if (err) {
		return err;
	}
	err = fuseq_assign_curr_xtime(fqw);
	if (err) {
		return err;
	}
	return 0;
}

static void fuseq_enq_active_op(struct silofs_fuseq_worker *fqw)
{
	struct silofs_fuseq_workset *fq_ws = &fqw->fq->fq_ws;
	struct silofs_task *task = task_of(fqw);

	fuseq_lock_op(fqw->fq);
	listq_push_front(&fq_ws->fws_curropsq, &fqw->lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fqw->fq);
}

static void fuseq_dec_active_op(struct silofs_fuseq_worker *fqw)
{
	struct silofs_fuseq_workset *fq_ws = &fqw->fq->fq_ws;
	struct silofs_task *task = task_of(fqw);

	fuseq_lock_op(fqw->fq);
	listq_remove(&fq_ws->fws_curropsq, &fqw->lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fqw->fq);
}

static struct silofs_fuseq_worker *fuseq_worker_of(struct silofs_list_head *lh)
{
	return container_of(lh, struct silofs_fuseq_worker, lh);
}

static void fuseq_interrupt_op(struct silofs_fuseq_worker *fqw, uint64_t unq)
{
	struct silofs_list_head *itr;
	const struct silofs_listq *lsq;
	struct silofs_fuseq_worker *fqw_other;

	fuseq_lock_op(fqw->fq);
	lsq = &fqw->fq->fq_ws.fws_curropsq;
	itr = lsq->ls.next;
	while (itr != &lsq->ls) {
		fqw_other = fuseq_worker_of(itr);
		if (fqw_other->opc->opc_task.t_oper.op_unique == unq) {
			fqw_other->opc->opc_task.t_interrupt++;
			break;
		}
		itr = itr->next;
	}
	fuseq_unlock_op(fqw->fq);

	/*
	 * TODO-0026: Re-anble FUSEINTERRUPT hook
	 *
	 * Current impl is buggy; for example, it breaks postgresql unit-test.
	 * Need to read carefully Kernel side code and see what can be done.
	 * Also, try to understand what the warding in kernel's Documentation
	 * in fuse.rst:#interrupting-filesystem-operations
	 */
	silofs_unused(do_interrupt);
}

static int fuseq_call_oper(struct silofs_fuseq_worker *fqw)
{
	int err;
	const struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	const unsigned long nodeid = in->u.hdr.hdr.nodeid;

	fuseq_enq_active_op(fqw);
	err = fqw->cmd->hook(fqw, (ino_t)nodeid, in);
	fuseq_dec_active_op(fqw);
	return err;
}

static int fuseq_exec_request(struct silofs_fuseq_worker *fqw)
{
	int err;

	err = fuseq_process_hdr(fqw);
	if (err) {
		err = fuseq_reply_err(fqw, err);
	} else {
		fqw->fq->fq_nopers++;
		fqw->fq->fq_times = silofs_time_now();
		err = fuseq_call_oper(fqw);
	}
	return err;
}

static void fuseq_reset_inhdr(struct silofs_fuseq_worker *fqw)
{
	struct silofs_fuseq_in *in = fuseq_in_of(fqw);

	memset(&in->u.hdr, 0, sizeof(in->u.hdr));
}

static int fuseq_check_inhdr(const struct silofs_fuseq_worker *fqw,
                             size_t nrd, bool full)
{
	const struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	const struct silofs_fuseq_hdr_in *hdr = &in->u.hdr;
	const size_t len = hdr->hdr.len;
	const size_t len_min = sizeof(*hdr);
	const size_t len_max = fqw->fq->fq_coni.max_inlen;
	const int opc = (int)hdr->hdr.opcode;

	if (nrd < len_min) {
		fuseq_log_err("illegal in-length: "\
		              "nrd=%lu len_min=%lu ", nrd, len_min);
		return -EPROTO;
	}
	if (len > len_max) {
		fuseq_log_err("illegal header: opc=%d len=%lu len_max=%lu",
		              opc, len, len_max);
		return -EPROTO;
	}
	if (full && (len != nrd)) {
		fuseq_log_err("header length mismatch: "\
		              "opc=%d nrd=%lu len=%lu ", opc, nrd, len);
		return -EIO;
	}
	return 0;
}

static int fuseq_check_pipe_pre(const struct silofs_fuseq_worker *fqw)
{
	const struct silofs_pipe *pipe = &fqw->piper.pipe;
	const size_t buffsize = fqw->fq->fq_coni.buffsize;

	if (buffsize != pipe->size) {
		fuseq_log_err("pipe-fuse mismatch: pipesize=%lu buffsize=%lu ",
		              pipe->size, buffsize);
		return -EIO;
	}
	if (pipe->pend != 0) {
		fuseq_log_err("pipe not empty: pend=%lu fuse_fd=%d",
		              pipe->pend, fqw->fq->fq_fuse_fd);
		return -EIO;
	}
	return 0;
}

static int fuseq_wait_request(const struct silofs_fuseq_worker *fqw)
{
	const int fuse_fd = fqw->fq->fq_fuse_fd;

	return silofs_sys_pollin_rfd(fuse_fd, 100 /* millisec */);
}

static int fuseq_recv_buf(const struct silofs_fuseq_worker *fqw,
                          void *buf, size_t cnt, size_t *out_sz)
{
	const int fuse_fd = fqw->fq->fq_fuse_fd;

	*out_sz = 0;
	return cnt ? silofs_sys_read(fuse_fd, buf, cnt, out_sz) : 0;
}

static int fuseq_recv_in_all(struct silofs_fuseq_worker *fqw, size_t *out_sz)
{
	struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	const size_t cnt = min(sizeof(*in), fqw->fq->fq_coni.max_inlen);

	return fuseq_recv_buf(fqw, in, cnt, out_sz);
}

static int fuseq_recv_copy_in(struct silofs_fuseq_worker *fqw)
{
	size_t len = 0;
	int err;

	err = fuseq_recv_in_all(fqw, &len);
	if (err == -ETIMEDOUT) {
		return err;
	}
	if (err) {
		fuseq_log_err("read fuse-to-buff failed: fuse_fd=%d err=%d",
		              fqw->fq->fq_fuse_fd, err);
		return err;
	}
	if (len < sizeof(struct fuse_in_header)) {
		fuseq_log_err("fuse read-in too-short: len=%lu", len);
		return -EIO;
	}
	return fuseq_check_inhdr(fqw, len, true);
}

static int fuseq_splice_into_pipe(struct silofs_fuseq_worker *fqw, size_t cnt)
{
	struct silofs_pipe *pipe = &fqw->piper.pipe;
	const int fuse_fd = fqw->fq->fq_fuse_fd;
	int err;

	silofs_assert_eq(pipe->pend, 0);
	silofs_assert_gt(cnt, 0);
	silofs_assert_le(cnt, pipe->size);

	err = silofs_pipe_splice_from_fd(pipe, fuse_fd,
	                                 NULL, cnt, FUSEQ_SPLICE_FLAGS);
	if (err) {
		fuseq_log_err("fuse splice-in failed: "
		              "fuse_fd=%d cnt=%lu err=%d", fuse_fd, cnt, err);
	}
	return err;
}

static int fuseq_copy_from_pipe_in(struct silofs_fuseq_worker *fqw,
                                   size_t head_sz, size_t cnt, size_t *out_ncp)
{
	struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	struct silofs_pipe *pipe = &fqw->piper.pipe;
	const size_t pre = pipe->pend;
	int err;

	err = silofs_pipe_copy_to_buf(pipe, tail_of(in, head_sz), cnt);
	if (err) {
		return err;
	}
	*out_ncp = pre - pipe->pend;
	return 0;
}

static bool fuseq_has_long_write_in(const struct silofs_fuseq_worker *fqw)
{
	const struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	const int opc = (int)in->u.hdr.hdr.opcode;

	return (opc == FUSE_WRITE) && (in->u.write.arg.size > FUSEQ_IOBUF_MAX);
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
static int fuseq_recv_splice_in(struct silofs_fuseq_worker *fqw)
{
	return fuseq_splice_into_pipe(fqw, fqw->fq->fq_coni.buffsize);
}

static int fuseq_copy_pipe_in(struct silofs_fuseq_worker *fqw)
{
	struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	struct silofs_fuseq_hdr_in *hdr_in = &in->u.hdr;
	const size_t nsp = fqw->piper.pipe.pend;
	const size_t cnt = min(sizeof(in->u.write), nsp);
	size_t ncp1 = 0;
	size_t ncp2 = 0;
	size_t rem;
	int err;

	err = fuseq_copy_from_pipe_in(fqw, 0, cnt, &ncp1);
	if (err) {
		return err;
	}
	rem = (size_t)hdr_in->hdr.len - ncp1;
	err = fuseq_check_inhdr(fqw, ncp1, rem == 0);
	if (err) {
		return err;
	}
	if (!rem || fuseq_has_long_write_in(fqw)) {
		return 0;
	}
	err = fuseq_copy_from_pipe_in(fqw, ncp1, rem, &ncp2);
	if (err) {
		return err;
	}
	err = fuseq_check_inhdr(fqw, ncp1 + ncp2, true);
	if (err) {
		return err;
	}
	return 0;
}

static bool fuseq_is_active(const struct silofs_fuseq *fq)
{
	return (fq->fq_active > 0) || (fq->fq_ws.fws_curropsq.sz > 0);
}

static bool fuseq_cap_splice_in(const struct silofs_fuseq_worker *fqw)
{
	return fuseq_cap_splice_read(fqw->fq);
}

static int fuseq_do_recv_in(struct silofs_fuseq_worker *fqw, bool *out_spliced)
{
	int err;

	if (!fuseq_is_active(fqw->fq)) {
		return -SILOFS_ENORX;
	}
	err = fuseq_wait_request(fqw);
	if (err) {
		return err;
	}
	if (!fuseq_cap_splice_in(fqw)) {
		return fuseq_recv_copy_in(fqw);
	}
	*out_spliced = true;
	return fuseq_recv_splice_in(fqw);
}

static int fuseq_recv_in_locked(struct silofs_fuseq_worker *fqw)
{
	int err = -SILOFS_ENORX;
	bool spliced = false;

	fuseq_lock_ch(fqw->fq);
	err = fuseq_do_recv_in(fqw, &spliced);
	if (err == -EINVAL) {
		fuseq_log_err("unexpected input error: fuse_fd=%d " \
		              "err=%d", fqw->fq->fq_fuse_fd, err);
		fqw->fq->fq_active = 0;
	} else if (err == -ENODEV) {
		/* umount case: set non-active under channel-lock */
		fuseq_log_err("input status: err=%d", err);
		fqw->fq->fq_active = 0;
	}
	fuseq_unlock_ch(fqw->fq);

	if (!err && spliced) {
		err = fuseq_copy_pipe_in(fqw);
	}
	return err;
}

static int fuseq_read_or_splice_request(struct silofs_fuseq_worker *fqw)
{
	int err;

	err = fuseq_check_pipe_pre(fqw);
	if (err) {
		return err;
	}
	err = fuseq_recv_in_locked(fqw);
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
		/* Filesystem unmounted, or connection aborted */
		fuseq_log_info("fuse connection aborted: err=%d", err);
		return err;
	}
	if (err) {
		fuseq_log_err("fuse recv-request: err=%d", err);
		return err;
	}
	return 0;
}

static int fuseq_prep_request(struct silofs_fuseq_worker *fqw)
{
	fuseq_reset_inhdr(fqw);
	return silofs_piper_dispose(&fqw->piper);
}

static int fuseq_recv_request(struct silofs_fuseq_worker *fqw)
{
	int err;

	err = fuseq_prep_request(fqw);
	if (err) {
		return err;
	}
	err = fuseq_read_or_splice_request(fqw);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *iob_new(struct silofs_alloc *alloc, size_t len)
{
	void *iob;
	const size_t bk_size = SILOFS_BK_SIZE;

	silofs_assert_le(len, 2 * SILOFS_MEGA);
	silofs_assert_ge(len, SILOFS_BK_SIZE);

	iob = silofs_allocate(alloc, len);
	if (iob != NULL) {
		silofs_memzero(iob, min(len, bk_size));
	}
	return iob;
}

static void iob_del(struct silofs_alloc *alloc, void *iob, size_t len)
{
	const size_t bk_size = SILOFS_BK_SIZE;

	silofs_assert_le(len, 2 * SILOFS_MEGA);
	silofs_assert_ge(len, SILOFS_BK_SIZE);

	silofs_memffff(iob, min(len, min(len, bk_size)));
	silofs_deallocate(alloc, iob, len);
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

static void outb_del(struct silofs_fuseq_outb *outb,
                     struct silofs_alloc *alloc)
{
	iob_del(alloc, outb, sizeof(*outb));
}

static struct silofs_fuseq_rw_iter *rwi_new(struct silofs_alloc *alloc)
{
	struct silofs_fuseq_rw_iter *rwi;

	rwi = silofs_allocate(alloc, sizeof(*rwi));
	if (rwi != NULL) {
		silofs_memzero(rwi, sizeof(*rwi));
	}
	return rwi;
}

static void rwi_del(struct silofs_fuseq_rw_iter *rwi,
                    struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, rwi, sizeof(*rwi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t fuseq_bufsize_max(const struct silofs_fuseq *fq)
{
	const struct silofs_fuseq_worker *fqw = &fq->fq_ws.fws_workers[0];
	const size_t inbuf_max = sizeof(*fqw->inb);
	const size_t outbuf_max = sizeof(*fqw->outb);

	unused(fqw); /* make clangscan happy */
	return max(inbuf_max, outbuf_max);
}

static int fuseq_init_conn_info(struct silofs_fuseq *fq)
{
	const struct silofs_fuseq_workset *fws = &fq->fq_ws;
	const size_t nworkers_max = fws->fws_nlimit;
	size_t pipe_size;
	size_t buff_size;
	size_t rdwr_size;
	size_t bufsize_max;
	size_t page_size;

	page_size = (size_t)silofs_sc_page_size();
	bufsize_max = fuseq_bufsize_max(fq);
	pipe_size = silofs_pipe_size_of(bufsize_max);
	buff_size = min(pipe_size, bufsize_max);
	if (buff_size < FUSE_MIN_READ_BUFFER) {
		fuseq_log_err("buffer too small: buff_size=%lu", buff_size);
		return -EPROTO;
	}
	rdwr_size = buff_size - page_size;

	fq->fq_coni.pagesize = page_size;
	fq->fq_coni.buffsize = buff_size;
	fq->fq_coni.max_write = rdwr_size;
	fq->fq_coni.max_read = rdwr_size;
	fq->fq_coni.max_readahead = rdwr_size;
	fq->fq_coni.max_background = nworkers_max; /* XXX is it? */
	fq->fq_coni.congestion_threshold = 2 * nworkers_max;
	fq->fq_coni.time_gran = 1;
	fq->fq_coni.max_inlen = buff_size;
	return 0;
}

static int fuseq_init_piper(struct silofs_fuseq_worker *fqw, size_t pipe_size)
{
	return silofs_piper_init(&fqw->piper, pipe_size);
}

static void fuseq_fini_piper(struct silofs_fuseq_worker *fqw)
{
	silofs_piper_fini(&fqw->piper);
}

static int fuseq_init_bufs(struct silofs_fuseq_worker *fqw)
{
	struct silofs_alloc *alloc = fqw->fq->fq_alloc;

	fqw->inb = inb_new(alloc);
	if (fqw->inb == NULL) {
		return -ENOMEM;
	}
	fqw->outb = outb_new(alloc);
	if (fqw->outb == NULL) {
		inb_del(fqw->inb, alloc);
		fqw->inb = NULL;
		return -ENOMEM;
	}
	return 0;
}

static void fuseq_fini_bufs(struct silofs_fuseq_worker *fqw)
{
	struct silofs_alloc *alloc = fqw->fq->fq_alloc;

	if (fqw->outb != NULL) {
		outb_del(fqw->outb, alloc);
		fqw->outb = NULL;
	}
	if (fqw->inb != NULL) {
		inb_del(fqw->inb, alloc);
		fqw->inb = NULL;
	}
}

static int fuseq_init_rwi(struct silofs_fuseq_worker *fqw)
{
	fqw->rwi = rwi_new(fqw->fq->fq_alloc);
	return (fqw->rwi != NULL) ? 0 : -ENOMEM;
}

static void fuseq_fini_rwi(struct silofs_fuseq_worker *fqw)
{
	if (fqw->rwi != NULL) {
		rwi_del(fqw->rwi, fqw->fq->fq_alloc);
		fqw->rwi = NULL;
	}
}

static int fuseq_init_opc(struct silofs_fuseq_worker *fqw)
{
	struct silofs_alloc *alloc = fqw->fq->fq_alloc;
	struct silofs_oper_ctx *opc = NULL;

	opc = silofs_allocate(alloc, sizeof(*opc));
	if (opc == NULL) {
		return -ENOMEM;
	}
	silofs_memzero(opc, sizeof(*opc));
	fqw->opc = opc;
	return 0;
}

static void fuseq_fini_opc(struct silofs_fuseq_worker *fqw)
{
	struct silofs_alloc *alloc = fqw->fq->fq_alloc;
	struct silofs_oper_ctx *opc = fqw->opc;

	if (opc != NULL) {
		silofs_memffff(opc, sizeof(*opc));
		silofs_deallocate(alloc, opc, sizeof(*opc));
		fqw->opc = NULL;
	}
}

static int fuseq_init_worker(struct silofs_fuseq_worker *fqw,
                             struct silofs_fuseq *fq, unsigned int idx)
{
	int err;
	const size_t pipe_size_want = fq->fq_coni.buffsize;

	STATICASSERT_LE(sizeof(*fqw), 256);

	list_head_init(&fqw->lh);
	fqw->fq  = fq;
	fqw->cmd = NULL;
	fqw->inb = NULL;
	fqw->outb = NULL;
	fqw->worker_index = idx;

	err = fuseq_init_bufs(fqw);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_rwi(fqw);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_opc(fqw);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_piper(fqw, pipe_size_want);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	fuseq_fini_piper(fqw);
	fuseq_fini_opc(fqw);
	fuseq_fini_rwi(fqw);
	fuseq_fini_bufs(fqw);
	return err;
}

static void fuseq_fini_worker(struct silofs_fuseq_worker *fqw)
{
	list_head_fini(&fqw->lh);
	fuseq_fini_piper(fqw);
	fuseq_fini_opc(fqw);
	fuseq_fini_rwi(fqw);
	fuseq_fini_bufs(fqw);
	fqw->cmd = NULL;
	fqw->fq  = NULL;
}

static int32_t clamp32(int32_t x, int32_t x_min, int32_t x_max)
{
	return silofs_max32(silofs_min32(x, x_max), x_min);
}

static int fuseq_init_workers_limit(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_workset *fws = &fq->fq_ws;
	const int nprocs = (int)silofs_sc_nproc_onln();
	const int nlimit = clamp32(nprocs, 1, 16);

	if (nprocs <= 0) {
		fuseq_log_err("nprocs=%d", nprocs);
		return -ENOMEDIUM;
	}
	fws->fws_nlimit = (unsigned int)nlimit;
	fws->fws_navail = 0;
	fws->fws_nactive = 0;
	return 0;
}

static int fuseq_init_workers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_workset *fws = &fq->fq_ws;
	size_t mem_size;
	int err;

	listq_init(&fws->fws_curropsq);
	mem_size = fws->fws_nlimit * sizeof(*fws->fws_workers);
	fws->fws_workers = silofs_allocate(fq->fq_alloc, mem_size);
	if (fws->fws_workers == NULL) {
		return -ENOMEM;
	}
	for (unsigned int i = 0; i < fws->fws_nlimit; ++i) {
		err = fuseq_init_worker(&fws->fws_workers[i], fq, i);
		if (err) {
			return err;
		}
		fws->fws_navail++;
	}
	return 0;
}

static void fuseq_fini_workers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_workset *fws = &fq->fq_ws;
	size_t mem_size;

	if (fws->fws_workers != NULL) {
		for (size_t i = 0; i < fws->fws_navail; ++i) {
			fuseq_fini_worker(&fws->fws_workers[i]);
		}
		mem_size = fws->fws_nlimit * sizeof(*fws->fws_workers);
		silofs_deallocate(fq->fq_alloc, fws->fws_workers, mem_size);
		fws->fws_workers = NULL;
		fws->fws_nlimit = 0;
		listq_fini(&fws->fws_curropsq);
	}
}

static int fuseq_init_locks(struct silofs_fuseq *fq)
{
	int err;

	err = silofs_mutex_init(&fq->fq_ch_lock);
	if (err) {
		return err;
	}
	err = silofs_mutex_init(&fq->fq_op_lock);
	if (err) {
		silofs_mutex_fini(&fq->fq_ch_lock);
		return err;
	}
	fq->fq_init_locks = true;
	return 0;
}

static void fuseq_fini_locks(struct silofs_fuseq *fq)
{
	if (fq->fq_init_locks) {
		silofs_mutex_fini(&fq->fq_op_lock);
		silofs_mutex_fini(&fq->fq_ch_lock);
	}
}

static void fuseq_init_common(struct silofs_fuseq *fq,
                              struct silofs_alloc *alloc)
{
	fq->fq_times = 0;
	fq->fq_uber = NULL;
	fq->fq_alloc = alloc;
	fq->fq_active = 0;
	fq->fq_nopers = 0;
	fq->fq_fuse_fd = -1;
	fq->fq_got_init = false;
	fq->fq_reply_init_ok = false;
	fq->fq_got_destroy = false;
	fq->fq_deny_others = false;
	fq->fq_mount = false;
	fq->fq_umount = false;
	fq->fq_writeback_cache = false;
	fq->fq_fs_owner = (uid_t)(-1);
}

int silofs_fuseq_init(struct silofs_fuseq *fq, struct silofs_alloc *alloc)
{
	int err;

	silofs_memzero(fq, sizeof(*fq));
	fuseq_init_common(fq, alloc);

	err = fuseq_init_workers_limit(fq);
	if (err) {
		return err;
	}
	err = fuseq_init_conn_info(fq);
	if (err) {
		return err;
	}
	err = fuseq_init_locks(fq);
	if (err) {
		goto out;
	}
	err = fuseq_init_workers(fq);
	if (err) {
		goto out;
	}
out:
	if (err) {
		fuseq_fini_workers(fq);
		fuseq_fini_locks(fq);
	}
	return err;
}

static void fuseq_fini_fuse_fd(struct silofs_fuseq *fq)
{
	if (fq->fq_fuse_fd > 0) {
		silofs_sys_close(fq->fq_fuse_fd);
		fq->fq_fuse_fd = -1;
	}
}

void silofs_fuseq_fini(struct silofs_fuseq *fq)
{
	fuseq_fini_fuse_fd(fq);
	fuseq_fini_workers(fq);
	fuseq_fini_locks(fq);
	fq->fq_alloc = NULL;
	fq->fq_uber = NULL;
}

int silofs_fuseq_mount(struct silofs_fuseq *fq,
                       struct silofs_fs_uber *uber, const char *path)
{
	const size_t max_read = fq->fq_coni.buffsize;
	const char *sock = SILOFS_MNTSOCK_NAME;
	struct silofs_sb_info *sbi = uber->ub_sbi;
	uint64_t ms_flags;
	uid_t uid;
	gid_t gid;
	int fd = -1;
	int err;
	bool allow_other;

	uid = sbi->sb_owner.uid;
	gid = sbi->sb_owner.gid;
	ms_flags = sbi->sb_ms_flags;
	allow_other = (sbi->sb_ctl_flags & SILOFS_SBCF_ALLOWOTHER) > 0;

	err = silofs_mntrpc_handshake(uid, gid);
	if (err) {
		fuseq_log_err("handshake with mountd failed: "\
		              "sock=@%s err=%d", sock, err);
		return err;
	}
	err = silofs_mntrpc_mount(path, uid, gid, max_read,
	                          ms_flags, allow_other, false, &fd);
	if (err) {
		fuseq_log_err("mount failed: path=%s max_read=%lu "\
		              "ms_flags=0x%lx allow_other=%d err=%d", path,
		              max_read, ms_flags, (int)allow_other, err);
		return err;
	}
	sbi->sb_ctl_flags |= SILOFS_SBCF_NLOOKUP;

	fq->fq_fs_owner = sbi->sb_owner.uid;
	fq->fq_fuse_fd = fd;
	fq->fq_mount = true;
	fq->fq_uber = uber;

	/* TODO: Looks like kernel needs time. why? */
	sleep(1);

	return 0;
}

void silofs_fuseq_term(struct silofs_fuseq *fq)
{
	fuseq_fini_fuse_fd(fq);
	fq->fq_uber = NULL;
}

static int fuseq_check_input(const struct silofs_fuseq_worker *fqw)
{
	const struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	const uint32_t in_len = in->u.hdr.hdr.len;
	const uint32_t opcode = in->u.hdr.hdr.opcode;

	if (!in_len || !opcode) {
		fuseq_log_warn("bad fuse input: in_len=%u opcode=%u",
		               in_len, opcode);
		return -SILOFS_ENORX;
	}
	return 0;
}

static int fuseq_exec_one(struct silofs_fuseq_worker *fqw)
{
	int err;

	if (!fuseq_is_active(fqw->fq)) {
		return -SILOFS_ENORX;
	}
	err = fuseq_recv_request(fqw);
	if (err) {
		return err;
	}
	err = fuseq_check_input(fqw);
	if (err) {
		return err;
	}
	err = fuseq_exec_request(fqw);
	if (err == -ENOENT) {
		/* probably due to FR_ABORTED on FUSE side (ENOENT means the
		 * operation was interrupted). */
		return -SILOFS_ENOTX;
	}
	if (err) {
		return err;
	}
	return 0;
}

static int fuseq_timeout_flags(const struct silofs_fuseq_worker *fqw)
{
	const time_t now = silofs_time_now();
	const time_t dif = labs(now - fqw->fq->fq_times);
	int flags = 0;

	if (dif > 10) {
		flags |= SILOFS_F_TIMEOUT;
	}
	if (dif > 30) {
		flags |= SILOFS_F_IDLE;
	}
	return flags;
}

static int fuseq_do_timeout(const struct silofs_fuseq_worker *fqw)
{
	int flags;
	int err;

	if (!fuseq_is_normal(fqw->fq)) {
		return 0;
	}
	flags = fuseq_timeout_flags(fqw);
	if (!flags) {
		return 0;
	}
	err = silofs_fs_timedout(task_self(fqw), flags);
	if (err) {
		fuseq_log_warn("timeout failure: err=%d", err);
		return err;
	}
	return 0;
}

static bool fuseq_all_workers_active(const struct silofs_fuseq_worker *fqw)
{
	return (fqw->fq->fq_ws.fws_nactive == fqw->fq->fq_ws.fws_navail);
}

static void fuseq_suspend(const struct silofs_fuseq_worker *fqw)
{
	/* TODO: tweak sleep based on state */
	silofs_unused(fqw);
	sleep(1);
}

static bool fuseq_allow_exec(const struct silofs_fuseq_worker *fqw)
{
	/* bootstrap case-1: not all worker-threads to started */
	if (!fuseq_all_workers_active(fqw)) {
		return false;
	}
	/* bootstrap case-2: only worker-0 may operate */
	if (fqw->worker_index && !fuseq_is_normal(fqw->fq)) {
		return false;
	}
	return true;
}

static int fuseq_sub_exec_loop(struct silofs_fuseq_worker *fqw)
{
	int err = 0;

	while (!err && fuseq_is_active(fqw->fq)) {
		/* allow only single worker on bootstrap */
		if (!fuseq_allow_exec(fqw)) {
			fuseq_suspend(fqw);
			continue;
		}
		/* serve single in-comming request */
		err = fuseq_exec_one(fqw);

		/* timeout case */
		if (err == -ETIMEDOUT) {
			fuseq_do_timeout(fqw);
			err = 0;
			continue;
		}
		/* umount case */
		if (err == -ENODEV) {
			fqw->fq->fq_active = 0; /* umount case */
			break;
		}
		/* no-lock & interrupt cases */
		if ((err == -SILOFS_ENORX) || (err == -SILOFS_ENOTX)) {
			fuseq_suspend(fqw);
			err = 0;
		}

		/* XXX FIXME */
		if (err == -ENOENT) {
			fuseq_log_err("unexpected fuseq-status: err=%d", err);
			fuseq_suspend(fqw);
			err = 0;
		}
	}
	return err;
}

static struct silofs_fuseq_worker *
thread_to_fuseq_worker(struct silofs_thread *th)
{
	return container_of(th, struct silofs_fuseq_worker, th);
}

static int fuseq_start(struct silofs_thread *th)
{
	struct silofs_fuseq_worker *fqw = thread_to_fuseq_worker(th);
	int err;

	fuseq_log_info("exec worker: %s", th->name);
	err = silofs_thread_sigblock_common();
	if (err) {
		fuseq_log_warn("unable to block signals: "\
		               "%s err=%d", th->name, err);
		goto out;
	}
	err = fuseq_sub_exec_loop(fqw);
	if (err) {
		fuseq_log_info("exec-loop completed: %s", th->name);
		goto out;
	}
out:
	fuseq_log_info("done worker: %s", th->name);
	return err;
}

static int fuseq_exec_thread(struct silofs_fuseq_worker *fqw)
{
	char name[32] = "";
	int err;

	snprintf(name, sizeof(name) - 1, "silofs-%u", fqw->worker_index + 1);
	err = silofs_thread_create(&fqw->th, fuseq_start, NULL, name);
	if (err) {
		fuseq_log_err("failed to create fuse worker: "\
		              "%s err=%d", name, err);
	}
	return err;
}

static int fuseq_join_thread(struct silofs_fuseq_worker *fqw)
{
	return silofs_thread_join(&fqw->th);
}

static void fuseq_suspend_while_active(const struct silofs_fuseq *fq)
{
	while (fuseq_is_active(fq)) {
		sleep(1);
	}
}

static int fuseq_start_workers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_workset *fws = &fq->fq_ws;
	int err;

	fuseq_log_info("start workers: nworkers=%d", fws->fws_navail);
	fq->fq_active = 1;
	fws->fws_nactive = 0;
	for (size_t i = 0; i < fws->fws_navail; ++i) {
		err = fuseq_exec_thread(&fws->fws_workers[i]);
		if (err) {
			return err;
		}
		fws->fws_nactive++;
	}
	return 0;
}

static void fuseq_finish_workers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_workset *fws = &fq->fq_ws;

	fuseq_log_info("finish workers: nworkers=%d", fws->fws_nactive);
	fq->fq_active = 0;
	for (size_t i = 0; i < fws->fws_nactive; ++i) {
		fuseq_join_thread(&fws->fws_workers[i]);
	}
}

int silofs_fuseq_exec(struct silofs_fuseq *fq)
{
	int err;

	fuseq_log_info("exec: nprocs=%ld", silofs_sc_nproc_onln());
	err = fuseq_start_workers(fq);
	if (!err) {
		fuseq_suspend_while_active(fq);
	}
	fuseq_finish_workers(fq);
	fuseq_log_info("done: nprocs=%ld", silofs_sc_nproc_onln());
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fuseq_lock_ch(struct silofs_fuseq *fq)
{
	silofs_mutex_lock(&fq->fq_ch_lock);
}

static void fuseq_unlock_ch(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_ch_lock);
}

static void fuseq_lock_fs(struct silofs_fuseq *fq)
{
	silofs_mutex_lock(&fq->fq_uber->ub_fs_lock);
}

static void fuseq_unlock_fs(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_uber->ub_fs_lock);
}

static void fuseq_lock_op(struct silofs_fuseq *fq)
{
	silofs_mutex_lock(&fq->fq_op_lock);
}

static void fuseq_unlock_op(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_op_lock);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/


typedef int (*silofs_opc_fn)(struct silofs_oper_ctx *);

static struct silofs_task *opc_task(struct silofs_oper_ctx *opc)
{
	return &opc->opc_task;
}

static int opc_setattr(struct silofs_oper_ctx *opc)
{
	struct silofs_task *task = opc_task(opc);
	const struct stat *tms = &opc->opc_in.setattr.tims;
	struct stat *out_st = &opc->opc_out.setattr.st;
	loff_t size;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	ino_t ino;
	int err;

	ino = opc->opc_in.setattr.ino;
	err = silofs_fs_getattr(task, ino, out_st);
	if (!err && opc->opc_in.setattr.set_amtime_now) {
		err = silofs_fs_utimens(task, ino, tms, out_st);
	}
	if (!err && opc->opc_in.setattr.set_mode) {
		mode = opc->opc_in.setattr.mode;
		err = silofs_fs_chmod(task, ino, mode, tms, out_st);
	}
	if (!err && opc->opc_in.setattr.set_uid_gid) {
		uid = opc->opc_in.setattr.uid;
		gid = opc->opc_in.setattr.gid;
		err = silofs_fs_chown(task, ino, uid, gid, tms, out_st);
	}
	if (!err && opc->opc_in.setattr.set_size) {
		size = opc->opc_in.setattr.size;
		err = silofs_fs_truncate(task, ino, size, out_st);
	}
	if (!err && opc->opc_in.setattr.set_amctime &&
	    !opc->opc_in.setattr.set_nontime) {
		err = silofs_fs_utimens(task, ino, tms, out_st);
	}
	return err;
}

static int opc_lookup(struct silofs_oper_ctx *opc)
{
	return silofs_fs_lookup(opc_task(opc),
	                        opc->opc_in.lookup.parent,
	                        opc->opc_in.lookup.name,
	                        &opc->opc_out.lookup.st);
}

static int opc_forget(struct silofs_oper_ctx *opc)
{
	return silofs_fs_forget(opc_task(opc),
	                        opc->opc_in.forget.ino,
	                        opc->opc_in.forget.nlookup);
}

static int opc_forget_one(struct silofs_oper_ctx *opc,
                          const struct fuse_forget_one *one)
{
	return silofs_fs_forget(opc_task(opc),
	                        (ino_t)(one->nodeid), one->nlookup);
}

static int opc_batch_forget(struct silofs_oper_ctx *opc)
{
	int err;

	for (size_t i = 0; i < opc->opc_in.batch_forget.count; ++i) {
		err = opc_forget_one(opc, &opc->opc_in.batch_forget.one[i]);
		unused(err);
	}
	return 0;
}

static int opc_getattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_getattr(opc_task(opc),
	                         opc->opc_in.getattr.ino,
	                         &opc->opc_out.getattr.st);
}

static int opc_readlink(struct silofs_oper_ctx *opc)
{
	return silofs_fs_readlink(opc_task(opc),
	                          opc->opc_in.readlink.ino,
	                          opc->opc_in.readlink.ptr,
	                          opc->opc_in.readlink.lim,
	                          &opc->opc_out.readlink.len);
}

static int opc_symlink(struct silofs_oper_ctx *opc)
{
	return silofs_fs_symlink(opc_task(opc),
	                         opc->opc_in.symlink.parent,
	                         opc->opc_in.symlink.name,
	                         opc->opc_in.symlink.symval,
	                         &opc->opc_out.symlink.st);
}

static int opc_mknod(struct silofs_oper_ctx *opc)
{
	return silofs_fs_mknod(opc_task(opc),
	                       opc->opc_in.mknod.parent,
	                       opc->opc_in.mknod.name,
	                       opc->opc_in.mknod.mode,
	                       opc->opc_in.mknod.rdev,
	                       &opc->opc_out.mknod.st);
}

static int opc_mkdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_mkdir(opc_task(opc),
	                       opc->opc_in.mkdir.parent,
	                       opc->opc_in.mkdir.name,
	                       opc->opc_in.mkdir.mode,
	                       &opc->opc_out.mkdir.st);
}

static int opc_unlink(struct silofs_oper_ctx *opc)
{
	return silofs_fs_unlink(opc_task(opc),
	                        opc->opc_in.unlink.parent,
	                        opc->opc_in.unlink.name);
}

static int opc_rmdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_rmdir(opc_task(opc),
	                       opc->opc_in.rmdir.parent,
	                       opc->opc_in.rmdir.name);
}

static int opc_rename(struct silofs_oper_ctx *opc)
{
	return silofs_fs_rename(opc_task(opc),
	                        opc->opc_in.rename.parent,
	                        opc->opc_in.rename.name,
	                        opc->opc_in.rename.newparent,
	                        opc->opc_in.rename.newname,
	                        opc->opc_in.rename.flags);
}

static int opc_link(struct silofs_oper_ctx *opc)
{
	return silofs_fs_link(opc_task(opc),
	                      opc->opc_in.link.ino,
	                      opc->opc_in.link.parent,
	                      opc->opc_in.link.name,
	                      &opc->opc_out.link.st);
}

static int opc_open(struct silofs_oper_ctx *opc)
{
	return silofs_fs_open(opc_task(opc),
	                      opc->opc_in.open.ino,
	                      opc->opc_in.open.o_flags);
}

static int opc_statfs(struct silofs_oper_ctx *opc)
{
	return silofs_fs_statfs(opc_task(opc),
	                        opc->opc_in.statfs.ino,
	                        &opc->opc_out.statfs.stv);
}

static int opc_release(struct silofs_oper_ctx *opc)
{
	return silofs_fs_release(opc_task(opc),
	                         opc->opc_in.release.ino,
	                         opc->opc_in.release.o_flags,
	                         opc->opc_in.release.flush);
}

static int opc_fsync(struct silofs_oper_ctx *opc)
{
	return silofs_fs_fsync(opc_task(opc),
	                       opc->opc_in.fsync.ino,
	                       opc->opc_in.fsync.datasync);
}

static int opc_setxattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_setxattr(opc_task(opc),
	                          opc->opc_in.setxattr.ino,
	                          opc->opc_in.setxattr.name,
	                          opc->opc_in.setxattr.value,
	                          opc->opc_in.setxattr.size,
	                          opc->opc_in.setxattr.flags,
	                          opc->opc_in.setxattr.kill_sgid);
}

static int opc_getxattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_getxattr(opc_task(opc),
	                          opc->opc_in.getxattr.ino,
	                          opc->opc_in.getxattr.name,
	                          opc->opc_in.getxattr.buf,
	                          opc->opc_in.getxattr.size,
	                          &opc->opc_out.getxattr.size);
}

static int opc_listxattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_listxattr(opc_task(opc),
	                           opc->opc_in.listxattr.ino,
	                           opc->opc_in.listxattr.lxa_ctx);
}

static int opc_removexattr(struct silofs_oper_ctx *opc)
{
	return silofs_fs_removexattr(opc_task(opc),
	                             opc->opc_in.removexattr.ino,
	                             opc->opc_in.removexattr.name);
}

static int opc_flush(struct silofs_oper_ctx *opc)
{
	return silofs_fs_flush(opc_task(opc), opc->opc_in.flush.ino);
}

static int opc_opendir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_opendir(opc_task(opc), opc->opc_in.opendir.ino);
}

static int opc_readdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_readdir(opc_task(opc),
	                         opc->opc_in.readdir.ino,
	                         opc->opc_in.readdir.rd_ctx);
}

static int opc_readdirplus(struct silofs_oper_ctx *opc)
{
	return silofs_fs_readdirplus(opc_task(opc),
	                             opc->opc_in.readdir.ino,
	                             opc->opc_in.readdir.rd_ctx);
}

static int opc_releasedir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_releasedir(opc_task(opc),
	                            opc->opc_in.releasedir.ino,
	                            opc->opc_in.releasedir.o_flags);
}

static int opc_fsyncdir(struct silofs_oper_ctx *opc)
{
	return silofs_fs_fsyncdir(opc_task(opc),
	                          opc->opc_in.fsyncdir.ino,
	                          opc->opc_in.fsyncdir.datasync);
}

static int opc_access(struct silofs_oper_ctx *opc)
{
	return silofs_fs_access(opc_task(opc),
	                        opc->opc_in.access.ino,
	                        opc->opc_in.access.mask);
}

static int opc_create(struct silofs_oper_ctx *opc)
{
	return silofs_fs_create(opc_task(opc),
	                        opc->opc_in.create.parent,
	                        opc->opc_in.create.name,
	                        opc->opc_in.create.o_flags,
	                        opc->opc_in.create.mode,
	                        &opc->opc_out.create.st);
}

static int opc_fallocate(struct silofs_oper_ctx *opc)
{
	return silofs_fs_fallocate(opc_task(opc),
	                           opc->opc_in.fallocate.ino,
	                           opc->opc_in.fallocate.mode,
	                           opc->opc_in.fallocate.off,
	                           opc->opc_in.fallocate.len);
}

static int opc_lseek(struct silofs_oper_ctx *opc)
{
	return silofs_fs_lseek(opc_task(opc),
	                       opc->opc_in.lseek.ino,
	                       opc->opc_in.lseek.off,
	                       opc->opc_in.lseek.whence,
	                       &opc->opc_out.lseek.off);
}

static int opc_copy_file_range(struct silofs_oper_ctx *opc)
{
	return silofs_fs_copy_file_range(opc_task(opc),
	                                 opc->opc_in.copy_file_range.ino_in,
	                                 opc->opc_in.copy_file_range.off_in,
	                                 opc->opc_in.copy_file_range.ino_out,
	                                 opc->opc_in.copy_file_range.off_out,
	                                 opc->opc_in.copy_file_range.len,
	                                 opc->opc_in.copy_file_range.flags,
	                                 &opc->opc_out.copy_file_range.ncp);
}

static int opc_read_buf(struct silofs_oper_ctx *opc)
{
	return silofs_fs_read(opc_task(opc),
	                      opc->opc_in.read.ino,
	                      opc->opc_in.read.buf,
	                      opc->opc_in.read.len,
	                      opc->opc_in.read.off,
	                      &opc->opc_out.read.nrd);
}

static int opc_read_iter(struct silofs_oper_ctx *opc)
{
	return silofs_fs_read_iter(opc_task(opc),
	                           opc->opc_in.read.ino,
	                           opc->opc_in.read.rwi_ctx);
}

static int opc_read(struct silofs_oper_ctx *opc)
{
	return (opc->opc_in.read.rwi_ctx != NULL) ?
	       opc_read_iter(opc) : opc_read_buf(opc);
}


static int opc_write_buf(struct silofs_oper_ctx *opc)
{
	return silofs_fs_write(opc_task(opc),
	                       opc->opc_in.write.ino,
	                       opc->opc_in.write.buf,
	                       opc->opc_in.write.len,
	                       opc->opc_in.write.off,
	                       &opc->opc_out.write.nwr);
}

static int opc_write_iter(struct silofs_oper_ctx *opc)
{
	return silofs_fs_write_iter(opc_task(opc),
	                            opc->opc_in.write.ino,
	                            opc->opc_in.write.rwi_ctx);
}

static int opc_write(struct silofs_oper_ctx *opc)
{
	return (opc->opc_in.write.rwi_ctx != NULL) ?
	       opc_write_iter(opc) : opc_write_buf(opc);
}

static int opc_syncfs(struct silofs_oper_ctx *opc)
{
	return silofs_fs_syncfs(opc_task(opc), opc->opc_in.syncfs.ino);
}

static int opc_ioctl_query(struct silofs_oper_ctx *opc)
{
	return silofs_fs_query(opc_task(opc),
	                       opc->opc_in.query.ino,
	                       opc->opc_in.query.qtype,
	                       &opc->opc_out.query.qry);
}

static int opc_ioctl_clone(struct silofs_oper_ctx *opc)
{
	return silofs_fs_clone(opc_task(opc),
	                       opc->opc_in.clone.ino,
	                       opc->opc_in.clone.flags,
	                       &opc->opc_out.clone.bsecs);
}

static int opc_ioctl(struct silofs_oper_ctx *opc)
{
	int ret;

	if (opc->opc_ioc_cmd == SILOFS_FS_IOC_QUERY) {
		ret = opc_ioctl_query(opc);
	} else if (opc->opc_ioc_cmd == SILOFS_FS_IOC_CLONE) {
		ret = opc_ioctl_clone(opc);
	} else {
		ret = -ENOSYS;
	}
	return ret;
}

static const silofs_opc_fn silofs_opc_tbl[] = {
	[FUSE_LOOKUP]           = opc_lookup,
	[FUSE_FORGET]           = opc_forget,
	[FUSE_GETATTR]          = opc_getattr,
	[FUSE_SETATTR]          = opc_setattr,
	[FUSE_READLINK]         = opc_readlink,
	[FUSE_SYMLINK]          = opc_symlink,
	[FUSE_MKNOD]            = opc_mknod,
	[FUSE_MKDIR]            = opc_mkdir,
	[FUSE_UNLINK]           = opc_unlink,
	[FUSE_RMDIR]            = opc_rmdir,
	[FUSE_RENAME]           = opc_rename,
	[FUSE_LINK]             = opc_link,
	[FUSE_OPEN]             = opc_open,
	[FUSE_READ]             = opc_read,
	[FUSE_WRITE]            = opc_write,
	[FUSE_STATFS]           = opc_statfs,
	[FUSE_RELEASE]          = opc_release,
	[FUSE_FSYNC]            = opc_fsync,
	[FUSE_SETXATTR]         = opc_setxattr,
	[FUSE_GETXATTR]         = opc_getxattr,
	[FUSE_LISTXATTR]        = opc_listxattr,
	[FUSE_REMOVEXATTR]      = opc_removexattr,
	[FUSE_FLUSH]            = opc_flush,
	[FUSE_OPENDIR]          = opc_opendir,
	[FUSE_READDIR]          = opc_readdir,
	[FUSE_RELEASEDIR]       = opc_releasedir,
	[FUSE_FSYNCDIR]         = opc_fsyncdir,
	[FUSE_ACCESS]           = opc_access,
	[FUSE_CREATE]           = opc_create,
	[FUSE_BATCH_FORGET]     = opc_batch_forget,
	[FUSE_FALLOCATE]        = opc_fallocate,
	[FUSE_READDIRPLUS]      = opc_readdirplus,
	[FUSE_RENAME2]          = opc_rename,
	[FUSE_LSEEK]            = opc_lseek,
	[FUSE_COPY_FILE_RANGE]  = opc_copy_file_range,
	[FUSE_SYNCFS]           = opc_syncfs,
	[FUSE_IOCTL]            = opc_ioctl,
};


static int opcode_of(const struct silofs_oper_ctx *opc)
{
	return opc->opc_task.t_oper.op_code;
}

static silofs_opc_fn hook_of(const struct silofs_oper_ctx *opc)
{
	const int opcode = opcode_of(opc);
	const size_t slot = (size_t)opcode;
	silofs_opc_fn hook = NULL;

	if (slot && (slot < ARRAY_SIZE(silofs_opc_tbl))) {
		hook = silofs_opc_tbl[slot];
	}
	return hook;
}

static int fuseq_exec_op(struct silofs_fuseq *fq, struct silofs_oper_ctx *opc)
{
	silofs_opc_fn hook = hook_of(opc);

	silofs_unused(fq);
	return likely(hook != NULL) ? hook(opc) : -ENOSYS;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define FUSEQ_HDR_IN_SIZE       (40)

#define REQUIRE_SIZEOF(type, size) \
	SILOFS_STATICASSERT(((sizeof(type) == size)) && ((size % 8) == 0))

#define REQUIRE_OFFSET(type, member, offset) \
	SILOFS_STATICASSERT_EQ(offsetof(type, member), offset)

#define REQUIRE_BASEOF(type, member) \
	REQUIRE_OFFSET(type, member, FUSEQ_HDR_IN_SIZE)

void silofs_guarantee_fuse_proto(void)
{
	REQUIRE_SIZEOF(struct fuse_setxattr1_in, FUSE_COMPAT_SETXATTR_IN_SIZE);
	REQUIRE_SIZEOF(struct silofs_fuseq_hdr_in, 40);
	REQUIRE_OFFSET(struct silofs_fuseq_hdr_in, hdr, 0);
	REQUIRE_SIZEOF(struct silofs_fuseq_init_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_init_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_setattr_in, 128);
	REQUIRE_BASEOF(struct silofs_fuseq_setattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_lookup_in, 296);
	REQUIRE_BASEOF(struct silofs_fuseq_lookup_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_forget_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_forget_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_getattr_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_getattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_symlink_in, 4392);
	REQUIRE_BASEOF(struct silofs_fuseq_symlink_in, name_target);
	REQUIRE_SIZEOF(struct silofs_fuseq_mknod_in, 312);
	REQUIRE_BASEOF(struct silofs_fuseq_mknod_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_mkdir_in, 304);
	REQUIRE_BASEOF(struct silofs_fuseq_mkdir_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_mkdir_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_unlink_in, 296);
	REQUIRE_BASEOF(struct silofs_fuseq_unlink_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_rmdir_in, 296);
	REQUIRE_BASEOF(struct silofs_fuseq_rmdir_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_rename_in, 560);
	REQUIRE_BASEOF(struct silofs_fuseq_rename_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_rename_in, name_newname, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_link_in, 304);
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
	REQUIRE_SIZEOF(struct silofs_fuseq_setxattr1_in, 4400);
	REQUIRE_BASEOF(struct silofs_fuseq_setxattr1_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_setxattr1_in, name_value, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_setxattr_in, 4408);
	REQUIRE_BASEOF(struct silofs_fuseq_setxattr_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_setxattr_in, name_value, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_getxattr_in, 304);
	REQUIRE_BASEOF(struct silofs_fuseq_getxattr_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_getxattr_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_listxattr_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_listxattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_removexattr_in, 296);
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
	REQUIRE_SIZEOF(struct silofs_fuseq_create_in, 312);
	REQUIRE_BASEOF(struct silofs_fuseq_create_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_create_in, name, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_interrupt_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_interrupt_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_interrupt_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_interrupt_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_ioctl_in, 4168);
	REQUIRE_BASEOF(struct silofs_fuseq_ioctl_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_ioctl_in, buf, 72);
	REQUIRE_SIZEOF(struct silofs_fuseq_rename2_in, 568);
	REQUIRE_BASEOF(struct silofs_fuseq_rename2_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_rename2_in, name_newname, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_lseek_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_lseek_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_read_in, 80);
	REQUIRE_BASEOF(struct silofs_fuseq_read_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_copy_file_range_in, 96);
	REQUIRE_BASEOF(struct silofs_fuseq_copy_file_range_in, arg);
}

