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

#define fuseq_log_dbg(fmt, ...)  silofs_log_debug("fuseq: " fmt, __VA_ARGS__)
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
static void fuseq_lock_op(struct silofs_fuseq *fq);
static void fuseq_unlock_op(struct silofs_fuseq *fq);
static void fuseq_lock_ctl(struct silofs_fuseq *fq);
static bool fuseq_trylock_ctl(struct silofs_fuseq *fq);
static void fuseq_unlock_ctl(struct silofs_fuseq *fq);
static void fuseq_lock_cmd(struct silofs_fuseq *fq, bool cop);
static void fuseq_unlock_cmd(struct silofs_fuseq *fq);
static void fuseq_interrupt_op(struct silofs_fuseq_worker *fqw, uint64_t unq);
static size_t fuseq_bufsize_max(const struct silofs_fuseq *fq);

static int exec_op(struct silofs_task *task, struct silofs_oper_args *args);
static const struct silofs_fuseq_cmd_desc *cmd_desc_of(unsigned int opc);

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
	uint8_t tail[SILOFS_LBK_SIZE - sizeof(struct fuse_in_header)];
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
};

struct silofs_fuseq_in {
	union silofs_fuseq_in_u u;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_fuseq_diter {
	char   buf[8 * SILOFS_UKILO];
	struct silofs_namebuf de_name;
	struct silofs_readdir_ctx rd_ctx;
	struct silofs_stat de_attr;
	size_t bsz;
	size_t len;
	size_t ndes;
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
	struct silofs_task *task;
	size_t cnt;
	size_t ncp;
	size_t nrd;
	size_t nrd_max;
};

struct silofs_fuseq_iob {
	uint8_t b[SILOFS_LBK_SIZE + SILOFS_IO_SIZE_MAX];
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

struct silofs_fuseq_cmd_ctx {
	struct silofs_fuseq_worker     *fqw;
	struct silofs_task             *task;
	struct silofs_oper_args        *args;
	const struct silofs_fuseq_in   *in;
	ino_t                           ino;
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

static void stat_to_fuse_attr(const struct silofs_stat *st,
                              struct fuse_attr *attr)
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

static void fill_fuse_entry(struct fuse_entry_out *ent,
                            const struct silofs_stat *st)
{
	memset(ent, 0, sizeof(*ent));
	ent->nodeid = st->st.st_ino;
	ent->generation = st->gen;
	ent->entry_valid = UINT_MAX;
	ent->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &ent->attr);
}

static void fill_fuse_attr(struct fuse_attr_out *attr,
                           const struct silofs_stat *st)
{
	memset(attr, 0, sizeof(*attr));
	attr->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &attr->attr);
}

static void fill_fuse_open(struct fuse_open_out *open, int noflush)
{
	memset(open, 0, sizeof(*open));
	open->open_flags = FOPEN_KEEP_CACHE | FOPEN_CACHE_DIR;
	if (noflush) {
		open->open_flags |= FOPEN_NOFLUSH;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void check_fh(const struct silofs_task *task, ino_t ino, uint64_t fh)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc;

	if (fh != 0) {
		cmd_desc = cmd_desc_of(task->t_oper.op_code);
		fuseq_log_warn("op=%s ino=%lu fh=0x%lx",
		               cmd_desc ? cmd_desc->name : "", ino, fh);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fill_out_header(struct fuse_out_header *out_hdr,
                            uint64_t unique, size_t len, int err)
{
	out_hdr->len = (uint32_t)len;
	out_hdr->error = -abs(err);
	out_hdr->unique = unique;
}

static void
fill_out_header_by(struct fuse_out_header *out_hdr,
                   const struct silofs_task *task, size_t len, int err)
{
	fill_out_header(out_hdr, task->t_oper.op_unique, len, err);
}

static int fuseq_send_msg(struct silofs_fuseq_worker *fqw,
                          const struct iovec *iov, size_t iovcnt)
{
	size_t nwr = 0;
	int fuse_fd;
	int err;

	fuse_fd = fqw->fq->fq_fuse_fd;
	err = silofs_sys_writev(fuse_fd, iov, (int)iovcnt, &nwr);
	if (err && (err != -ENOENT)) {
		fuseq_log_warn("send-to-fuse failed: fuse_fd=%d "\
		               "iovcnt=%lu err=%d", fuse_fd, iovcnt, err);
	}
	return err;
}

static int fuseq_reply_arg(struct silofs_fuseq_worker *fqw,
                           const struct silofs_task *task,
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
	fill_out_header_by(&hdr, task, hdrsz + argsz, 0);
	return fuseq_send_msg(fqw, iov, cnt);
}

static int fuseq_reply_arg2(struct silofs_fuseq_worker *fqw,
                            const struct silofs_task *task,
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

	fill_out_header_by(&hdr, task, hdrsz + argsz + bufsz, 0);
	return fuseq_send_msg(fqw, iov, 3);
}

static int fuseq_reply_buf(struct silofs_fuseq_worker *fqw,
                           const struct silofs_task *task,
                           const void *buf, size_t bsz)
{
	return fuseq_reply_arg(fqw, task, buf, bsz);
}

static int sanitize_err(int err, uint32_t opcode)
{
	int err2 = abs(err);

	if (unlikely(err2 >= SILOFS_ERRBASE2)) {
		fuseq_log_err("unexpected internal error: "
		              "err=%d op=%u", err, opcode);
		err2 = silofs_remap_status_code(err);
	} else if (err2 >= SILOFS_ERRBASE) {
		err2 = silofs_remap_status_code(err);
	}
	return err2;
}

static int fuseq_reply_err(struct silofs_fuseq_worker *fqw,
                           const struct silofs_task *task, int err)
{
	struct fuse_out_header hdr;
	struct iovec iov[1];
	const size_t hdrsz = sizeof(hdr);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsz;

	err = sanitize_err(err, task->t_oper.op_code);
	fill_out_header_by(&hdr, task, hdrsz, err);
	return fuseq_send_msg(fqw, iov, 1);
}

static int fuseq_reply_intr(struct silofs_fuseq_worker *fqw,
                            const struct silofs_task *task)
{
	return fuseq_reply_err(fqw, task, -EINTR);
}

static int fuseq_reply_status(struct silofs_fuseq_worker *fqw,
                              const struct silofs_task *task, int status)
{
	return fuseq_reply_err(fqw, task, status);
}

static int fuseq_reply_none(struct silofs_fuseq_worker *fqw)
{
	unused(fqw);
	return 0;
}

static int fuseq_reply_entry_ok(struct silofs_fuseq_worker *fqw,
                                const struct silofs_task *task,
                                const struct silofs_stat *st)
{
	struct fuse_entry_out arg;

	fill_fuse_entry(&arg, st);
	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_create_ok(struct silofs_fuseq_worker *fqw,
                                 const struct silofs_task *task,
                                 const struct silofs_stat *st)
{
	struct fuseq_create_out {
		struct fuse_entry_out ent;
		struct fuse_open_out  open;
	} silofs_packed_aligned16 arg;

	fill_fuse_entry(&arg.ent, st);
	fill_fuse_open(&arg.open, 0);
	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_attr_ok(struct silofs_fuseq_worker *fqw,
                               const struct silofs_task *task,
                               const struct silofs_stat *st)
{
	struct fuse_attr_out arg;

	fill_fuse_attr(&arg, st);
	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_statfs_ok(struct silofs_fuseq_worker *fqw,
                                 const struct silofs_task *task,
                                 const struct statvfs *stv)
{
	struct fuse_statfs_out arg;

	statfs_to_fuse_kstatfs(stv, &arg.st);
	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_buf_ok(struct silofs_fuseq_worker *fqw,
                              const struct silofs_task *task,
                              const char *buf, size_t bsz)
{
	return fuseq_reply_arg(fqw, task, buf, bsz);
}

static int fuseq_reply_readlink_ok(struct silofs_fuseq_worker *fqw,
                                   const struct silofs_task *task,
                                   const char *lnk, size_t len)
{
	return fuseq_reply_buf_ok(fqw, task, lnk, len);
}

static int fuseq_reply_open_ok(struct silofs_fuseq_worker *fqw,
                               const struct silofs_task *task, int noflush)
{
	struct fuse_open_out arg;

	fill_fuse_open(&arg, noflush);
	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_opendir_ok(struct silofs_fuseq_worker *fqw,
                                  const struct silofs_task *task)
{
	return fuseq_reply_open_ok(fqw, task, 0);
}

static int fuseq_reply_write_ok(struct silofs_fuseq_worker *fqw,
                                const struct silofs_task *task, size_t cnt)
{
	struct fuse_write_out arg = {
		.size = (uint32_t)cnt
	};

	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_lseek_ok(struct silofs_fuseq_worker *fqw,
                                const struct silofs_task *task, loff_t off)
{
	struct fuse_lseek_out arg = {
		.offset = (uint64_t)off
	};

	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_xattr_len(struct silofs_fuseq_worker *fqw,
                                 const struct silofs_task *task, size_t len)
{
	struct fuse_getxattr_out arg = {
		.size = (uint32_t)len
	};

	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_xattr_buf(struct silofs_fuseq_worker *fqw,
                                 const struct silofs_task *task,
                                 const void *buf, size_t len)
{
	return fuseq_reply_buf(fqw, task, buf, len);
}

static int fuseq_reply_init_ok(struct silofs_fuseq_worker *fqw,
                               const struct silofs_task *task,
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

	return fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
}

static int fuseq_reply_ioctl_ok(struct silofs_fuseq_worker *fqw,
                                const struct silofs_task *task, int result,
                                const void *buf, size_t size)
{
	struct fuse_ioctl_out arg;
	int ret;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;

	if (size && buf) {
		ret = fuseq_reply_arg2(fqw, task, &arg,
		                       sizeof(arg), buf, size);
	} else {
		ret = fuseq_reply_arg(fqw, task, &arg, sizeof(arg));
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool task_interrupted(const struct silofs_task *task)
{
	return unlikely(task->t_interrupt > 0);
}

static int fuseq_reply_attr(struct silofs_fuseq_worker *fqw,
                            const struct silofs_task *task,
                            const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_attr_ok(fqw, task, st);
	}
	return ret;
}

static int fuseq_reply_entry(struct silofs_fuseq_worker *fqw,
                             const struct silofs_task *task,
                             const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_entry_ok(fqw, task, st);
	}
	return ret;
}

static int fuseq_reply_create(struct silofs_fuseq_worker *fqw,
                              const struct silofs_task *task,
                              const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_create_ok(fqw, task, st);
	}
	return ret;
}

static int fuseq_reply_readlink(struct silofs_fuseq_worker *fqw,
                                const struct silofs_task *task,
                                const char *lnk, size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_readlink_ok(fqw, task, lnk, len);
	}
	return ret;
}

static int fuseq_reply_statfs(struct silofs_fuseq_worker *fqw,
                              const struct silofs_task *task,
                              const struct statvfs *stv, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_statfs_ok(fqw, task, stv);
	}
	return ret;
}

static int fuseq_reply_open(struct silofs_fuseq_worker *fqw,
                            const struct silofs_task *task,
                            int noflush, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_open_ok(fqw, task, noflush);
	}
	return ret;
}

static int fuseq_reply_xattr(struct silofs_fuseq_worker *fqw,
                             const struct silofs_task *task,
                             const void *buf, size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else if (buf == NULL) {
		ret = fuseq_reply_xattr_len(fqw, task, len);
	} else {
		ret = fuseq_reply_xattr_buf(fqw, task, buf, len);
	}
	return ret;
}

static int fuseq_reply_opendir(struct silofs_fuseq_worker *fqw,
                               const struct silofs_task *task, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_opendir_ok(fqw, task);
	}
	return ret;
}

static int fuseq_reply_readdir(struct silofs_fuseq_worker *fqw,
                               const struct silofs_task *task,
                               const struct silofs_fuseq_diter *di, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_buf(fqw, task, di->buf, di->len);
	}
	return ret;
}

static int fuseq_reply_lseek(struct silofs_fuseq_worker *fqw,
                             const struct silofs_task *task,
                             loff_t off, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_lseek_ok(fqw, task, off);
	}
	return ret;
}

static int fuseq_reply_copy_file_range(struct silofs_fuseq_worker *fqw,
                                       const struct silofs_task *task,
                                       size_t cnt, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_write_ok(fqw, task, cnt);
	}
	return ret;
}

static int fuseq_reply_init(struct silofs_fuseq_worker *fqw,
                            const struct silofs_task *task, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_init_ok(fqw, task, &fqw->fq->fq_coni);
	}
	return ret;
}

static int fuseq_reply_ioctl(struct silofs_fuseq_worker *fqw,
                             const struct silofs_task *task, int result,
                             const void *buf, size_t size, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_ioctl_ok(fqw, task, result, buf, size);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_reply_write(struct silofs_fuseq_worker *fqw,
                             const struct silofs_task *task,
                             size_t cnt, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_write_ok(fqw, task, cnt);
	}
	return ret;
}

static int fuseq_reply_read_buf(struct silofs_fuseq_worker *fqw,
                                const struct silofs_task *task,
                                const void *dat, size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
	} else {
		ret = fuseq_reply_buf_ok(fqw, task, dat, len);
	}
	return ret;
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

static int fuseq_append_hdr_to_pipe(struct silofs_fuseq_worker *fqw,
                                    const struct silofs_task *task, size_t len)
{
	struct fuse_out_header hdr;
	struct silofs_pipe *pipe = &fqw->piper.pipe;

	fill_out_header_by(&hdr, task, sizeof(hdr) + len, 0);
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
			err = -SILOFS_EINVAL;
		}
	}
	return err;
}

static int fuseq_send_pipe(struct silofs_fuseq_worker *fqw)
{
	struct silofs_pipe *pipe = &fqw->piper.pipe;

	return silofs_pipe_flush_to_fd(pipe, fqw->fq->fq_fuse_fd);
}

static int fuseq_reply_read_data(struct silofs_fuseq_worker *fqw,
                                 const struct silofs_task *task, size_t nrd,
                                 const struct silofs_iovec *iov)
{
	return fuseq_reply_arg(fqw, task, iov->iov_base, nrd);
}

static int fuseq_reply_read_iov(struct silofs_fuseq_rd_iter *fq_rdi)
{
	struct silofs_iovec iov;
	const struct silofs_iovec *itr = NULL;
	size_t cur = 0;
	int err = 0;
	int ret = 0;

	err = fuseq_append_hdr_to_pipe(fq_rdi->fqw, fq_rdi->task, fq_rdi->nrd);
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
		err = fuseq_append_data_to_pipe(fq_rdi->fqw, &iov, 1);
		if (err) {
			goto out;
		}
		fq_rdi->ncp += cur;
	}
out:
	if (err) {
		ret = fuseq_reply_err(fq_rdi->fqw, fq_rdi->task, err);
	} else {
		ret = fuseq_send_pipe(fq_rdi->fqw);
	}
	return ret ? ret : err;
}

static int fuseq_reply_read_ok(struct silofs_fuseq_rd_iter *fq_rdi)
{
	struct silofs_fuseq_worker *fqw = fq_rdi->fqw;
	struct silofs_task *task = fq_rdi->task;
	int ret;

	if ((fq_rdi->cnt <= 1) && (fq_rdi->iov[0].iov_fd < 0)) {
		ret = fuseq_reply_read_data(fqw, task,
		                            fq_rdi->nrd, fq_rdi->iov);
	} else {
		ret = fuseq_reply_read_iov(fq_rdi);
	}
	return ret;
}

static int fuseq_reply_read_iter(struct silofs_fuseq_rd_iter *fq_rdi, int err)
{
	struct silofs_fuseq_worker *fqw = fq_rdi->fqw;
	struct silofs_task *task = fq_rdi->task;
	int ret;

	if (task->t_interrupt) {
		ret = fuseq_reply_intr(fqw, task);
	} else if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, task, err);
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
                const struct silofs_stat *st, loff_t off, size_t *out_sz)
{
	size_t entlen;
	size_t entlen_padded;
	struct fuse_direntplus *fdp = buf;
	struct fuse_dirent *fde = &fdp->dirent;

	entlen = FUSE_NAME_OFFSET_DIRENTPLUS + nlen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if (entlen_padded > bsz) {
		return -SILOFS_EINVAL;
	}

	memset(&fdp->entry_out, 0, sizeof(fdp->entry_out));
	fill_fuse_entry(&fdp->entry_out, st);

	fde->ino = st->st.st_ino;
	fde->off = (uint64_t)off;
	fde->namelen = (uint32_t)nlen;
	fde->type =  IFTODT(st->st.st_mode);
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
		return -SILOFS_EINVAL;
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

static void setup_cap_want(struct silofs_fuseq_conn_info *coni, uint32_t cap)
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

static int do_init(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_conn_info *coni = &fcc->fqw->fq->fq_coni;
	const uint32_t in_major = fcc->in->u.init.arg.major;
	const uint32_t in_minor = fcc->in->u.init.arg.minor;
	const uint32_t in_flags = fcc->in->u.init.arg.flags;
	int err = 0;
	int ret;

	fuseq_log_info("init: ino=%ld version=%d.%d flags=0x%x",
	               fcc->ino, in_major, in_minor, in_flags);

	err = check_init(fcc->fqw, &fcc->in->u.init.arg);
	if (err) {
		goto out;
	}
	fcc->fqw->fq->fq_got_init = true;
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
	if (fcc->fqw->fq->fq_writeback_cache) {
		setup_cap_want(coni, FUSE_WRITEBACK_CACHE);
	}

	/*
	 * TODO-0025: Have support for ACLs
	 *
	 * Enable FUSE_POSIX_ACL (plus, "system." prefix in xattr)
	 */
	/* setup_cap_want(coni, FUSE_POSIX_ACL); */

out:
	ret = fuseq_reply_init(fcc->fqw, fcc->task, err);
	if (!err && !ret) {
		fcc->fqw->fq->fq_reply_init_ok = true;
	}
	return err ? err : ret;
}

static int do_destroy(const struct silofs_fuseq_cmd_ctx *fcc)
{
	fuseq_lock_ctl(fcc->fqw->fq);
	fcc->fqw->fq->fq_got_destroy = true;
	fcc->fqw->fq->fq_active = 0;
	fuseq_unlock_ctl(fcc->fqw->fq);

	return fuseq_reply_status(fcc->fqw, fcc->task, 0);
}

static bool fuseq_has_cap(const struct silofs_fuseq *fq, uint32_t cap_mask)
{
	const uint32_t cap_want = fq->fq_coni.cap_want;

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

static int do_exec_op(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return exec_op(fcc->task, fcc->args);
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

static int do_setattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct stat attr = { .st_size = -1 };
	const int to_set = (int)(fcc->in->u.setattr.arg.valid & FATTR_MASK);
	int err;

	silofs_memzero(&fcc->args->in.setattr, sizeof(fcc->args->in.setattr));
	fuse_setattr_to_stat(&fcc->in->u.setattr.arg, &attr);

	utimens_of(&attr, to_set, &fcc->args->in.setattr.tims);
	if (to_set & (FATTR_UID | FATTR_GID)) {
		uid_gid_of(&attr, to_set, &fcc->args->in.setattr.uid,
		           &fcc->args->in.setattr.gid);
		fcc->args->in.setattr.set_uid_gid = true;
	}
	if (to_set & FATTR_AMTIME_NOW) {
		fcc->args->in.setattr.set_amtime_now = true;
	}
	if (to_set & FATTR_MODE) {
		fcc->args->in.setattr.mode = attr.st_mode;
		fcc->args->in.setattr.set_mode = true;
	}
	if (to_set & FATTR_SIZE) {
		fcc->args->in.setattr.size = attr.st_size;
		fcc->args->in.setattr.set_size = true;
	}
	if (to_set & FATTR_AMCTIME) {
		fcc->args->in.setattr.set_amctime = true;
	}
	if (to_set & FATTR_NONTIME) {
		fcc->args->in.setattr.set_nontime = true;
	}
	fcc->args->in.setattr.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fuseq_reply_attr(fcc->fqw, fcc->task,
	                        &fcc->args->out.setattr.st, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_lookup(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.lookup.parent = fcc->ino;
	fcc->args->in.lookup.name = fcc->in->u.lookup.name;
	err = do_exec_op(fcc);
	return fuseq_reply_entry(fcc->fqw, fcc->task,
	                         &fcc->args->out.lookup.st, err);
}

static int do_forget(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.forget.ino = fcc->ino;
	fcc->args->in.forget.nlookup = fcc->in->u.forget.arg.nlookup;
	err = do_exec_op(fcc);
	unused(err);
	return fuseq_reply_none(fcc->fqw);
}

static int do_batch_forget(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.batch_forget.count = fcc->in->u.batch_forget.arg.count;
	fcc->args->in.batch_forget.one = fcc->in->u.batch_forget.one;
	err = do_exec_op(fcc);
	unused(err);
	return fuseq_reply_none(fcc->fqw);
}

static int do_getattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.getattr.arg.fh);
	fcc->args->in.getattr.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fuseq_reply_attr(fcc->fqw, fcc->task,
	                        &fcc->args->out.getattr.st, err);
}

static int do_readlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_pathbuf *pab = &fcc->fqw->outb->u.pab;
	char *lnk = pab->path;
	int err;

	fcc->args->in.readlink.ino = fcc->ino;
	fcc->args->in.readlink.ptr = lnk;
	fcc->args->in.readlink.lim = sizeof(pab->path);
	fcc->args->out.readlink.len = 0;
	err = do_exec_op(fcc);
	return fuseq_reply_readlink(fcc->fqw, fcc->task, lnk,
	                            fcc->args->out.readlink.len, err);
}

static int do_symlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.symlink.parent = fcc->ino;
	fcc->args->in.symlink.name = fcc->in->u.symlink.name_target;
	fcc->args->in.symlink.symval = after_name(fcc->args->in.symlink.name);
	err = do_exec_op(fcc);
	return fuseq_reply_entry(fcc->fqw, fcc->task,
	                         &fcc->args->out.symlink.st, err);
}

static int do_mknod(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.mknod.parent = fcc->ino;
	fcc->args->in.mknod.name = fcc->in->u.mknod.name;
	fcc->args->in.mknod.rdev = (dev_t)fcc->in->u.mknod.arg.rdev;
	fcc->args->in.mknod.mode = (mode_t)fcc->in->u.mknod.arg.mode;
	fcc->args->in.mknod.umask = (mode_t)fcc->in->u.mknod.arg.umask;
	silofs_task_set_umask(fcc->task, fcc->args->in.mknod.umask);
	err = do_exec_op(fcc);
	return fuseq_reply_entry(fcc->fqw, fcc->task,
	                         &fcc->args->out.mknod.st, err);
}

static int do_mkdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.mkdir.parent = fcc->ino;
	fcc->args->in.mkdir.name = fcc->in->u.mkdir.name;
	fcc->args->in.mkdir.mode = (mode_t)(fcc->in->u.mkdir.arg.mode);
	fcc->args->in.mkdir.mode |= S_IFDIR;
	fcc->args->in.mkdir.umask = (mode_t)fcc->in->u.mkdir.arg.umask;
	silofs_task_set_umask(fcc->task, fcc->args->in.mkdir.umask);
	err = do_exec_op(fcc);
	return fuseq_reply_entry(fcc->fqw, fcc->task,
	                         &fcc->args->out.mkdir.st, err);
}

static int do_unlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.unlink.parent = fcc->ino;
	fcc->args->in.unlink.name = fcc->in->u.unlink.name;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_rmdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.rmdir.parent = fcc->ino;
	fcc->args->in.rmdir.name = fcc->in->u.rmdir.name;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
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
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_link(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.link.ino = (ino_t)(fcc->in->u.link.arg.oldnodeid);
	fcc->args->in.link.parent = fcc->ino;
	fcc->args->in.link.name = fcc->in->u.link.name;
	err = do_exec_op(fcc);
	return fuseq_reply_entry(fcc->fqw, fcc->task,
	                         &fcc->args->out.link.st, err);
}

static int do_open(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.open.ino = fcc->ino;
	fcc->args->in.open.o_flags = (int)(fcc->in->u.open.arg.flags);
	fcc->args->in.open.noflush =
	        (fcc->args->in.open.o_flags & O_ACCMODE) == O_RDONLY;
	err = do_exec_op(fcc);
	return fuseq_reply_open(fcc->fqw, fcc->task,
	                        fcc->args->in.open.noflush, err);
}

static int do_statfs(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.statfs.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fuseq_reply_statfs(fcc->fqw, fcc->task,
	                          &fcc->args->out.statfs.stv, err);
}

static int do_release(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.release.arg.fh);
	fcc->args->in.release.ino = fcc->ino;
	fcc->args->in.release.o_flags = (int)fcc->in->u.release.arg.flags;
	fcc->args->in.release.flush =
	        (fcc->in->u.release.arg.flags & FUSE_RELEASE_FLUSH) > 0;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_fsync(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.fsync.arg.fh);
	fcc->args->in.fsync.ino = fcc->ino;
	fcc->args->in.fsync.datasync =
	        (fcc->in->u.fsync.arg.fsync_flags & 1) != 0;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
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
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
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
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_setxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return (fcc->fqw->fq->fq_coni.proto_minor <= 33) ?
	       do_setxattr1(fcc) : do_setxattr2(fcc);
}

static int do_getxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_xattrbuf *xab = &fcc->fqw->outb->u.xab;
	int err;

	fcc->args->in.getxattr.ino = fcc->ino;
	fcc->args->in.getxattr.name = fcc->in->u.getxattr.name;
	fcc->args->in.getxattr.size =
	        min(fcc->in->u.getxattr.arg.size, sizeof(xab->value));
	fcc->args->in.getxattr.buf =
	        fcc->args->in.getxattr.size ? xab->value : NULL;
	fcc->args->out.getxattr.size = 0;
	err = do_exec_op(fcc);
	return fuseq_reply_xattr(fcc->fqw, fcc->task,
	                         fcc->args->in.getxattr.buf,
	                         fcc->args->out.getxattr.size, err);
}

static int do_listxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_xiter *xit = &fcc->fqw->outb->u.xit;
	int ret;
	int err;

	xiter_prep(xit, fcc->in->u.listxattr.arg.size);
	fcc->args->in.listxattr.ino = fcc->ino;
	fcc->args->in.listxattr.lxa_ctx = &xit->lxa;
	err = do_exec_op(fcc);
	ret = fuseq_reply_xattr(fcc->fqw, fcc->task, xit->beg, xit->cnt, err);
	xiter_done(xit);
	return ret;
}

static int do_removexattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.removexattr.ino = fcc->ino;
	fcc->args->in.removexattr.name = fcc->in->u.removexattr.name;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_flush(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.flush.arg.fh);
	fcc->args->in.flush.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_opendir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	/* TODO: use OPENDIR's o_flags */
	fcc->args->in.opendir.ino = fcc->ino;
	fcc->args->in.opendir.o_flags = (int)(fcc->in->u.opendir.arg.flags);
	err = do_exec_op(fcc);
	return fuseq_reply_opendir(fcc->fqw, fcc->task, err);
}

static int do_readdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_diter *dit = &fcc->fqw->outb->u.dit;
	const size_t size = fcc->in->u.readdir.arg.size;
	const loff_t off = (loff_t)(fcc->in->u.readdir.arg.offset);
	int ret;
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 0);
	fcc->args->in.readdir.ino = fcc->ino;
	fcc->args->in.readdir.rd_ctx = &dit->rd_ctx;
	err = do_exec_op(fcc);
	ret = fuseq_reply_readdir(fcc->fqw, fcc->task, dit, err);
	diter_done(dit);
	return ret;
}

static int do_readdirplus(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_diter *dit = &fcc->fqw->outb->u.dit;
	const size_t size = fcc->in->u.readdir.arg.size;
	const loff_t off = (loff_t)(fcc->in->u.readdir.arg.offset);
	int ret;
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 1);
	fcc->args->in.readdir.ino = fcc->ino;
	fcc->args->in.readdir.rd_ctx = &dit->rd_ctx;
	err = do_exec_op(fcc);
	ret = fuseq_reply_readdir(fcc->fqw, fcc->task, dit, err);
	diter_done(dit);
	return ret;
}

static int do_releasedir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.releasedir.arg.fh);
	fcc->args->in.releasedir.ino = fcc->ino;
	fcc->args->in.releasedir.o_flags =
	        (int)(fcc->in->u.releasedir.arg.flags);
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_fsyncdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.fsyncdir.arg.fh);
	fcc->args->in.fsyncdir.ino = fcc->ino;
	fcc->args->in.fsyncdir.datasync =
	        (fcc->in->u.fsyncdir.arg.fsync_flags & 1) != 0;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_access(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.access.ino = fcc->ino;
	fcc->args->in.access.mask = (int)(fcc->in->u.access.arg.mask);
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_create(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.create.parent = fcc->ino;
	fcc->args->in.create.name = fcc->in->u.create.name;
	fcc->args->in.create.o_flags = (int)(fcc->in->u.create.arg.flags);
	fcc->args->in.create.mode = (mode_t)(fcc->in->u.create.arg.mode);
	fcc->args->in.create.umask = (mode_t)(fcc->in->u.create.arg.umask);
	silofs_task_set_umask(fcc->task, fcc->args->in.create.umask);
	err = do_exec_op(fcc);
	return fuseq_reply_create(fcc->fqw, fcc->task,
	                          &fcc->args->out.create.st, err);
}

static int do_fallocate(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.fallocate.arg.fh);
	fcc->args->in.fallocate.ino = fcc->ino;
	fcc->args->in.fallocate.mode = (int)(fcc->in->u.fallocate.arg.mode);
	fcc->args->in.fallocate.off =
	        (loff_t)(fcc->in->u.fallocate.arg.offset);
	fcc->args->in.fallocate.len =
	        (loff_t)(fcc->in->u.fallocate.arg.length);
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
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
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_lseek(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	check_fh(fcc->task, fcc->ino, fcc->in->u.lseek.arg.fh);
	fcc->args->in.lseek.ino = fcc->ino;
	fcc->args->in.lseek.off = (loff_t)(fcc->in->u.lseek.arg.offset);
	fcc->args->in.lseek.whence = (int)(fcc->in->u.lseek.arg.whence);
	fcc->args->out.lseek.off = -1;
	err = do_exec_op(fcc);
	return fuseq_reply_lseek(fcc->fqw, fcc->task,
	                         fcc->args->out.lseek.off, err);
}


static int do_copy_file_range(const struct silofs_fuseq_cmd_ctx *fcc)
{
	size_t ncp = 0;
	int err;

	check_fh(fcc->task, fcc->ino,
	         fcc->in->u.copy_file_range.arg.fh_in);
	fcc->args->in.copy_file_range.ino_in = fcc->ino;
	fcc->args->in.copy_file_range.off_in =
	        (loff_t)fcc->in->u.copy_file_range.arg.off_in;
	fcc->args->in.copy_file_range.ino_out =
	        (ino_t)fcc->in->u.copy_file_range.arg.nodeid_out;
	fcc->args->in.copy_file_range.off_out =
	        (loff_t)fcc->in->u.copy_file_range.arg.off_out;
	fcc->args->in.copy_file_range.len = fcc->in->u.copy_file_range.arg.len;
	fcc->args->in.copy_file_range.flags =
	        (int)fcc->in->u.copy_file_range.arg.flags;
	fcc->args->out.copy_file_range.ncp = 0;
	err = do_exec_op(fcc);
	ncp = fcc->args->out.copy_file_range.ncp;
	return fuseq_reply_copy_file_range(fcc->fqw, fcc->task, ncp, err);
}

static int do_syncfs(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.syncfs.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fuseq_reply_status(fcc->fqw, fcc->task, err);
}

static int do_interrupt(const struct silofs_fuseq_cmd_ctx *fcc)
{
	uint64_t unq;

	if (fcc->ino == 0) {
		unq = fcc->in->u.interrupt.arg.unique;
		fuseq_interrupt_op(fcc->fqw, unq);
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
		return -SILOFS_EINVAL;
	}
	if (!(fq_rdi->cnt < ARRAY_SIZE(fq_rdi->iov))) {
		return -SILOFS_EINVAL;
	}
	if ((fq_rdi->nrd + iov->iov_len) > fq_rdi->nrd_max) {
		return -SILOFS_EINVAL;
	}
	iovec_assign(&fq_rdi->iov[fq_rdi->cnt++], iov);
	fq_rdi->nrd += iov->iov_len;
	return 0;
}

static void fuseq_setup_rd_iter(struct silofs_fuseq_worker *fqw,
                                struct silofs_task *task,
                                struct silofs_fuseq_rd_iter *fq_rdi,
                                size_t len, loff_t off)
{
	fq_rdi->fqw = fqw;
	fq_rdi->task = task;
	fq_rdi->cnt = 0;
	fq_rdi->ncp = 0;
	fq_rdi->nrd = 0;
	fq_rdi->nrd_max = len;
	fq_rdi->rwi.len = len;
	fq_rdi->rwi.off = off;
	fq_rdi->rwi.actor = fuseq_rd_iter_actor;
}

static int do_rdwr_post(struct silofs_task *task, int wr_mode,
                        const struct silofs_iovec *iov, size_t cnt)
{
	return silofs_fs_rdwr_post(task, wr_mode, iov, cnt);
}

static int do_read_iter(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_rd_iter *fq_rdi = &fcc->fqw->rwi->u.rdi;
	size_t len;
	int ret;
	int err;

	len = min(fcc->in->u.read.arg.size, fcc->fqw->fq->fq_coni.max_read);
	fcc->args->in.read.ino = fcc->ino;
	fcc->args->in.read.buf = NULL;
	fcc->args->in.read.off = (loff_t)(fcc->in->u.read.arg.offset);
	fcc->args->in.read.len = len;
	fcc->args->in.read.rwi_ctx = &fq_rdi->rwi;
	fuseq_setup_rd_iter(fcc->fqw, fcc->task,
	                    fq_rdi, len, fcc->args->in.read.off);
	err = do_exec_op(fcc);
	ret = fuseq_reply_read_iter(fq_rdi, err);
	do_rdwr_post(fcc->task, 0, fq_rdi->iov, fq_rdi->cnt);
	return ret;
}

static int do_read_buf(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_databuf *dab = &fcc->fqw->outb->u.dab;
	size_t len;
	int err;

	len = min(fcc->in->u.read.arg.size, fcc->fqw->fq->fq_coni.max_read);
	fcc->args->in.read.ino = fcc->ino;
	fcc->args->in.read.buf = dab->buf;
	fcc->args->in.read.off = (loff_t)(fcc->in->u.read.arg.offset);
	fcc->args->in.read.len = len;
	fcc->args->in.read.rwi_ctx = NULL;
	fcc->args->out.read.nrd = 0;
	err = do_exec_op(fcc);
	return fuseq_reply_read_buf(fcc->fqw, fcc->task, dab->buf,
	                            fcc->args->out.read.nrd, err);
}

static bool fuseq_cap_splice_out(const struct silofs_fuseq_worker *fqw)
{
	return fuseq_cap_splice_write(fqw->fq);
}

static int do_read(const struct silofs_fuseq_cmd_ctx *fcc)
{
	const size_t rd_size = fcc->in->u.read.arg.size;
	int ret;

	check_fh(fcc->task, fcc->ino, fcc->in->u.read.arg.fh);

	if ((rd_size > FUSEQ_IOBUF_MAX) && fuseq_cap_splice_out(fcc->fqw)) {
		ret = do_read_iter(fcc);
	} else {
		ret = do_read_buf(fcc);
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
		err = -SILOFS_EINVAL;
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
		return -SILOFS_EINVAL;
	}
	if (iov->iov_off < 0) {
		return -SILOFS_EINVAL;
	}
	if ((iov->iov_fd < 0) && (iov->iov_base == NULL)) {
		return -SILOFS_EINVAL;
	}
	if ((fq_wri->nwr + iov->iov_len) > fq_wri->nwr_max) {
		return -SILOFS_EINVAL;
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

static int fuseq_wr_iter_async_actor(struct silofs_rwiter_ctx *rwi,
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

static bool fuseq_asyncwr_mode(const struct silofs_fuseq_worker *fqw)
{
	return (fqw->fq->fq_uber->ub_ctl_flags & SILOFS_UBF_ASYNCWR) > 0;
}

static void fuseq_setup_wr_iter(struct silofs_fuseq_worker *fqw,
                                struct silofs_fuseq_wr_iter *fq_rwi,
                                size_t len, loff_t off)
{
	fq_rwi->fqw = fqw;
	fq_rwi->nwr = 0;
	fq_rwi->cnt = 0;
	fq_rwi->ncp = 0;
	fq_rwi->nwr_max = len;
	fq_rwi->rwi.len = len;
	fq_rwi->rwi.off = off;
	fq_rwi->rwi.actor = fuseq_asyncwr_mode(fqw) ?
	                    fuseq_wr_iter_async_actor :
	                    fuseq_wr_iter_actor;
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

	check_fh(fcc->task, fcc->ino, fcc->in->u.write.arg.fh);
	fcc->args->in.write.ino = fcc->ino;
	fcc->args->in.write.buf = tail_of(fcc->in, sizeof(fcc->in->u.write));
	fcc->args->in.write.len = fcc->in->u.write.arg.size;
	fcc->args->in.write.off = (loff_t)(fcc->in->u.write.arg.offset);
	fcc->args->in.write.rwi_ctx = NULL;
	fcc->args->out.write.nwr = 0;
	err = do_exec_op(fcc);
	ret = fuseq_reply_write(fcc->fqw, fcc->task,
	                        fcc->args->out.write.nwr, err);
	return ret;
}

static int do_write_iter(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_wr_iter *fq_wri = &fcc->fqw->rwi->u.wri;
	size_t len;
	int err1 = 0;
	int err2 = 0;
	int ret = 0;

	check_fh(fcc->task, fcc->ino, fcc->in->u.write.arg.fh);
	len = min(fcc->in->u.write.arg.size, fcc->fqw->fq->fq_coni.max_write);
	fcc->args->in.write.ino = fcc->ino;
	fcc->args->in.write.buf = NULL;
	fcc->args->in.write.len = len;
	fcc->args->in.write.off = (loff_t)(fcc->in->u.write.arg.offset);
	fcc->args->in.write.rwi_ctx = &fq_wri->rwi;
	fcc->args->out.write.nwr = 0;
	fuseq_setup_wr_iter(fcc->fqw, fq_wri, len, fcc->args->in.write.off);
	err1 = do_exec_op(fcc);
	if (!err1 || (err1 == -ENOSPC)) {
		err2 = fuseq_wr_iter_copy_iov(fq_wri); /* unlocked */
	}
	do_rdwr_post(fcc->task, 1, fq_wri->iov, fq_wri->cnt);
	ret = fuseq_reply_write(fcc->fqw, fcc->task,
	                        fq_wri->nwr, err1 ? err1 : err2);
	return ret;
}

static int do_write(const struct silofs_fuseq_cmd_ctx *fcc)
{
	const size_t wsz = fcc->in->u.write.arg.size;

	return (wsz <= FUSEQ_IOBUF_MAX) ?
	       do_write_buf(fcc) : do_write_iter(fcc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

union silofs_ioc_u {
	uint8_t buf[SILOFS_IOC_SIZE_MAX];
	struct silofs_ioc_query qry;
	struct silofs_ioc_clone cl;
	struct silofs_ioc_sync  syn;
};

static int do_ioc_notimpl(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return fuseq_reply_err(fcc->fqw, fcc->task, -ENOTTY);
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
	fcc->task->t_oper.op_code = FUSE_GETATTR;
	fcc->args->in.getattr.ino = fcc->ino;
	err = do_exec_op(fcc);
	if (err) {
		goto out;
	}
	/* TODO: proper impl */
	attr = (long)(FS_NOATIME_FL);
out:
	return fuseq_reply_ioctl(fcc->fqw, fcc->task, 0,
	                         &attr, sizeof(attr), err);
}

static int do_ioc_query(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	const void *buf_in = fcc->in->u.ioctl.buf;
	const struct silofs_ioc_query *qry_in = &ioc_u.qry;
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

	if (!bsz_out && (flags | FUSE_IOCTL_RETRY)) {
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
	return fuseq_reply_ioctl(fcc->fqw, fcc->task, 0,
	                         &fcc->args->out.query.qry,
	                         sizeof(fcc->args->out.query.qry), err);
}

static void uuid_of(const struct silofs_bootsecs *bsecs,
                    size_t idx, struct silofs_uuid *out_uuid)
{
	silofs_bootsec_uuid(&bsecs->bsec[idx], out_uuid);
}

static int do_ioc_clone(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	void *buf_out = fcc->fqw->outb->u.iob.b;
	struct silofs_ioc_clone *cl_out = &ioc_u.cl;
	const size_t bsz_in_min = 1;
	const size_t bsz_in_max = sizeof(*cl_out);
	const size_t bsz_out_min = sizeof(*cl_out);
	const size_t bsz_in = fcc->in->u.ioctl.arg.in_size;
	const size_t bsz_out = fcc->in->u.ioctl.arg.out_size;
	const int flags = (int)(fcc->in->u.ioctl.arg.flags);
	int err;

	if (!bsz_out && (flags | FUSE_IOCTL_RETRY)) {
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
	fcc->args->ioc_cmd = SILOFS_IOC_CLONE;
	fcc->args->in.clone.ino = fcc->ino;
	fcc->args->in.clone.flags = 0;
	err = do_exec_op(fcc);
	if (err) {
		goto out;
	}
	uuid_of(&fcc->args->out.clone.bsecs, 0, &cl_out->uuid_new);
	uuid_of(&fcc->args->out.clone.bsecs, 1, &cl_out->uuid_alt);
	memcpy(buf_out, cl_out, sizeof(*cl_out));
out:
	return fuseq_reply_ioctl(fcc->fqw, fcc->task, 0,
	                         cl_out, sizeof(*cl_out), err);
}

static int do_ioc_sync(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	const void *buf_in = fcc->in->u.ioctl.buf;
	const size_t bsz_in = fcc->in->u.ioctl.arg.in_size;
	const size_t bsz_out = fcc->in->u.ioctl.arg.out_size;
	int err;

	if ((bsz_in < sizeof(ioc_u.syn)) || (bsz_in > sizeof(ioc_u))) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	if (bsz_out > 0) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	memcpy(&ioc_u.syn, buf_in, sizeof(ioc_u.syn));
	fcc->args->ioc_cmd = SILOFS_IOC_SYNC;
	fcc->args->in.syncfs.ino = fcc->ino;
	fcc->args->in.syncfs.flags = (int)ioc_u.syn.flags;
	err = do_exec_op(fcc);
	if (err) {
		goto out;
	}
out:
	return fuseq_reply_ioctl(fcc->fqw, fcc->task, 0, NULL, 0, err);
}


static int fuseq_check_ioctl_flags(struct silofs_fuseq_worker *fqw,
                                   const struct silofs_fuseq_in *in)
{
	const int flags = (int)(in->u.ioctl.arg.flags);

	if (flags & FUSE_IOCTL_COMPAT) {
		return -SILOFS_ENOSYS;
	}
	if ((flags & FUSE_IOCTL_DIR) && (flags & FUSE_IOCTL_UNRESTRICTED)) {
		return -SILOFS_ENOSYS;
	}
	unused(fqw);
	return 0;
}

static int fuseq_check_ioctl_in_size(struct silofs_fuseq_worker *fqw,
                                     const struct silofs_fuseq_in *in)
{
	const size_t in_size = in->u.ioctl.arg.in_size;
	const size_t bsz_max = fuseq_bufsize_max(fqw->fq);

	return (in_size < bsz_max) ? 0 : -SILOFS_EINVAL;
}

static int do_ioctl(const struct silofs_fuseq_cmd_ctx *fcc)
{
	long ioc_cmd;
	int err;
	int ret;

	err = fuseq_check_ioctl_flags(fcc->fqw, fcc->in);
	if (err) {
		ret = fuseq_reply_err(fcc->fqw, fcc->task, err);
		goto out;
	}
	err = fuseq_check_ioctl_in_size(fcc->fqw, fcc->in);
	if (err) {
		ret = fuseq_reply_err(fcc->fqw, fcc->task, err);
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
	case SILOFS_IOC_CLONE:
		ret = do_ioc_clone(fcc);
		break;
	case SILOFS_IOC_SYNC:
		ret = do_ioc_sync(fcc);
		break;
	default:
		ret = do_ioc_notimpl(fcc);
		break;
	}
out:
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define FUSEQ_CMD_MAX   (64)

#define FUSEQ_CMD(opcode_, hook_, rtime_) \
	[opcode_] = { hook_, SILOFS_STR(opcode_), opcode_, rtime_ }

static const struct silofs_fuseq_cmd_desc fuseq_cmd_tbl[FUSEQ_CMD_MAX] = {
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
};

static const struct silofs_fuseq_cmd_desc *cmd_desc_of(uint32_t opc)
{
	const struct silofs_fuseq_cmd_desc *cmd = NULL;

	STATICASSERT_EQ(ARRAY_SIZE(fuseq_cmd_tbl), FUSEQ_CMD_MAX);

	if (opc && (opc < ARRAY_SIZE(fuseq_cmd_tbl))) {
		cmd = &fuseq_cmd_tbl[opc];
	}
	return cmd;
}

static int
fuseq_check_opcode(const struct silofs_fuseq_worker *fqw, uint32_t op_code)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc = cmd_desc_of(op_code);

	if ((cmd_desc == NULL) || (cmd_desc->hook == NULL)) {
		/* TODO: handle cases of FUSE_INTERUPT properly */
		return -SILOFS_ENOSYS;
	}
	if (!fqw->fq->fq_got_init && (cmd_desc->code != FUSE_INIT)) {
		return -SILOFS_EIO;
	}
	if (fqw->fq->fq_got_init && (cmd_desc->code == FUSE_INIT)) {
		return -SILOFS_EIO;
	}
	return 0;
}

static int fuseq_check_perm(const struct silofs_fuseq_worker *fqw,
                            uid_t op_uid, uint32_t op_code)
{
	if (!fqw->fq->fq_deny_others) {
		return 0;
	}
	if ((op_uid == 0) || (op_uid == fqw->fq->fq_fs_owner)) {
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

static struct silofs_fuseq_in *
fuseq_in_of(const struct silofs_fuseq_worker *fqw)
{
	const struct silofs_fuseq_in *in = &fqw->inb->u.in;

	return unconst(in);
}

static int fuseq_setup_task(const struct silofs_fuseq_worker *fqw,
                            struct silofs_task *task)
{
	const struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	const struct fuse_in_header *hdr = &in->u.hdr.hdr;
	const pid_t pid = (pid_t)hdr->pid;
	int err;

	err = silofs_task_init(task, fqw->fq->fq_uber);
	if (!err) {
		silofs_task_set_creds(task, hdr->uid, hdr->gid, pid);
		task->t_oper.op_unique = hdr->unique;
		task->t_oper.op_code = hdr->opcode;
	}
	return err;
}

static int fuseq_setup_self_task(const struct silofs_fuseq_worker *fqw,
                                 struct silofs_task *task)
{
	const struct silofs_fs_args *args = fqw->fq->fq_uber->ub.fs_args;
	int err;

	err = silofs_task_init(task, fqw->fq->fq_uber);
	if (!err) {
		silofs_task_set_ts(task, false);
		silofs_task_set_umask(task, args->umask);
		silofs_task_set_creds(task, args->uid, args->gid, args->pid);
	}
	return err;
}

static void fuseq_update_task(const struct silofs_fuseq_worker *fqw,
                              struct silofs_task *task)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc;

	cmd_desc = cmd_desc_of(task->t_oper.op_code);
	silofs_task_set_ts(task, cmd_desc && (cmd_desc->realtime > 0));
	silofs_unused(fqw);
}

static int fuseq_finish_task(struct silofs_fuseq_worker *fqw,
                             struct silofs_task *task)
{
	int err;

	err = silofs_task_submit(task, false);
	silofs_task_fini(task);
	silofs_unused(fqw);
	return err;
}

static int fuseq_check_task(struct silofs_fuseq_worker *fqw,
                            const struct silofs_task *task)
{
	const unsigned int op_code = task->t_oper.op_code;
	const uid_t uid = task->t_oper.op_creds.xcred.uid;
	int err;

	err = fuseq_check_opcode(fqw, op_code);
	if (err) {
		return err;
	}
	err = fuseq_check_perm(fqw, uid, op_code);
	if (err) {
		return err;
	}
	return 0;
}

static void fuseq_set_time_stamp(struct silofs_fuseq_worker *fqw)
{
	fqw->fq->fq_time_stamp = silofs_time_now();
}

static time_t fuseq_dif_time_stamp(const struct silofs_fuseq_worker *fqw)
{
	return (time_t)(labs(silofs_time_now() - fqw->fq->fq_time_stamp));
}

static void fuseq_track_oper(struct silofs_fuseq_worker *fqw, bool init)
{
	fuseq_lock_ctl(fqw->fq);
	if (init) {
		fuseq_set_time_stamp(fqw);
		fqw->fq->fq_nopers++;
	} else {
		fqw->fq->fq_nopers_done++;
	}
	fuseq_unlock_ctl(fqw->fq);
}

static void fuseq_enq_active_op(struct silofs_fuseq_worker *fqw,
                                struct silofs_task *task)
{
	struct silofs_fuseq_workset *fq_ws = &fqw->fq->fq_ws;

	fuseq_lock_op(fqw->fq);
	listq_push_front(&fq_ws->fws_curropsq, &fqw->lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fqw->fq);
}

static void fuseq_dec_active_op(struct silofs_fuseq_worker *fqw,
                                struct silofs_task *task)
{
	struct silofs_fuseq_workset *fq_ws = &fqw->fq->fq_ws;

	fuseq_lock_op(fqw->fq);
	listq_remove(&fq_ws->fws_curropsq, &fqw->lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fqw->fq);
}

static void fuseq_interrupt_op(struct silofs_fuseq_worker *fqw, uint64_t unq)
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
		fuseq_lock_op(fqw->fq);
		fuseq_unlock_op(fqw->fq);
	}
	silofs_unused(do_interrupt);
}

static bool is_unicmd(const struct silofs_fuseq_cmd_ctx *fcc,
                      const struct silofs_task *task)
{
	long ioc_cmd;
	bool ret = false;

	if (task->t_oper.op_code == FUSE_IOCTL) {
		ioc_cmd = (long)(fcc->in->u.ioctl.arg.cmd);
		ret = (ioc_cmd == SILOFS_IOC_CLONE) ||
		      (ioc_cmd == SILOFS_IOC_SYNC);
	}
	return ret;
}

static int fuseq_call_oper_of(const struct silofs_fuseq_cmd_ctx *fcc,
                              const struct silofs_fuseq_cmd_desc *cd,
                              struct silofs_task *task)
{
	int ret;
	const bool uni = is_unicmd(fcc, task);

	fuseq_lock_cmd(fcc->fqw->fq, uni);
	ret = cd->hook(fcc);
	fuseq_unlock_cmd(fcc->fqw->fq);
	return ret;
}

static int fuseq_call_oper(struct silofs_fuseq_worker *fqw,
                           struct silofs_task *task)
{
	const struct silofs_fuseq_cmd_desc *cd = NULL;
	const struct silofs_fuseq_in *in = fuseq_in_of(fqw);
	struct silofs_fuseq_cmd_ctx fcc = {
		.fqw = fqw,
		.task = task,
		.args = fqw->args,
		.in = in,
		.ino = in->u.hdr.hdr.nodeid,
	};
	int err = -SILOFS_ENOSYS;

	cd = cmd_desc_of(task->t_oper.op_code);
	if (likely(cd != NULL)) {
		fuseq_enq_active_op(fqw, task);
		err = fuseq_call_oper_of(&fcc, cd, task);
		fuseq_dec_active_op(fqw, task);
	}
	return err;
}

static int fuseq_exec_request(struct silofs_fuseq_worker *fqw)
{
	struct silofs_task task;
	int err;
	int err2;

	err = fuseq_setup_task(fqw, &task);
	if (err) {
		return err;
	}
	err = fuseq_check_task(fqw, &task);
	if (err) {
		err = fuseq_reply_err(fqw, &task, err);
	} else {
		fuseq_update_task(fqw, &task);
		fuseq_track_oper(fqw, true);
		err = fuseq_call_oper(fqw, &task);
		fuseq_track_oper(fqw, false);
	}
	err2 = fuseq_finish_task(fqw, &task);
	return err ? err : err2;
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
		return -SILOFS_EPROTO;
	}
	if (len > len_max) {
		fuseq_log_err("illegal header: opc=%d len=%lu len_max=%lu",
		              opc, len, len_max);
		return -SILOFS_EPROTO;
	}
	if (full && (len != nrd)) {
		fuseq_log_err("header length mismatch: "\
		              "opc=%d nrd=%lu len=%lu ", opc, nrd, len);
		return -SILOFS_EIO;
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
		return -SILOFS_EIO;
	}
	if (pipe->pend != 0) {
		fuseq_log_err("pipe not empty: pend=%lu fuse_fd=%d",
		              pipe->pend, fqw->fq->fq_fuse_fd);
		return -SILOFS_EIO;
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
		return -SILOFS_EIO;
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
 * copy in smaller chunks, we get -SILOFS_EINVAL.
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
	int err;
	bool spliced = false;

	fuseq_lock_ch(fqw->fq);
	err = fuseq_do_recv_in(fqw, &spliced);
	if (err == -SILOFS_EINVAL) {
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
		/* unmount or connection aborted */
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
	fqw->req_count++;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *iob_new(struct silofs_alloc *alloc, size_t len)
{
	void *iob;

	silofs_assert_le(len, 2 * SILOFS_MEGA);
	silofs_assert_ge(len, SILOFS_LBK_SIZE);

	iob = silofs_allocate(alloc, len);
	return iob;
}

static void iob_del(struct silofs_alloc *alloc, void *iob, size_t len)
{
	const size_t bk_size = SILOFS_LBK_SIZE;

	silofs_assert_le(len, 2 * SILOFS_MEGA);
	silofs_assert_ge(len, SILOFS_LBK_SIZE);

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
	fq->fq_coni.time_gran = 1;
	fq->fq_coni.max_inlen = buff_size;

	/* values as defaults in libfuse:lib/fuse_lowlevel.c */
	fq->fq_coni.max_background = (1 << 16) - 1;
	fq->fq_coni.congestion_threshold = fq->fq_coni.max_background * 3 / 4;
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

static struct silofs_alloc *fuseq_alloc(const struct silofs_fuseq_worker *fqw)
{
	return fqw->fq->fq_alloc;
}

static int fuseq_init_bufs(struct silofs_fuseq_worker *fqw)
{
	struct silofs_alloc *alloc = fuseq_alloc(fqw);

	fqw->inb = inb_new(alloc);
	if (fqw->inb == NULL) {
		return -SILOFS_ENOMEM;
	}
	fqw->outb = outb_new(alloc);
	if (fqw->outb == NULL) {
		inb_del(fqw->inb, alloc);
		fqw->inb = NULL;
		return -SILOFS_ENOMEM;
	}
	return 0;
}

static void fuseq_fini_bufs(struct silofs_fuseq_worker *fqw)
{
	struct silofs_alloc *alloc = fuseq_alloc(fqw);

	if (fqw->outb != NULL) {
		outb_del(fqw->outb, alloc);
		fqw->outb = NULL;
	}
	if (fqw->inb != NULL) {
		inb_del(fqw->inb, alloc);
		fqw->inb = NULL;
	}
}

static int fuseq_renew_bufs(struct silofs_fuseq_worker *fqw)
{
	struct silofs_alloc *alloc = fuseq_alloc(fqw);
	struct silofs_fuseq_inb *inb = NULL;
	struct silofs_fuseq_outb *outb = NULL;

	inb = inb_new(alloc);
	if (inb == NULL) {
		return -SILOFS_ENOMEM;
	}
	if (fqw->inb != NULL) {
		inb_del(fqw->inb, alloc);
	}
	fqw->inb = inb;

	outb = outb_new(alloc);
	if (outb == NULL) {
		return -SILOFS_ENOMEM;
	}
	if (fqw->outb != NULL) {
		outb_del(fqw->outb, alloc);
	}
	fqw->outb = outb;
	return 0;
}

static int fuseq_init_rwi(struct silofs_fuseq_worker *fqw)
{
	fqw->rwi = rwi_new(fuseq_alloc(fqw));
	return (fqw->rwi != NULL) ? 0 : -SILOFS_ENOMEM;
}

static void fuseq_fini_rwi(struct silofs_fuseq_worker *fqw)
{
	if (fqw->rwi != NULL) {
		rwi_del(fqw->rwi, fuseq_alloc(fqw));
		fqw->rwi = NULL;
	}
}

static int fuseq_init_op_args(struct silofs_fuseq_worker *fqw)
{
	struct silofs_oper_args *op_args = NULL;

	op_args = silofs_allocate(fuseq_alloc(fqw), sizeof(*op_args));
	if (op_args == NULL) {
		return -SILOFS_ENOMEM;
	}
	silofs_memzero(op_args, sizeof(*op_args));
	fqw->args = op_args;
	return 0;
}

static void fuseq_fini_op_args(struct silofs_fuseq_worker *fqw)
{
	struct silofs_oper_args *op_args = fqw->args;

	if (op_args != NULL) {
		silofs_memffff(op_args, sizeof(*op_args));
		silofs_deallocate(fuseq_alloc(fqw), op_args, sizeof(*op_args));
		fqw->args = NULL;
	}
}

static int fuseq_init_worker(struct silofs_fuseq_worker *fqw,
                             struct silofs_fuseq *fq, unsigned int idx)
{
	const size_t pipe_size_want = fq->fq_coni.buffsize;
	int err;

	STATICASSERT_LE(sizeof(*fqw), 256);

	list_head_init(&fqw->lh);
	fqw->fq  = fq;
	fqw->inb = NULL;
	fqw->outb = NULL;
	fqw->req_count = 0;
	fqw->worker_index = idx;

	err = fuseq_init_bufs(fqw);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_rwi(fqw);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_op_args(fqw);
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
	fuseq_fini_op_args(fqw);
	fuseq_fini_rwi(fqw);
	fuseq_fini_bufs(fqw);
	return err;
}

static void fuseq_fini_worker(struct silofs_fuseq_worker *fqw)
{
	list_head_fini(&fqw->lh);
	fuseq_fini_piper(fqw);
	fuseq_fini_op_args(fqw);
	fuseq_fini_rwi(fqw);
	fuseq_fini_bufs(fqw);
	fqw->fq  = NULL;
}

static int fuseq_init_workers_limit(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_workset *fws = &fq->fq_ws;

	fws->fws_nlimit = silofs_num_worker_threads();
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
		return -SILOFS_ENOMEM;
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
		goto out_err;
	}
	err = silofs_mutex_init(&fq->fq_op_lock);
	if (err) {
		goto out_err1;
	}
	err = silofs_mutex_init(&fq->fq_ctl_lock);
	if (err) {
		goto out_err2;
	}
	err = silofs_rwlock_init(&fq->fq_cmd_lock);
	if (err) {
		goto out_err3;
	}
	fq->fq_init_locks = true;
	return 0;

out_err3:
	silofs_mutex_fini(&fq->fq_ctl_lock);
out_err2:
	silofs_mutex_fini(&fq->fq_op_lock);
out_err1:
	silofs_mutex_fini(&fq->fq_ch_lock);
out_err:
	return err;
}

static void fuseq_fini_locks(struct silofs_fuseq *fq)
{
	if (fq->fq_init_locks) {
		silofs_rwlock_fini(&fq->fq_cmd_lock);
		silofs_mutex_fini(&fq->fq_ctl_lock);
		silofs_mutex_fini(&fq->fq_op_lock);
		silofs_mutex_fini(&fq->fq_ch_lock);
	}
}

static void fuseq_init_common(struct silofs_fuseq *fq,
                              struct silofs_alloc *alloc)
{
	fq->fq_uber = NULL;
	fq->fq_alloc = alloc;
	fq->fq_active = 0;
	fq->fq_time_stamp = 0;
	fq->fq_nopers = 0;
	fq->fq_nopers_done = 0;
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
                       struct silofs_uber *uber, const char *path)
{
	const size_t max_read = fq->fq_coni.buffsize;
	const char *sock = SILOFS_MNTSOCK_NAME;
	uint64_t ms_flags;
	uid_t uid;
	gid_t gid;
	int fd = -1;
	int err;
	bool allow_other;

	uid = uber->ub_owner.uid;
	gid = uber->ub_owner.gid;
	ms_flags = uber->ub_ms_flags;
	allow_other = (uber->ub_ctl_flags & SILOFS_UBF_ALLOWOTHER) > 0;

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

	fq->fq_fs_owner = uber->ub_owner.uid;
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

static int fuseq_exec_one_request(struct silofs_fuseq_worker *fqw)
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
	time_t dif;
	int flags = 0;

	dif = fuseq_dif_time_stamp(fqw);
	if (dif > 5) {
		flags |= SILOFS_F_TIMEOUT;
	}
	if (dif > 15) {
		flags |= SILOFS_F_IDLE;
	}
	return flags;
}

static int fuseq_do_timeout_with(struct silofs_fuseq_worker *fqw, int flags)
{
	struct silofs_task task;
	int err1 = 0;
	int err2 = 0;

	err1 = fuseq_setup_self_task(fqw, &task);
	if (!err1) {
		fuseq_update_task(fqw, &task);
		err1 = silofs_fs_timedout(&task, flags);
		err2 = fuseq_finish_task(fqw, &task);
	}
	return err1 ? err1 : err2;
}

static int fuseq_do_timeout_locked(struct silofs_fuseq_worker *fqw, int flags)
{
	int err;

	if (!flags) {
		return 0;
	}
	err = fuseq_do_timeout_with(fqw, flags);
	if (err) {
		return err;
	}
	if (flags & SILOFS_F_IDLE) {
		fuseq_set_time_stamp(fqw);
	}
	return 0;
}

static bool fuseq_timeout_trylock(const struct silofs_fuseq_worker *fqw)
{
	return fuseq_is_normal(fqw->fq) && fuseq_trylock_ctl(fqw->fq);
}

static void fuseq_timeout_unlock(const struct silofs_fuseq_worker *fqw)
{
	fuseq_unlock_ctl(fqw->fq);
}

static int fuseq_do_timeout(struct silofs_fuseq_worker *fqw)
{
	int flags = 0;
	int err = 0;
	bool idle = false;

	if (fuseq_timeout_trylock(fqw)) {
		flags = fuseq_timeout_flags(fqw);
		err = fuseq_do_timeout_locked(fqw, flags);
		fuseq_timeout_unlock(fqw);
		idle = (flags & SILOFS_F_IDLE) > 0;
	}
	if (!err && idle && fqw->req_count) {
		err = fuseq_renew_bufs(fqw);
		fqw->req_count = 0;
	}
	return err;
}

static bool fuseq_all_workers_active(const struct silofs_fuseq_worker *fqw)
{
	return (fqw->fq->fq_ws.fws_nactive == fqw->fq->fq_ws.fws_navail);
}

static void fuseq_suspend(const struct silofs_fuseq_worker *fqw)
{
	/* TODO: tweak sleep based on state */
	silofs_unused(fqw);
	silofs_suspend_secs(1);
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

static int fuseq_sub_exec_once(struct silofs_fuseq_worker *fqw)
{
	int err = 0;

	/* allow only single worker on bootstrap */
	if (!fuseq_allow_exec(fqw)) {
		fuseq_suspend(fqw);
		return 0;
	}
	/* serve single in-comming request */
	err = fuseq_exec_one_request(fqw);

	/* timeout case */
	if (err == -ETIMEDOUT) {
		fuseq_do_timeout(fqw);
		return 0;
	}
	/* no-lock & interrupt cases */
	if ((err == -SILOFS_ENORX) || (err == -SILOFS_ENOTX)) {
		fuseq_suspend(fqw);
		return 0;
	}

	/* umount case */
	if (err == -ENODEV) {
		fqw->fq->fq_active = 0; /* umount case */
		fuseq_log_info("umount fuseq-status: err=%d", err);
	} else if (err == -ENOENT) {
		fuseq_log_err("unexpected fuseq-status: err=%d", err);
		fuseq_suspend(fqw);
	}
	return err;
}

static int fuseq_sub_exec_loop(struct silofs_fuseq_worker *fqw)
{
	int err = 0;

	while (fuseq_is_active(fqw->fq) && !err) {
		err = fuseq_sub_exec_once(fqw);
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

	fuseq_log_info("start fuseq worker: %s", th->name);
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
	fuseq_log_info("finish fuseq worker: %s", th->name);
	return err;
}

static void fuseq_make_thread_name(const struct silofs_fuseq_worker *fqw,
                                   char *name_buf, size_t name_bsz)
{
	snprintf(name_buf, name_bsz, "silofs-worker%u", fqw->worker_index + 1);
}

static int fuseq_exec_thread(struct silofs_fuseq_worker *fqw)
{
	char name[32] = "";
	int err;

	fuseq_make_thread_name(fqw, name, sizeof(name) - 1);
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

	fuseq_log_dbg("start workers: nworkers=%d", fws->fws_navail);
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

	fuseq_log_dbg("finish workers: nworkers=%d", fws->fws_nactive);
	fq->fq_active = 0;
	for (size_t i = 0; i < fws->fws_nactive; ++i) {
		fuseq_join_thread(&fws->fws_workers[i]);
	}
}

int silofs_fuseq_exec(struct silofs_fuseq *fq)
{
	int err;

	err = fuseq_start_workers(fq);
	if (!err) {
		fuseq_suspend_while_active(fq);
	}
	fuseq_finish_workers(fq);
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

static bool fuseq_trylock_ctl(struct silofs_fuseq *fq)
{
	return silofs_mutex_trylock(&fq->fq_ctl_lock);
}

static void fuseq_unlock_ctl(struct silofs_fuseq *fq)
{
	silofs_mutex_unlock(&fq->fq_ctl_lock);
}

static void fuseq_lock_cmd(struct silofs_fuseq *fq, bool unicmd)
{
	if (unicmd) {
		silofs_rwlock_wrlock(&fq->fq_cmd_lock);
	} else {
		silofs_rwlock_rdlock(&fq->fq_cmd_lock);
	}
}

static void fuseq_unlock_cmd(struct silofs_fuseq *fq)
{
	silofs_rwlock_unlock(&fq->fq_cmd_lock);
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/


typedef int (*silofs_oper_fn)(struct silofs_task *, struct silofs_oper_args *);

static int op_setattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	const struct stat *tms = &args->in.setattr.tims;
	struct silofs_stat *out_st = &args->out.setattr.st;
	loff_t size;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	ino_t ino;
	int err;

	ino = args->in.setattr.ino;
	err = silofs_fs_getattr(task, ino, out_st);
	if (!err && args->in.setattr.set_amtime_now) {
		err = silofs_fs_utimens(task, ino, tms, out_st);
	}
	if (!err && args->in.setattr.set_mode) {
		mode = args->in.setattr.mode;
		err = silofs_fs_chmod(task, ino, mode, tms, out_st);
	}
	if (!err && args->in.setattr.set_uid_gid) {
		uid = args->in.setattr.uid;
		gid = args->in.setattr.gid;
		err = silofs_fs_chown(task, ino, uid, gid, tms, out_st);
	}
	if (!err && args->in.setattr.set_size) {
		size = args->in.setattr.size;
		err = silofs_fs_truncate(task, ino, size, out_st);
	}
	if (!err && args->in.setattr.set_amctime &&
	    !args->in.setattr.set_nontime) {
		err = silofs_fs_utimens(task, ino, tms, out_st);
	}
	return err;
}

static int op_lookup(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_lookup(task,
	                        args->in.lookup.parent,
	                        args->in.lookup.name,
	                        &args->out.lookup.st);
}

static int op_forget(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_forget(task,
	                        args->in.forget.ino,
	                        args->in.forget.nlookup);
}

static int op_forget_one(struct silofs_task *task,
                         const struct fuse_forget_one *one)
{
	return silofs_fs_forget(task, (ino_t)(one->nodeid), one->nlookup);
}

static int op_batch_forget(struct silofs_task *task,
                           struct silofs_oper_args *args)
{
	const struct fuse_forget_one *one;
	int err;

	for (size_t i = 0; i < args->in.batch_forget.count; ++i) {
		one = &args->in.batch_forget.one[i];
		err = op_forget_one(task, one);
		unused(err);
	}
	return 0;
}

static int op_getattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_getattr(task,
	                         args->in.getattr.ino,
	                         &args->out.getattr.st);
}

static int op_readlink(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_readlink(task,
	                          args->in.readlink.ino,
	                          args->in.readlink.ptr,
	                          args->in.readlink.lim,
	                          &args->out.readlink.len);
}

static int op_symlink(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_symlink(task,
	                         args->in.symlink.parent,
	                         args->in.symlink.name,
	                         args->in.symlink.symval,
	                         &args->out.symlink.st);
}

static int op_mknod(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_mknod(task,
	                       args->in.mknod.parent,
	                       args->in.mknod.name,
	                       args->in.mknod.mode,
	                       args->in.mknod.rdev,
	                       &args->out.mknod.st);
}

static int op_mkdir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_mkdir(task,
	                       args->in.mkdir.parent,
	                       args->in.mkdir.name,
	                       args->in.mkdir.mode,
	                       &args->out.mkdir.st);
}

static int op_unlink(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_unlink(task,
	                        args->in.unlink.parent,
	                        args->in.unlink.name);
}

static int op_rmdir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_rmdir(task,
	                       args->in.rmdir.parent,
	                       args->in.rmdir.name);
}

static int op_rename(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_rename(task,
	                        args->in.rename.parent,
	                        args->in.rename.name,
	                        args->in.rename.newparent,
	                        args->in.rename.newname,
	                        args->in.rename.flags);
}

static int op_link(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_link(task,
	                      args->in.link.ino,
	                      args->in.link.parent,
	                      args->in.link.name,
	                      &args->out.link.st);
}

static int op_open(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_open(task,
	                      args->in.open.ino,
	                      args->in.open.o_flags);
}

static int op_statfs(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_statfs(task,
	                        args->in.statfs.ino,
	                        &args->out.statfs.stv);
}

static int op_release(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_release(task,
	                         args->in.release.ino,
	                         args->in.release.o_flags,
	                         args->in.release.flush);
}

static int op_fsync(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_fsync(task,
	                       args->in.fsync.ino,
	                       args->in.fsync.datasync);
}

static int op_setxattr(struct silofs_task *task,
                       struct silofs_oper_args *args)
{
	return silofs_fs_setxattr(task,
	                          args->in.setxattr.ino,
	                          args->in.setxattr.name,
	                          args->in.setxattr.value,
	                          args->in.setxattr.size,
	                          args->in.setxattr.flags,
	                          args->in.setxattr.kill_sgid);
}

static int op_getxattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_getxattr(task,
	                          args->in.getxattr.ino,
	                          args->in.getxattr.name,
	                          args->in.getxattr.buf,
	                          args->in.getxattr.size,
	                          &args->out.getxattr.size);
}

static int op_listxattr(struct silofs_task *task,
                        struct silofs_oper_args *args)
{
	return silofs_fs_listxattr(task,
	                           args->in.listxattr.ino,
	                           args->in.listxattr.lxa_ctx);
}

static int op_removexattr(struct silofs_task *task,
                          struct silofs_oper_args *args)
{
	return silofs_fs_removexattr(task,
	                             args->in.removexattr.ino,
	                             args->in.removexattr.name);
}

static int op_flush(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_flush(task, args->in.flush.ino,
	                       args->in.flush.ino == 0);
}

static int op_opendir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_opendir(task, args->in.opendir.ino);
}

static int op_readdir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_readdir(task,
	                         args->in.readdir.ino,
	                         args->in.readdir.rd_ctx);
}

static int op_readdirplus(struct silofs_task *task,
                          struct silofs_oper_args *args)
{
	return silofs_fs_readdirplus(task,
	                             args->in.readdir.ino,
	                             args->in.readdir.rd_ctx);
}

static int op_releasedir(struct silofs_task *task,
                         struct silofs_oper_args *args)
{
	return silofs_fs_releasedir(task,
	                            args->in.releasedir.ino,
	                            args->in.releasedir.o_flags);
}

static int op_fsyncdir(struct silofs_task *task,
                       struct silofs_oper_args *args)
{
	return silofs_fs_fsyncdir(task,
	                          args->in.fsyncdir.ino,
	                          args->in.fsyncdir.datasync);
}

static int op_access(struct silofs_task *task,
                     struct silofs_oper_args *args)
{
	return silofs_fs_access(task,
	                        args->in.access.ino,
	                        args->in.access.mask);
}

static int op_create(struct silofs_task *task,
                     struct silofs_oper_args *args)
{
	return silofs_fs_create(task,
	                        args->in.create.parent,
	                        args->in.create.name,
	                        args->in.create.o_flags,
	                        args->in.create.mode,
	                        &args->out.create.st);
}

static int op_fallocate(struct silofs_task *task,
                        struct silofs_oper_args *args)
{
	return silofs_fs_fallocate(task,
	                           args->in.fallocate.ino,
	                           args->in.fallocate.mode,
	                           args->in.fallocate.off,
	                           args->in.fallocate.len);
}

static int op_lseek(struct silofs_task *task,
                    struct silofs_oper_args *args)
{
	return silofs_fs_lseek(task,
	                       args->in.lseek.ino,
	                       args->in.lseek.off,
	                       args->in.lseek.whence,
	                       &args->out.lseek.off);
}

static int op_copy_file_range(struct silofs_task *task,
                              struct silofs_oper_args *args)
{
	return silofs_fs_copy_file_range(task,
	                                 args->in.copy_file_range.ino_in,
	                                 args->in.copy_file_range.off_in,
	                                 args->in.copy_file_range.ino_out,
	                                 args->in.copy_file_range.off_out,
	                                 args->in.copy_file_range.len,
	                                 args->in.copy_file_range.flags,
	                                 &args->out.copy_file_range.ncp);
}

static int op_read_buf(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_read(task,
	                      args->in.read.ino,
	                      args->in.read.buf,
	                      args->in.read.len,
	                      args->in.read.off,
	                      &args->out.read.nrd);
}

static int op_read_iter(struct silofs_task *task,
                        struct silofs_oper_args *args)
{
	return silofs_fs_read_iter(task,
	                           args->in.read.ino,
	                           args->in.read.rwi_ctx);
}

static int op_read(struct silofs_task *task, struct silofs_oper_args *args)
{
	return (args->in.read.rwi_ctx != NULL) ?
	       op_read_iter(task, args) : op_read_buf(task, args);
}


static int op_write_buf(struct silofs_task *task,
                        struct silofs_oper_args *args)
{
	return silofs_fs_write(task,
	                       args->in.write.ino,
	                       args->in.write.buf,
	                       args->in.write.len,
	                       args->in.write.off,
	                       &args->out.write.nwr);
}

static int op_write_iter(struct silofs_task *task,
                         struct silofs_oper_args *args)
{
	return silofs_fs_write_iter(task,
	                            args->in.write.ino,
	                            args->in.write.rwi_ctx);
}

static int op_write(struct silofs_task *task, struct silofs_oper_args *args)
{
	return (args->in.write.rwi_ctx != NULL) ?
	       op_write_iter(task, args) : op_write_buf(task, args);
}

static int op_syncfs(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_syncfs(task,
	                        args->in.syncfs.ino,
	                        args->in.syncfs.flags);
}

static int op_ioctl_query(struct silofs_task *task,
                          struct silofs_oper_args *args)
{
	return silofs_fs_query(task,
	                       args->in.query.ino,
	                       args->in.query.qtype,
	                       &args->out.query.qry);
}

static int op_ioctl_clone(struct silofs_task *task,
                          struct silofs_oper_args *args)
{
	return silofs_fs_clone(task,
	                       args->in.clone.ino,
	                       args->in.clone.flags,
	                       &args->out.clone.bsecs);
}

static int op_ioctl_sync(struct silofs_task *task,
                         struct silofs_oper_args *args)
{
	/*
	 * Currently (Linux kernel v6.3) fuse has 'fc->sync_fs = true' only for
	 * fs/fuse/virtio_fs.c code-path. Thus, implement full sync-fs via
	 * dedicated ioctl.
	 */
	return op_syncfs(task, args);
}

static int op_ioctl(struct silofs_task *task,
                    struct silofs_oper_args *args)
{
	int ret;

	switch (args->ioc_cmd) {
	case SILOFS_IOC_QUERY:
		ret = op_ioctl_query(task, args);
		break;
	case SILOFS_IOC_CLONE:
		ret = op_ioctl_clone(task, args);
		break;
	case SILOFS_IOC_SYNC:
		ret = op_ioctl_sync(task, args);
		break;
	default:
		ret = -SILOFS_ENOSYS;
		break;
	}
	return ret;
}

static const silofs_oper_fn silofs_op_tbl[FUSEQ_CMD_MAX] = {
	[FUSE_LOOKUP]           = op_lookup,
	[FUSE_FORGET]           = op_forget,
	[FUSE_GETATTR]          = op_getattr,
	[FUSE_SETATTR]          = op_setattr,
	[FUSE_READLINK]         = op_readlink,
	[FUSE_SYMLINK]          = op_symlink,
	[FUSE_MKNOD]            = op_mknod,
	[FUSE_MKDIR]            = op_mkdir,
	[FUSE_UNLINK]           = op_unlink,
	[FUSE_RMDIR]            = op_rmdir,
	[FUSE_RENAME]           = op_rename,
	[FUSE_LINK]             = op_link,
	[FUSE_OPEN]             = op_open,
	[FUSE_READ]             = op_read,
	[FUSE_WRITE]            = op_write,
	[FUSE_STATFS]           = op_statfs,
	[FUSE_RELEASE]          = op_release,
	[FUSE_FSYNC]            = op_fsync,
	[FUSE_SETXATTR]         = op_setxattr,
	[FUSE_GETXATTR]         = op_getxattr,
	[FUSE_LISTXATTR]        = op_listxattr,
	[FUSE_REMOVEXATTR]      = op_removexattr,
	[FUSE_FLUSH]            = op_flush,
	[FUSE_OPENDIR]          = op_opendir,
	[FUSE_READDIR]          = op_readdir,
	[FUSE_RELEASEDIR]       = op_releasedir,
	[FUSE_FSYNCDIR]         = op_fsyncdir,
	[FUSE_ACCESS]           = op_access,
	[FUSE_CREATE]           = op_create,
	[FUSE_BATCH_FORGET]     = op_batch_forget,
	[FUSE_FALLOCATE]        = op_fallocate,
	[FUSE_READDIRPLUS]      = op_readdirplus,
	[FUSE_RENAME2]          = op_rename,
	[FUSE_LSEEK]            = op_lseek,
	[FUSE_COPY_FILE_RANGE]  = op_copy_file_range,
	[FUSE_SYNCFS]           = op_syncfs,
	[FUSE_IOCTL]            = op_ioctl,
};

static silofs_oper_fn hook_of(uint32_t op_code)
{
	silofs_oper_fn hook = NULL;

	STATICASSERT_EQ(ARRAY_SIZE(silofs_op_tbl), FUSEQ_CMD_MAX);

	if (op_code && (op_code < ARRAY_SIZE(silofs_op_tbl))) {
		hook = silofs_op_tbl[op_code];
	}
	return hook;
}

static int exec_op(struct silofs_task *task, struct silofs_oper_args *args)
{
	silofs_oper_fn hook = hook_of(task->t_oper.op_code);

	return likely(hook != NULL) ? hook(task, args) : -SILOFS_ENOSYS;
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

