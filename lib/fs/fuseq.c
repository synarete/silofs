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
#include <silofs/ioctls.h>
#include <silofs/fs.h>
#include <silofs/fs/fuseq.h>
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

#if FUSE_KERNEL_VERSION != 7
#error "wrong FUSE_KERNEL_VERSION"
#endif
#if FUSE_KERNEL_MINOR_VERSION < 36
#error "wrong FUSE_KERNEL_MINOR_VERSION"
#endif

/* constants from libfuse::lib/fuse_i.h */

/* room needed in buffer to accommodate header */
#define FUSE_BUFFER_HEADER_SIZE 0x1000

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
static void fqd_interrupt_op(struct silofs_fuseq_dispatcher *fqd, uint64_t uq);
static bool fqd_has_large_write_in(const struct silofs_fuseq_dispatcher *fqd);
static bool fqd_has_large_read_in(const struct silofs_fuseq_dispatcher *fqd);
static void fuseq_lock_ctl(struct silofs_fuseq *fq);
static void fuseq_unlock_ctl(struct silofs_fuseq *fq);
static void fuseq_update_nexecs(struct silofs_fuseq *fq, int n);
static bool fuseq_has_live_opers(const struct silofs_fuseq *fq);
static bool fuseq_is_active(const struct silofs_fuseq *fq);
static void fuseq_set_active(struct silofs_fuseq *fq);
static void fuseq_set_non_active(struct silofs_fuseq *fq);
static int exec_op(struct silofs_task *task, struct silofs_oper_args *args);
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
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_SYMLNK_MAX];
};

struct silofs_fuseq_setxattr_in {
	struct fuse_in_header hdr;
	struct fuse_setxattr_in arg;
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_SYMLNK_MAX];
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
};

struct silofs_fuseq_in {
	union silofs_fuseq_in_u u;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_fuseq_diter {
	char buf[8 * SILOFS_UKILO];
	struct silofs_strbuf de_name;
	struct silofs_readdir_ctx rd_ctx;
	struct silofs_stat de_attr;
	size_t bsz;
	size_t len;
	size_t ndes;
	loff_t de_off;
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
	struct silofs_fuseq_dispatcher *fqd;
	size_t cnt;
	size_t ncp;
	size_t nwr;
	size_t nwr_max;
};

struct silofs_fuseq_rd_iter {
	struct silofs_iovec iovec[SILOFS_FILE_NITER_MAX];
	struct silofs_rwiter_ctx rwi;
	struct silofs_fuseq_dispatcher *fqd;
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
	struct silofs_fuseq_dispatcher *fqd;
	struct silofs_task *task;
	struct silofs_oper_args *args;
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
fill_fuse_entry(struct fuse_entry_out *ent, const struct silofs_stat *st)
{
	memset(ent, 0, sizeof(*ent));
	ent->nodeid = st->st.st_ino;
	ent->generation = st->gen;
	ent->entry_valid = UINT_MAX;
	ent->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &ent->attr);
}

static void fill_fuse_noentry(struct fuse_entry_out *ent)
{
	memset(ent, 0, sizeof(*ent));
	ent->nodeid = 0;
	ent->entry_valid = UINT_MAX;
}

static void
fill_fuse_attr(struct fuse_attr_out *attr, const struct silofs_stat *st)
{
	memset(attr, 0, sizeof(*attr));
	attr->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &attr->attr);
}

static void fill_fuse_open(struct fuse_open_out *open, int noflush, int isdir)
{
	memset(open, 0, sizeof(*open));
	open->open_flags = FOPEN_KEEP_CACHE;
	if (noflush) {
		open->open_flags |= FOPEN_NOFLUSH;
	}
	if (isdir) {
		open->open_flags = FOPEN_CACHE_DIR;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
task_init_by(struct silofs_task *task, const struct silofs_fuseq *fq)
{
	silofs_task_init(task, fq->fq_fsenv);
}

static void task_fini(struct silofs_task *task)
{
	silofs_task_fini(task);
}

static void task_refresh_by_cmd(struct silofs_task *task)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc;

	cmd_desc = cmd_desc_of(task->t_oper.op_code);
	silofs_task_set_ts(task, cmd_desc && (cmd_desc->realtime > 0));
}

static void
task_check_fh(const struct silofs_task *task, ino_t ino, uint64_t fh)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc;

	if (fh != 0) {
		cmd_desc = cmd_desc_of(task->t_oper.op_code);
		fuseq_log_warn("op=%s ino=%lu fh=0x%lx",
			       cmd_desc ? cmd_desc->name : "", ino, fh);
	}
}

static int task_submit(struct silofs_task *task)
{
	return silofs_task_submit(task, false);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t operid_of(const struct silofs_task *task)
{
	return task->t_oper.op_unique;
}

static uint32_t opcode_of(const struct silofs_task *task)
{
	return task->t_oper.op_code;
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

static int sanitize_err_by(int err, const struct silofs_task *task)
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
			       const struct silofs_task *task, size_t xlen)
{
	fill_out_header(out_hdr, operid_of(task), sizeof(*out_hdr) + xlen, 0);
}

static void fill_out_header_err(struct fuse_out_header *out_hdr,
				const struct silofs_task *task, int err)
{
	fill_out_header(out_hdr, operid_of(task), sizeof(*out_hdr),
			sanitize_err_by(err, task));
}

static const struct silofs_fuseq *
fqd_fuseq(const struct silofs_fuseq_dispatcher *fqd)
{
	return fqd->fqd_th.fq;
}

static struct silofs_fuseq *fqd_fuseq2(struct silofs_fuseq_dispatcher *fqd)
{
	return fqd->fqd_th.fq;
}

static int fqd_fuse_fd(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);

	return fq->fq_fuse_fd;
}

static int fqd_send_msg(struct silofs_fuseq_dispatcher *fqd,
			const struct iovec *iov, size_t iovcnt)
{
	size_t nwr = 0;
	int fuse_fd;
	int err;

	fuse_fd = fqd_fuse_fd(fqd);
	err = silofs_sys_writev(fuse_fd, iov, (int)iovcnt, &nwr);
	if (err && (err != -ENOENT)) {
		fuseq_log_warn("send-to-fuse failed: fuse_fd=%d "
			       "iovcnt=%lu err=%d",
			       fuse_fd, iovcnt, err);
	}
	return err;
}

static int
fqd_reply_arg(struct silofs_fuseq_dispatcher *fqd,
	      const struct silofs_task *task, const void *arg, size_t argsz)
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
	return fqd_send_msg(fqd, iov, 2);
}

static int fqd_reply_arg2(struct silofs_fuseq_dispatcher *fqd,
			  const struct silofs_task *task, const void *arg1,
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
	return fqd_send_msg(fqd, iov, 3);
}

static int
fqd_reply_buf(struct silofs_fuseq_dispatcher *fqd,
	      const struct silofs_task *task, const void *buf, size_t bsz)
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
	return fqd_send_msg(fqd, iov, cnt);
}

static int fqd_reply_err(struct silofs_fuseq_dispatcher *fqd,
			 const struct silofs_task *task, int err)
{
	struct fuse_out_header hdr;
	const struct iovec iov = { .iov_base = &hdr, .iov_len = sizeof(hdr) };

	fill_out_header_err(&hdr, task, err);
	return fqd_send_msg(fqd, &iov, 1);
}

static int fqd_reply_intr(struct silofs_fuseq_dispatcher *fqd,
			  const struct silofs_task *task)
{
	return fqd_reply_err(fqd, task, -EINTR);
}

static int fqd_reply_status(struct silofs_fuseq_dispatcher *fqd,
			    const struct silofs_task *task, int status)
{
	return fqd_reply_err(fqd, task, status);
}

static int fqd_reply_none(struct silofs_fuseq_dispatcher *fqd)
{
	unused(fqd);
	return 0;
}

static int fqd_reply_entry_ok(struct silofs_fuseq_dispatcher *fqd,
			      const struct silofs_task *task,
			      const struct silofs_stat *st)
{
	struct fuse_entry_out arg;

	fill_fuse_entry(&arg, st);
	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_lookup_noent(struct silofs_fuseq_dispatcher *fqd,
				  const struct silofs_task *task)
{
	struct fuse_entry_out arg;

	fill_fuse_noentry(&arg);
	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_create_ok(struct silofs_fuseq_dispatcher *fqd,
			       const struct silofs_task *task,
			       const struct silofs_stat *st)
{
	struct fuse_entry_out arg1;
	struct fuse_open_out arg2;

	fill_fuse_entry(&arg1, st);
	fill_fuse_open(&arg2, 0, 0);
	return fqd_reply_arg2(fqd, task, &arg1, sizeof(arg1), &arg2,
			      sizeof(arg2));
}

static int
fqd_reply_attr_ok(struct silofs_fuseq_dispatcher *fqd,
		  const struct silofs_task *task, const struct silofs_stat *st)
{
	struct fuse_attr_out arg;

	fill_fuse_attr(&arg, st);
	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int
fqd_reply_statfs_ok(struct silofs_fuseq_dispatcher *fqd,
		    const struct silofs_task *task, const struct statvfs *stv)
{
	struct fuse_statfs_out arg;

	statfs_to_fuse_kstatfs(stv, &arg.st);
	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_readlink_ok(struct silofs_fuseq_dispatcher *fqd,
				 const struct silofs_task *task,
				 const char *lnk, size_t len)
{
	return fqd_reply_buf(fqd, task, lnk, len);
}

static int
fqd_reply_open_ok(struct silofs_fuseq_dispatcher *fqd,
		  const struct silofs_task *task, int noflush, int isdir)
{
	struct fuse_open_out arg;

	fill_fuse_open(&arg, noflush, isdir);
	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_opendir_ok(struct silofs_fuseq_dispatcher *fqd,
				const struct silofs_task *task)
{
	return fqd_reply_open_ok(fqd, task, 0, 1);
}

static int fqd_reply_write_ok(struct silofs_fuseq_dispatcher *fqd,
			      const struct silofs_task *task, size_t cnt)
{
	struct fuse_write_out arg = { .size = (uint32_t)cnt };

	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_lseek_ok(struct silofs_fuseq_dispatcher *fqd,
			      const struct silofs_task *task, loff_t off)
{
	const struct fuse_lseek_out arg = { .offset = (uint64_t)off };

	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_xattr_len(struct silofs_fuseq_dispatcher *fqd,
			       const struct silofs_task *task, size_t len)
{
	const struct fuse_getxattr_out arg = { .size = (uint32_t)len };

	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_xattr_buf(struct silofs_fuseq_dispatcher *fqd,
			       const struct silofs_task *task, const void *buf,
			       size_t len)
{
	return fqd_reply_buf(fqd, task, buf, len);
}

static int fqd_reply_init_ok(struct silofs_fuseq_dispatcher *fqd,
			     const struct silofs_task *task,
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

	return fqd_reply_arg(fqd, task, &arg, sizeof(arg));
}

static int fqd_reply_ioctl_ok(struct silofs_fuseq_dispatcher *fqd,
			      const struct silofs_task *task, int result,
			      const void *buf, size_t size)
{
	struct fuse_ioctl_out arg;
	int ret;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;

	if (size && buf) {
		ret = fqd_reply_arg2(fqd, task, &arg, sizeof(arg), buf, size);
	} else {
		ret = fqd_reply_arg(fqd, task, &arg, sizeof(arg));
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool task_interrupted(const struct silofs_task *task)
{
	return unlikely(task->t_interrupt > 0);
}

static int fqd_reply_attr(struct silofs_fuseq_dispatcher *fqd,
			  const struct silofs_task *task,
			  const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_attr_ok(fqd, task, st);
	}
	return ret;
}

static int fqd_reply_entry(struct silofs_fuseq_dispatcher *fqd,
			   const struct silofs_task *task,
			   const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_entry_ok(fqd, task, st);
	}
	return ret;
}

static int fqd_reply_lookup(struct silofs_fuseq_dispatcher *fqd,
			    const struct silofs_task *task,
			    const struct silofs_stat *st, int err)
{
	const int status = sanitize_err_by(err, task);
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (status == -ENOENT) {
		ret = fqd_reply_lookup_noent(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_entry_ok(fqd, task, st);
	}
	return ret;
}

static int fqd_reply_create(struct silofs_fuseq_dispatcher *fqd,
			    const struct silofs_task *task,
			    const struct silofs_stat *st, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_create_ok(fqd, task, st);
	}
	return ret;
}

static int fqd_reply_readlink(struct silofs_fuseq_dispatcher *fqd,
			      const struct silofs_task *task, const char *lnk,
			      size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_readlink_ok(fqd, task, lnk, len);
	}
	return ret;
}

static int fqd_reply_statfs(struct silofs_fuseq_dispatcher *fqd,
			    const struct silofs_task *task,
			    const struct statvfs *stv, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_statfs_ok(fqd, task, stv);
	}
	return ret;
}

static int fqd_reply_open(struct silofs_fuseq_dispatcher *fqd,
			  const struct silofs_task *task, int noflush, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_open_ok(fqd, task, noflush, 0);
	}
	return ret;
}

static int fqd_reply_xattr(struct silofs_fuseq_dispatcher *fqd,
			   const struct silofs_task *task, const void *buf,
			   size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else if (buf == NULL) {
		ret = fqd_reply_xattr_len(fqd, task, len);
	} else {
		ret = fqd_reply_xattr_buf(fqd, task, buf, len);
	}
	return ret;
}

static int fqd_reply_opendir(struct silofs_fuseq_dispatcher *fqd,
			     const struct silofs_task *task, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_opendir_ok(fqd, task);
	}
	return ret;
}

static int fqd_reply_readdir(struct silofs_fuseq_dispatcher *fqd,
			     const struct silofs_task *task,
			     const struct silofs_fuseq_diter *di, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_buf(fqd, task, di->buf, di->len);
	}
	return ret;
}

static int fqd_reply_lseek(struct silofs_fuseq_dispatcher *fqd,
			   const struct silofs_task *task, loff_t off, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_lseek_ok(fqd, task, off);
	}
	return ret;
}

static int
fqd_reply_copy_file_range(struct silofs_fuseq_dispatcher *fqd,
			  const struct silofs_task *task, size_t cnt, int err)
{
	int ret;

	STATICASSERT_LT(FUSEQ_COPY_FILE_RANGE_MAX, UINT32_MAX);

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_write_ok(fqd, task, cnt);
	}
	return ret;
}

static int fqd_reply_init(struct silofs_fuseq_dispatcher *fqd,
			  const struct silofs_task *task, int err)
{
	const struct silofs_fuseq *fq;
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		fq = fqd_fuseq(fqd);
		ret = fqd_reply_init_ok(fqd, task, &fq->fq_coni);
	}
	return ret;
}

static int fqd_reply_ioctl(struct silofs_fuseq_dispatcher *fqd,
			   const struct silofs_task *task, int result,
			   const void *buf, size_t size, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_ioctl_ok(fqd, task, result, buf, size);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fqd_reply_write(struct silofs_fuseq_dispatcher *fqd,
			   const struct silofs_task *task, size_t cnt, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_write_ok(fqd, task, cnt);
	}
	return ret;
}

static int fqd_reply_read_buf(struct silofs_fuseq_dispatcher *fqd,
			      const struct silofs_task *task, const void *dat,
			      size_t len, int err)
{
	int ret;

	if (task_interrupted(task)) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
	} else {
		ret = fqd_reply_buf(fqd, task, dat, len);
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
	const loff_t end1 = off_end(iovec1->iov_off, iovec1->iov.iov_len);
	const loff_t beg2 = iovec2->iov_off;
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

static int fqd_append_hdr_to_pipe(struct silofs_fuseq_dispatcher *fqd,
				  const struct silofs_task *task, size_t len)
{
	struct fuse_out_header hdr;
	struct silofs_pipe *pipe = &fqd->fqd_piper.pipe;

	fill_out_header_ok(&hdr, task, len);
	return silofs_pipe_append_from_buf(pipe, &hdr, sizeof(hdr));
}

static int
fqd_append_data_to_pipe(struct silofs_fuseq_dispatcher *fqd,
			const struct silofs_iovec *iovec, size_t cnt)
{
	struct iovec iov[48];
	struct silofs_pipe *pipe = &fqd->fqd_piper.pipe;
	size_t ncp = 0;
	size_t cur = 0;
	int err;

	STATICASSERT_LE(ARRAY_SIZE(iov), SILOFS_FILE_NITER_MAX);

	while (ncp < cnt) {
		cur = min(cnt - ncp, ARRAY_SIZE(iov));
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

static int fqd_send_pipe(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_pipe *pipe = &fqd->fqd_piper.pipe;
	const int fuse_fd = fqd_fuse_fd(fqd);

	return silofs_pipe_flush_to_fd(pipe, fuse_fd, 0);
}

static int fqd_reply_read_data(struct silofs_fuseq_dispatcher *fqd,
			       const struct silofs_task *task, size_t nrd,
			       const struct silofs_iovec *iovec)
{
	return fqd_reply_buf(fqd, task, iovec->iov.iov_base, nrd);
}

static int fq_rdi_reply_read_iov(struct silofs_fuseq_rd_iter *fq_rdi)
{
	const struct silofs_iovec *iov = NULL;
	size_t rem = 0;
	int err = 0;
	int ret = 0;

	err = fqd_append_hdr_to_pipe(fq_rdi->fqd, fq_rdi->task, fq_rdi->nrd);
	if (err) {
		goto out;
	}
	if (fq_rdi->ncp < fq_rdi->cnt) {
		iov = fq_rdi->iovec + fq_rdi->ncp;
		rem = fq_rdi->cnt - fq_rdi->ncp;
		err = fqd_append_data_to_pipe(fq_rdi->fqd, iov, rem);
		if (err) {
			goto out;
		}
		fq_rdi->ncp += rem;
	}
out:
	if (err) {
		ret = fqd_reply_err(fq_rdi->fqd, fq_rdi->task, err);
	} else {
		ret = fqd_send_pipe(fq_rdi->fqd);
	}
	return ret ? ret : err;
}

static int fq_rdi_reply_read_ok(struct silofs_fuseq_rd_iter *fq_rdi)
{
	struct silofs_fuseq_dispatcher *fqd = fq_rdi->fqd;
	struct silofs_task *task = fq_rdi->task;
	int ret;

	if ((fq_rdi->cnt <= 1) && (fq_rdi->iovec[0].iov_fd < 0)) {
		ret = fqd_reply_read_data(fqd, task, fq_rdi->nrd,
					  fq_rdi->iovec);
	} else {
		ret = fq_rdi_reply_read_iov(fq_rdi);
	}
	return ret;
}

static int fq_rdi_reply_read_iter(struct silofs_fuseq_rd_iter *fq_rdi, int err)
{
	struct silofs_fuseq_dispatcher *fqd = fq_rdi->fqd;
	struct silofs_task *task = fq_rdi->task;
	int ret;

	if (task->t_interrupt) {
		ret = fqd_reply_intr(fqd, task);
	} else if (unlikely(err)) {
		ret = fqd_reply_err(fqd, task, err);
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
	fde->type = IFTODT(st->st.st_mode);
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
	const char *name = di->de_name.str;
	size_t cnt = 0;
	int err;

	if (rem <= di->de_nlen) {
		return -SILOFS_EINVAL;
	}
	err = likely(di->plus) ? emit_direntplus(buf, rem, name, nlen,
						 &di->de_attr, off, &cnt) :
				 emit_direntonly(buf, rem, name, nlen, ino,
						 di->de_dt, off, &cnt);
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
	di->de_nlen = min(rdi->namelen, nbuf_sz - 1);
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
diter_prep(struct silofs_fuseq_diter *di, size_t bsz, loff_t pos, int plus)
{
	di->ndes = 0;
	di->de_off = 0;
	di->de_nlen = 0;
	di->de_ino = 0;
	di->de_dt = 0;
	di->de_name.str[0] = '\0';
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

static int fqd_check_init(const struct silofs_fuseq_dispatcher *fqd,
			  const struct fuse_init_in *arg)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);
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
	const int writeback_cache = fcc->fq->fq_writeback_cache;

	coni->kern_cap = in_flags;
	coni->want_cap |= FUSE_BIG_WRITES; /* same as in libfuse */
	update_cap_want(coni, FUSE_ATOMIC_O_TRUNC);
	update_cap_want(coni, FUSE_EXPORT_SUPPORT);
	update_cap_want(coni, FUSE_SPLICE_WRITE);
	update_cap_want(coni, FUSE_SPLICE_READ);
	update_cap_want(coni, FUSE_PARALLEL_DIROPS);
	update_cap_want(coni, FUSE_HANDLE_KILLPRIV);
	update_cap_want(coni, FUSE_MAX_PAGES);
	update_cap_want(coni, FUSE_CACHE_SYMLINKS);
	update_cap_want(coni, FUSE_DO_READDIRPLUS);
	update_cap_want(coni, FUSE_SETXATTR_EXT);
	if (writeback_cache) {
		update_cap_want(coni, FUSE_WRITEBACK_CACHE);
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
		       fq->fq_may_splice ? "pipe-splice" : "buffer-copy");
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

	err = fqd_check_init(fcc->fqd, &fcc->in->u.init.arg);
	if (!err) {
		coni->kern_proto_major = in_major;
		coni->kern_proto_minor = in_minor;
		do_init_capabilities(fcc);
		fcc->fq->fq_got_init = true;
	}

	do_init_log_conn_info(fcc);

	ret = fqd_reply_init(fcc->fqd, fcc->task, err);
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

	return fqd_reply_status(fcc->fqd, fcc->task, 0);
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

static bool fuseq_may_splice(const struct silofs_fuseq *fq)
{
	return fq->fq_may_splice && fuseq_is_normal(fq) && (fq->fq_nopers > 2);
}

static bool fuseq_cap_splice(const struct silofs_fuseq *fq)
{
	return fuseq_has_cap(fq, FUSE_SPLICE_READ | FUSE_SPLICE_WRITE);
}

static bool fuseq_allowed_splice(const struct silofs_fuseq *fq)
{
	return fuseq_may_splice(fq) && fuseq_cap_splice(fq);
}

static bool fuseq_has_nactive_disptch(const struct silofs_fuseq *fq)
{
	return (fq->fq_subx.fq_ndisptch_run == fq->fq_subx.fq_ndisptch_lim);
}

static bool fuseq_is_nexecs_idle(struct silofs_fuseq *fq)
{
	const int ndisptch_run = (int)(fq->fq_subx.fq_ndisptch_run);
	bool ret;

	fuseq_lock_ctl(fq);
	ret = (fq->fq_nexecs < -ndisptch_run);
	fuseq_unlock_ctl(fq);
	return ret;
}

static void fuseq_update_nexecs(struct silofs_fuseq *fq, int n)
{
	fuseq_lock_ctl(fq);
	if (n > 0) {
		fq->fq_nopers += n;
		fq->fq_nexecs = silofs_max_i64(1, fq->fq_nexecs + n);
	} else if (n < 0) {
		fq->fq_nexecs = silofs_min_i64(fq->fq_subx.fq_ndisptch_run,
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

static int do_exec_op(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return exec_op(fcc->task, fcc->args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define FATTR_MASK                                                       \
	(FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE | FATTR_ATIME | \
	 FATTR_MTIME | FATTR_FH | FATTR_ATIME_NOW | FATTR_MTIME_NOW |    \
	 FATTR_LOCKOWNER | FATTR_CTIME)

#define FATTR_AMTIME_NOW (FATTR_ATIME_NOW | FATTR_MTIME_NOW)

#define FATTR_AMCTIME (FATTR_ATIME | FATTR_MTIME | FATTR_CTIME)

#define FATTR_NONTIME (FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE)

static int
uid_gid_of(const struct stat *attr, int to_set, uid_t *uid, gid_t *gid)
{
	*uid = (to_set & FATTR_UID) ? attr->st_uid : (uid_t)(-1);
	*gid = (to_set & FATTR_GID) ? attr->st_gid : (gid_t)(-1);
	return 0; /* TODO: Check valid ranges */
}

static void utimens_of(const struct stat *st, int to_set, struct stat *times)
{
	const int set_ctime_now = FATTR_AMTIME_NOW | FATTR_AMCTIME |
				  FATTR_MODE | FATTR_UID | FATTR_GID |
				  FATTR_SIZE;

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
	return fqd_reply_attr(fcc->fqd, fcc->task, &fcc->args->out.setattr.st,
			      err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_lookup(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.lookup.parent = fcc->ino;
	fcc->args->in.lookup.name = fcc->in->u.lookup.name;
	err = do_exec_op(fcc);
	return fqd_reply_lookup(fcc->fqd, fcc->task, &fcc->args->out.lookup.st,
				err);
}

static int do_forget(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.forget.ino = fcc->ino;
	fcc->args->in.forget.nlookup = fcc->in->u.forget.arg.nlookup;
	err = do_exec_op(fcc);
	unused(err);
	return fqd_reply_none(fcc->fqd);
}

static int do_batch_forget(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.batch_forget.count = fcc->in->u.batch_forget.arg.count;
	fcc->args->in.batch_forget.one = fcc->in->u.batch_forget.one;
	err = do_exec_op(fcc);
	unused(err);
	return fqd_reply_none(fcc->fqd);
}

static int do_getattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.getattr.arg.fh);
	fcc->args->in.getattr.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqd_reply_attr(fcc->fqd, fcc->task, &fcc->args->out.getattr.st,
			      err);
}

static int do_readlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_pathbuf *pab = &fcc->fqd->fqd_outb->u.pab;
	char *lnk = pab->path;
	int err;

	fcc->args->in.readlink.ino = fcc->ino;
	fcc->args->in.readlink.ptr = lnk;
	fcc->args->in.readlink.lim = sizeof(pab->path);
	fcc->args->out.readlink.len = 0;
	err = do_exec_op(fcc);
	return fqd_reply_readlink(fcc->fqd, fcc->task, lnk,
				  fcc->args->out.readlink.len, err);
}

static int do_symlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.symlink.parent = fcc->ino;
	fcc->args->in.symlink.name = fcc->in->u.symlink.name_target;
	fcc->args->in.symlink.symval = after_name(fcc->args->in.symlink.name);
	err = do_exec_op(fcc);
	return fqd_reply_entry(fcc->fqd, fcc->task, &fcc->args->out.symlink.st,
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
	return fqd_reply_entry(fcc->fqd, fcc->task, &fcc->args->out.mknod.st,
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
	return fqd_reply_entry(fcc->fqd, fcc->task, &fcc->args->out.mkdir.st,
			       err);
}

static int do_unlink(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.unlink.parent = fcc->ino;
	fcc->args->in.unlink.name = fcc->in->u.unlink.name;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_rmdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.rmdir.parent = fcc->ino;
	fcc->args->in.rmdir.name = fcc->in->u.rmdir.name;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
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
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_link(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.link.ino = (ino_t)(fcc->in->u.link.arg.oldnodeid);
	fcc->args->in.link.parent = fcc->ino;
	fcc->args->in.link.name = fcc->in->u.link.name;
	err = do_exec_op(fcc);
	return fqd_reply_entry(fcc->fqd, fcc->task, &fcc->args->out.link.st,
			       err);
}

static int do_open(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.open.ino = fcc->ino;
	fcc->args->in.open.o_flags = (int)(fcc->in->u.open.arg.flags);
	fcc->args->in.open.noflush =
		(fcc->args->in.open.o_flags & O_ACCMODE) == O_RDONLY;
	err = do_exec_op(fcc);
	return fqd_reply_open(fcc->fqd, fcc->task, fcc->args->in.open.noflush,
			      err);
}

static int do_statfs(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.statfs.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqd_reply_statfs(fcc->fqd, fcc->task,
				&fcc->args->out.statfs.stv, err);
}

static int do_release(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.release.arg.fh);
	fcc->args->in.release.ino = fcc->ino;
	fcc->args->in.release.o_flags = (int)fcc->in->u.release.arg.flags;
	fcc->args->in.release.flush =
		(fcc->in->u.release.arg.flags & FUSE_RELEASE_FLUSH) > 0;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_fsync(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.fsync.arg.fh);
	fcc->args->in.fsync.ino = fcc->ino;
	fcc->args->in.fsync.datasync =
		(fcc->in->u.fsync.arg.fsync_flags & 1) != 0;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
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
	return fqd_reply_status(fcc->fqd, fcc->task, err);
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
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_setxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return (fcc->fq->fq_coni.kern_proto_minor <= 33) ? do_setxattr1(fcc) :
							   do_setxattr2(fcc);
}

static int do_getxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_xattrbuf *xab = &fcc->fqd->fqd_outb->u.xab;
	int err;

	fcc->args->in.getxattr.ino = fcc->ino;
	fcc->args->in.getxattr.name = fcc->in->u.getxattr.name;
	fcc->args->in.getxattr.size =
		min(fcc->in->u.getxattr.arg.size, sizeof(xab->value));
	fcc->args->in.getxattr.buf = fcc->args->in.getxattr.size ? xab->value :
								   NULL;
	fcc->args->out.getxattr.size = 0;
	err = do_exec_op(fcc);
	return fqd_reply_xattr(fcc->fqd, fcc->task, fcc->args->in.getxattr.buf,
			       fcc->args->out.getxattr.size, err);
}

static int do_listxattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_xiter *xit = &fcc->fqd->fqd_outb->u.xit;
	int ret;
	int err;

	xiter_prep(xit, fcc->in->u.listxattr.arg.size);
	fcc->args->in.listxattr.ino = fcc->ino;
	fcc->args->in.listxattr.lxa_ctx = &xit->lxa;
	err = do_exec_op(fcc);
	ret = fqd_reply_xattr(fcc->fqd, fcc->task, xit->beg, xit->cnt, err);
	xiter_done(xit);
	return ret;
}

static int do_removexattr(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.removexattr.ino = fcc->ino;
	fcc->args->in.removexattr.name = fcc->in->u.removexattr.name;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_flush(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.flush.arg.fh);
	fcc->args->in.flush.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_opendir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.opendir.ino = fcc->ino;
	fcc->args->in.opendir.o_flags = (int)(fcc->in->u.opendir.arg.flags);
	err = do_exec_op(fcc);
	return fqd_reply_opendir(fcc->fqd, fcc->task, err);
}

static int do_readdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_diter *dit = &fcc->fqd->fqd_outb->u.dit;
	const size_t size = fcc->in->u.readdir.arg.size;
	const loff_t off = (loff_t)(fcc->in->u.readdir.arg.offset);
	int ret;
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 0);
	fcc->args->in.readdir.ino = fcc->ino;
	fcc->args->in.readdir.rd_ctx = &dit->rd_ctx;
	err = do_exec_op(fcc);
	ret = fqd_reply_readdir(fcc->fqd, fcc->task, dit, err);
	diter_done(dit);
	return ret;
}

static int do_readdirplus(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_diter *dit = &fcc->fqd->fqd_outb->u.dit;
	const size_t size = fcc->in->u.readdir.arg.size;
	const loff_t off = (loff_t)(fcc->in->u.readdir.arg.offset);
	int ret;
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 1);
	fcc->args->in.readdir.ino = fcc->ino;
	fcc->args->in.readdir.rd_ctx = &dit->rd_ctx;
	err = do_exec_op(fcc);
	ret = fqd_reply_readdir(fcc->fqd, fcc->task, dit, err);
	diter_done(dit);
	return ret;
}

static int do_releasedir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.releasedir.arg.fh);
	fcc->args->in.releasedir.ino = fcc->ino;
	fcc->args->in.releasedir.o_flags =
		(int)(fcc->in->u.releasedir.arg.flags);
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_fsyncdir(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.fsyncdir.arg.fh);
	fcc->args->in.fsyncdir.ino = fcc->ino;
	fcc->args->in.fsyncdir.datasync =
		(fcc->in->u.fsyncdir.arg.fsync_flags & 1) != 0;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_access(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.access.ino = fcc->ino;
	fcc->args->in.access.mask = (int)(fcc->in->u.access.arg.mask);
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_create(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.create.parent = fcc->ino;
	fcc->args->in.create.name = fcc->in->u.create.name;
	fcc->args->in.create.o_flags = (int)(fcc->in->u.create.arg.flags);
	fcc->args->in.create.mode = (mode_t)(fcc->in->u.create.arg.mode);
	fcc->args->in.create.umask = (mode_t)(fcc->in->u.create.arg.umask);
	silofs_task_update_umask(fcc->task, fcc->args->in.create.umask);
	err = do_exec_op(fcc);
	return fqd_reply_create(fcc->fqd, fcc->task, &fcc->args->out.create.st,
				err);
}

static int do_fallocate(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.fallocate.arg.fh);
	fcc->args->in.fallocate.ino = fcc->ino;
	fcc->args->in.fallocate.mode = (int)(fcc->in->u.fallocate.arg.mode);
	fcc->args->in.fallocate.off =
		(loff_t)(fcc->in->u.fallocate.arg.offset);
	fcc->args->in.fallocate.len =
		(loff_t)(fcc->in->u.fallocate.arg.length);
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
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
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_lseek(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.lseek.arg.fh);
	fcc->args->in.lseek.ino = fcc->ino;
	fcc->args->in.lseek.off = (loff_t)(fcc->in->u.lseek.arg.offset);
	fcc->args->in.lseek.whence = (int)(fcc->in->u.lseek.arg.whence);
	fcc->args->out.lseek.off = -1;
	err = do_exec_op(fcc);
	return fqd_reply_lseek(fcc->fqd, fcc->task, fcc->args->out.lseek.off,
			       err);
}

static int do_copy_file_range(const struct silofs_fuseq_cmd_ctx *fcc)
{
	size_t len = 0;
	size_t ncp = 0;
	int err;

	task_check_fh(fcc->task, fcc->ino,
		      fcc->in->u.copy_file_range.arg.fh_in);
	len = min(fcc->in->u.copy_file_range.arg.len,
		  FUSEQ_COPY_FILE_RANGE_MAX);
	fcc->args->in.copy_file_range.ino_in = fcc->ino;
	fcc->args->in.copy_file_range.off_in =
		(loff_t)fcc->in->u.copy_file_range.arg.off_in;
	fcc->args->in.copy_file_range.ino_out =
		(ino_t)fcc->in->u.copy_file_range.arg.nodeid_out;
	fcc->args->in.copy_file_range.off_out =
		(loff_t)fcc->in->u.copy_file_range.arg.off_out;
	fcc->args->in.copy_file_range.len = len;
	fcc->args->in.copy_file_range.flags =
		(int)fcc->in->u.copy_file_range.arg.flags;
	fcc->args->out.copy_file_range.ncp = 0;
	err = do_exec_op(fcc);
	ncp = fcc->args->out.copy_file_range.ncp;
	return fqd_reply_copy_file_range(fcc->fqd, fcc->task, ncp, err);
}

static int do_syncfs(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int err;

	fcc->args->in.syncfs.ino = fcc->ino;
	err = do_exec_op(fcc);
	return fqd_reply_status(fcc->fqd, fcc->task, err);
}

static int do_interrupt(const struct silofs_fuseq_cmd_ctx *fcc)
{
	uint64_t unq;

	if (fcc->ino == 0) {
		unq = fcc->in->u.interrupt.arg.unique;
		fqd_interrupt_op(fcc->fqd, unq);
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
fqd_setup_rd_iter(struct silofs_fuseq_dispatcher *fqd,
		  struct silofs_task *task,
		  struct silofs_fuseq_rd_iter *fq_rdi, size_t len, loff_t off)
{
	fq_rdi->fqd = fqd;
	fq_rdi->task = task;
	fq_rdi->cnt = 0;
	fq_rdi->ncp = 0;
	fq_rdi->nrd = 0;
	fq_rdi->nrd_max = len;
	fq_rdi->rwi.len = len;
	fq_rdi->rwi.off = off;
	fq_rdi->rwi.actor = fq_rdi_actor;
}

static int do_rdwr_post(struct silofs_task *task, int wr_mode,
			const struct silofs_iovec *iov, size_t cnt)
{
	return silofs_fs_rdwr_post(task, wr_mode, iov, cnt);
}

static int do_read_iter(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_rd_iter *fq_rdi = &fcc->fqd->fqd_rwi->u.rdi;
	size_t len;
	int ret;
	int err;

	len = min(fcc->in->u.read.arg.size, fcc->fq->fq_coni.max_read);
	fcc->args->in.read.ino = fcc->ino;
	fcc->args->in.read.off = (loff_t)(fcc->in->u.read.arg.offset);
	fcc->args->in.read.len = len;
	fcc->args->in.read.buf = NULL;
	fcc->args->in.read.rwi_ctx = &fq_rdi->rwi;
	fcc->args->in.read.o_flags = (int)(fcc->in->u.read.arg.flags);
	fqd_setup_rd_iter(fcc->fqd, fcc->task, fq_rdi, len,
			  fcc->args->in.read.off);
	err = do_exec_op(fcc);
	ret = fq_rdi_reply_read_iter(fq_rdi, err);
	do_rdwr_post(fcc->task, 0, fq_rdi->iovec, fq_rdi->cnt);
	return ret;
}

static int do_read_buf(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_databuf *dab = &fcc->fqd->fqd_outb->u.dab;
	size_t len;
	int err;

	len = min(fcc->in->u.read.arg.size, fcc->fq->fq_coni.max_read);
	fcc->args->in.read.ino = fcc->ino;
	fcc->args->in.read.off = (loff_t)(fcc->in->u.read.arg.offset);
	fcc->args->in.read.len = len;
	fcc->args->in.read.buf = dab->buf;
	fcc->args->in.read.rwi_ctx = NULL;
	fcc->args->in.read.o_flags = (int)(fcc->in->u.read.arg.flags);
	fcc->args->out.read.nrd = 0;
	err = do_exec_op(fcc);
	return fqd_reply_read_buf(fcc->fqd, fcc->task, dab->buf,
				  fcc->args->out.read.nrd, err);
}

static bool fqd_cap_read_iter(const struct silofs_fuseq_dispatcher *fqd)
{
	return fuseq_allowed_splice(fqd_fuseq(fqd));
}

static bool fqd_may_read_iter(const struct silofs_fuseq_dispatcher *fqd)
{
	return fqd_cap_read_iter(fqd) && fqd_has_large_read_in(fqd);
}

static int do_read(const struct silofs_fuseq_cmd_ctx *fcc)
{
	int ret;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.read.arg.fh);
	if (fqd_may_read_iter(fcc->fqd)) {
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

static int fqd_extract_from_pipe_by_fd(struct silofs_fuseq_dispatcher *fqd,
				       const struct silofs_iovec *iovec)
{
	struct silofs_pipe *pipe = &fqd->fqd_piper.pipe;
	loff_t off = iovec->iov_off;

	return silofs_pipe_splice_to_fd(pipe, iovec->iov_fd, &off,
					iovec->iov.iov_len,
					SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
}

static int fqd_extract_from_pipe_by_iov(struct silofs_fuseq_dispatcher *fqd,
					const struct silofs_iovec *iovec)
{
	return silofs_pipe_vmsplice_to_iov(&fqd->fqd_piper.pipe, &iovec->iov,
					   1,
					   SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
}

static int fqd_extract_data_from_pipe(struct silofs_fuseq_dispatcher *fqd,
				      const struct silofs_iovec *iovec)
{
	int err;

	if (iovec->iov_fd > 0) {
		err = fqd_extract_from_pipe_by_fd(fqd, iovec);
	} else if (iovec->iov.iov_base != NULL) {
		err = fqd_extract_from_pipe_by_iov(fqd, iovec);
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
	const struct silofs_fuseq *fq = fqd_fuseq(fq_wri->fqd);

	if (!fq->fq_active) {
		return -EROFS;
	}
	if (!(fq_wri->cnt < ARRAY_SIZE(fq_wri->iovec))) {
		return -SILOFS_EINVAL;
	}
	if (iovec->iov_off < 0) {
		return -SILOFS_EINVAL;
	}
	if ((iovec->iov_fd < 0) && (iovec->iov.iov_base == NULL)) {
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
	err = fqd_extract_data_from_pipe(fq_wri->fqd, iovec);
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
	struct silofs_fuseq_dispatcher *fqd = fq_wri->fqd;
	const struct silofs_iovec *itr = NULL;
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
		err = fqd_extract_data_from_pipe(fqd, &iovec);
		if (err) {
			return err;
		}
		fq_wri->nwr += iovec.iov.iov_len;
		fq_wri->ncp += cur;
	}
	return 0;
}

static bool fqd_asyncwr_mode(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);
	const enum silofs_env_flags mask = SILOFS_ENVF_ASYNCWR;

	return (fq->fq_fsenv->fse_ctl_flags & mask) == mask;
}

static void
fqd_setup_wr_iter(struct silofs_fuseq_dispatcher *fqd,
		  struct silofs_fuseq_wr_iter *fq_rwi, size_t len, loff_t off)
{
	fq_rwi->fqd = fqd;
	fq_rwi->nwr = 0;
	fq_rwi->cnt = 0;
	fq_rwi->ncp = 0;
	fq_rwi->nwr_max = len;
	fq_rwi->rwi.len = len;
	fq_rwi->rwi.off = off;
	fq_rwi->rwi.actor = fqd_asyncwr_mode(fqd) ? fq_wri_async_actor :
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

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.write.arg.fh);
	fcc->args->in.write.ino = fcc->ino;
	fcc->args->in.write.len = fcc->in->u.write.arg.size;
	fcc->args->in.write.off = (loff_t)(fcc->in->u.write.arg.offset);
	fcc->args->in.write.buf = tail_of(fcc->in, sizeof(fcc->in->u.write));
	fcc->args->in.write.rwi_ctx = NULL;
	fcc->args->in.write.o_flags = (int)(fcc->in->u.write.arg.flags);
	fcc->args->out.write.nwr = 0;
	err = do_exec_op(fcc);
	ret = fqd_reply_write(fcc->fqd, fcc->task, fcc->args->out.write.nwr,
			      err);
	return ret;
}

static int do_write_iter(const struct silofs_fuseq_cmd_ctx *fcc)
{
	struct silofs_fuseq_wr_iter *fq_wri = &fcc->fqd->fqd_rwi->u.wri;
	const size_t con_max_write = fcc->fq->fq_coni.max_write;
	size_t len = 0;
	int err1 = 0;
	int err2 = 0;
	int ret = 0;

	task_check_fh(fcc->task, fcc->ino, fcc->in->u.write.arg.fh);
	len = min(fcc->in->u.write.arg.size, con_max_write);
	fcc->args->in.write.ino = fcc->ino;
	fcc->args->in.write.len = len;
	fcc->args->in.write.off = (loff_t)(fcc->in->u.write.arg.offset);
	fcc->args->in.write.buf = NULL;
	fcc->args->in.write.rwi_ctx = &fq_wri->rwi;
	fcc->args->in.write.o_flags = (int)(fcc->in->u.write.arg.flags);
	fcc->args->out.write.nwr = 0;
	fqd_setup_wr_iter(fcc->fqd, fq_wri, len, fcc->args->in.write.off);
	err1 = do_exec_op(fcc);
	if (!err1 || (err1 == -ENOSPC)) {
		err2 = fq_wri_copy_iov(fq_wri); /* unlocked */
	}
	do_rdwr_post(fcc->task, 1, fq_wri->iovec, fq_wri->cnt);
	ret = fqd_reply_write(fcc->fqd, fcc->task, fq_wri->nwr,
			      err1 ? err1 : err2);
	return ret;
}

static bool fqd_cap_write_iter(const struct silofs_fuseq_dispatcher *fqd)
{
	return fuseq_allowed_splice(fqd_fuseq(fqd));
}

static bool fqd_may_write_iter(const struct silofs_fuseq_dispatcher *fqd)
{
	return fqd_cap_write_iter(fqd) && fqd_has_large_write_in(fqd);
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
	if (fqd_may_write_iter(fcc->fqd)) {
		ret = do_write_iter(fcc);
	} else {
		ret = do_write_buf(fcc);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_ioc_notimpl(const struct silofs_fuseq_cmd_ctx *fcc)
{
	return fqd_reply_err(fcc->fqd, fcc->task, -ENOTTY);
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
	return fqd_reply_ioctl(fcc->fqd, fcc->task, 0, &attr, sizeof(attr),
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
	return fqd_reply_ioctl(fcc->fqd, fcc->task, 0,
			       &fcc->args->out.query.qry,
			       sizeof(fcc->args->out.query.qry), err);
}

static int do_ioc_clone(const struct silofs_fuseq_cmd_ctx *fcc)
{
	union silofs_ioc_u ioc_u;
	const struct silofs_bootrecs *brecs = &fcc->args->out.clone.brecs;
	void *buf_out = fcc->fqd->fqd_outb->u.iob.b;
	struct silofs_ioc_clone *cl_out = &ioc_u.clone;
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

	memset(cl_out, 0, sizeof(*cl_out));
	silofs_caddr_to_name2(&brecs->caddr_new, cl_out->boot_new);
	silofs_caddr_to_name2(&brecs->caddr_alt, cl_out->boot_alt);
	memcpy(buf_out, cl_out, sizeof(*cl_out));
out:
	return fqd_reply_ioctl(fcc->fqd, fcc->task, 0, cl_out, sizeof(*cl_out),
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
	return fqd_reply_ioctl(fcc->fqd, fcc->task, 0, NULL, 0, err);
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
	return fqd_reply_ioctl(fcc->fqd, fcc->task, 0, NULL, 0, err);
}

static int fqd_check_ioctl_flags(struct silofs_fuseq_dispatcher *fqd,
				 const struct silofs_fuseq_in *in)
{
	const int flags = (int)(in->u.ioctl.arg.flags);

	if (flags & FUSE_IOCTL_COMPAT) {
		return -SILOFS_ENOSYS;
	}
	if ((flags & FUSE_IOCTL_DIR) && (flags & FUSE_IOCTL_UNRESTRICTED)) {
		return -SILOFS_ENOSYS;
	}
	unused(fqd);
	return 0;
}

static int fqd_check_ioctl_in_size(const struct silofs_fuseq_dispatcher *fqd,
				   const struct silofs_fuseq_in *in)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);
	const size_t in_size = in->u.ioctl.arg.in_size;
	const size_t bsz_max = fq->fq_coni.buffsize;

	return (in_size < bsz_max) ? 0 : -SILOFS_EINVAL;
}

static int do_ioctl(const struct silofs_fuseq_cmd_ctx *fcc)
{
	long ioc_cmd;
	int err;
	int ret;

	err = fqd_check_ioctl_flags(fcc->fqd, fcc->in);
	if (err) {
		ret = fqd_reply_err(fcc->fqd, fcc->task, err);
		goto out;
	}
	err = fqd_check_ioctl_in_size(fcc->fqd, fcc->in);
	if (err) {
		ret = fqd_reply_err(fcc->fqd, fcc->task, err);
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
	fqt->fq = NULL;
	fqt->idx = UINT32_MAX;
}

static void fqt_make_thread_name(const struct silofs_fuseq_thread *fqt,
				 const char *s, struct silofs_strbuf *out_name)
{
	silofs_strbuf_reset(out_name);
	if (s != NULL) {
		silofs_strbuf_sprintf(out_name, "silofs-%s%u", s, fqt->idx);
	}
}

static int fqt_exec_thread(struct silofs_fuseq_thread *fqt,
			   silofs_execute_fn start_fn, const char *s)
{
	struct silofs_strbuf name;
	int err;

	fqt_make_thread_name(fqt, s, &name);
	err = silofs_thread_create(&fqt->th, start_fn, NULL, name.str);
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

#define FUSEQ_CMD_MAX (64)

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

static bool is_exclusive_cmd(const struct silofs_fuseq_in *in)
{
	long ioc_cmd;
	bool ret = false;

	if (in->u.hdr.hdr.opcode == FUSE_IOCTL) {
		ioc_cmd = (long)(in->u.ioctl.arg.cmd);
		ret = (ioc_cmd == SILOFS_IOC_CLONE) ||
		      (ioc_cmd == SILOFS_IOC_SYNCFS);
	}
	return ret;
}

static int
fqd_check_opcode(const struct silofs_fuseq_dispatcher *fqd, uint32_t op_code)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);
	const struct silofs_fuseq_cmd_desc *cmd_desc = cmd_desc_of(op_code);

	if ((cmd_desc == NULL) || (cmd_desc->hook == NULL)) {
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

static int fqd_check_perm(const struct silofs_fuseq_dispatcher *fqd,
			  uid_t op_uid, uint32_t op_code)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);

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

static struct silofs_fuseq_in *
fqd_in_of(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq_in *in = &fqd->fqd_inb->u.in;

	return unconst(in);
}

static bool is_large_io(loff_t off, size_t size)
{
	loff_t end;

	if (size <= SILOFS_PAGE_SIZE_MIN) {
		return false;
	}
	end = silofs_off_end(off, size);
	if (end <= SILOFS_LBK_SIZE) {
		return false;
	}
	return true;
}

static bool fqd_has_large_write_in(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq_in *in = fqd_in_of(fqd);
	const int opc = (int)in->u.hdr.hdr.opcode;
	loff_t off = 0;
	bool ret = false;

	if (opc == FUSE_WRITE) {
		off = (loff_t)in->u.write.arg.offset;
		ret = is_large_io(off, in->u.write.arg.size);
	}
	return ret;
}

static bool fqd_has_large_read_in(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq_in *in = fqd_in_of(fqd);
	const int opc = (int)in->u.hdr.hdr.opcode;
	loff_t off = 0;
	bool ret = false;

	if (opc == FUSE_READ) {
		off = (loff_t)in->u.read.arg.offset;
		ret = is_large_io(off, in->u.read.arg.size);
	}
	return ret;
}

static void fqd_update_task(const struct silofs_fuseq_dispatcher *fqd,
			    struct silofs_task *task)
{
	const struct silofs_fuseq_in *in = fqd_in_of(fqd);
	const struct fuse_in_header *hdr = &in->u.hdr.hdr;

	silofs_task_set_creds(task, hdr->uid, hdr->gid, 0);
	task->t_oper.op_pid = (pid_t)hdr->pid;
	task->t_oper.op_unique = hdr->unique;
	task->t_oper.op_code = hdr->opcode;
	task->t_exclusive = is_exclusive_cmd(in);
}

static int fqd_check_task(struct silofs_fuseq_dispatcher *fqd,
			  const struct silofs_task *task)
{
	const unsigned int op_code = task->t_oper.op_code;
	const uid_t uid = task->t_oper.op_creds.host_cred.uid;
	int err;

	err = fqd_check_opcode(fqd, op_code);
	if (err) {
		return err;
	}
	err = fqd_check_perm(fqd, uid, op_code);
	if (err) {
		return err;
	}
	return 0;
}

static void fqd_pre_exec_request(struct silofs_fuseq_dispatcher *fqd)
{
	fuseq_update_nexecs(fqd_fuseq2(fqd), 1);
}

static void fqd_enq_active_op(struct silofs_fuseq_dispatcher *fqd,
			      struct silofs_task *task)
{
	struct silofs_fuseq *fq = fqd_fuseq2(fqd);

	fuseq_lock_op(fq);
	listq_push_front(&fq->fq_curr_opers, &fqd->fqd_lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fq);
}

static void fqd_dec_active_op(struct silofs_fuseq_dispatcher *fqd,
			      struct silofs_task *task)
{
	struct silofs_fuseq *fq = fqd_fuseq2(fqd);

	fuseq_lock_op(fq);
	listq_remove(&fq->fq_curr_opers, &fqd->fqd_lh);
	task->t_interrupt = 0;
	fuseq_unlock_op(fq);
}

static void fqd_interrupt_op(struct silofs_fuseq_dispatcher *fqd, uint64_t unq)
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
		struct silofs_fuseq *fq = fqd_fuseq2(fqd);

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
fqd_call_oper(struct silofs_fuseq_dispatcher *fqd, struct silofs_task *task)
{
	const struct silofs_fuseq_cmd_desc *cmd_desc = NULL;
	const struct silofs_fuseq_in *in = fqd_in_of(fqd);
	const struct silofs_fuseq_cmd_ctx fcc = {
		.fq = fqd_fuseq2(fqd),
		.fqd = fqd,
		.task = task,
		.args = &fqd->fqd_args,
		.in = in,
		.ino = in->u.hdr.hdr.nodeid,
	};
	int err = -SILOFS_ENOSYS;

	cmd_desc = cmd_desc_of(task->t_oper.op_code);
	if (likely(cmd_desc != NULL)) {
		fqd_enq_active_op(fqd, task);
		err = call_oper_of(&fcc, cmd_desc);
		fqd_dec_active_op(fqd, task);
	}
	return err;
}

static int fqd_do_exec_request(struct silofs_fuseq_dispatcher *fqd,
			       struct silofs_task *task)
{
	int err1;
	int err2;

	fqd_pre_exec_request(fqd);
	silofs_task_rwlock_fs(task);
	err1 = fqd_call_oper(fqd, task);
	err2 = task_submit(task);
	silofs_task_rwunlock_fs(task);

	return err1 ? err1 : err2;
}

static int fqd_exec_request(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_task task;
	int err;

	task_init_by(&task, fqd_fuseq2(fqd));
	fqd_update_task(fqd, &task);
	err = fqd_check_task(fqd, &task);
	if (unlikely(err)) {
		err = fqd_reply_err(fqd, &task, err);
	} else {
		task_refresh_by_cmd(&task);
		err = fqd_do_exec_request(fqd, &task);
	}
	task_fini(&task);
	return err;
}

static void fqd_reset_inhdr(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_fuseq_in *in = fqd_in_of(fqd);
	struct silofs_fuseq_hdr_in *hdr = &in->u.hdr;

	memset(hdr, 0, sizeof(*hdr));
}

static size_t fqd_max_inlen(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);
	const struct silofs_fuseq_in *in = fqd_in_of(fqd);
	const size_t len_max = fq->fq_coni.buffsize;

	silofs_assert_gt(len_max, FUSE_BUFFER_HEADER_SIZE);
	silofs_assert_le(len_max, sizeof(*in));
	silofs_unused(in); /* make clangscan happy */

	return len_max;
}

static int fqd_check_inhdr(const struct silofs_fuseq_dispatcher *fqd,
			   size_t nrd, bool full)
{
	const struct silofs_fuseq_in *in = fqd_in_of(fqd);
	const struct silofs_fuseq_hdr_in *hdr = &in->u.hdr;
	const size_t len = hdr->hdr.len;
	const size_t len_min = sizeof(*hdr);
	const size_t len_max = fqd_max_inlen(fqd);
	const int opc = (int)hdr->hdr.opcode;

	if (unlikely(nrd < len_min)) {
		fuseq_log_err("illegal in-length: "
			      "nrd=%lu len_min=%lu ",
			      nrd, len_min);
		return -SILOFS_EPROTO;
	}
	if (unlikely(len > len_max)) {
		fuseq_log_err("illegal header: opc=%d len=%lu len_max=%lu",
			      opc, len, len_max);
		return -SILOFS_EPROTO;
	}
	if (unlikely(full && (len != nrd))) {
		fuseq_log_err("header length mismatch: "
			      "opc=%d nrd=%lu len=%lu ",
			      opc, nrd, len);
		return -SILOFS_EIO;
	}
	return 0;
}

static int fqd_check_pipe_pre(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);
	const struct silofs_pipe *pipe = &fqd->fqd_piper.pipe;
	const size_t buffsize = fq->fq_coni.buffsize;

	if (unlikely((int)buffsize < pipe->size)) {
		fuseq_log_err("pipe-fuse mismatch: pipesize=%d buffsize=%zu ",
			      pipe->size, buffsize);
		return -SILOFS_EIO;
	}
	if (unlikely(pipe->pend != 0)) {
		fuseq_log_err("pipe not empty: pend=%d fuse_fd=%d", pipe->pend,
			      fq->fq_fuse_fd);
		return -SILOFS_EIO;
	}
	return 0;
}

static int fqd_wait_request(const struct silofs_fuseq_dispatcher *fqd)
{
	const int fuse_fd = fqd_fuse_fd(fqd);
	const int timout_millisec = 100 + (int)(fqd->fqd_th.idx);

	return silofs_sys_pollin_rfd(fuse_fd, timout_millisec);
}

static int fqd_recv_buf(const struct silofs_fuseq_dispatcher *fqd, void *buf,
			size_t cnt, size_t *out_sz)
{
	const int fuse_fd = fqd_fuse_fd(fqd);

	*out_sz = 0;
	return cnt ? silofs_sys_read(fuse_fd, buf, cnt, out_sz) : 0;
}

static int fqd_recv_in_all(struct silofs_fuseq_dispatcher *fqd, size_t *out_sz)
{
	struct silofs_fuseq_in *in = fqd_in_of(fqd);

	return fqd_recv_buf(fqd, in, fqd_max_inlen(fqd), out_sz);
}

static int fqd_recv_copy_in(struct silofs_fuseq_dispatcher *fqd)
{
	size_t len = 0;
	int err;

	err = fqd_recv_in_all(fqd, &len);
	if (err == -ETIMEDOUT) {
		return err;
	}
	if (unlikely(err)) {
		fuseq_log_err("read fuse-to-buff failed: fuse_fd=%d err=%d",
			      fqd_fuse_fd(fqd), err);
		return err;
	}
	if (unlikely(len < sizeof(struct fuse_in_header))) {
		fuseq_log_err("fuse read-in too-short: len=%lu", len);
		return -SILOFS_EIO;
	}
	return fqd_check_inhdr(fqd, len, true);
}

static int
fqd_splice_into_pipe(struct silofs_fuseq_dispatcher *fqd, size_t cnt)
{
	struct silofs_pipe *pipe = &fqd->fqd_piper.pipe;
	const int fuse_fd = fqd_fuse_fd(fqd);
	int err;

	silofs_assert_eq(pipe->pend, 0);
	silofs_assert_gt(cnt, 0);
	silofs_assert_le(cnt, pipe->size);

	err = silofs_pipe_splice_from_fd(pipe, fuse_fd, NULL, cnt,
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

static int fqd_copy_from_pipe_in(struct silofs_fuseq_dispatcher *fqd,
				 size_t head_sz, size_t cnt, size_t *out_ncp)
{
	struct silofs_fuseq_in *in = fqd_in_of(fqd);
	struct silofs_pipe *pipe = &fqd->fqd_piper.pipe;
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
static int fqd_recv_splice_in(struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);

	return fqd_splice_into_pipe(fqd, fq->fq_coni.buffsize);
}

/*
 * TODO-0056: Copy into in-buffer with offset to make I/O page-aligned
 *
 * When doing FUSE_WRITE in non-large mode, copy data into in buffer with
 * proper initial skip to make each sub-io copy operation touch only a single
 * memory page. Check that it improves performance.
 */
static int fqd_copy_pipe_in(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_fuseq_in *in = fqd_in_of(fqd);
	struct silofs_fuseq_hdr_in *hdr_in = &in->u.hdr;
	const size_t nsp = (size_t)(fqd->fqd_piper.pipe.pend);
	const size_t cnt = min(sizeof(in->u.write), nsp);
	size_t ncp1 = 0;
	size_t ncp2 = 0;
	size_t rem;
	int err;

	err = fqd_copy_from_pipe_in(fqd, 0, cnt, &ncp1);
	if (err) {
		return err;
	}
	rem = (size_t)hdr_in->hdr.len - ncp1;
	err = fqd_check_inhdr(fqd, ncp1, rem == 0);
	if (unlikely(err)) {
		return err;
	}
	if (!rem || fqd_has_large_write_in(fqd)) {
		return 0;
	}
	err = fqd_copy_from_pipe_in(fqd, ncp1, rem, &ncp2);
	if (unlikely(err)) {
		return err;
	}
	err = fqd_check_inhdr(fqd, ncp1 + ncp2, true);
	if (unlikely(err)) {
		return err;
	}
	return 0;
}

static bool fqd_has_exec_mode(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);

	return fuseq_is_active(fq) || fuseq_has_live_opers(fq);
}

static bool fqd_allowed_splice_in(const struct silofs_fuseq_dispatcher *fqd)
{
	return fuseq_allowed_splice(fqd_fuseq(fqd));
}

static int fqd_do_recv_in(struct silofs_fuseq_dispatcher *fqd, bool *out_spl)
{
	int err;

	if (!fqd_has_exec_mode(fqd)) {
		return -SILOFS_ENORX;
	}
	err = fqd_wait_request(fqd);
	if (err) {
		return err;
	}
	if (!fqd_allowed_splice_in(fqd)) {
		return fqd_recv_copy_in(fqd);
	}
	*out_spl = true;
	return fqd_recv_splice_in(fqd);
}

static int fqd_recv_in_locked(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_fuseq *fq = fqd_fuseq2(fqd);
	int err = 0;
	bool spliced = false;

	fuseq_lock_ch(fq);
	err = fqd_do_recv_in(fqd, &spliced);
	if (err == -SILOFS_EINVAL) {
		fuseq_log_err("unexpected input error: fuse_fd=%d err=%d",
			      fqd_fuse_fd(fqd), err);
		fuseq_set_non_active(fq);
	} else if (err == -ENODEV) {
		/* umount case: set non-active under channel-lock */
		fuseq_log_info("input status: err=%d", err);
		fuseq_set_non_active(fq);
	}
	fuseq_unlock_ch(fq);

	if (!err && spliced) {
		err = fqd_copy_pipe_in(fqd);
	}
	return err;
}

static int fqd_read_or_splice_request(struct silofs_fuseq_dispatcher *fqd)
{
	int err;

	err = fqd_check_pipe_pre(fqd);
	if (err) {
		return err;
	}
	err = fqd_recv_in_locked(fqd);
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

static int fqd_prep_request(struct silofs_fuseq_dispatcher *fqd)
{
	fqd_reset_inhdr(fqd);
	return silofs_piper_dispose(&fqd->fqd_piper);
}

static int fqd_recv_request(struct silofs_fuseq_dispatcher *fqd)
{
	int err;

	err = fqd_prep_request(fqd);
	if (err) {
		return err;
	}
	err = fqd_read_or_splice_request(fqd);
	if (err) {
		return err;
	}
	fqd->fqd_req_count++;
	return 0;
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
	if (rwi != NULL) {
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

static void fqd_init_piper(struct silofs_fuseq_dispatcher *fqd)
{
	silofs_piper_init(&fqd->fqd_piper);
}

static void fqd_fini_piper(struct silofs_fuseq_dispatcher *fqd)
{
	silofs_piper_close(&fqd->fqd_piper);
	silofs_piper_fini(&fqd->fqd_piper);
}

static struct silofs_alloc *
fqd_alloc(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);

	return fq->fq_alloc;
}

static int fqd_init_bufs(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_alloc *alloc = fqd_alloc(fqd);

	fqd->fqd_inb = inb_new(alloc);
	if (fqd->fqd_inb == NULL) {
		return -SILOFS_ENOMEM;
	}
	fqd->fqd_outb = outb_new(alloc);
	if (fqd->fqd_outb == NULL) {
		inb_del(fqd->fqd_inb, alloc);
		fqd->fqd_inb = NULL;
		return -SILOFS_ENOMEM;
	}
	return 0;
}

static void fqd_fini_bufs(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_alloc *alloc = fqd_alloc(fqd);

	if (fqd->fqd_outb != NULL) {
		outb_del(fqd->fqd_outb, alloc);
		fqd->fqd_outb = NULL;
	}
	if (fqd->fqd_inb != NULL) {
		inb_del(fqd->fqd_inb, alloc);
		fqd->fqd_inb = NULL;
	}
}

static int fqd_renew_bufs(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_alloc *alloc = fqd_alloc(fqd);
	struct silofs_fuseq_inb *inb = NULL;
	struct silofs_fuseq_outb *outb = NULL;

	inb = inb_new(alloc);
	if (inb == NULL) {
		return -SILOFS_ENOMEM;
	}
	if (fqd->fqd_inb != NULL) {
		inb_del(fqd->fqd_inb, alloc);
	}
	fqd->fqd_inb = inb;

	outb = outb_new(alloc);
	if (outb == NULL) {
		return -SILOFS_ENOMEM;
	}
	if (fqd->fqd_outb != NULL) {
		outb_del(fqd->fqd_outb, alloc);
	}
	fqd->fqd_outb = outb;
	return 0;
}

static int fqd_init_rwi(struct silofs_fuseq_dispatcher *fqd)
{
	fqd->fqd_rwi = rwi_new(fqd_alloc(fqd));
	return (fqd->fqd_rwi != NULL) ? 0 : -SILOFS_ENOMEM;
}

static void fqd_fini_rwi(struct silofs_fuseq_dispatcher *fqd)
{
	if (fqd->fqd_rwi != NULL) {
		rwi_del(fqd->fqd_rwi, fqd_alloc(fqd));
		fqd->fqd_rwi = NULL;
	}
}

static int fqd_init_op_args(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_oper_args *op_args = &fqd->fqd_args;

	silofs_memzero(op_args, sizeof(*op_args));
	return 0;
}

static void fqd_fini_op_args(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_oper_args *op_args = &fqd->fqd_args;

	silofs_memffff(op_args, sizeof(*op_args));
}

static int fqd_init(struct silofs_fuseq_dispatcher *fqd,
		    struct silofs_fuseq *fq, uint32_t idx)
{
	int err;

	STATICASSERT_LE(sizeof(*fqd), 4096);

	silofs_memzero(fqd, sizeof(*fqd));
	fqt_init(&fqd->fqd_th, fq, idx);
	list_head_init(&fqd->fqd_lh);
	fqd->fqd_inb = NULL;
	fqd->fqd_outb = NULL;
	fqd->fqd_req_count = 0;
	fqd->fqd_init_ok = false;

	err = fqd_init_bufs(fqd);
	if (err) {
		goto out_err;
	}
	err = fqd_init_rwi(fqd);
	if (err) {
		goto out_err;
	}
	err = fqd_init_op_args(fqd);
	if (err) {
		goto out_err;
	}
	fqd_init_piper(fqd);
	fqd->fqd_init_ok = true;
	return 0;
out_err:
	fqd_fini_op_args(fqd);
	fqd_fini_rwi(fqd);
	fqd_fini_bufs(fqd);
	return err;
}

static void fqd_fini(struct silofs_fuseq_dispatcher *fqd)
{
	list_head_fini(&fqd->fqd_lh);
	fqd_fini_piper(fqd);
	fqd_fini_op_args(fqd);
	fqd_fini_rwi(fqd);
	fqd_fini_bufs(fqd);
	fqt_fini(&fqd->fqd_th);
}

static int
fqd_open_piper(struct silofs_fuseq_dispatcher *fqd, size_t pipe_size_want)
{
	struct silofs_piper *piper = &fqd->fqd_piper;
	int err;

	err = silofs_piper_open(piper);
	if (err) {
		fuseq_log_warn("failed to open piper: err=%d", err);
		return err;
	}
	err = silofs_piper_try_grow(piper, pipe_size_want);
	if (err) {
		fuseq_log_warn("failed to grow pipe size: "
			       "pipe_size_curr=%d pipe_size_want=%zu err=%d",
			       piper->pipe.size, pipe_size_want, err);
		return err;
	}
	return 0;
}

static void fqd_close_piper(struct silofs_fuseq_dispatcher *fqd)
{
	silofs_piper_close(&fqd->fqd_piper);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fqd_check_input(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq_in *in = fqd_in_of(fqd);
	const uint32_t in_len = in->u.hdr.hdr.len;
	const uint32_t opcode = in->u.hdr.hdr.opcode;

	if (!in_len || !opcode) {
		fuseq_log_warn("bad fuse input: in_len=%u opcode=%u", in_len,
			       opcode);
		return -SILOFS_ENORX;
	}
	return 0;
}

static int fqd_recv_exec_request(struct silofs_fuseq_dispatcher *fqd)
{
	int err;

	if (!fqd_has_exec_mode(fqd)) {
		return -SILOFS_ENORX;
	}
	err = fqd_recv_request(fqd);
	if (err) {
		return err;
	}
	err = fqd_check_input(fqd);
	if (err) {
		return err;
	}
	err = fqd_exec_request(fqd);
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

static void fqd_post_timedout(struct silofs_fuseq_dispatcher *fqd)
{
	if (fqd->fqd_req_count > 0) {
		/* renew base state */
		fqd_renew_bufs(fqd);
		fqd->fqd_req_count = 0;
	}
}

static int fqd_exec_timedout(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_fuseq *fq = fqd_fuseq2(fqd);

	if (fuseq_is_normal(fq)) {
		fuseq_update_nexecs(fq, -1);
		fqd_post_timedout(fqd);
	}
	return 0;
}

static void fqd_suspend(const struct silofs_fuseq_dispatcher *fqd)
{
	silofs_unused(fqd);
	silofs_suspend_secs(1);
}

static bool fqd_is_leader(const struct silofs_fuseq_dispatcher *fqd)
{
	return (fqd->fqd_th.idx == 0);
}

static bool fqd_allowed_exec(const struct silofs_fuseq_dispatcher *fqd)
{
	const struct silofs_fuseq *fq = fqd_fuseq(fqd);

	/* bootstrap case-1: not all worker-threads to started */
	if (!fuseq_has_nactive_disptch(fq)) {
		return false;
	}
	/* bootstrap case-2: only first (leader) may operate */
	if (!fqd_is_leader(fqd) && !fuseq_is_normal(fq)) {
		return false;
	}
	return true;
}

static struct silofs_fuseq_thread *fqt_from_th(struct silofs_thread *th)
{
	return container_of(th, struct silofs_fuseq_thread, th);
}

static struct silofs_fuseq_dispatcher *fqd_from_th(struct silofs_thread *th)
{
	struct silofs_fuseq_thread *fqt = fqt_from_th(th);

	return container_of(fqt, struct silofs_fuseq_dispatcher, fqd_th);
}

static const char *fqd_thread_name(const struct silofs_fuseq_dispatcher *fqd)
{
	return fqd->fqd_th.th.name;
}

static void fqd_deactivate_fuseq(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_fuseq *fq = fqd_fuseq2(fqd);

	if (fq->fq_active) {
		fuseq_set_non_active(fq);
		fuseq_log_info("deactivated by: %s", fqd_thread_name(fqd));
	}
}

static int fqd_post_exec_once(struct silofs_fuseq_dispatcher *fqd, int status)
{
	const int err = -abs(status);

	/* normal case */
	if (!err) {
		return 0;
	}
	/* umount case */
	if (err == -ENODEV) {
		fqd_deactivate_fuseq(fqd);
		return err;
	}
	/* no-lock & interrupt cases */
	if ((err == -SILOFS_ENORX) || (err == -SILOFS_ENOTX)) {
		fqd_suspend(fqd);
		return 0;
	}
	/* termination case */
	if (err == -ENOENT) {
		fqd_suspend(fqd);
		return err;
	}
	/* abnormal failure */
	fuseq_log_err("abnormal error: %s err=%d", fqd_thread_name(fqd), err);
	return err;
}

static int fqd_exec_once(struct silofs_fuseq_dispatcher *fqd)
{
	int err = 0;

	/* allow only single worker on bootstrap */
	if (!fqd_allowed_exec(fqd)) {
		fqd_suspend(fqd);
		return 0;
	}
	/* serve single in-comming request */
	err = fqd_recv_exec_request(fqd);

	/* timeout case */
	if (err == -ETIMEDOUT) {
		fqd_exec_timedout(fqd);
		return 0;
	}

	/* post-execution action based on status code */
	return fqd_post_exec_once(fqd, err);
}

static int fqd_exec_loop(struct silofs_fuseq_dispatcher *fqd)
{
	int err = 0;

	while (fqd_has_exec_mode(fqd) && !err) {
		err = fqd_exec_once(fqd);
	}
	if (err && (err != -ENODEV)) {
		fuseq_log_warn("dispatch done: err=%d", err);
	}
	return err;
}

static int fqd_start(struct silofs_thread *th)
{
	struct silofs_fuseq_dispatcher *fqd = fqd_from_th(th);
	int err;

	fuseq_log_info("start: %s", th->name);
	err = fqt_block_thread_signals(&fqd->fqd_th);
	if (!err) {
		err = fqd_exec_loop(fqd);
	}
	fuseq_log_info("finish: %s", th->name);
	return err;
}

static int fqd_exec_thread(struct silofs_fuseq_dispatcher *fqd)
{
	return fqt_exec_thread(&fqd->fqd_th, fqd_start, "d");
}

static bool fqd_try_join_thread(struct silofs_fuseq_dispatcher *fqd)
{
	struct silofs_fuseq_thread *fqt = &fqd->fqd_th;

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

static int fqw_init(struct silofs_fuseq_worker *fqw, struct silofs_fuseq *fq,
		    uint32_t idx)
{
	STATICASSERT_LE(sizeof(*fqw), 256);

	silofs_memzero(fqw, sizeof(*fqw));
	fqt_init(&fqw->fqw_th, fq, idx);
	return 0;
}

static void fqw_fini(struct silofs_fuseq_worker *fqw)
{
	fqt_fini(&fqw->fqw_th);
}

static struct silofs_fuseq_worker *fqw_from_th(struct silofs_thread *th)
{
	return container_of(th, struct silofs_fuseq_worker, fqw_th);
}

static const struct silofs_fuseq *
fqw_fuseq(const struct silofs_fuseq_worker *fqw)
{
	return fqw->fqw_th.fq;
}

static struct silofs_fuseq *fqw_fuseq2(const struct silofs_fuseq_worker *fqw)
{
	return fqw->fqw_th.fq;
}

static void fqw_setup_self_task(const struct silofs_fuseq_worker *fqw,
				struct silofs_task *task)
{
	const struct silofs_fuseq *fq = fqw_fuseq(fqw);
	const struct silofs_fsenv *fsenv = fq->fq_fsenv;
	const struct silofs_fs_args *args = &fsenv->fse_args;

	silofs_task_set_creds(task, args->uid, args->gid, args->umask);
	silofs_task_set_ts(task, false);
	task->t_oper.op_pid = args->pid;
	task->t_exclusive = false;
}

static int fqw_do_exec_maintain(struct silofs_fuseq_worker *fqw,
				struct silofs_task *task, int flags)
{
	int err1 = 0;
	int err2 = 0;

	fqw_setup_self_task(fqw, task);
	silofs_task_rwlock_fs(task);
	err1 = silofs_fs_maintain(task, flags);
	err2 = task_submit(task);
	silofs_task_rwunlock_fs(task);

	return err1 ? err1 : err2;
}

static int fqw_exec_maintain(struct silofs_fuseq_worker *fqw, int flags)
{
	struct silofs_task task;
	int err;

	task_init_by(&task, fqw_fuseq2(fqw));
	err = fqw_do_exec_maintain(fqw, &task, flags);
	task_fini(&task);
	return err;
}

static int fqw_exec_once(struct silofs_fuseq_worker *fqw)
{
	struct silofs_fuseq *fq = fqw_fuseq2(fqw);
	int ret = 0;

	if (!fuseq_is_normal(fq)) {
		/* yield to let other have a chance to do some work */
		silofs_sys_sched_yield();
	} else if (fuseq_is_nexecs_idle(fq)) {
		/* do flush-and-relax in idle mode */
		ret = fqw_exec_maintain(fqw, SILOFS_F_IDLE);
	} else {
		/* do flush-and-relax along-side dispatcher threads */
		ret = fqw_exec_maintain(fqw, SILOFS_F_INTERN);
	}
	return ret;
}

static void fqw_post_exec(const struct silofs_fuseq_worker *fqw)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
	struct silofs_fuseq *fq = fqw_fuseq2(fqw);

	if (fuseq_has_memory_pressure(fq)) {
		/* has memory-pressure */
		ts.tv_nsec = 10000;
	} else if (!fuseq_is_nexecs_idle(fq)) {
		/* active mode */
		ts.tv_nsec = 1000000;
	} else {
		/* idle mode */
		ts.tv_sec = 1;
	}
	silofs_suspend_ts(&ts);
}

static bool fqw_has_exec_mode(const struct silofs_fuseq_worker *fqw)
{
	const struct silofs_fuseq *fq = fqw_fuseq(fqw);

	return fuseq_is_active(fq) || fuseq_has_live_opers(fq);
}

static int fqw_exec_loop(struct silofs_fuseq_worker *fqw)
{
	int err = 0;

	while (fqw_has_exec_mode(fqw) && !err) {
		err = fqw_exec_once(fqw);
		fqw_post_exec(fqw);
	}
	return err;
}

static int fqw_start(struct silofs_thread *th)
{
	struct silofs_fuseq_worker *fqw = fqw_from_th(th);
	int err;

	fuseq_log_info("start: %s", th->name);
	err = fqt_block_thread_signals(&fqw->fqw_th);
	if (!err) {
		err = fqw_exec_loop(fqw);
		fuseq_log_warn("worker done: err=%d", err);
	}
	fuseq_log_info("finish: %s", th->name);
	return err;
}

static int fqw_exec_thread(struct silofs_fuseq_worker *fqw)
{
	return fqt_exec_thread(&fqw->fqw_th, fqw_start, "w");
}

static bool fqw_try_join_thread(struct silofs_fuseq_worker *fqw)
{
	struct silofs_fuseq_thread *fqt = &fqw->fqw_th;

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

static int fuseq_update_dispatchers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_dispatcher *fqd = NULL;
	const size_t buffsize = fq->fq_coni.buffsize;
	const size_t pipesize = buffsize;
	size_t cnt = 0;
	int err;

	if (!fq->fq_may_splice) {
		/* operate in non-splice mode */
		return 0;
	}
	fuseq_log_dbg("set splice-mode: pipesize=%zu", pipesize);
	for (size_t i = 0; i < fq->fq_subx.fq_ndisptch_lim; ++i) {
		fqd = &fq->fq_subx.fq_disptchs[i];
		err = fqd_open_piper(fqd, pipesize);
		if (err == -EPERM) {
			goto can_not_splice;
		} else if (err) {
			return err;
		}
		cnt++;
	}
	/* normal mode: all workers set with proper pipe */
	return 0;

can_not_splice:
	/* can not have proper pipe size: fallback to buffer-only mode */
	fuseq_log_dbg("disable splice mode: cnt=%zu", cnt);
	for (size_t i = 0; i < cnt; ++i) {
		fqd = &fq->fq_subx.fq_disptchs[i];
		fqd_close_piper(fqd);
	}
	fq->fq_may_splice = false;
	return 0;
}

static int fuseq_init_locks(struct silofs_fuseq *fq)
{
	int err;

	err = silofs_sem_init(&fq->fq_sem);
	if (err) {
		return err;
	}
	err = silofs_mutex_init(&fq->fq_ch_lock);
	if (err) {
		goto out_err1;
	}
	err = silofs_mutex_init(&fq->fq_op_lock);
	if (err) {
		goto out_err2;
	}
	err = silofs_mutex_init(&fq->fq_ctl_lock);
	if (err) {
		goto out_err3;
	}
	fq->fq_init_locks = true;
	return 0;

out_err3:
	silofs_mutex_fini(&fq->fq_op_lock);
out_err2:
	silofs_mutex_fini(&fq->fq_ch_lock);
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
		silofs_sem_fini(&fq->fq_sem);
	}
}

static void
fuseq_init_common(struct silofs_fuseq *fq, struct silofs_alloc *alloc,
		  const struct silofs_fuseq_subx *subx)
{
	memcpy(&fq->fq_subx, subx, sizeof(fq->fq_subx));
	fq->fq_subx.fq_nworkers_run = 0;
	fq->fq_subx.fq_ndisptch_run = 0;
	listq_init(&fq->fq_curr_opers);
	fq->fq_fsenv = NULL;
	fq->fq_pagesize = (size_t)silofs_sc_page_size();
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
	fq->fq_writeback_cache = false;
	fq->fq_may_splice = true;
	fq->fq_fs_owner = (uid_t)(-1);
}

static int fuseq_init_workers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_worker *fqw = NULL;
	int err;

	for (uint32_t i = 0; i < fq->fq_subx.fq_nworkers_lim; ++i) {
		fqw = &fq->fq_subx.fq_workers[i];
		err = fqw_init(fqw, fq, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static void fuseq_fini_workers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_worker *fqw = NULL;

	silofs_assert_gt(fq->fq_subx.fq_nworkers_lim, 0);
	for (size_t i = 0; i < fq->fq_subx.fq_nworkers_lim; ++i) {
		fqw = &fq->fq_subx.fq_workers[i];
		fqw_fini(fqw);
	}
}

static int fuseq_init_dispatchers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_dispatcher *fqd = NULL;
	int err;

	for (uint32_t i = 0; i < fq->fq_subx.fq_ndisptch_lim; ++i) {
		fqd = &fq->fq_subx.fq_disptchs[i];
		err = fqd_init(fqd, fq, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static void fuseq_fini_dispatchers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_dispatcher *fqd = NULL;

	for (uint32_t i = 0; i < fq->fq_subx.fq_ndisptch_lim; ++i) {
		fqd = &fq->fq_subx.fq_disptchs[i];
		fqd_fini(fqd);
	}
}

static size_t fuseq_bufsize_max(const struct silofs_fuseq *fq)
{
	const struct silofs_fuseq_dispatcher *fqd =
		&fq->fq_subx.fq_disptchs[0];
	const size_t inbuf_max = sizeof(*fqd->fqd_inb);
	const size_t outbuf_max = sizeof(*fqd->fqd_outb);

	unused(fqd); /* make clangscan happy */
	return max(inbuf_max, outbuf_max);
}

static int
fuseq_resolve_bufsize(const struct silofs_fuseq *fq, size_t *out_bufsize)
{
	const size_t page_size = fq->fq_pagesize;
	size_t bufsize_min;
	size_t bufsize_max;
	size_t bufsize_may;
	size_t bufsize;

	STATICASSERT_GE(FUSE_MIN_READ_BUFFER, 2 * FUSE_BUFFER_HEADER_SIZE);

	bufsize_min = min(FUSE_MIN_READ_BUFFER, 2 * SILOFS_LBK_SIZE);
	bufsize_max = fuseq_bufsize_max(fq);
	if (fq->fq_may_splice) {
		bufsize_may = silofs_pipe_size_of(bufsize_max);
	} else {
		bufsize_may = bufsize_max;
	}
	bufsize = (min(bufsize_may, bufsize_max) / page_size) * page_size;
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
	if (max_write < max(2 * page_size, FUSE_MIN_READ_BUFFER)) {
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
	coni->max_pages = (uint32_t)min(max_pages, UINT16_MAX);

	return 0;
}

static void fuseq_init_conn_info(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_conn_info *coni = &fq->fq_coni;

	memset(coni, 0, sizeof(*coni));
	coni->proto_major = FUSE_KERNEL_VERSION;
	coni->proto_minor = FUSE_KERNEL_MINOR_VERSION;
	coni->time_gran = 1;

	/*
	 * Follow similar values as those at libfuse:lib/fuse_lowlevel.c
	 * However, libfuse has: congestion_threshold = max_background * 3 / 4
	 * but it is hard to understand from its code or kernel code why it is
	 * defined that way. Needs further investigation.
	 */
	coni->max_background = (1 << 16) - 1;
	coni->congestion_threshold = coni->max_background / 2;
}

static int fuseq_init(struct silofs_fuseq *fq, struct silofs_alloc *alloc,
		      const struct silofs_fuseq_subx *subx)
{
	int err;

	fuseq_init_common(fq, alloc, subx);
	fuseq_init_conn_info(fq);

	err = fuseq_init_locks(fq);
	if (err) {
		return err;
	}
	err = fuseq_init_workers(fq);
	if (err) {
		goto out_err;
	}
	err = fuseq_init_dispatchers(fq);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	fuseq_fini_dispatchers(fq);
	fuseq_fini_workers(fq);
	fuseq_fini_locks(fq);
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
	fuseq_fini_dispatchers(fq);
	fuseq_fini_workers(fq);
	fuseq_fini_locks(fq);
	listq_fini(&fq->fq_curr_opers);
	fq->fq_alloc = NULL;
	fq->fq_fsenv = NULL;
}

int silofs_fuseq_update(struct silofs_fuseq *fq)
{
	const bool may_splice = fq->fq_may_splice;
	int err;

	err = fuseq_update_conn_info(fq);
	if (err) {
		return err;
	}
	err = fuseq_update_dispatchers(fq);
	if (err) {
		return err;
	}
	/*
	 * Special case: fallback from pipe-splice mode to buffer-copy mode due
	 * to insufficient resources to create big-enough pipes. Need to update
	 * connection-info settings.
	 */
	if (may_splice != fq->fq_may_splice) {
		err = fuseq_update_conn_info(fq);
		if (err) {
			return err;
		}
	}
	return 0;
}

static bool has_allow_other_mode(const struct silofs_fsenv *fsenv)
{
	const enum silofs_env_flags mask = SILOFS_ENVF_ALLOWOTHER;

	return (fsenv->fse_ctl_flags & mask) == mask;
}

int silofs_fuseq_mount(struct silofs_fuseq *fq, struct silofs_fsenv *fsenv,
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

	uid = fsenv->fse_owner.uid;
	gid = fsenv->fse_owner.gid;
	ms_flags = fsenv->fse_ms_flags;
	allow_other = has_allow_other_mode(fsenv);

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

	fq->fq_fs_owner = fsenv->fse_owner.uid;
	fq->fq_fuse_fd = fd;
	fq->fq_mount = true;
	fq->fq_fsenv = fsenv;

	/* TODO: Looks like kernel needs time. why? */
	silofs_suspend_secs(1);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_start_workers(struct silofs_fuseq *fq)
{
	const size_t nworkers_lim = fq->fq_subx.fq_nworkers_lim;
	int err;

	fuseq_log_dbg("start workers: lim=%zu", nworkers_lim);
	fq->fq_subx.fq_nworkers_run = 0;
	for (size_t i = 0; i < nworkers_lim; ++i) {
		err = fqw_exec_thread(&fq->fq_subx.fq_workers[i]);
		if (err) {
			return err;
		}
		silofs_sys_sched_yield();
		fq->fq_subx.fq_nworkers_run++;
	}
	return 0;
}

static bool fuseq_join_workers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_worker *fqw = NULL;
	size_t njoined = 0;

	for (size_t i = 0; i < fq->fq_subx.fq_nworkers_run; ++i) {
		fqw = &fq->fq_subx.fq_workers[i];
		if (fqw->fqw_th.joined) {
			njoined++;
		} else if (fqw_try_join_thread(fqw)) {
			njoined++;
		}
		silofs_sys_sched_yield();
	}
	return (njoined == fq->fq_subx.fq_nworkers_run);
}

static void fuseq_finish_workers(struct silofs_fuseq *fq)
{
	const size_t nworkers_run = fq->fq_subx.fq_nworkers_run;
	int retry = 30;

	fuseq_log_dbg("finish workers: nworkers_run=%zu", nworkers_run);
	while (--retry > 0) {
		if (fuseq_join_workers(fq)) {
			break;
		}
		silofs_suspend_secs(1);
	}
	if (retry == 0) {
		silofs_panic("failed to join all worker threads: "
			     "nworkers_run=%zu",
			     nworkers_run);
	}
	fq->fq_subx.fq_nworkers_run = 0;
}

static int fuseq_start_dispatchers(struct silofs_fuseq *fq)
{
	const size_t ndisptch_lim = fq->fq_subx.fq_ndisptch_lim;
	int err;

	fuseq_log_dbg("start dispatchers: lim=%zu", ndisptch_lim);
	fq->fq_subx.fq_ndisptch_run = 0;
	for (size_t i = 0; i < ndisptch_lim; ++i) {
		err = fqd_exec_thread(&fq->fq_subx.fq_disptchs[i]);
		if (err) {
			return err;
		}
		silofs_sys_sched_yield();
		fq->fq_subx.fq_ndisptch_run++;
	}
	return 0;
}

static bool fuseq_join_dispatchers(struct silofs_fuseq *fq)
{
	struct silofs_fuseq_dispatcher *fqd = NULL;
	size_t njoined = 0;

	for (size_t i = 0; i < fq->fq_subx.fq_ndisptch_run; ++i) {
		fqd = &fq->fq_subx.fq_disptchs[i];
		if (fqd->fqd_th.joined) {
			njoined++;
		} else if (fqd_try_join_thread(fqd)) {
			njoined++;
		}
		silofs_sys_sched_yield();
	}
	return (njoined == fq->fq_subx.fq_ndisptch_run);
}

static void fuseq_finish_dispatchers(struct silofs_fuseq *fq)
{
	const size_t ndisptch_run = fq->fq_subx.fq_ndisptch_run;
	int retry = 30;

	fuseq_log_dbg("finish dispatchers: ndisptch_run=%zu", ndisptch_run);
	while (--retry > 0) {
		if (fuseq_join_dispatchers(fq)) {
			break;
		}
		silofs_suspend_secs(1);
	}
	if (retry == 0) {
		silofs_panic("failed to join all dispatchers threads: "
			     "ndisptch_run=%zu",
			     ndisptch_run);
	}
	fq->fq_subx.fq_ndisptch_run = 0;
}

static int fuseq_start_exec_threads(struct silofs_fuseq *fq)
{
	int err;

	fuseq_set_active(fq);
	err = fuseq_start_workers(fq);
	if (err) {
		return err;
	}
	err = fuseq_start_dispatchers(fq);
	if (err) {
		return err;
	}
	return 0;
}

static void fuseq_finish_exec_threads(struct silofs_fuseq *fq)
{
	fuseq_set_non_active(fq);
	fuseq_finish_dispatchers(fq);
	fuseq_finish_workers(fq);
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
			silofs_suspend_secs(1);
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
	fq->fq_fsenv = NULL;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

typedef int (*silofs_oper_fn)(struct silofs_task *, struct silofs_oper_args *);

static int op_setattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	struct silofs_stat *out_st = &args->out.setattr.st;
	const struct stat *tms = &args->in.setattr.tims;
	const loff_t size = args->in.setattr.size;
	const mode_t mode = args->in.setattr.mode;
	const uid_t uid = args->in.setattr.uid;
	const gid_t gid = args->in.setattr.gid;
	const ino_t ino = args->in.setattr.ino;
	int err = 0;

	out_st->gen = 0;
	if (args->in.setattr.set_amtime_now) {
		err = silofs_fs_utimens(task, ino, tms, out_st);
		if (err) {
			goto out;
		}
	}
	if (args->in.setattr.set_mode) {
		err = silofs_fs_chmod(task, ino, mode, tms, out_st);
		if (err) {
			goto out;
		}
	}
	if (args->in.setattr.set_uid_gid) {
		err = silofs_fs_chown(task, ino, uid, gid, tms, out_st);
		if (err) {
			goto out;
		}
	}
	if (args->in.setattr.set_size) {
		err = silofs_fs_truncate(task, ino, size, out_st);
		if (err) {
			goto out;
		}
	}
	if (args->in.setattr.set_amctime && !args->in.setattr.set_nontime) {
		err = silofs_fs_utimens(task, ino, tms, out_st);
		if (err) {
			goto out;
		}
	}
out:
	if (!err && !out_st->gen) {
		err = silofs_fs_getattr(task, ino, out_st);
	}
	return err;
}

static int op_lookup(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_lookup(task, args->in.lookup.parent,
				args->in.lookup.name, &args->out.lookup.st);
}

static int op_forget(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_forget(task, args->in.forget.ino,
				args->in.forget.nlookup);
}

static int
op_forget_one(struct silofs_task *task, const struct fuse_forget_one *one)
{
	return silofs_fs_forget(task, (ino_t)(one->nodeid), one->nlookup);
}

static int
op_batch_forget(struct silofs_task *task, struct silofs_oper_args *args)
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
	return silofs_fs_getattr(task, args->in.getattr.ino,
				 &args->out.getattr.st);
}

static int op_readlink(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_readlink(task, args->in.readlink.ino,
				  args->in.readlink.ptr, args->in.readlink.lim,
				  &args->out.readlink.len);
}

static int op_symlink(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_symlink(task, args->in.symlink.parent,
				 args->in.symlink.name,
				 args->in.symlink.symval,
				 &args->out.symlink.st);
}

static int op_mknod(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_mknod(task, args->in.mknod.parent,
			       args->in.mknod.name, args->in.mknod.mode,
			       args->in.mknod.rdev, &args->out.mknod.st);
}

static int op_mkdir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_mkdir(task, args->in.mkdir.parent,
			       args->in.mkdir.name, args->in.mkdir.mode,
			       &args->out.mkdir.st);
}

static int op_unlink(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_unlink(task, args->in.unlink.parent,
				args->in.unlink.name);
}

static int op_rmdir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_rmdir(task, args->in.rmdir.parent,
			       args->in.rmdir.name);
}

static int op_rename(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_rename(task, args->in.rename.parent,
				args->in.rename.name,
				args->in.rename.newparent,
				args->in.rename.newname,
				args->in.rename.flags);
}

static int op_link(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_link(task, args->in.link.ino, args->in.link.parent,
			      args->in.link.name, &args->out.link.st);
}

static int op_open(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_open(task, args->in.open.ino, args->in.open.o_flags);
}

static int op_statfs(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_statfs(task, args->in.statfs.ino,
				&args->out.statfs.stv);
}

static int op_release(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_release(task, args->in.release.ino,
				 args->in.release.o_flags,
				 args->in.release.flush);
}

static int op_fsync(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_fsync(task, args->in.fsync.ino,
			       args->in.fsync.datasync);
}

static int op_setxattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_setxattr(
		task, args->in.setxattr.ino, args->in.setxattr.name,
		args->in.setxattr.value, args->in.setxattr.size,
		args->in.setxattr.flags, args->in.setxattr.kill_sgid);
}

static int op_getxattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_getxattr(task, args->in.getxattr.ino,
				  args->in.getxattr.name,
				  args->in.getxattr.buf,
				  args->in.getxattr.size,
				  &args->out.getxattr.size);
}

static int
op_listxattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_listxattr(task, args->in.listxattr.ino,
				   args->in.listxattr.lxa_ctx);
}

static int
op_removexattr(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_removexattr(task, args->in.removexattr.ino,
				     args->in.removexattr.name);
}

static int op_flush(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_flush(task, args->in.flush.ino,
			       args->in.flush.ino == 0);
}

static int op_opendir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_opendir(task, args->in.opendir.ino,
				 args->in.opendir.o_flags);
}

static int op_readdir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_readdir(task, args->in.readdir.ino,
				 args->in.readdir.rd_ctx);
}

static int
op_readdirplus(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_readdirplus(task, args->in.readdir.ino,
				     args->in.readdir.rd_ctx);
}

static int
op_releasedir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_releasedir(task, args->in.releasedir.ino,
				    args->in.releasedir.o_flags);
}

static int op_fsyncdir(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_fsyncdir(task, args->in.fsyncdir.ino,
				  args->in.fsyncdir.datasync);
}

static int op_access(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_access(task, args->in.access.ino,
				args->in.access.mask);
}

static int op_create(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_create(task, args->in.create.parent,
				args->in.create.name, args->in.create.o_flags,
				args->in.create.mode, &args->out.create.st);
}

static int
op_fallocate(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_fallocate(task, args->in.fallocate.ino,
				   args->in.fallocate.mode,
				   args->in.fallocate.off,
				   args->in.fallocate.len);
}

static int op_lseek(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_lseek(task, args->in.lseek.ino, args->in.lseek.off,
			       args->in.lseek.whence, &args->out.lseek.off);
}

static int
op_copy_file_range(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_copy_file_range(task, args->in.copy_file_range.ino_in,
					 args->in.copy_file_range.off_in,
					 args->in.copy_file_range.ino_out,
					 args->in.copy_file_range.off_out,
					 args->in.copy_file_range.len,
					 args->in.copy_file_range.flags,
					 &args->out.copy_file_range.ncp);
}

static int op_read_buf(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_read(task, args->in.read.ino, args->in.read.buf,
			      args->in.read.len, args->in.read.off,
			      args->in.read.o_flags, &args->out.read.nrd);
}

static int
op_read_iter(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_read_iter(task, args->in.read.ino,
				   args->in.read.o_flags,
				   args->in.read.rwi_ctx);
}

static int op_read(struct silofs_task *task, struct silofs_oper_args *args)
{
	return (args->in.read.rwi_ctx != NULL) ? op_read_iter(task, args) :
						 op_read_buf(task, args);
}

static int
op_write_buf(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_write(task, args->in.write.ino, args->in.write.buf,
			       args->in.write.len, args->in.write.off,
			       args->in.write.o_flags, &args->out.write.nwr);
}

static int
op_write_iter(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_write_iter(task, args->in.write.ino,
				    args->in.write.o_flags,
				    args->in.write.rwi_ctx);
}

static int op_write(struct silofs_task *task, struct silofs_oper_args *args)
{
	return (args->in.write.rwi_ctx != NULL) ? op_write_iter(task, args) :
						  op_write_buf(task, args);
}

static int op_syncfs(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_syncfs(task, args->in.syncfs.ino,
				args->in.syncfs.flags);
}

static int
op_ioctl_query(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_query(task, args->in.query.ino, args->in.query.qtype,
			       &args->out.query.qry);
}

static int
op_ioctl_clone(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_clone(task, args->in.clone.ino, args->in.clone.flags,
			       &args->out.clone.brecs);
}

static int
op_ioctl_syncfs(struct silofs_task *task, struct silofs_oper_args *args)
{
	/*
	 * Currently (Linux kernel v6.3) fuse has 'fc->sync_fs = true' only for
	 * fs/fuse/virtio_fs.c code-path. Thus, implement full sync-fs via
	 * dedicated ioctl.
	 */
	return op_syncfs(task, args);
}

static int
op_ioctl_tune(struct silofs_task *task, struct silofs_oper_args *args)
{
	return silofs_fs_tune(task, args->in.tune.ino,
			      args->in.tune.iflags_want,
			      args->in.tune.iflags_dont);
}

static int op_ioctl(struct silofs_task *task, struct silofs_oper_args *args)
{
	int ret;

	switch (args->ioc_cmd) {
	case SILOFS_IOC_QUERY:
		ret = op_ioctl_query(task, args);
		break;
	case SILOFS_IOC_CLONE:
		ret = op_ioctl_clone(task, args);
		break;
	case SILOFS_IOC_SYNCFS:
		ret = op_ioctl_syncfs(task, args);
		break;
	case SILOFS_IOC_TUNE:
		ret = op_ioctl_tune(task, args);
		break;
	default:
		ret = -SILOFS_ENOSYS;
		break;
	}
	return ret;
}

static const silofs_oper_fn silofs_op_tbl[FUSEQ_CMD_MAX] = {
	[FUSE_LOOKUP] = op_lookup,
	[FUSE_FORGET] = op_forget,
	[FUSE_GETATTR] = op_getattr,
	[FUSE_SETATTR] = op_setattr,
	[FUSE_READLINK] = op_readlink,
	[FUSE_SYMLINK] = op_symlink,
	[FUSE_MKNOD] = op_mknod,
	[FUSE_MKDIR] = op_mkdir,
	[FUSE_UNLINK] = op_unlink,
	[FUSE_RMDIR] = op_rmdir,
	[FUSE_RENAME] = op_rename,
	[FUSE_LINK] = op_link,
	[FUSE_OPEN] = op_open,
	[FUSE_READ] = op_read,
	[FUSE_WRITE] = op_write,
	[FUSE_STATFS] = op_statfs,
	[FUSE_RELEASE] = op_release,
	[FUSE_FSYNC] = op_fsync,
	[FUSE_SETXATTR] = op_setxattr,
	[FUSE_GETXATTR] = op_getxattr,
	[FUSE_LISTXATTR] = op_listxattr,
	[FUSE_REMOVEXATTR] = op_removexattr,
	[FUSE_FLUSH] = op_flush,
	[FUSE_OPENDIR] = op_opendir,
	[FUSE_READDIR] = op_readdir,
	[FUSE_RELEASEDIR] = op_releasedir,
	[FUSE_FSYNCDIR] = op_fsyncdir,
	[FUSE_ACCESS] = op_access,
	[FUSE_CREATE] = op_create,
	[FUSE_BATCH_FORGET] = op_batch_forget,
	[FUSE_FALLOCATE] = op_fallocate,
	[FUSE_READDIRPLUS] = op_readdirplus,
	[FUSE_RENAME2] = op_rename,
	[FUSE_LSEEK] = op_lseek,
	[FUSE_COPY_FILE_RANGE] = op_copy_file_range,
	[FUSE_SYNCFS] = op_syncfs,
	[FUSE_IOCTL] = op_ioctl,
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

static void *address_at(void *ptr, ptrdiff_t dif)
{
	return (int8_t *)ptr + dif;
}

static uint32_t calc_ndisptch_lim(uint32_t nwant)
{
	return clamp(nwant, 2, 16);
}

static uint32_t calc_nworksers_lim(uint32_t nwant)
{
	return clamp(nwant, 1, 8);
}

static size_t fuseq_calc_selfsize(const struct silofs_fuseq *fq,
				  const struct silofs_fuseq_subx *subx)
{
	const size_t pgsz = (size_t)silofs_sc_page_size();
	const size_t dsz = sizeof(subx->fq_disptchs[0]);
	const size_t wsz = sizeof(subx->fq_workers[0]);
	size_t sz;

	sz = sizeof(*fq);
	sz += (subx->fq_ndisptch_lim * dsz);
	sz += (subx->fq_nworkers_lim * wsz);
	sz = div_round_up(sz, pgsz) * pgsz;
	return sz;
}

static void
fuseq_resolve_subx(struct silofs_fuseq *fq, struct silofs_fuseq_subx *subx)
{
	const size_t nds = subx->fq_ndisptch_lim;
	const size_t dsz = sizeof(subx->fq_disptchs[0]);
	const size_t dssz = dsz * nds;

	subx->fq_disptchs = address_at(fq, sizeof(*fq));
	subx->fq_workers = address_at(subx->fq_disptchs, (ptrdiff_t)dssz);
}

int silofs_fuseq_new(struct silofs_alloc *alloc, struct silofs_fuseq **out_fq)
{
	struct silofs_fuseq *fq = NULL;
	const uint32_t nproc = (uint32_t)silofs_sc_nproc_onln();
	struct silofs_fuseq_subx fq_subx = {
		.fq_workers = NULL,
		.fq_disptchs = NULL,
		.fq_nworkers_lim = calc_nworksers_lim(nproc / 2),
		.fq_nworkers_run = 0,
		.fq_ndisptch_lim = calc_ndisptch_lim(nproc),
		.fq_ndisptch_run = 0
	};
	size_t fq_msz = 0;
	void *fq_mem = NULL;
	int err;

	fq_msz = fuseq_calc_selfsize(fq, &fq_subx);
	fq_mem = silofs_memalloc(alloc, fq_msz, SILOFS_ALLOCF_BZERO);
	if (fq_mem == NULL) {
		return -SILOFS_ENOMEM;
	}

	fq = fq_mem;
	fuseq_resolve_subx(fq, &fq_subx);
	err = fuseq_init(fq, alloc, &fq_subx);
	if (err) {
		silofs_memfree(alloc, fq_mem, fq_msz, 0);
		return err;
	}
	fq->fq_selfsize = fq_msz;

	*out_fq = fq;
	return 0;
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
	REQUIRE_SIZEOF(struct silofs_fuseq_init_in, 104);
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
