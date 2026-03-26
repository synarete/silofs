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
#ifndef SILOFS_FQTYPES_H_
#define SILOFS_FQTYPES_H_

#include <linux/fuse.h>
#include <silofs/ondisk.h>

#define SILOFS_CMD_TAIL_MAX \
	(SILOFS_IO_SIZE_MAX - sizeof(struct fuse_in_header))

#define SILOFS_CMD_FORGET_ONE_MAX \
	(SILOFS_CMD_TAIL_MAX / sizeof(struct fuse_forget_one))

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
	uint8_t               cmd[SILOFS_IO_SIZE_MAX];
	uint8_t tail[SILOFS_LBK_SIZE - sizeof(struct fuse_in_header)];
};

struct silofs_fuseq_init_in {
	struct fuse_in_header hdr;
	struct fuse_init_in   arg;
};

struct silofs_fuseq_setattr_in {
	struct fuse_in_header  hdr;
	struct fuse_setattr_in arg;
};

struct silofs_fuseq_lookup_in {
	struct fuse_in_header hdr;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_forget_in {
	struct fuse_in_header hdr;
	struct fuse_forget_in arg;
};

struct silofs_fuseq_batch_forget_in {
	struct fuse_in_header       hdr;
	struct fuse_batch_forget_in arg;
	struct fuse_forget_one      one[SILOFS_CMD_FORGET_ONE_MAX];
};

struct silofs_fuseq_getattr_in {
	struct fuse_in_header  hdr;
	struct fuse_getattr_in arg;
};

struct silofs_fuseq_symlink_in {
	struct fuse_in_header hdr;
	char name_target[SILOFS_NAME_MAX + 1 + SILOFS_SYMLNK_MAX];
};

struct silofs_fuseq_mknod_in {
	struct fuse_in_header hdr;
	struct fuse_mknod_in  arg;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_mkdir_in {
	struct fuse_in_header hdr;
	struct fuse_mkdir_in  arg;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_unlink_in {
	struct fuse_in_header hdr;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_rmdir_in {
	struct fuse_in_header hdr;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_rename_in {
	struct fuse_in_header hdr;
	struct fuse_rename_in arg;
	char                  name_newname[2 * (SILOFS_NAME_MAX + 1)];
};

struct silofs_fuseq_link_in {
	struct fuse_in_header hdr;
	struct fuse_link_in   arg;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_open_in {
	struct fuse_in_header hdr;
	struct fuse_open_in   arg;
};

struct silofs_fuseq_release_in {
	struct fuse_in_header  hdr;
	struct fuse_release_in arg;
};

struct silofs_fuseq_fsync_in {
	struct fuse_in_header hdr;
	struct fuse_fsync_in  arg;
};

struct silofs_fuseq_setxattr1_in {
	struct fuse_in_header    hdr;
	struct fuse_setxattr1_in arg;
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_XATTR_VALUE_MAX];
};

struct silofs_fuseq_setxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_setxattr_in arg;
	char name_value[SILOFS_NAME_MAX + 1 + SILOFS_XATTR_VALUE_MAX];
};

struct silofs_fuseq_getxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getxattr_in arg;
	char                    name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_listxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getxattr_in arg;
};

struct silofs_fuseq_removexattr_in {
	struct fuse_in_header hdr;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_flush_in {
	struct fuse_in_header hdr;
	struct fuse_flush_in  arg;
};

struct silofs_fuseq_opendir_in {
	struct fuse_in_header hdr;
	struct fuse_open_in   arg;
};

struct silofs_fuseq_readdir_in {
	struct fuse_in_header hdr;
	struct fuse_read_in   arg;
};

struct silofs_fuseq_releasedir_in {
	struct fuse_in_header  hdr;
	struct fuse_release_in arg;
};

struct silofs_fuseq_fsyncdir_in {
	struct fuse_in_header hdr;
	struct fuse_fsync_in  arg;
};

struct silofs_fuseq_access_in {
	struct fuse_in_header hdr;
	struct fuse_access_in arg;
};

struct silofs_fuseq_create_in {
	struct fuse_in_header hdr;
	struct fuse_create_in arg;
	char                  name[SILOFS_NAME_MAX + 1];
};

struct silofs_fuseq_interrupt_in {
	struct fuse_in_header    hdr;
	struct fuse_interrupt_in arg;
};

struct silofs_fuseq_ioctl_in {
	struct fuse_in_header hdr;
	struct fuse_ioctl_in  arg;
	char                  buf[SILOFS_PAGE_SIZE_MIN];
};

struct silofs_fuseq_fallocate_in {
	struct fuse_in_header    hdr;
	struct fuse_fallocate_in arg;
};

struct silofs_fuseq_rename2_in {
	struct fuse_in_header  hdr;
	struct fuse_rename2_in arg;
	char                   name_newname[2 * (SILOFS_NAME_MAX + 1)];
};

struct silofs_fuseq_lseek_in {
	struct fuse_in_header hdr;
	struct fuse_lseek_in  arg;
};

struct silofs_fuseq_read_in {
	struct fuse_in_header hdr;
	struct fuse_read_in   arg;
};

struct silofs_fuseq_write_in {
	struct fuse_in_header hdr;
	struct fuse_write_in  arg;
};

struct silofs_fuseq_copy_file_range_in {
	struct fuse_in_header          hdr;
	struct fuse_copy_file_range_in arg;
};

struct silofs_fuseq_syncfs_in {
	struct fuse_in_header hdr;
	struct fuse_syncfs_in arg;
};

struct silofs_fuseq_statx_in {
	struct fuse_in_header hdr;
	struct fuse_statx_in  arg;
};

union silofs_fuseq_in_u {
	struct silofs_fuseq_hdr_in             hdr;
	struct silofs_fuseq_cmd_in             cmd;
	struct silofs_fuseq_init_in            init;
	struct silofs_fuseq_setattr_in         setattr;
	struct silofs_fuseq_lookup_in          lookup;
	struct silofs_fuseq_forget_in          forget;
	struct silofs_fuseq_batch_forget_in    batch_forget;
	struct silofs_fuseq_getattr_in         getattr;
	struct silofs_fuseq_symlink_in         symlink;
	struct silofs_fuseq_mknod_in           mknod;
	struct silofs_fuseq_mkdir_in           mkdir;
	struct silofs_fuseq_unlink_in          unlink;
	struct silofs_fuseq_rmdir_in           rmdir;
	struct silofs_fuseq_rename_in          rename;
	struct silofs_fuseq_link_in            link;
	struct silofs_fuseq_open_in            open;
	struct silofs_fuseq_release_in         release;
	struct silofs_fuseq_fsync_in           fsync;
	struct silofs_fuseq_setxattr1_in       setxattr1;
	struct silofs_fuseq_setxattr_in        setxattr;
	struct silofs_fuseq_getxattr_in        getxattr;
	struct silofs_fuseq_listxattr_in       listxattr;
	struct silofs_fuseq_removexattr_in     removexattr;
	struct silofs_fuseq_flush_in           flush;
	struct silofs_fuseq_opendir_in         opendir;
	struct silofs_fuseq_readdir_in         readdir;
	struct silofs_fuseq_releasedir_in      releasedir;
	struct silofs_fuseq_fsyncdir_in        fsyncdir;
	struct silofs_fuseq_access_in          access;
	struct silofs_fuseq_create_in          create;
	struct silofs_fuseq_interrupt_in       interrupt;
	struct silofs_fuseq_ioctl_in           ioctl;
	struct silofs_fuseq_fallocate_in       fallocate;
	struct silofs_fuseq_rename2_in         rename2;
	struct silofs_fuseq_lseek_in           lseek;
	struct silofs_fuseq_read_in            read;
	struct silofs_fuseq_write_in           write;
	struct silofs_fuseq_copy_file_range_in copy_file_range;
	struct silofs_fuseq_statx_in           statx;
};

struct silofs_fuseq_in {
	union silofs_fuseq_in_u u;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_fuseq_diter {
	uint8_t                   buf[8192];
	struct silofs_strbuf      de_name;
	struct silofs_readdir_ctx rd_ctx;
	struct silofs_stat        de_attr;
	size_t                    bsz;
	size_t                    len;
	size_t                    ndes;
	off_t                     de_off;
	size_t                    de_nlen;
	ino_t                     de_ino;
	mode_t                    de_dt;
	int                       plus;
};

struct silofs_fuseq_xiter {
	struct silofs_listxattr_ctx lxa;
	size_t                      cnt;
	const char                 *beg;
	const char                 *end;
	char                       *cur;
	char                        buf[64 * SILOFS_UKILO];
};

struct silofs_fuseq_wr_iter {
	struct silofs_iovec      iovec[SILOFS_FILE_NITER_MAX];
	struct silofs_rwiter_ctx rwi;
	struct silofs_fuseq_sub *fqs;
	size_t                   cnt;
	size_t                   ncp;
	size_t                   nwr;
	size_t                   nwr_max;
};

struct silofs_fuseq_rd_iter {
	struct silofs_iovec      iovec[SILOFS_FILE_NITER_MAX];
	struct silofs_rwiter_ctx rwi;
	struct silofs_fuseq_sub *fqs;
	struct silofs_task_ctx  *task;
	size_t                   cnt;
	size_t                   ncp;
	size_t                   nrd;
	size_t                   nrd_max;
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
	struct silofs_fuseq_databuf  dab;
	struct silofs_fuseq_pathbuf  pab;
	struct silofs_fuseq_xattrbuf xab;
	struct silofs_fuseq_xiter    xit;
	struct silofs_fuseq_diter    dit;
	struct silofs_fuseq_iob      iob;
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
	struct silofs_fuseq          *fq;
	struct silofs_fuseq_sub      *fqs;
	struct silofs_task_ctx       *task;
	struct silofs_vfs_args       *args;
	const struct silofs_fuseq_in *in;
	ino_t                         ino;
};

typedef int (*silofs_fuseq_hook)(const struct silofs_fuseq_cmd_ctx *);

struct silofs_fuseq_cmd_desc {
	silofs_fuseq_hook hook;
	const char       *name;
	int               code;
	int               realtime;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_check_fuse_proto(void);

#endif /* SILOFS_FQTYPES_H_ */
