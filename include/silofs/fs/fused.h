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
#ifndef SILOFS_FUSED_H_
#define SILOFS_FUSED_H_

#include <sys/stat.h>
#include <sys/statvfs.h>

/* forward declarations */
struct fuse_forget_one;


struct silofs_opc_lookup_in {
	ino_t parent;
	const char *name;
};

struct silofs_opc_lookup_out {
	struct stat st;
};

struct silofs_opc_forget_in {
	ino_t ino;
	size_t nlookup;
};

struct silofs_opc_batch_forget_in {
	const struct fuse_forget_one *one;
	size_t count;
};

struct silofs_opc_getattr_in {
	ino_t ino;
};

struct silofs_opc_getattr_out {
	struct stat st;
};

struct silofs_opc_setattr_in {
	struct stat tims;
	ino_t ino;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	loff_t size;
	bool set_mode;
	bool set_size;
	bool set_uid_gid;
	bool set_amtime_now;
	bool set_amctime;
	bool set_nontime;
};

struct silofs_opc_setattr_out {
	struct stat st;
};

struct silofs_opc_readlink_in {
	ino_t ino;
	char *ptr;
	size_t lim;
};

struct silofs_opc_readlink_out {
	size_t len;
};

struct silofs_opc_symlink_in {
	ino_t parent;
	const char *name;
	const char *symval;
};

struct silofs_opc_symlink_out {
	struct stat st;
};

struct silofs_opc_mknod_in {
	ino_t parent;
	const char *name;
	dev_t rdev;
	mode_t mode;
	mode_t umask;
};

struct silofs_opc_mknod_out {
	struct stat st;
};

struct silofs_opc_mkdir_in {
	ino_t parent;
	const char *name;
	mode_t mode;
	mode_t umask;
};

struct silofs_opc_mkdir_out {
	struct stat st;
};

struct silofs_opc_unlink_in {
	ino_t parent;
	const char *name;
};

struct silofs_opc_rmdir_in {
	ino_t parent;
	const char *name;
};

struct silofs_opc_rename_in {
	ino_t parent;
	const char *name;
	ino_t newparent;
	const char *newname;
	int flags;
};

struct silofs_opc_link_in {
	ino_t ino;
	ino_t parent;
	const char *name;
};

struct silofs_opc_link_out {
	struct stat st;
};

struct silofs_opc_open_in {
	ino_t ino;
	int o_flags;
	int noflush;
};

struct silofs_opc_statfs_in {
	ino_t ino;
};

struct silofs_opc_statfs_out {
	struct statvfs stv;
};

struct silofs_opc_release_in {
	ino_t ino;
	int o_flags;
	bool flush;
};

struct silofs_opc_fsync_in {
	ino_t ino;
	bool datasync;
};

struct silofs_opc_setxattr_in {
	ino_t ino;
	const char *name;
	const void *value;
	size_t size;
	int flags;
	bool kill_sgid;
};

struct silofs_opc_getxattr_in {
	ino_t ino;
	const char *name;
	void *buf;
	size_t size;
};

struct silofs_opc_getxattr_out {
	size_t size;
};

struct silofs_opc_listxattr_in {
	ino_t ino;
	struct silofs_listxattr_ctx *lxa_ctx;
};

struct silofs_opc_removexattr_in {
	ino_t ino;
	const char *name;
};

struct silofs_opc_flush_in {
	ino_t ino;
};

struct silofs_opc_opendir_in {
	ino_t ino;
	int o_flags;
};

struct silofs_opc_readdir_in {
	ino_t ino;
	struct silofs_readdir_ctx *rd_ctx;
};

struct silofs_opc_releasedir_in {
	ino_t ino;
	int o_flags;
};

struct silofs_opc_fsyncdir_in {
	ino_t ino;
	int datasync;
};

struct silofs_opc_access_in {
	ino_t ino;
	int mask;
};

struct silofs_opc_create_in {
	ino_t parent;
	const char *name;
	int o_flags;
	mode_t mode;
	mode_t umask;
};

struct silofs_opc_create_out {
	struct stat st;
};

struct silofs_opc_fallocate_in {
	ino_t ino;
	int mode;
	loff_t off;
	loff_t len;
};

struct silofs_opc_lseek_in {
	ino_t ino;
	loff_t off;
	int whence;
};

struct silofs_opc_lseek_out {
	loff_t off;
};

struct silofs_opc_copy_file_range_in {
	ino_t ino_in;
	loff_t off_in;
	ino_t ino_out;
	loff_t off_out;
	size_t len;
	int flags;
};

struct silofs_opc_copy_file_range_out {
	size_t  ncp;
};

struct silofs_opc_read_in {
	ino_t ino;
	void *buf;
	size_t len;
	loff_t off;
	struct silofs_rwiter_ctx *rwi_ctx;
};

struct silofs_opc_read_out {
	size_t nrd;
};

struct silofs_opc_write_in {
	ino_t ino;
	const void *buf;
	size_t len;
	loff_t off;
	struct silofs_rwiter_ctx *rwi_ctx;
};

struct silofs_opc_write_out {
	size_t nwr;
};

struct silofs_opc_syncfs_in {
	ino_t ino;
};

struct silofs_opc_query_in {
	ino_t ino;
	int qtype;
};

struct silofs_opc_query_out {
	struct silofs_ioc_query qry;
};

struct silofs_opc_clone_in {
	ino_t ino;
	const char *name;
	int flags;
};


union silofs_oper_ctx_in {
	struct silofs_opc_lookup_in             lookup;
	struct silofs_opc_forget_in             forget;
	struct silofs_opc_batch_forget_in       batch_forget;
	struct silofs_opc_getattr_in            getattr;
	struct silofs_opc_setattr_in            setattr;
	struct silofs_opc_readlink_in           readlink;
	struct silofs_opc_symlink_in            symlink;
	struct silofs_opc_mknod_in              mknod;
	struct silofs_opc_mkdir_in              mkdir;
	struct silofs_opc_unlink_in             unlink;
	struct silofs_opc_rmdir_in              rmdir;
	struct silofs_opc_rename_in             rename;
	struct silofs_opc_link_in               link;
	struct silofs_opc_open_in               open;
	struct silofs_opc_statfs_in             statfs;
	struct silofs_opc_release_in            release;
	struct silofs_opc_fsync_in              fsync;
	struct silofs_opc_setxattr_in           setxattr;
	struct silofs_opc_getxattr_in           getxattr;
	struct silofs_opc_listxattr_in          listxattr;
	struct silofs_opc_removexattr_in        removexattr;
	struct silofs_opc_flush_in              flush;
	struct silofs_opc_opendir_in            opendir;
	struct silofs_opc_readdir_in            readdir;
	struct silofs_opc_releasedir_in         releasedir;
	struct silofs_opc_fsyncdir_in           fsyncdir;
	struct silofs_opc_access_in             access;
	struct silofs_opc_create_in             create;
	struct silofs_opc_fallocate_in          fallocate;
	struct silofs_opc_lseek_in              lseek;
	struct silofs_opc_copy_file_range_in    copy_file_range;
	struct silofs_opc_read_in               read;
	struct silofs_opc_write_in              write;
	struct silofs_opc_syncfs_in             syncfs;
	struct silofs_opc_query_in              query;
	struct silofs_opc_clone_in              clone;
} silofs_aligned64;

union silofs_oper_ctx_out {
	struct silofs_opc_lookup_out            lookup;
	struct silofs_opc_getattr_out           getattr;
	struct silofs_opc_setattr_out           setattr;
	struct silofs_opc_readlink_out          readlink;
	struct silofs_opc_symlink_out           symlink;
	struct silofs_opc_mknod_out             mknod;
	struct silofs_opc_mkdir_out             mkdir;
	struct silofs_opc_link_out              link;
	struct silofs_opc_statfs_out            statfs;
	struct silofs_opc_getxattr_out          getxattr;
	struct silofs_opc_create_out            create;
	struct silofs_opc_lseek_out             lseek;
	struct silofs_opc_copy_file_range_out   copy_file_range;
	struct silofs_opc_read_out              read;
	struct silofs_opc_write_out             write;
	struct silofs_opc_query_out             query;
} silofs_aligned64;

struct silofs_oper_ctx {
	union silofs_oper_ctx_in        opc_in;
	union silofs_oper_ctx_out       opc_out;
	struct silofs_fs_ctx            opc_fsc;
	long opc_ioc_cmd;
} silofs_aligned64;


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_operctx_init(struct silofs_oper_ctx *opc);

void silofs_operctx_fini(struct silofs_oper_ctx *opc);


int silofs_exec_fs_oper(struct silofs_oper_ctx *opc);

int silofs_wait_fs_oper(struct silofs_oper_ctx *opc);


#endif /* SILOFS_FUSED_H_ */
