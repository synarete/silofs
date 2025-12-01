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
#ifndef SILOFS_CALL_H_
#define SILOFS_CALL_H_

#include <sys/stat.h>
#include <sys/statvfs.h>
#include "infra.h"
#include "addr.h"
#include "vfs.h"
#include "gbr.h"

struct silofs_lookup_in {
	ino_t       parent;
	const char *name;
};

struct silofs_lookup_out {
	struct silofs_stat st;
};

struct silofs_forget_in {
	ino_t  ino;
	size_t nlookup;
};

struct silofs_batch_forget_in {
	const struct silofs_forget_in *one;
	size_t                         count;
};

struct silofs_getattr_in {
	ino_t ino;
};

struct silofs_getattr_out {
	struct silofs_stat st;
};

struct silofs_statx_in {
	ino_t    ino;
	uint32_t sx_mask;
};

struct silofs_statx_out {
	struct silofs_stat st;
};

struct silofs_setattr_in {
	struct silofs_itimes itimes;
	ino_t                ino;
	uid_t                uid;
	gid_t                gid;
	mode_t               mode;
	off_t                size;
	bool                 set_mode;
	bool                 set_size;
	bool                 set_uid_gid;
	bool                 set_amtime_now;
	bool                 set_amctime;
	bool                 set_nontime;
	bool                 kill_suidgid;
};

struct silofs_setattr_out {
	struct silofs_stat st;
};

struct silofs_readlink_in {
	ino_t  ino;
	char  *ptr;
	size_t lim;
};

struct silofs_readlink_out {
	size_t len;
};

struct silofs_symlink_in {
	ino_t       parent;
	const char *name;
	const char *symval;
};

struct silofs_symlink_out {
	struct silofs_stat st;
};

struct silofs_mknod_in {
	ino_t       parent;
	const char *name;
	dev_t       rdev;
	mode_t      mode;
	mode_t      umask;
};

struct silofs_mknod_out {
	struct silofs_stat st;
};

struct silofs_mkdir_in {
	ino_t       parent;
	const char *name;
	mode_t      mode;
	mode_t      umask;
};

struct silofs_mkdir_out {
	struct silofs_stat st;
};

struct silofs_unlink_in {
	ino_t       parent;
	const char *name;
};

struct silofs_rmdir_in {
	ino_t       parent;
	const char *name;
};

struct silofs_rename_in {
	ino_t       parent;
	const char *name;
	ino_t       newparent;
	const char *newname;
	int         flags;
};

struct silofs_link_in {
	ino_t       ino;
	ino_t       parent;
	const char *name;
};

struct silofs_link_out {
	struct silofs_stat st;
};

struct silofs_open_in {
	ino_t ino;
	int   o_flags;
	int   noflush;
	bool  kill_suidgid;
};

struct silofs_statfs_in {
	ino_t ino;
};

struct silofs_statfs_out {
	struct statvfs stv;
};

struct silofs_release_in {
	ino_t ino;
	int   o_flags;
	bool  flush;
};

struct silofs_fsync_in {
	ino_t ino;
	bool  datasync;
};

struct silofs_setxattr_in {
	ino_t       ino;
	const char *name;
	const void *value;
	size_t      size;
	int         flags;
	bool        kill_sgid;
};

struct silofs_getxattr_in {
	ino_t       ino;
	const char *name;
	void       *buf;
	size_t      size;
};

struct silofs_getxattr_out {
	size_t size;
};

struct silofs_listxattr_in {
	ino_t                        ino;
	struct silofs_listxattr_ctx *lxa_ctx;
};

struct silofs_removexattr_in {
	ino_t       ino;
	const char *name;
};

struct silofs_flush_in {
	ino_t ino;
};

struct silofs_opendir_in {
	ino_t ino;
	int   o_flags;
};

struct silofs_readdir_in {
	ino_t                      ino;
	struct silofs_readdir_ctx *rd_ctx;
};

struct silofs_releasedir_in {
	ino_t ino;
	int   o_flags;
};

struct silofs_fsyncdir_in {
	ino_t ino;
	int   datasync;
};

struct silofs_access_in {
	ino_t ino;
	int   mask;
};

struct silofs_create_in {
	ino_t       parent;
	const char *name;
	int         o_flags;
	mode_t      mode;
	mode_t      umask;
	bool        kill_suidgid;
};

struct silofs_create_out {
	struct silofs_stat st;
};

struct silofs_fallocate_in {
	ino_t ino;
	int   mode;
	off_t off;
	off_t len;
};

struct silofs_lseek_in {
	ino_t ino;
	off_t off;
	int   whence;
};

struct silofs_lseek_out {
	off_t off;
};

struct silofs_copy_file_range_in {
	ino_t  ino_in;
	off_t  off_in;
	ino_t  ino_out;
	off_t  off_out;
	size_t len;
	int    flags;
};

struct silofs_copy_file_range_out {
	size_t ncp;
};

struct silofs_read_in {
	ino_t                     ino;
	size_t                    len;
	off_t                     off;
	void                     *buf;
	struct silofs_rwiter_ctx *rwi_ctx;
	int                       o_flags;
};

struct silofs_read_out {
	size_t nrd;
};

struct silofs_write_in {
	ino_t                     ino;
	size_t                    len;
	off_t                     off;
	const void               *buf;
	struct silofs_rwiter_ctx *rwi_ctx;
	int                       o_flags;
	bool                      kill_suidgid;
};

struct silofs_write_out {
	size_t nwr;
};

struct silofs_query_in {
	ino_t                  ino;
	enum silofs_query_type qtype;
};

struct silofs_query_out {
	struct silofs_ioc_query qry;
};

struct silofs_clone_in {
	ino_t ino;
	int   flags;
};

struct silofs_clone_out {
	struct silofs_gbrefs gbrefs;
};

struct silofs_syncfs_in {
	ino_t ino;
	int   flags;
};

struct silofs_tune_in {
	ino_t ino;
	int   iflags_want;
	int   iflags_dont;
};

union silofs_call_args_in {
	struct silofs_lookup_in          lookup;
	struct silofs_forget_in          forget;
	struct silofs_batch_forget_in    batch_forget;
	struct silofs_getattr_in         getattr;
	struct silofs_statx_in           statx;
	struct silofs_setattr_in         setattr;
	struct silofs_readlink_in        readlink;
	struct silofs_symlink_in         symlink;
	struct silofs_mknod_in           mknod;
	struct silofs_mkdir_in           mkdir;
	struct silofs_unlink_in          unlink;
	struct silofs_rmdir_in           rmdir;
	struct silofs_rename_in          rename;
	struct silofs_link_in            link;
	struct silofs_open_in            open;
	struct silofs_statfs_in          statfs;
	struct silofs_release_in         release;
	struct silofs_fsync_in           fsync;
	struct silofs_setxattr_in        setxattr;
	struct silofs_getxattr_in        getxattr;
	struct silofs_listxattr_in       listxattr;
	struct silofs_removexattr_in     removexattr;
	struct silofs_flush_in           flush;
	struct silofs_opendir_in         opendir;
	struct silofs_readdir_in         readdir;
	struct silofs_releasedir_in      releasedir;
	struct silofs_fsyncdir_in        fsyncdir;
	struct silofs_access_in          access;
	struct silofs_create_in          create;
	struct silofs_fallocate_in       fallocate;
	struct silofs_lseek_in           lseek;
	struct silofs_copy_file_range_in copy_file_range;
	struct silofs_read_in            read;
	struct silofs_write_in           write;
	struct silofs_syncfs_in          syncfs;
	struct silofs_query_in           query;
	struct silofs_clone_in           clone;
	struct silofs_tune_in            tune;
} silofs_attr_aligned64;

union silofs_call_args_out {
	struct silofs_lookup_out          lookup;
	struct silofs_getattr_out         getattr;
	struct silofs_statx_out           statx;
	struct silofs_setattr_out         setattr;
	struct silofs_readlink_out        readlink;
	struct silofs_symlink_out         symlink;
	struct silofs_mknod_out           mknod;
	struct silofs_mkdir_out           mkdir;
	struct silofs_link_out            link;
	struct silofs_statfs_out          statfs;
	struct silofs_getxattr_out        getxattr;
	struct silofs_create_out          create;
	struct silofs_lseek_out           lseek;
	struct silofs_copy_file_range_out copy_file_range;
	struct silofs_read_out            read;
	struct silofs_write_out           write;
	struct silofs_query_out           query;
	struct silofs_clone_out           clone;
} silofs_attr_aligned64;

struct silofs_call_args {
	union silofs_call_args_in  in;
	union silofs_call_args_out out;
	long                       ioc_cmd;
} silofs_attr_aligned64;

typedef int (*silofs_call_fn)(struct silofs_task_ctx *,
                              struct silofs_call_args *);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_call_setattr(struct silofs_task_ctx  *task,
                        struct silofs_call_args *args);

int silofs_call_lookup(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_forget(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_batch_forget(struct silofs_task_ctx  *task,
                             struct silofs_call_args *args);

int silofs_call_getattr(struct silofs_task_ctx  *task,
                        struct silofs_call_args *args);

int silofs_call_statx(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_readlink(struct silofs_task_ctx  *task,
                         struct silofs_call_args *args);

int silofs_call_symlink(struct silofs_task_ctx  *task,
                        struct silofs_call_args *args);

int silofs_call_mknod(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_mkdir(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_unlink(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_rmdir(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_rename(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_link(struct silofs_task_ctx  *task,
                     struct silofs_call_args *args);

int silofs_call_open(struct silofs_task_ctx  *task,
                     struct silofs_call_args *args);

int silofs_call_statfs(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_release(struct silofs_task_ctx  *task,
                        struct silofs_call_args *args);

int silofs_call_fsync(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_setxattr(struct silofs_task_ctx  *task,
                         struct silofs_call_args *args);

int silofs_call_getxattr(struct silofs_task_ctx  *task,
                         struct silofs_call_args *args);

int silofs_call_listxattr(struct silofs_task_ctx  *task,
                          struct silofs_call_args *args);

int silofs_call_removexattr(struct silofs_task_ctx  *task,
                            struct silofs_call_args *args);

int silofs_call_flush(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_opendir(struct silofs_task_ctx  *task,
                        struct silofs_call_args *args);

int silofs_call_readdir(struct silofs_task_ctx  *task,
                        struct silofs_call_args *args);

int silofs_call_readdirplus(struct silofs_task_ctx  *task,
                            struct silofs_call_args *args);

int silofs_call_releasedir(struct silofs_task_ctx  *task,
                           struct silofs_call_args *args);

int silofs_call_fsyncdir(struct silofs_task_ctx  *task,
                         struct silofs_call_args *args);

int silofs_call_access(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_create(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_fallocate(struct silofs_task_ctx  *task,
                          struct silofs_call_args *args);

int silofs_call_lseek(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_copy_file_range(struct silofs_task_ctx  *task,
                                struct silofs_call_args *args);

int silofs_call_read(struct silofs_task_ctx  *task,
                     struct silofs_call_args *args);

int silofs_call_write(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

int silofs_call_syncfs(struct silofs_task_ctx  *task,
                       struct silofs_call_args *args);

int silofs_call_ioctl(struct silofs_task_ctx  *task,
                      struct silofs_call_args *args);

#endif /* SILOFS_CALL_H_ */
