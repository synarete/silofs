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
#ifndef SILOFS_OPERS_H_
#define SILOFS_OPERS_H_

#include <sys/stat.h>
#include <sys/statvfs.h>

/* forward declarations */
struct fuse_forget_one;
struct silofs_bootsec;
struct silofs_uber;
struct silofs_task;
struct silofs_ioc_query;
struct silofs_ioc_iterfs;

struct silofs_op_lookup_in {
	ino_t parent;
	const char *name;
};

struct silofs_op_lookup_out {
	struct silofs_stat st;
};

struct silofs_op_forget_in {
	ino_t ino;
	size_t nlookup;
};

struct silofs_op_batch_forget_in {
	const struct fuse_forget_one *one;
	size_t count;
};

struct silofs_op_getattr_in {
	ino_t ino;
};

struct silofs_op_getattr_out {
	struct silofs_stat st;
};

struct silofs_op_setattr_in {
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

struct silofs_op_setattr_out {
	struct silofs_stat st;
};

struct silofs_op_readlink_in {
	ino_t ino;
	char *ptr;
	size_t lim;
};

struct silofs_op_readlink_out {
	size_t len;
};

struct silofs_op_symlink_in {
	ino_t parent;
	const char *name;
	const char *symval;
};

struct silofs_op_symlink_out {
	struct silofs_stat st;
};

struct silofs_op_mknod_in {
	ino_t parent;
	const char *name;
	dev_t rdev;
	mode_t mode;
	mode_t umask;
};

struct silofs_op_mknod_out {
	struct silofs_stat st;
};

struct silofs_op_mkdir_in {
	ino_t parent;
	const char *name;
	mode_t mode;
	mode_t umask;
};

struct silofs_op_mkdir_out {
	struct silofs_stat st;
};

struct silofs_op_unlink_in {
	ino_t parent;
	const char *name;
};

struct silofs_op_rmdir_in {
	ino_t parent;
	const char *name;
};

struct silofs_op_rename_in {
	ino_t parent;
	const char *name;
	ino_t newparent;
	const char *newname;
	int flags;
};

struct silofs_op_link_in {
	ino_t ino;
	ino_t parent;
	const char *name;
};

struct silofs_op_link_out {
	struct silofs_stat st;
};

struct silofs_op_open_in {
	ino_t ino;
	int o_flags;
	int noflush;
};

struct silofs_op_statfs_in {
	ino_t ino;
};

struct silofs_op_statfs_out {
	struct statvfs stv;
};

struct silofs_op_release_in {
	ino_t ino;
	int o_flags;
	bool flush;
};

struct silofs_op_fsync_in {
	ino_t ino;
	bool datasync;
};

struct silofs_op_setxattr_in {
	ino_t ino;
	const char *name;
	const void *value;
	size_t size;
	int flags;
	bool kill_sgid;
};

struct silofs_op_getxattr_in {
	ino_t ino;
	const char *name;
	void *buf;
	size_t size;
};

struct silofs_op_getxattr_out {
	size_t size;
};

struct silofs_op_listxattr_in {
	ino_t ino;
	struct silofs_listxattr_ctx *lxa_ctx;
};

struct silofs_op_removexattr_in {
	ino_t ino;
	const char *name;
};

struct silofs_op_flush_in {
	ino_t ino;
};

struct silofs_op_opendir_in {
	ino_t ino;
	int o_flags;
};

struct silofs_op_readdir_in {
	ino_t ino;
	struct silofs_readdir_ctx *rd_ctx;
};

struct silofs_op_releasedir_in {
	ino_t ino;
	int o_flags;
};

struct silofs_op_fsyncdir_in {
	ino_t ino;
	int datasync;
};

struct silofs_op_access_in {
	ino_t ino;
	int mask;
};

struct silofs_op_create_in {
	ino_t parent;
	const char *name;
	int o_flags;
	mode_t mode;
	mode_t umask;
};

struct silofs_op_create_out {
	struct silofs_stat st;
};

struct silofs_op_fallocate_in {
	ino_t ino;
	int mode;
	loff_t off;
	loff_t len;
};

struct silofs_op_lseek_in {
	ino_t ino;
	loff_t off;
	int whence;
};

struct silofs_op_lseek_out {
	loff_t off;
};

struct silofs_op_copy_file_range_in {
	ino_t ino_in;
	loff_t off_in;
	ino_t ino_out;
	loff_t off_out;
	size_t len;
	int flags;
};

struct silofs_op_copy_file_range_out {
	size_t  ncp;
};

struct silofs_op_read_in {
	ino_t ino;
	void *buf;
	size_t len;
	loff_t off;
	struct silofs_rwiter_ctx *rwi_ctx;
};

struct silofs_op_read_out {
	size_t nrd;
};

struct silofs_op_write_in {
	ino_t ino;
	const void *buf;
	size_t len;
	loff_t off;
	struct silofs_rwiter_ctx *rwi_ctx;
};

struct silofs_op_write_out {
	size_t nwr;
};

struct silofs_op_syncfs_in {
	ino_t ino;
	int flags;
};

struct silofs_op_query_in {
	ino_t ino;
	enum silofs_query_type qtype;
};

struct silofs_op_query_out {
	struct silofs_ioc_query qry;
};

struct silofs_op_clone_in {
	ino_t ino;
	int flags;
};

struct silofs_op_clone_out {
	struct silofs_bootsecs bsecs;
};

struct silofs_op_sync_in {
	ino_t ino;
	int flags;
};


union silofs_oper_args_in {
	struct silofs_op_lookup_in              lookup;
	struct silofs_op_forget_in              forget;
	struct silofs_op_batch_forget_in        batch_forget;
	struct silofs_op_getattr_in             getattr;
	struct silofs_op_setattr_in             setattr;
	struct silofs_op_readlink_in            readlink;
	struct silofs_op_symlink_in             symlink;
	struct silofs_op_mknod_in               mknod;
	struct silofs_op_mkdir_in               mkdir;
	struct silofs_op_unlink_in              unlink;
	struct silofs_op_rmdir_in               rmdir;
	struct silofs_op_rename_in              rename;
	struct silofs_op_link_in                link;
	struct silofs_op_open_in                open;
	struct silofs_op_statfs_in              statfs;
	struct silofs_op_release_in             release;
	struct silofs_op_fsync_in               fsync;
	struct silofs_op_setxattr_in            setxattr;
	struct silofs_op_getxattr_in            getxattr;
	struct silofs_op_listxattr_in           listxattr;
	struct silofs_op_removexattr_in         removexattr;
	struct silofs_op_flush_in               flush;
	struct silofs_op_opendir_in             opendir;
	struct silofs_op_readdir_in             readdir;
	struct silofs_op_releasedir_in          releasedir;
	struct silofs_op_fsyncdir_in            fsyncdir;
	struct silofs_op_access_in              access;
	struct silofs_op_create_in              create;
	struct silofs_op_fallocate_in           fallocate;
	struct silofs_op_lseek_in               lseek;
	struct silofs_op_copy_file_range_in     copy_file_range;
	struct silofs_op_read_in                read;
	struct silofs_op_write_in               write;
	struct silofs_op_syncfs_in              syncfs;
	struct silofs_op_query_in               query;
	struct silofs_op_clone_in               clone;
} silofs_aligned64;

union silofs_oper_args_out {
	struct silofs_op_lookup_out             lookup;
	struct silofs_op_getattr_out            getattr;
	struct silofs_op_setattr_out            setattr;
	struct silofs_op_readlink_out           readlink;
	struct silofs_op_symlink_out            symlink;
	struct silofs_op_mknod_out              mknod;
	struct silofs_op_mkdir_out              mkdir;
	struct silofs_op_link_out               link;
	struct silofs_op_statfs_out             statfs;
	struct silofs_op_getxattr_out           getxattr;
	struct silofs_op_create_out             create;
	struct silofs_op_lseek_out              lseek;
	struct silofs_op_copy_file_range_out    copy_file_range;
	struct silofs_op_read_out               read;
	struct silofs_op_write_out              write;
	struct silofs_op_query_out              query;
	struct silofs_op_clone_out              clone;
} silofs_aligned64;

struct silofs_oper_args {
	union silofs_oper_args_in               in;
	union silofs_oper_args_out              out;
	long ioc_cmd;
} silofs_aligned64;


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fs_forget(struct silofs_task *task, ino_t ino, size_t nlookup);

int silofs_fs_statfs(struct silofs_task *task,
                     ino_t ino, struct statvfs *stvfs);

int silofs_fs_lookup(struct silofs_task *task, ino_t parent,
                     const char *name, struct silofs_stat *out_stat);

int silofs_fs_getattr(struct silofs_task *task,
                      ino_t ino, struct silofs_stat *out_stat);

int silofs_fs_mkdir(struct silofs_task *task, ino_t parent,
                    const char *name, mode_t mode,
                    struct silofs_stat *out_stat);

int silofs_fs_rmdir(struct silofs_task *task,
                    ino_t parent, const char *name);

int silofs_fs_access(struct silofs_task *task, ino_t ino, int mode);

int silofs_fs_chmod(struct silofs_task *task, ino_t ino, mode_t mode,
                    const struct stat *st, struct silofs_stat *out_stat);

int silofs_fs_chown(struct silofs_task *task, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st,
                    struct silofs_stat *out_stat);

int silofs_fs_truncate(struct silofs_task *task,
                       ino_t ino, loff_t len, struct silofs_stat *out_stat);

int silofs_fs_utimens(struct silofs_task *task, ino_t ino,
                      const struct stat *times, struct silofs_stat *out_stat);

int silofs_fs_symlink(struct silofs_task *task, ino_t parent,
                      const char *name, const char *symval,
                      struct silofs_stat *out_stat);

int silofs_fs_readlink(struct silofs_task *task, ino_t ino,
                       char *ptr, size_t lim, size_t *out_len);

int silofs_fs_unlink(struct silofs_task *task,
                     ino_t parent, const char *name);

int silofs_fs_link(struct silofs_task *task, ino_t ino, ino_t parent,
                   const char *name, struct silofs_stat *out_stat);

int silofs_fs_rename(struct silofs_task *task, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags);

int silofs_fs_opendir(struct silofs_task *task, ino_t ino);

int silofs_fs_releasedir(struct silofs_task *task, ino_t ino, int o_flags);

int silofs_fs_readdir(struct silofs_task *task, ino_t ino,
                      struct silofs_readdir_ctx *rd_ctx);

int silofs_fs_readdirplus(struct silofs_task *task, ino_t ino,
                          struct silofs_readdir_ctx *rd_ctx);

int silofs_fs_fsyncdir(struct silofs_task *task, ino_t ino, bool datasync);

int silofs_fs_create(struct silofs_task *task, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct silofs_stat *out_stat);

int silofs_fs_open(struct silofs_task *task, ino_t ino, int o_flags);

int silofs_fs_mknod(struct silofs_task *task, ino_t parent,
                    const char *name, mode_t mode, dev_t rdev,
                    struct silofs_stat *out_stat);

int silofs_fs_release(struct silofs_task *task,
                      ino_t ino, int o_flags, bool flush);

int silofs_fs_flush(struct silofs_task *task, ino_t ino, bool now);

int silofs_fs_fsync(struct silofs_task *task, ino_t ino, bool datasync);

int silofs_fs_getxattr(struct silofs_task *task, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size);

int silofs_fs_setxattr(struct silofs_task *task, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags, bool kill_sgid);

int silofs_fs_listxattr(struct silofs_task *task, ino_t ino,
                        struct silofs_listxattr_ctx *lxa_ctx);

int silofs_fs_removexattr(struct silofs_task *task,
                          ino_t ino, const char *name);

int silofs_fs_fallocate(struct silofs_task *task, ino_t ino,
                        int mode, loff_t offset, loff_t length);

int silofs_fs_lseek(struct silofs_task *task, ino_t ino,
                    loff_t off, int whence, loff_t *out_off);

int silofs_fs_copy_file_range(struct silofs_task *task, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp);

int silofs_fs_read(struct silofs_task *task, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len);

int silofs_fs_read_iter(struct silofs_task *task, ino_t ino,
                        struct silofs_rwiter_ctx *rwi_ctx);

int silofs_fs_write(struct silofs_task *task, ino_t ino,
                    const void *buf, size_t len, loff_t off, size_t *out_len);

int silofs_fs_write_iter(struct silofs_task *task, ino_t ino,
                         struct silofs_rwiter_ctx *rwi_ctx);

int silofs_fs_statx(struct silofs_task *task, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx);

int silofs_fs_fiemap(struct silofs_task *task,
                     ino_t ino, struct fiemap *fm);

int silofs_fs_syncfs(struct silofs_task *task, ino_t ino, int flags);

int silofs_fs_query(struct silofs_task *task, ino_t ino,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *out_qry);

int silofs_fs_clone(struct silofs_task *task, ino_t ino,
                    int flags, struct silofs_bootsecs *out_bsecs);

int silofs_fs_rdwr_post(const struct silofs_task *task, int wr_mode,
                        const struct silofs_iovec *iov, size_t cnt);

int silofs_fs_timedout(struct silofs_task *task, int flags);

int silofs_fs_inspect(struct silofs_task *task);

int silofs_fs_unrefs(struct silofs_task *task);

int silofs_remap_status_code(int status);

#endif /* SILOFS_OPERS_H_ */
