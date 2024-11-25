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
#ifndef SILOFS_FUNTESTS_SYSCALL_H_
#define SILOFS_FUNTESTS_SYSCALL_H_

/* wrappers over system calls */
void ft_do_syncfs(int fd, const char *fl, int ln);

void ft_do_fsync(int fd, const char *fl, int ln);

void ft_do_fsync_err(int fd, int err, const char *fl, int ln);

void ft_do_utime(const char *path, const struct utimbuf *tm, const char *fl,
		 int ln);

void ft_do_utimes(const char *path, const struct timeval tm[2], const char *fl,
		  int ln);

void ft_do_utimensat(int dirfd, const char *name, const struct timespec tm[2],
		     int flags, const char *fl, int ln);

void ft_do_futimens(int fd, const struct timespec tm[2], const char *fl,
		    int ln);

void ft_do_stat(const char *path, struct stat *st, const char *fl, int ln);

void ft_do_stat_err(const char *path, int err, const char *fl, int ln);

void ft_do_stat_noent(const char *path, const char *fl, int ln);

void ft_do_fstat(int fd, struct stat *st, const char *fl, int ln);

void ft_do_lstat(const char *path, struct stat *st, const char *fl, int ln);

void ft_do_lstat_err(const char *path, int err, const char *fl, int ln);

void ft_do_fstatat(int dirfd, const char *name, struct stat *st, int flags,
		   const char *fl, int ln);

void ft_do_fstatat_err(int dirfd, const char *name, int flags, int err,
		       const char *fl, int ln);

void ft_do_statx(int dirfd, const char *name, int flags, unsigned int mask,
		 struct statx *stx, const char *fl, int ln);

void ft_do_statvfs(const char *path, struct statvfs *stv, const char *fl,
		   int ln);

void ft_do_statvfs_err(const char *path, int err, const char *fl, int ln);

void ft_do_fstatvfs(int fd, struct statvfs *stvfs, const char *fl, int ln);

void ft_do_mkdir(const char *path, mode_t mode, const char *fl, int ln);

void ft_do_mkdir_err(const char *path, mode_t mode, int err, const char *fl,
		     int ln);

void ft_do_mkdirat(int dirfd, const char *name, mode_t mode, const char *fl,
		   int ln);

void ft_do_rmdir(const char *path, const char *fl, int ln);

void ft_do_rmdir_err(const char *path, int err, const char *fl, int ln);

void ft_do_unlink(const char *path, const char *fl, int ln);

void ft_do_unlink_err(const char *path, int err, const char *fl, int ln);

void ft_do_unlink_noent(const char *path, const char *fl, int ln);

void ft_do_unlinkat(int dirfd, const char *name, int flags, const char *fl,
		    int ln);

void ft_do_unlinkat_noent(int dirfd, const char *name, const char *fl, int ln);

void ft_do_open(const char *path, int flags, mode_t mode, int *out_fd,
		const char *fl, int ln);

void ft_do_open_err(const char *path, int flags, mode_t mode, int err,
		    const char *fl, int ln);

void ft_do_openat(int dirfd, const char *name, int flags, mode_t mode,
		  int *out_fd, const char *fl, int ln);

void ft_do_openat_err(int dirfd, const char *name, int flags, mode_t mode,
		      int err, const char *fl, int ln);

void ft_do_creat(const char *path, mode_t mode, int *out_fd, const char *fl,
		 int ln);

void ft_do_close(int fd, const char *fl, int ln);

void ft_do_truncate(const char *path, loff_t len, const char *fl, int ln);

void ft_do_ftruncate(int fd, loff_t len, const char *fl, int ln);

void ft_do_llseek(int fd, loff_t off, int whence, loff_t *out_pos,
		  const char *fl, int ln);

void ft_do_llseek_err(int fd, loff_t off, int whence, int err, const char *fl,
		      int ln);

void ft_do_write(int fd, const void *buf, size_t cnt, size_t *out_nwr,
		 const char *fl, int ln);

void ft_do_write_err(int fd, const void *buf, size_t cnt, int err,
		     const char *fl, int ln);

void ft_do_pwrite(int fd, const void *buf, size_t cnt, loff_t off,
		  size_t *out_nwr, const char *fl, int ln);

void ft_do_pwrite_err(int fd, const void *buf, size_t cnt, loff_t off, int err,
		      const char *fl, int ln);

void ft_do_read(int fd, void *buf, size_t cnt, size_t *out_nrd, const char *fl,
		int ln);

void ft_do_read_err(int fd, void *buf, size_t cnt, int err, const char *fl,
		    int ln);

void ft_do_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *out_nrd,
		 const char *fl, int ln);

void ft_do_fallocate(int fd, int mode, loff_t off, loff_t len, const char *fl,
		     int ln);

void ft_do_fallocate_err(int fd, int mode, loff_t off, loff_t len, int err,
			 const char *fl, int ln);

void ft_do_fdatasync(int fd, const char *fl, int ln);

void ft_do_mkfifo(const char *path, mode_t mode, const char *fl, int ln);

void ft_do_mkfifoat(int dirfd, const char *name, mode_t mode, const char *fl,
		    int ln);

void ft_do_mknod(const char *path, mode_t mode, dev_t dev, const char *fl,
		 int ln);

void ft_do_mknodat(int dirfd, const char *name, mode_t mode, dev_t dev,
		   const char *fl, int ln);

void ft_do_symlink(const char *oldpath, const char *newpath, const char *fl,
		   int ln);

void ft_do_symlinkat(const char *target, int dirfd, const char *linkpath,
		     const char *fl, int ln);

void ft_do_readlink(const char *path, char *buf, size_t bsz, size_t *out_cnt,
		    const char *fl, int ln);

void ft_do_readlink_err(const char *path, char *buf, size_t bsz, int err,
			const char *fl, int ln);

void ft_do_readlinkat(int dirfd, const char *name, char *buf, size_t bsz,
		      size_t *out_cnt, const char *fl, int ln);

void ft_do_rename(const char *oldpath, const char *newpath, const char *fl,
		  int ln);

void ft_do_rename_err(const char *oldpath, const char *newpath, int err,
		      const char *fl, int ln);

void ft_do_renameat(int olddirfd, const char *oldpath, int newdirfd,
		    const char *newpath, const char *fl, int ln);

void ft_do_renameat2(int olddirfd, const char *oldpath, int newdirfd,
		     const char *newpath, unsigned int flags, const char *fl,
		     int ln);

void ft_do_link(const char *oldpath, const char *newpath, const char *fl,
		int ln);

void ft_do_link_err(const char *oldpath, const char *newpath, int err,
		    const char *fl, int ln);

void ft_do_linkat(int olddirfd, const char *oldpath, int newdirfd,
		  const char *newpath, int flags, const char *fl, int ln);

void ft_do_linkat_err(int olddirfd, const char *oldpath, int newdirfd,
		      const char *newpath, int flags, int err, const char *fl,
		      int ln);

void ft_do_chmod(const char *path, mode_t mode, const char *fl, int ln);

void ft_do_fchmod(int fd, mode_t mode, const char *fl, int ln);

void ft_do_fchmod_err(int fd, mode_t mode, int err, const char *fl, int ln);

void ft_do_chown(const char *path, uid_t uid, gid_t gid, const char *fl,
		 int ln);

void ft_do_fchown(int fd, uid_t uid, gid_t gid, const char *fl, int ln);

void ft_do_access(const char *path, int mode, const char *fl, int ln);

void ft_do_access_err(const char *path, int mode, int err, const char *fl,
		      int ln);

void ft_do_mmap(void *addr, size_t len, int prot, int flags, int fd,
		loff_t offset, void **out, const char *fl, int ln);

void ft_do_munmap(void *addr, size_t len, const char *fl, int ln);

void ft_do_msync(void *addr, size_t len, int flags, const char *fl, int ln);

void ft_do_madvise(void *addr, size_t len, int advice, const char *fl, int ln);

void ft_do_setxattr(const char *path, const char *name, const void *value,
		    size_t size, int flags, const char *fl, int ln);

void ft_do_lsetxattr(const char *path, const char *name, const void *value,
		     size_t size, int flags, const char *fl, int ln);

void ft_do_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags, const char *fl, int ln);

void ft_do_getxattr(const char *path, const char *name, void *value,
		    size_t size, size_t *out_cnt, const char *fl, int ln);

void ft_do_getxattr_err(const char *path, const char *name, int err,
			const char *fl, int ln);

void ft_do_lgetxattr(const char *path, const char *name, void *value,
		     size_t size, size_t *out_cnt, const char *fl, int ln);

void ft_do_fgetxattr(int fd, const char *name, void *value, size_t size,
		     size_t *out_cnt, const char *fl, int ln);

void ft_do_fgetxattr_err(int fd, const char *name, int err, const char *fl,
			 int ln);

void ft_do_removexattr(const char *path, const char *name, const char *fl,
		       int ln);

void ft_do_lremovexattr(const char *path, const char *name, const char *fl,
			int ln);

void ft_do_fremovexattr(int fd, const char *name, const char *fl, int ln);

void ft_do_fremovexattr_err(int fd, const char *name, int err, const char *fl,
			    int ln);

void ft_do_listxattr(const char *path, char *list, size_t size, size_t *out,
		     const char *fl, int ln);

void ft_do_llistxattr(const char *path, char *list, size_t size, size_t *out,
		      const char *fl, int ln);

void ft_do_flistxattr(int fd, char *list, size_t size, size_t *out,
		      const char *fl, int ln);

void ft_do_flistxattr_err(int fd, char *list, size_t size, int err,
			  const char *fl, int ln);

void ft_do_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
			   loff_t *off_out, size_t len, size_t *out_ncp,
			   const char *fl, int ln);

void ft_do_fiemap(int fd, struct fiemap *fm, const char *fl, int ln);

void ft_do_getdents(int fd, void *buf, size_t bsz, struct dirent64 *des,
		    size_t ndes, size_t *out_ndes, const char *fl, int ln);

void ft_do_getdent(int fd, struct dirent64 *dent, const char *fl, int ln);

/* complex wrappers */
void ft_do_readn(int fd, void *buf, size_t cnt, const char *fl, int ln);

void ft_do_preadn(int fd, void *buf, size_t cnt, loff_t off, const char *fl,
		  int ln);

void ft_do_writen(int fd, const void *buf, size_t cnt, const char *fl, int ln);

void ft_do_pwriten(int fd, const void *buf, size_t cnt, loff_t off,
		   const char *fl, int ln);

/* ioctl wrappers */
void ft_do_ioctl_syncfs(int fd, const char *fl, int ln);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* wrapper-macros over system calls with caller's location (file:line)  */
#define ft_syncfs(fd_) ft_do_syncfs(fd_, FT_FL_LN_)

#define ft_fsync(fd_) ft_do_fsync(fd_, FT_FL_LN_)

#define ft_fsync_err(fd_, err_) ft_do_fsync_err(fd_, err_, FT_FL_LN_)

#define ft_utime(path_, tm_) ft_do_utime(path_, tm_, FT_FL_LN_)

#define ft_utimes(path_, tm_) ft_do_utimes(path_, tm_, FT_FL_LN_)

#define ft_utimensat(dirfd_, name_, tm_, flags_) \
	ft_do_utimensat(dirfd_, name_, tm_, flags_, FT_FL_LN_)

#define ft_futimens(fd_, tm_) ft_do_futimens(fd_, tm_, FT_FL_LN_)

#define ft_stat(path_, st_) ft_do_stat(path_, st_, FT_FL_LN_)

#define ft_stat_err(path_, err_) ft_do_stat_err(path_, err_, FT_FL_LN_)

#define ft_stat_noent(path_) ft_do_stat_noent(path_, FT_FL_LN_)

#define ft_fstat(fd_, st_) ft_do_fstat(fd_, st_, FT_FL_LN_)

#define ft_lstat(path_, st_) ft_do_lstat(path_, st_, FT_FL_LN_)

#define ft_lstat_err(path_, err_) ft_do_lstat_err(path_, err_, FT_FL_LN_)

#define ft_fstatat(dirfd_, name_, st_, flags_) \
	ft_do_fstatat(dirfd_, name_, st_, flags_, FT_FL_LN_)

#define ft_fstatat_err(dirfd_, name_, flags_, err_) \
	ft_do_fstatat_err(dirfd_, name_, flags_, err_, FT_FL_LN_)

#define ft_statx(dirfd_, name_, flags_, mask_, stx_) \
	ft_do_statx(dirfd_, name_, flags_, mask_, stx_, FT_FL_LN_)

#define ft_statvfs(path_, stv_) ft_do_statvfs(path_, stv_, FT_FL_LN_)

#define ft_statvfs_err(path_, stv_) ft_do_statvfs_err(path_, stv_, FT_FL_LN_)

#define ft_fstatvfs(fd_, stv_) ft_do_fstatvfs(fd_, stv_, FT_FL_LN_)

#define ft_mkdir(path_, mode_) ft_do_mkdir(path_, mode_, FT_FL_LN_)

#define ft_mkdir_err(path_, mode_, err_) \
	ft_do_mkdir_err(path_, mode_, err_, FT_FL_LN_)

#define ft_mkdirat(dirfd_, name_, mode_) \
	ft_do_mkdirat(dirfd_, name_, mode_, FT_FL_LN_)

#define ft_rmdir(path_) ft_do_rmdir(path_, FT_FL_LN_)

#define ft_rmdir_err(path_, err_) ft_do_rmdir_err(path_, err_, FT_FL_LN_)

#define ft_unlink(path_) ft_do_unlink(path_, FT_FL_LN_)

#define ft_unlink_err(path_, err_) ft_do_unlink_err(path_, err_, FT_FL_LN_)

#define ft_unlink_noent(path_) ft_do_unlink_noent(path_, FT_FL_LN_)

#define ft_unlinkat(dirfd_, name_, flags_) \
	ft_do_unlinkat(dirfd_, name_, flags_, FT_FL_LN_)

#define ft_unlinkat_noent(dirfd_, name_) \
	ft_do_unlinkat_noent(dirfd_, name_, FT_FL_LN_)

#define ft_open(path_, flags_, mode_, out_fd_) \
	ft_do_open(path_, flags_, mode_, out_fd_, FT_FL_LN_)

#define ft_open_err(path_, flags_, mode_, err_) \
	ft_do_open_err(path_, flags_, mode_, err_, FT_FL_LN_)

#define ft_openat(dirfd_, name_, flags_, mode_, out_fd_) \
	ft_do_openat(dirfd_, name_, flags_, mode_, out_fd_, FT_FL_LN_)

#define ft_openat_err(dirfd_, name_, flags_, mode_, err_) \
	ft_do_openat_err(dirfd_, name_, flags_, mode_, err_, FT_FL_LN_)

#define ft_creat(path_, mode_, out_fd_) \
	ft_do_creat(path_, mode_, out_fd_, FT_FL_LN_)

#define ft_close(fd_) ft_do_close(fd_, FT_FL_LN_)

#define ft_truncate(path_, len_) ft_do_truncate(path, len_, FT_FL_LN_)

#define ft_ftruncate(fd_, len_) ft_do_ftruncate(fd_, len_, FT_FL_LN_)

#define ft_llseek(fd_, off_, whence_, out_pos_) \
	ft_do_llseek(fd_, off_, whence_, out_pos_, FT_FL_LN_)

#define ft_llseek_err(fd_, off_, whence_, err_) \
	ft_do_llseek_err(fd_, off_, whence_, err_, FT_FL_LN_)

#define ft_write(fd_, buf_, cnt_, out_nwr_) \
	ft_do_write(fd_, buf_, cnt_, out_nwr_, FT_FL_LN_)

#define ft_write_err(fd_, buf_, cnt_, err_) \
	ft_do_write_err(fd_, buf_, cnt_, err_, FT_FL_LN_)

#define ft_pwrite(fd_, buf_, cnt_, off_, out_nwr_) \
	ft_do_pwrite(fd_, buf_, cnt_, off_, out_nwr_, FT_FL_LN_)

#define ft_pwrite_err(fd_, buf_, cnt_, off_, err_) \
	ft_do_pwrite_err(fd_, buf_, cnt_, off_, err_, FT_FL_LN_)

#define ft_read(fd_, buf_, cnt_, out_nrd_) \
	ft_do_read(fd_, buf_, cnt_, out_nrd_, FT_FL_LN_)

#define ft_read_err(fd_, buf_, cnt_, err_) \
	ft_do_read_err(fd_, buf_, cnt_, err_, FT_FL_LN_)

#define ft_pread(fd_, buf_, cnt_, off_, out_nrd_) \
	ft_do_pread(fd_, buf_, cnt_, off_, out_nrd_, FT_FL_LN_)

#define ft_fallocate(fd_, mode_, off_, len_) \
	ft_do_fallocate(fd_, mode_, off_, len_, FT_FL_LN_)

#define ft_fallocate_err(fd_, mode_, off_, len_, err_) \
	ft_do_fallocate_err(fd_, mode_, off_, len_, err_, FT_FL_LN_)

#define ft_fdatasync(fd_) ft_do_fdatasync(fd_, FT_FL_LN_)

#define ft_mkfifo(path_, mode_) ft_do_mkfifo(path_, mode_, FT_FL_LN_)

#define ft_mkfifoat(dirfd_, name_, mode_) \
	ft_do_mkfifoat(dirfd_, name_, mode_, FT_FL_LN_)

#define ft_mknod(path_, mode_, dev_) \
	ft_do_mknod((path_, mode_, dev_, FT_FL_LN_)

#define ft_mknodat(dirfd_, name_, mode_, dev_) \
	ft_do_mknodat(dirfd_, name_, mode_, dev_, FT_FL_LN_)

#define ft_symlink(oldpath_, newpath_) \
	ft_do_symlink(oldpath_, newpath_, FT_FL_LN_)

#define ft_symlinkat(target_, dirfd_, linkpath_) \
	ft_do_symlinkat(target_, dirfd_, linkpath_, FT_FL_LN_)

#define ft_readlink(path_, buf_, bsz_, out_cnt_) \
	ft_do_readlink(path_, buf_, bsz_, out_cnt_, FT_FL_LN_)

#define ft_readlink_err(path_, buf_, bsz_, err_) \
	ft_do_readlink_err(path_, buf_, bsz_, err_, FT_FL_LN_)

#define ft_readlinkat(dirfd_, name_, buf_, bsz_, out_cnt_) \
	ft_do_readlinkat(dirfd_, name_, buf_, bsz_, out_cnt_, FT_FL_LN_)

#define ft_rename(oldpath_, newpath_) \
	ft_do_rename(oldpath_, newpath_, FT_FL_LN_)

#define ft_rename_err(oldpath_, newpath_, err_) \
	ft_do_rename_err(oldpath_, newpath_, err_, FT_FL_LN_)

#define ft_renameat(olddirfd_, oldpath_, newdirfd_, newpath_) \
	ft_do_renameat(olddirfd_, oldpath_, newdirfd_, newpath_, FT_FL_LN_)

#define ft_renameat2(olddirfd_, oldpath_, newdirfd_, newpath_, flags_)    \
	ft_do_renameat2(olddirfd_, oldpath_, newdirfd_, newpath_, flags_, \
			FT_FL_LN_)

#define ft_link(oldpath_, newpath_) ft_do_link(oldpath_, newpath_, FT_FL_LN_)

#define ft_link_err(oldpath_, newpath_, err_) \
	ft_do_link_err(oldpath_, newpath_, err_, FT_FL_LN_)

#define ft_linkat(olddirfd_, oldpath_, newdirfd_, newpath_, flags_)    \
	ft_do_linkat(olddirfd_, oldpath_, newdirfd_, newpath_, flags_, \
		     FT_FL_LN_)

#define ft_linkat_err(olddirfd_, oldpath_, newdirfd_, newpath_, flags_, err_) \
	ft_do_linkat_err(olddirfd_, oldpath_, newdirfd_, newpath_, flags_,    \
			 err_, FT_FL_LN_)

#define ft_chmod(path_, mode_) ft_do_chmod(path_, mode_, FT_FL_LN_)

#define ft_fchmod(fd_, mode_) ft_do_fchmod(fd_, mode_, FT_FL_LN_)

#define ft_fchmod_err(fd_, mode_, err_) \
	ft_do_fchmod_err(fd_, mode_, err_, FT_FL_LN_)

#define ft_chown(path_, uid_, gid_) ft_do_chown(path_, uid_, gid_, FT_FL_LN_)

#define ft_fchown(fd_, uid_, gid_) ft_do_fchown(fd_, uid_, gid_, FT_FL_LN_)

#define ft_access(path_, mode_) ft_do_access(path_, mode_, FT_FL_LN_)

#define ft_access_err(path_, mode_, err_) \
	ft_do_access_err(path_, mode_, err_, FT_FL_LN_)

#define ft_mmap(addr_, len_, prot_, flags_, fd_, offset_, out_) \
	ft_do_mmap(addr_, len_, prot_, flags_, fd_, offset_, out_, FT_FL_LN_)

#define ft_munmap(addr_, len_) ft_do_munmap(addr_, len_, FT_FL_LN_)

#define ft_msync(addr_, len_, flags_) \
	ft_do_msync(addr_, len_, flags_, FT_FL_LN_)

#define ft_madvise(addr_, len_, advice_) \
	ft_do_madvise(addr_, len_, advice_, FT_FL_LN_)

#define ft_setxattr(path_, name_, value_, size_, flags_) \
	ft_do_setxattr(path_, name_, value_, size_, flags_, FT_FL_LN_)

#define ft_lsetxattr(path_, name_, value_, size_, flags_) \
	ft_do_lsetxattr(path_, name_, value_, size_, flags_, FT_FL_LN_)

#define ft_fsetxattr(fd_, name_, value_, size_, flags_) \
	ft_do_fsetxattr(fd_, name_, value_, size_, flags_, FT_FL_LN_)

#define ft_getxattr(path_, name_, value_, size_, out_cnt_) \
	ft_do_getxattr(path_, name_, value_, size_, out_cnt_, FT_FL_LN_)

#define ft_getxattr_err(path_, name_, err_) \
	ft_do_getxattr_err(path_, name_, err_, FT_FL_LN_)

#define ft_lgetxattr(path_, name_, value_, size_, out_cnt_) \
	ft_do_lgetxattr(path_, name_, value_, size_, out_cnt_, FT_FL_LN_)

#define ft_fgetxattr(fd_, name_, value_, size_, out_cnt_) \
	ft_do_fgetxattr(fd_, name_, value_, size_, out_cnt_, FT_FL_LN_)

#define ft_fgetxattr_err(fd_, name_, err_) \
	ft_do_fgetxattr_err(fd_, name_, err_, FT_FL_LN_)

#define ft_removexattr(path_, name_) ft_do_removexattr(path_, name_, FT_FL_LN_)

#define ft_lremovexattr(path_, name_) \
	ft_do_lremovexattr(path_, name_, FT_FL_LN_)

#define ft_fremovexattr(fd_, name_) ft_do_fremovexattr(fd_, name_, FT_FL_LN_)

#define ft_fremovexattr_err(fd_, name_, err_) \
	ft_do_fremovexattr_err(fd_, name_, err_, FT_FL_LN_)

#define ft_listxattr(path_, list_, size_, out_) \
	ft_do_listxattr(path_, list_, size_, out_, FT_FL_LN_)

#define ft_llistxattr(path_, list_, size_, out_) \
	ft_do_llistxattr(path_, list_, size_, out_, FT_FL_LN_)

#define ft_flistxattr(fd_, list_, size_, out_) \
	ft_do_flistxattr(fd_, list_, size_, out_, FT_FL_LN_)

#define ft_flistxattr_err(fd_, list_, size_, err_) \
	ft_do_flistxattr_err(fd_, list_, size_, err_, FT_FL_LN_)

#define ft_copy_file_range(fd_in_, off_in_, fd_out_, off_out_, len_, out_nc_) \
	ft_do_copy_file_range(fd_in_, off_in_, fd_out_, off_out_, len_,       \
			      out_nc_, FT_FL_LN_)

#define ft_fiemap(fd_, fm) ft_do_fiemap(fd_, fm, FT_FL_LN_)

#define ft_getdents(fd_, buf_, bsz_, des_, ndes_, out_ndes_) \
	ft_do_getdents(fd_, buf_, bsz_, des_, ndes_, out_ndes_, FT_FL_LN_)

#define ft_getdent(fd_, dent_) ft_do_getdent(fd_, dent_, FT_FL_LN_)

#define ft_readn(fd_, buf_, cnt_) ft_do_readn(fd_, buf_, cnt_, FT_FL_LN_)

#define ft_preadn(fd_, buf_, cnt_, off_) \
	ft_do_preadn(fd_, buf_, cnt_, off_, FT_FL_LN_)

#define ft_writen(fd_, buf_, cnt_) ft_do_writen(fd_, buf_, cnt_, FT_FL_LN_)

#define ft_pwriten(fd_, buf_, cnt_, off_) \
	ft_do_pwriten(fd_, buf_, cnt_, off_, FT_FL_LN_)

#define ft_ioctl_syncfs(fd_) ft_do_ioctl_syncfs(fd_, FT_FL_LN_)

#endif /* SILOFS_FUNTESTS_SYSCALL_H_ */
