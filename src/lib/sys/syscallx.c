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
#include <silofs/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void *buffer_at(const void *buf, size_t step)
{
	union {
		const void *p;
		void *q;
	} u = {
		.p = (const uint8_t *)buf + step
	};

	return u.q;
}

static loff_t offset_at(loff_t base, size_t step)
{
	return base + (loff_t)step;
}

static int io_status(int err, size_t nexpected, size_t ncomplete)
{
	if (err) {
		return err;
	}
	if (nexpected != ncomplete) {
		return -EIO;
	}
	return 0;
}

int silofs_sys_readn(int fd, void *buf, size_t cnt)
{
	uint8_t *ptr;
	size_t nrd_cur;
	size_t nrd = 0;
	int err = 0;

	while (nrd < cnt) {
		ptr = buffer_at(buf, nrd);
		nrd_cur = 0;
		err = silofs_sys_read(fd, ptr, cnt - nrd, &nrd_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	return io_status(err, nrd, cnt);
}

int silofs_sys_preadn(int fd, void *buf, size_t cnt, loff_t off)
{
	uint8_t *ptr;
	loff_t pos;
	size_t nrd_cur;
	size_t nrd = 0;
	int err = 0;

	while (nrd < cnt) {
		ptr = buffer_at(buf, nrd);
		pos = offset_at(off, nrd);
		nrd_cur = 0;
		err = silofs_sys_pread(fd, ptr, cnt - nrd, pos, &nrd_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	return io_status(err, nrd, cnt);
}

int silofs_sys_writen(int fd, const void *buf, size_t cnt)
{
	const uint8_t *ptr;
	size_t nwr_cur;
	size_t nwr = 0;
	int err = 0;

	while (nwr < cnt) {
		ptr = buffer_at(buf, nwr);
		nwr_cur = 0;
		err = silofs_sys_write(fd, ptr, cnt - nwr, &nwr_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nwr_cur) {
			break;
		}
		nwr += nwr_cur;
	}
	return io_status(err, nwr, cnt);
}

int silofs_sys_pwriten(int fd, const void *buf, size_t cnt, loff_t off)
{
	const uint8_t *ptr;
	loff_t pos;
	size_t nwr_cur;
	size_t nwr = 0;
	int err = 0;

	while (nwr < cnt) {
		ptr = buffer_at(buf, nwr);
		pos = offset_at(off, nwr);
		nwr_cur = 0;
		err = silofs_sys_pwrite(fd, ptr, cnt - nwr, pos, &nwr_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nwr_cur) {
			break;
		}
		nwr += nwr_cur;
	}
	return io_status(err, nwr, cnt);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void iov_clone(const struct iovec *iov, struct iovec *other, int cnt)
{
	memcpy(other, iov, (size_t)cnt * sizeof(*other));
}

static size_t iov_length(const struct iovec *iov, int cnt)
{
	size_t len = 0;

	for (int i = 0; i < cnt; ++i) {
		len += iov[i].iov_len;
	}
	return len;
}

static void iov_advance(struct iovec **p_iov, size_t len)
{
	struct iovec *iov = *p_iov;

	while (len && (len >= iov->iov_len)) {
		len -= iov->iov_len;
		iov++;
	}
	iov->iov_len -= len;
	*p_iov = iov;
}

static int do_sys_pwritevn(int fd, struct iovec *iov, int cnt,
                           loff_t off, loff_t *out_off)
{
	size_t nwr_cur;
	size_t nwr = 0;
	const size_t len = iov_length(iov, cnt);
	int err = 0;

	while (nwr < len) {
		err = silofs_sys_pwritev(fd, iov, cnt, off, &nwr_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nwr_cur) {
			break;
		}
		iov_advance(&iov, nwr_cur);
		nwr += nwr_cur;
		off += (loff_t)nwr_cur;
	}
	*out_off = off;
	return io_status(err, nwr, len);
}

#define PWRITEVN_IOV_MAX 128

int silofs_sys_pwritevn(int fd, const struct iovec *iov, int cnt, loff_t off)
{
	struct iovec iov2[PWRITEVN_IOV_MAX];
	const int cnt_max = PWRITEVN_IOV_MAX;
	int cnt2;
	int err = 0;

	while ((cnt > 0) && !err) {
		cnt2 = (cnt > cnt_max) ? cnt_max : cnt;
		iov_clone(iov, iov2, cnt2);
		err = do_sys_pwritevn(fd, iov2, cnt2, off, &off);
		iov += cnt2;
		cnt -= cnt2;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sys_opendir(const char *path, int *out_fd)
{
	return silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, out_fd);
}

int silofs_sys_opendirat(int dfd, const char *pathname, int *out_fd)
{
	return silofs_sys_openat(dfd, pathname,
	                         O_DIRECTORY | O_RDONLY, 0, out_fd);
}

int silofs_sys_closefd(int *pfd)
{
	int err = 0;

	if ((pfd != NULL) && (*pfd > 0)) {
		err = silofs_sys_close(*pfd);
		if (!err) {
			*pfd = -1;
		}
	}
	return err;
}

int silofs_sys_munmapp(void **p_addr, size_t length)
{
	int err = 0;

	if ((*p_addr != NULL) && (length > 0)) {
		err = silofs_sys_munmap(*p_addr, length);
		if (!err) {
			*p_addr = NULL;
		}
	}
	return err;
}

int silofs_sys_llseek_data(int fd, loff_t off, loff_t *out_data_off)
{
	int err;
	loff_t pos = 0;

	err = silofs_sys_llseek(fd, off, SEEK_SET, &pos);
	if (err) {
		return err;
	}
	err = silofs_sys_llseek(fd, pos, SEEK_DATA, out_data_off);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sys_pselect_rfd(int fd, const struct timespec *ts)
{
	fd_set rfds;
	int err;
	int nfds = 0;

	if (fd >= FD_SETSIZE) {
		return -EBADF;
	}
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	err = silofs_sys_pselect(fd + 1, &rfds, NULL, NULL, ts, NULL, &nfds);
	if (err) {
		return err;
	}
	if (!nfds || !FD_ISSET(fd, &rfds)) {
		return -ETIMEDOUT;
	}
	return 0;
}

int silofs_sys_pollin_rfd(int fd, int timeout)
{
	struct pollfd fds = {
		.fd = fd,
		.events = POLLIN,
		.revents = 0,
	};
	int nfds = 0;
	int err;

	err = silofs_sys_poll(&fds, 1, timeout, &nfds);
	if (err) {
		return err;
	}
	if (!nfds || !fds.revents) {
		return -ETIMEDOUT;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sys_readfile(int dfd, const char *filename,
                        void *buf, size_t bsz, int flags, size_t *nrd)
{
	int err;
	int fd = -1;

	err = silofs_sys_openat(dfd, filename, flags, 0, &fd);
	if (err) {
		return err;
	}
	err = silofs_sys_read(fd, buf, bsz, nrd);
	if (err) {
		silofs_sys_close(fd);
		return err;
	}
	err = silofs_sys_close(fd);
	if (err) {
		return err;
	}
	return 0;
}

static int sys_readproc(const char *procdir, const char *filename,
                        void *buf, size_t bsz, size_t *nrd)
{
	int err;
	int dfd = -1;

	err = silofs_sys_open(procdir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		return err;
	}
	err = sys_readfile(dfd, filename, buf, bsz, O_RDONLY, nrd);
	if (err) {
		silofs_sys_close(dfd);
		return err;
	}
	err = silofs_sys_close(dfd);
	if (err) {
		return err;
	}
	return 0;
}

static int sys_readproc_long(const char *pathname, long *out_value)
{
	char buf[128];
	size_t nrd = 0;
	char *end = NULL;
	int err;

	memset(buf, 0, sizeof(buf));
	err = sys_readproc("/proc", pathname, buf, sizeof(buf) - 1, &nrd);
	if (err) {
		return err;
	}
	if (!nrd || !strlen(buf)) {
		return -ENODATA;
	}
	errno = 0;
	*out_value = strtol(buf, &end, 10);
	return -errno;
}

int silofs_proc_get_value(const char *pathname, long *out_value)
{
	return sys_readproc_long(pathname, out_value);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long silofs_sc_l1_dcache_linesize(void)
{
	return sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
}

long silofs_sc_page_size(void)
{
	return sysconf(_SC_PAGE_SIZE);
}

long silofs_sc_phys_pages(void)
{
	return sysconf(_SC_PHYS_PAGES);
}

long silofs_sc_avphys_pages(void)
{
	return sysconf(_SC_AVPHYS_PAGES);
}

long silofs_sc_nproc_conf(void)
{
	return sysconf(_SC_NPROCESSORS_CONF);
}

long silofs_sc_nproc_onln(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

long silofs_sc_iov_max(void)
{
	return sysconf(_SC_IOV_MAX);
}
