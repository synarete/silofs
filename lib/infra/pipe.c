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
#include <silofs/errors.h>
#include <silofs/infra/utility.h>
#include <silofs/infra/logging.h>
#include <silofs/infra/pipe.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Find last set bit in a non-zero 32-bit word */
static unsigned fls32(uint32_t x)
{
	return 32 - (unsigned)silofs_clz_u32(x);
}

static long roundup_pow_of_two(long n)
{
	return 1L << fls32((uint32_t)(n - 1));
}

/*
 * Linux kernel want pipe size to be power-of-2. The current limit value of
 * pipe size (on a given machine) is visible at '/proc/sys/fs/pipe-max-size'.
 * Clap pipe size to range of [2-pages, 2M], unless system's limit is below
 * two pages (should not happen on modern machines).
 *
 * Note: the size from '/proc/sys/fs/pipe-max-size' is just a hint to pipe-size
 * limit. In real world, a user may not have enough resources to allocate
 * such size (e.g. due to low threshold in '/proc/sys/fs/pipe-user-pages-soft'
 * or when other processes cosume too many pipe pages).
 *
 * See also 'pipe_set_size' and 'round_pipe_size' in Linux kernel.
 */
static long calc_pipe_size_of(long pipe_size_want)
{
	struct silofs_pipe_limits pipe_lim = { .pipe_max_size = -1 };
	long page_size;
	long pipe_size;
	long pipe_size_lim;
	long pipe_size_min;
	long pipe_size_max;
	int err;

	page_size = silofs_sc_page_size();
	pipe_size_min = 2 * page_size;
	pipe_size_max = (1L << 21); /* 2M */

	err = silofs_proc_pipe_limits(&pipe_lim);
	if (!err) {
		pipe_size_lim = roundup_pow_of_two(pipe_lim.pipe_max_size);
		if (pipe_size_max > pipe_size_lim) {
			pipe_size_max = pipe_size_lim;
		}
		if (pipe_size_min > pipe_size_max) {
			pipe_size_min = pipe_size_max;
		}
	} else {
		pipe_size_max = 16 * page_size;
	}

	if (pipe_size_want >= pipe_size_max) {
		pipe_size = pipe_size_max;
	} else if (pipe_size_want <= pipe_size_min) {
		pipe_size = pipe_size_min;
	} else {
		pipe_size = roundup_pow_of_two(pipe_size_want);
	}
	return pipe_size;
}

size_t silofs_pipe_size_of(size_t pipe_size_want)
{
	return (size_t)calc_pipe_size_of((long)pipe_size_want);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t iov_length(const struct iovec *iov, size_t niov)
{
	size_t len = 0;

	for (size_t i = 0; i < niov; ++i) {
		len += iov[i].iov_len;
	}
	return len;
}

static size_t
iov_count_ceil(const struct iovec *iov, size_t niov, size_t len_max)
{
	size_t cnt = 0;
	size_t len = 0;

	for (size_t i = 0; i < niov; ++i) {
		if (len >= len_max) {
			break;
		}
		cnt++;
		len += iov[i].iov_len;
	}
	return cnt;
}

void silofs_pipe_init(struct silofs_pipe *pipe)
{
	pipe->fd[0] = -1;
	pipe->fd[1] = -1;
	pipe->size = 0;
	pipe->pend = 0; /* TODO: maybe use 'ioctl(FIONREAD)' ? */
}

int silofs_pipe_open(struct silofs_pipe *pipe)
{
	const long pagesz = silofs_sc_page_size();
	int pipesz = 0;
	int err;

	err = silofs_sys_pipe2(pipe->fd, O_CLOEXEC | O_NONBLOCK);
	if (err) {
		silofs_log_warn("failed to create pipe: err=%d", err);
		return err;
	}
	err = silofs_sys_fcntl_getpipesz(pipe->fd[0], &pipesz);
	if (err) {
		silofs_log_warn("failed to get pipe-size: err=%d", err);
		silofs_pipe_close(pipe);
		return err;
	}
	if (pipesz < pagesz) {
		silofs_log_warn("illegal pipe-size: pipesz=%d pagesz=%zu",
				pipesz, pagesz);
		silofs_pipe_close(pipe);
		return -EINVAL;
	}
	pipe->size = pipesz;
	return 0;
}

static int pipe_setsize(struct silofs_pipe *pipe, size_t size_want)
{
	size_t size_set;
	int err;

	size_set = silofs_pipe_size_of(size_want);
	if ((int)size_set == pipe->size) {
		return 0; /* no-op */
	}
	err = silofs_sys_fcntl_setpipesz(pipe->fd[0], (int)size_set);
	if (err) {
		return err;
	}
	pipe->size = (int)size_set;
	return 0;
}

static bool pipe_isopen(const struct silofs_pipe *pipe)
{
	return (pipe->size > 0);
}

static int pipe_try_grow(struct silofs_pipe *pipe, size_t pipe_size_want)
{
	long page_size;
	long pipe_size;
	int err = 0;

	if (!pipe_isopen(pipe)) {
		return -SILOFS_EBADF;
	}
	page_size = silofs_sc_page_size();
	if (((long)pipe_size_want < page_size) ||
	    (long)pipe_size_want > (1024 * page_size)) {
		return -SILOFS_EINVAL;
	}
	pipe_size = calc_pipe_size_of((long)pipe_size_want);
	if ((long)pipe->size < pipe_size) {
		err = pipe_setsize(pipe, (size_t)pipe_size);
	}
	return err;
}

void silofs_pipe_close(struct silofs_pipe *pipe)
{
	if (pipe->fd[0] > 0) {
		silofs_sys_close(pipe->fd[0]);
		pipe->fd[0] = -1;
	}
	if (pipe->fd[1] > 0) {
		silofs_sys_close(pipe->fd[1]);
		pipe->fd[1] = -1;
	}
}

void silofs_pipe_fini(struct silofs_pipe *pipe)
{
	silofs_pipe_close(pipe);
	pipe->size = 0;
	pipe->pend = -1;
}

static size_t pipe_avail(const struct silofs_pipe *pipe)
{
	return (size_t)(pipe->size - pipe->pend);
}

int silofs_pipe_splice_from_fd(struct silofs_pipe *pipe, int fd, loff_t *off,
			       size_t len, unsigned int flags)
{
	size_t cnt;
	size_t nsp = 0;
	loff_t off_in = (off != NULL) ? *off : 0;
	const int fd_in = pipe->fd[1];
	int err;

	if (!pipe_isopen(pipe)) {
		return -SILOFS_EBADF;
	}

	cnt = silofs_min(pipe_avail(pipe), len);
	err = silofs_sys_splice(fd, &off_in, fd_in, NULL, cnt, flags, &nsp);
	if (err) {
		silofs_log_warn("splice-error: fd_in=%d off_in=%ld "
				"fd_out=%d cnt=%zu flags=%u err=%d",
				fd, off_in, fd_in, cnt, flags, err);
		return err;
	}
	if (nsp > cnt) {
		silofs_log_error("bad-splice: fd_in=%d off_in=%ld fd_out=%d "
				 "cnt=%zu flags=%u nsp=%zu",
				 fd, off_in, fd_in, cnt, flags, nsp);
		return -SILOFS_EIO;
	}
	pipe->pend += (int)nsp;
	return 0;
}

int silofs_pipe_vmsplice_from_iov(struct silofs_pipe *pipe,
				  const struct iovec *iov, size_t niov,
				  unsigned int flags)
{
	size_t cnt;
	size_t nsp = 0;
	const int fd = pipe->fd[1];
	int err;

	if (!pipe_isopen(pipe)) {
		return -SILOFS_EBADF;
	}

	cnt = iov_count_ceil(iov, niov, pipe_avail(pipe));
	err = silofs_sys_vmsplice(fd, iov, cnt, flags, &nsp);
	if (err) {
		silofs_log_warn("vmsplice-error: fd=%d cnt=%zu "
				"flags=%u err=%d",
				fd, cnt, flags, err);
		return err;
	}
	pipe->pend += (int)nsp;
	return 0;
}

int silofs_pipe_splice_to_fd(struct silofs_pipe *pipe, int fd, loff_t *off,
			     size_t len, unsigned int flags)
{
	loff_t off_out = (off != NULL) ? *off : 0;
	size_t cnt = 0;
	size_t nsp = 0;
	const int fd_in = pipe->fd[0];
	int nonblock_err;
	int err;

	if (!pipe_isopen(pipe)) {
		return -SILOFS_EBADF;
	}

	cnt = silofs_min((size_t)pipe->pend, len);
	err = silofs_sys_splice(fd_in, NULL, fd, &off_out, cnt, flags, &nsp);
	nonblock_err = (err == -EAGAIN) && ((flags & SPLICE_F_NONBLOCK) > 0);
	if (nonblock_err) {
		silofs_log_debug("partial-splice: fd_in=%d fd_out=%d "
				 "off_out=%ld cnt=%zu flags=%u nsp=%zu",
				 fd_in, fd, off_out, cnt, flags, nsp);
	} else if (err) {
		silofs_log_error("splice-error: fd_in=%d fd_out=%d "
				 "off_out=%ld cnt=%zu flags=%u err=%d",
				 fd_in, fd, off_out, cnt, flags, err);
		return err;
	}
	if ((int)nsp > pipe->pend) {
		silofs_log_error("bad-splice: fd_in=%d fd_out=%d off_out=%ld"
				 "cnt=%zu flags=%u nsp=%zu",
				 pipe->fd[0], fd, off_out, cnt, flags, nsp);
		return -SILOFS_EIO;
	}
	pipe->pend -= (int)nsp;
	return err; /* OK or -EAGAIN if SPLICE_F_NONBLOCK */
}

int silofs_pipe_vmsplice_to_iov(struct silofs_pipe *pipe,
				const struct iovec *iov, size_t niov,
				unsigned int flags)
{
	size_t len;
	size_t cnt;
	size_t nsp = 0;
	const int fd = pipe->fd[0];
	int err;

	if (!pipe_isopen(pipe)) {
		return -SILOFS_EBADF;
	}

	cnt = iov_count_ceil(iov, niov, (size_t)(pipe->pend));
	len = iov_length(iov, cnt);
	err = silofs_sys_vmsplice(fd, iov, cnt, flags, &nsp);
	if (err) {
		silofs_log_error("vmsplice-error: fd=%d cnt=%zu "
				 "flags=%u err=%d",
				 pipe->fd[1], cnt, flags, err);
		return err;
	}
	if ((nsp != len) || ((int)nsp > pipe->pend)) {
		silofs_log_error("bad-vmsplice: fd=%d cnt=%zu "
				 "flags=%u nsp=%zu",
				 fd, cnt, flags, nsp);
		return -SILOFS_EIO;
	}
	pipe->pend -= (int)nsp;
	return 0;
}

int silofs_pipe_copy_to_buf(struct silofs_pipe *pipe, void *buf, size_t len)
{
	size_t cnt;
	const int fd = pipe->fd[0];
	int err;

	if (!pipe_isopen(pipe)) {
		return -SILOFS_EBADF;
	}

	cnt = silofs_min((size_t)pipe->pend, len);
	err = silofs_sys_readn(pipe->fd[0], buf, cnt);
	if (err) {
		silofs_log_error("readn-from-pipe: fd=%d cnt=%zu err=%d", fd,
				 cnt, err);
		return err;
	}
	pipe->pend -= (int)cnt;
	return 0;
}

int silofs_pipe_append_from_buf(struct silofs_pipe *pipe, const void *buf,
				size_t len)
{
	size_t cnt = 0;
	const int fd = pipe->fd[1];
	int err;

	if (!pipe_isopen(pipe)) {
		return -SILOFS_EBADF;
	}

	cnt = silofs_min((size_t)pipe->size, len);
	err = silofs_sys_writen(fd, buf, cnt);
	if (err) {
		silofs_log_error("writen-to-pipe: fd=%d cnt=%zu err=%d", fd,
				 cnt, err);
		return err;
	}
	pipe->pend += (int)cnt;
	return 0;
}

int silofs_pipe_flush_to_fd(struct silofs_pipe *pipe, int fd,
			    unsigned int flags)
{
	return (pipe->pend > 0) ?
		       silofs_pipe_splice_to_fd(pipe, fd, NULL,
						(size_t)pipe->pend, flags) :
		       0;
}

int silofs_pipe_dispose(struct silofs_pipe *pipe,
			const struct silofs_nilfd *nfd)
{
	return silofs_pipe_flush_to_fd(pipe, nfd->fd, 0);
}

static int pipe_kcopy_by_splice(struct silofs_pipe *pipe, int fd_in,
				loff_t *off_in, int fd_out, loff_t *off_out,
				size_t len, unsigned int flags)
{
	int err;

	err = silofs_pipe_splice_from_fd(pipe, fd_in, off_in, len, flags);
	if (err) {
		return err;
	}
	err = silofs_pipe_splice_to_fd(pipe, fd_out, off_out, len, flags);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void silofs_nilfd_close(struct silofs_nilfd *nfd)
{
	if (!(nfd->fd < 0)) {
		silofs_sys_closefd(&nfd->fd);
	}
}

static void silofs_nilfd_init(struct silofs_nilfd *nfd)
{
	nfd->fd = -1;
}

static void silofs_nilfd_fini(struct silofs_nilfd *nfd)
{
	silofs_nilfd_close(nfd);
	nfd->fd = -1;
}

static int silofs_nilfd_open(struct silofs_nilfd *nfd)
{
	const char *path = "/dev/null";
	const int o_flags = O_WRONLY | O_CREAT | O_TRUNC;
	int err = 0;

	if (nfd->fd < 0) {
		err = silofs_sys_open(path, o_flags, 0666, &nfd->fd);
		if (err) {
			silofs_log_warn("failed to open: path=%s"
					"o_flags=%o err=%d",
					path, o_flags, err);
		}
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_piper_init(struct silofs_piper *piper)
{
	silofs_pipe_init(&piper->pipe);
	silofs_nilfd_init(&piper->nfd);
}

void silofs_piper_fini(struct silofs_piper *piper)
{
	silofs_nilfd_fini(&piper->nfd);
	silofs_pipe_fini(&piper->pipe);
}

int silofs_piper_open(struct silofs_piper *piper)
{
	int err;

	err = silofs_nilfd_open(&piper->nfd);
	if (err) {
		return err;
	}
	err = silofs_pipe_open(&piper->pipe);
	if (err) {
		silofs_nilfd_close(&piper->nfd);
		return err;
	}
	return 0;
}

void silofs_piper_close(struct silofs_piper *piper)
{
	silofs_nilfd_close(&piper->nfd);
	silofs_pipe_close(&piper->pipe);
}

int silofs_piper_try_grow(struct silofs_piper *piper, size_t sz)
{
	int ret = 0;

	if ((int)sz != piper->pipe.size) {
		ret = pipe_try_grow(&piper->pipe, sz);
	}
	return ret;
}

int silofs_piper_dispose(struct silofs_piper *piper)
{
	return silofs_pipe_dispose(&piper->pipe, &piper->nfd);
}

int silofs_piper_kcopy(struct silofs_piper *piper, int fd_in, loff_t *off_in,
		       int fd_out, loff_t *off_out, size_t len,
		       unsigned int flags)
{
	return pipe_kcopy_by_splice(&piper->pipe, fd_in, off_in, fd_out,
				    off_out, len, flags);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_proc_pipe_limits(struct silofs_pipe_limits *pl)
{
	const long page_size = silofs_sc_page_size();
	int err;

	err = silofs_proc_get_value("sys/fs/pipe-max-size",
				    &pl->pipe_max_size);
	if (err) {
		return err;
	}
	err = silofs_proc_get_value("sys/fs/pipe-user-pages-hard",
				    &pl->pipe_user_pages_hard);
	if (err) {
		return err;
	}
	err = silofs_proc_get_value("sys/fs/pipe-user-pages-soft",
				    &pl->pipe_user_pages_soft);
	if (err) {
		return err;
	}
	pl->pipe_max_pages = (pl->pipe_max_size / page_size);

	return 0;
}
