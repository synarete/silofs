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
#include <silofs/syscall.h>
#include <silofs/errors.h>
#include <silofs/infra/utility.h>
#include <silofs/infra/logging.h>
#include <silofs/infra/pipe.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Find last set bit in a non-zero 32-bit word */
static unsigned fls32(uint32_t x)
{
	return 32 - (unsigned)silofs_clz32(x);
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
 * See also 'pipe_set_size' and 'round_pipe_size' in Linux kernel.
 */
static long calc_pipe_size_of(long pipe_size_want)
{
	long page_size;
	long pipe_size;
	long pipe_size_lim;
	long pipe_size_min;
	long pipe_size_max;
	int err;

	page_size = silofs_sc_page_size();
	pipe_size_min = 2 * page_size;
	pipe_size_max = (1L << 21); /* 2M */

	err = silofs_proc_pipe_max_size(&pipe_size_lim);
	if (!err) {
		pipe_size_lim = roundup_pow_of_two(pipe_size_lim);
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

static size_t iov_count_ceil(const struct iovec *iov,
                             size_t niov, size_t len_max)
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
		silofs_log_warn("illegal pipe-size: pipesz=%d pagesz=%lu",
		                pipesz, pagesz);
		silofs_pipe_close(pipe);
		return -EINVAL;
	}
	pipe->size = (size_t)pipesz;
	return 0;
}

int silofs_pipe_setsize(struct silofs_pipe *pipe, size_t size_want)
{
	size_t size_set;
	int err;

	size_set = silofs_pipe_size_of(size_want);
	if (size_set == pipe->size) {
		return 0; /* no-op */
	}
	err = silofs_sys_fcntl_setpipesz(pipe->fd[0], (int)size_set);
	if (err) {
		silofs_log_warn("failed to set pipe size: size=%lu err=%d",
		                size_set, err);
		return err;
	}
	pipe->size = size_set;
	return 0;
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
	pipe->pend = 0;
}

static size_t pipe_avail(const struct silofs_pipe *pipe)
{
	return (pipe->size - pipe->pend);
}

int silofs_pipe_splice_from_fd(struct silofs_pipe *pipe, int fd, loff_t *off,
                               size_t len, unsigned int flags)
{
	size_t cnt;
	size_t nsp = 0;
	const loff_t off_in = off ? *off : 0;
	int err;

	cnt = silofs_min(pipe_avail(pipe), len);
	err = silofs_sys_splice(fd, off, pipe->fd[1], NULL, cnt, flags, &nsp);
	if (err) {
		silofs_log_error("splice-error: fd_in=%d off_in=%ld "\
		                 "fd_out=%d cnt=%lu flags=%u err=%d",
		                 fd, off_in, pipe->fd[1], cnt, flags, err);
		return err;
	}
	if (nsp > cnt) {
		silofs_log_error("bad-splice: fd_in=%d off_in=%ld fd_out=%d "\
		                 "cnt=%lu flags=%u nsp=%lu", fd, off_in,
		                 pipe->fd[1], cnt, flags, nsp);
		return -SILOFS_EIO;
	}
	pipe->pend += nsp;
	return 0;
}

int silofs_pipe_vmsplice_from_iov(struct silofs_pipe *pipe,
                                  const struct iovec *iov,
                                  size_t niov, unsigned int flags)
{
	size_t cnt;
	size_t nsp = 0;
	int err;

	cnt = iov_count_ceil(iov, niov, pipe_avail(pipe));
	err = silofs_sys_vmsplice(pipe->fd[1], iov, cnt, flags, &nsp);
	if (err) {
		silofs_log_error("vmsplice-error: fd=%d cnt=%lu "\
		                 "flags=%u err=%d",
		                 pipe->fd[1], cnt, flags, err);
		return err;
	}
	pipe->pend += nsp;
	return 0;
}

int silofs_pipe_splice_to_fd(struct silofs_pipe *pipe, int fd,
                             loff_t *off, size_t len, unsigned int flags)
{
	size_t cnt;
	size_t nsp = 0;
	const loff_t off_out = off ? *off : 0;
	int err;

	cnt = silofs_min(pipe->pend, len);
	err = silofs_sys_splice(pipe->fd[0], NULL, fd, off, cnt, flags, &nsp);
	if (err) {
		silofs_log_error("splice-error: fd_in=%d fd_out=%d "\
		                 "off_out=%ld cnt=%lu flags=%u err=%d",
		                 pipe->fd[0], fd, off_out, cnt, flags, err);
		return err;
	}
	if (nsp > pipe->pend) {
		silofs_log_error("bad-splice: fd_in=%d fd_out=%d off_out=%ld"\
		                 "cnt=%lu flags=%u nsp=%lu",
		                 pipe->fd[0], fd, off_out, cnt, flags, nsp);
		return -SILOFS_EIO;
	}
	pipe->pend -= nsp;
	return 0;
}

int silofs_pipe_vmsplice_to_iov(struct silofs_pipe *pipe,
                                const struct iovec *iov,
                                size_t niov, unsigned int flags)
{
	size_t len;
	size_t cnt;
	size_t nsp = 0;
	int err;

	cnt = iov_count_ceil(iov, niov, pipe->pend);
	len = iov_length(iov, cnt);
	err = silofs_sys_vmsplice(pipe->fd[0], iov, cnt, flags, &nsp);
	if (err) {
		silofs_log_error("vmsplice-error: fd=%d cnt=%lu "
		                 "flags=%u err=%d", pipe->fd[1],
		                 cnt, flags, err);
		return err;
	}
	if ((nsp != len) || (nsp > pipe->pend)) {
		silofs_log_error("bad-vmsplice: fd=%d cnt=%lu "
		                 "flags=%u nsp=%lu", pipe->fd[1],
		                 cnt, flags, nsp);
		return -SILOFS_EIO;
	}
	pipe->pend -= nsp;
	return 0;
}

int silofs_pipe_copy_to_buf(struct silofs_pipe *pipe, void *buf, size_t len)
{
	size_t cnt;
	int err;

	cnt = silofs_min(pipe->pend, len);
	err = silofs_sys_readn(pipe->fd[0], buf, cnt);
	if (err) {
		silofs_log_error("readn-from-pipe: fd=%ld cnt=%lu err=%d",
		                 pipe->fd[0], cnt, err);
		return err;
	}
	pipe->pend -= cnt;
	return 0;
}

int silofs_pipe_append_from_buf(struct silofs_pipe *pipe,
                                const void *buf, size_t len)
{
	size_t cnt;
	int err;

	cnt = silofs_min(pipe->size, len);
	err = silofs_sys_writen(pipe->fd[1], buf, cnt);
	if (err) {
		silofs_log_error("writen-to-pipe: fd=%ld cnt=%lu err=%d",
		                 pipe->fd[1], cnt, err);
		return err;
	}
	pipe->pend += cnt;
	return 0;
}

int silofs_pipe_flush_to_fd(struct silofs_pipe *pipe, int fd)
{
	int ret = 0;

	if (pipe->pend > 0) {
		ret = silofs_pipe_splice_to_fd(pipe, fd, NULL,
		                               pipe->pend, SPLICE_F_NONBLOCK);
	}
	return ret;
}

int silofs_pipe_dispose(struct silofs_pipe *pipe,
                        const struct silofs_nilfd *nfd)
{
	return silofs_pipe_flush_to_fd(pipe, nfd->fd);
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

static int silofs_nilfd_init(struct silofs_nilfd *nfd)
{
	const char *path = "/dev/null";
	const int o_flags = O_WRONLY | O_CREAT | O_TRUNC;
	int err;

	err = silofs_sys_open(path, o_flags, 0666, &nfd->fd);
	if (err) {
		silofs_log_warn("failed to open '%s': o_flags=%o err=%d",
		                path, o_flags, err);
	}
	return err;
}

static void silofs_nilfd_fini(struct silofs_nilfd *nfd)
{
	silofs_sys_closefd(&nfd->fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_piper_init(struct silofs_piper *piper, size_t pipe_size)
{
	struct silofs_nilfd *nfd = &piper->nfd;
	struct silofs_pipe *pipe = &piper->pipe;
	int err;

	silofs_pipe_init(pipe);
	err = silofs_pipe_open(pipe);
	if (err) {
		return err;
	}
	err = silofs_pipe_setsize(pipe, pipe_size);
	if (err) {
		goto out_err;
	}
	err = silofs_nilfd_init(nfd);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_pipe_fini(pipe);
	return err;
}

void silofs_piper_fini(struct silofs_piper *piper)
{
	silofs_nilfd_fini(&piper->nfd);
	silofs_pipe_fini(&piper->pipe);
}

int silofs_piper_dispose(struct silofs_piper *piper)
{
	return silofs_pipe_dispose(&piper->pipe, &piper->nfd);
}

int silofs_piper_kcopy(struct silofs_piper *piper, int fd_in, loff_t *off_in,
                       int fd_out, loff_t *off_out, size_t len,
                       unsigned int flags)
{
	return pipe_kcopy_by_splice(&piper->pipe, fd_in, off_in,
	                            fd_out, off_out, len, flags);
}
