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
#ifndef SILOFS_PIPE_H_
#define SILOFS_PIPE_H_

#include <stdlib.h>

struct iovec;

struct silofs_pipe {
	int fd[2];
	size_t size;
	size_t pend;
};

struct silofs_nilfd {
	int fd;
};

struct silofs_piper {
	struct silofs_nilfd     nfd;
	struct silofs_pipe      pipe;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_pipe_size_of(size_t pipe_size_want);


void silofs_pipe_init(struct silofs_pipe *pipe);

int silofs_pipe_open(struct silofs_pipe *pipe);

int silofs_pipe_setsize(struct silofs_pipe *pipe, size_t size);

void silofs_pipe_close(struct silofs_pipe *pipe);

void silofs_pipe_fini(struct silofs_pipe *pipe);

int silofs_pipe_splice_from_fd(struct silofs_pipe *pipe, int fd, loff_t *off,
                               size_t len, unsigned int flags);

int silofs_pipe_vmsplice_from_iov(struct silofs_pipe *pipe,
                                  const struct iovec *iov,
                                  size_t niov, unsigned int flags);

int silofs_pipe_splice_to_fd(struct silofs_pipe *pipe, int fd,
                             loff_t *off, size_t len, unsigned int flags);

int silofs_pipe_vmsplice_to_iov(struct silofs_pipe *pipe,
                                const struct iovec *iov,
                                size_t niov, unsigned int flags);

int silofs_pipe_copy_to_buf(struct silofs_pipe *pipe, void *buf, size_t len);

int silofs_pipe_append_from_buf(struct silofs_pipe *pipe,
                                const void *buf, size_t len);

int silofs_pipe_flush_to_fd(struct silofs_pipe *pipe, int fd);

int silofs_pipe_dispose(struct silofs_pipe *pipe,
                        const struct silofs_nilfd *nfd);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_piper_init(struct silofs_piper *piper, size_t pipe_size);

void silofs_piper_fini(struct silofs_piper *piper);

int silofs_piper_dispose(struct silofs_piper *piper);

int silofs_piper_kcopy(struct silofs_piper *piper, int fd_in, loff_t *off_in,
                       int fd_out, loff_t *off_out, size_t len,
                       unsigned int flags);

#endif /* SILOFS_PIPE_H_ */
