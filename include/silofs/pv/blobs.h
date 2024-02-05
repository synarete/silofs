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
#ifndef SILOFS_BLOBS_H_
#define SILOFS_BLOBS_H_


/* blob file-handle */
struct silofs_blob_fh {
	struct silofs_hmapq_elem        bf_hmqe;
	struct silofs_blobid            bf_blobid;
	ssize_t                         bf_size;
	int                             bf_fd;
};

/* persistent-volume blobs store */
struct silofs_bstore {
	struct silofs_mutex             bs_mutex;
	struct silofs_hmapq             bs_hmapq;
	struct silofs_alloc            *bs_alloc;
	int                             bs_dirfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_init(struct silofs_bstore *bstore,
                       struct silofs_alloc *alloc);

void silofs_bstore_fini(struct silofs_bstore *bstore);

int silofs_bstore_open(struct silofs_bstore *bstore, const char *pathname);

void silofs_bstore_close(struct silofs_bstore *bstore);

int silofs_bstore_mkblob(struct silofs_bstore *bstore,
                         const struct silofs_blobid *blobid);

int silofs_bstore_rmblob(struct silofs_bstore *bstore,
                         const struct silofs_blobid *blobid);

int silofs_bstore_append(struct silofs_bstore *bstore,
                         const struct silofs_blobid *blobid,
                         const void *dat, size_t len);

int silofs_bstore_pread(struct silofs_bstore *bstore,
                        const struct silofs_blobid *blobid,
                        loff_t off, size_t len, void *dat);

int silofs_bstore_flush(struct silofs_bstore *bstore,
                        const struct silofs_blobid *blobid);

#endif /* SILOFS_BLOBS_H_ */
