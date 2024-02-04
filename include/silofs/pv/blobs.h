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
	struct silofs_pvsegid           bf_pvsid;
	struct silofs_list_head         bf_htb_lh;
	struct silofs_list_head         bf_lru_lh;
	ssize_t                         bf_size;
	int                             bf_fd;
};

/* blobs storage */
struct silofs_blobstore {
	struct silofs_alloc            *bs_alloc;
	struct silofs_mutex             bs_mutex;
	struct silofs_hmapq             bs_hmapq;
	int                             bs_dirfd;
};

#endif /* SILOFS_BLOBS_H_ */
