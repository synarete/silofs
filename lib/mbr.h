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
#ifndef SILOFS_MBR_H_
#define SILOFS_MBR_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"
#include "bs.h"

struct silofs_env;

/* main boot-record, in-memory representation */
struct silofs_mbr {
	struct silofs_ivkey  main_ivkey;
	struct silofs_uuid   uuid;
	struct silofs_uaddr  sb_addr;
	struct silofs_baddr  arix_addr;
	enum silofs_mbr_kind kind;
	uint32_t             flags;
	int                  cipher_algo;
	int                  cipher_mode;
};

/* a tuple of content-addressable references to main boot-records */
struct silofs_mrefs {
	struct silofs_baddr main;
	struct silofs_baddr base;
	struct silofs_baddr fork;
};

/* main boot-record controller */
struct silofs_mbrinfo {
	struct silofs_mbr     fs_mbr;
	struct silofs_mbr     ar_mbr;
	struct silofs_cipher  cipher;
	struct silofs_mdigest mdigest;
	struct silofs_ivkey   ivkey;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbr_set_ar_addr(struct silofs_mbr         *mbr,
                            const struct silofs_baddr *baddr);

void silofs_make_mbr_uaddr(const union silofs_blobidu *blobid,
                           struct silofs_uaddr        *out_uaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mbri_init(struct silofs_mbrinfo *mbri);

void silofs_mbri_fini(struct silofs_mbrinfo *mbri);

int silofs_mbri_derive_ivkey(struct silofs_mbrinfo        *mbri,
                             const struct silofs_password *pw);

void silofs_mbri_update_sb_addr(struct silofs_mbrinfo     *mbri,
                                const struct silofs_uaddr *sb_uaddr);

int silofs_mbri_arix_addr(const struct silofs_mbrinfo *mbri,
                          struct silofs_baddr         *out_arix_baddr);

void silofs_mbri_update_arix_addr(struct silofs_mbrinfo     *mbri,
                                  const struct silofs_baddr *arix_baddr);

int silofs_mbri_regenerate_fs_mbr(struct silofs_mbrinfo *mbri);

int silofs_mbri_encode_mbr(const struct silofs_mbrinfo *mbri,
                           enum silofs_mbr_kind         mkind,
                           struct silofs_baddr         *out_mref,
                           struct silofs_mbr1k         *out_mbr1k);

int silofs_mbri_decode_mbr(struct silofs_mbrinfo     *mbri,
                           enum silofs_mbr_kind       mkind,
                           const struct silofs_baddr *mref,
                           const struct silofs_mbr1k *mbr1k);

int silofs_mbri_sync_mbrs(struct silofs_mbrinfo *mbri,
                          enum silofs_mbr_kind   dst_mkind);

#endif /* SILOFS_MBR_H_ */
