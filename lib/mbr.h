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

/* a tuple of content-addressable references to main boot-records */
struct silofs_mrefs {
	struct silofs_paddr main;
	struct silofs_paddr base;
	struct silofs_paddr fork;
};

/* root address based on mbr sub-type */
union silofs_mbr_root {
	struct silofs_paddr uber_addr;
	struct silofs_paddr arix_addr;
};

/* main boot-record, in-memory representation */
struct silofs_mbr {
	struct silofs_ivkey  main_ivkey;
	struct silofs_uuid   uuid;
	struct silofs_paddr  root;
	struct silofs_uaddr  sb_addr;
	enum silofs_mbr_kind kind;
	uint32_t             flags;
	int                  cipher_algo;
	int                  cipher_mode;
};

/* main boot records controller */
struct silofs_mbrs {
	struct silofs_mbr     fs_mbr;
	struct silofs_mbr     ar_mbr;
	struct silofs_cipher  cipher;
	struct silofs_mdigest mdigest;
	struct silofs_ivkey   ivkey;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mbrs_init(struct silofs_mbrs *mbrs);

void silofs_mbrs_fini(struct silofs_mbrs *mbrs);

int silofs_mbrs_derive_ivkey(struct silofs_mbrs           *mbrs,
                             const struct silofs_password *pw);

void silofs_mbrs_update_sb_addr(struct silofs_mbrs        *mbrs,
                                const struct silofs_uaddr *sb_uaddr);

int silofs_mbrs_root(const struct silofs_mbrs *mbrs,
                     enum silofs_mbr_kind      mkind,
                     struct silofs_paddr      *out_paddr);

void silofs_mbrs_set_root(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind,
                          const struct silofs_paddr *paddr);

int silofs_mbrs_regen(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind);

int silofs_mbrs_encode(const struct silofs_mbrs *mbrs,
                       enum silofs_mbr_kind      mkind,
                       struct silofs_paddr      *out_mref,
                       struct silofs_mbr1k      *out_mbr1k);

int silofs_mbrs_decode(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind,
                       const struct silofs_paddr *mref,
                       const struct silofs_mbr1k *mbr1k);

int silofs_mbrs_update(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind);

#endif /* SILOFS_MBR_H_ */
