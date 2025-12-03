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
#include "nodes.h"
#include "bstore.h"

struct silofs_env;

/* a tuple of references (CAS) to main boot-records */
struct silofs_mbrefs {
	struct silofs_paddr main;
	struct silofs_paddr base;
	struct silofs_paddr fork;
};

/* main boot-record, in-memory representation */
struct silofs_mbr {
	struct silofs_pmeta  root;
	struct silofs_uuid   uuid;
	struct silofs_uaddr  sb_addr;
	enum silofs_mbr_kind kind;
	unsigned             flags;
};

/* main boot-record, in-memory representation */
struct silofs_mbr_info {
	struct silofs_cmeta mb_cmeta;
	struct silofs_mbr1k mb_mbr1k;
};

/* global boot-records state */
struct silofs_mbrstate {
	struct silofs_mbr   fs_mbr;
	struct silofs_mbr   ar_mbr;
	struct silofs_cmeta cmeta;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbr_init(struct silofs_mbr *mbr, enum silofs_mbr_kind kind);

void silofs_mbr_fini(struct silofs_mbr *mbr);

int silofs_mbr_root(const struct silofs_mbr *mbr,
                    struct silofs_pmeta     *out_pmeta);

void silofs_mbr_set_root(struct silofs_mbr         *mbr,
                         const struct silofs_pmeta *pmeta);

void silofs_mbr_set_rootc_by(struct silofs_mbr       *mbr,
                             const struct silofs_mbr *other);

void silofs_mbr_update_sb(struct silofs_mbr         *mbr,
                          const struct silofs_uaddr *sb_uaddr);

int silofs_mbr_encode_by(const struct silofs_mbr   *mbr,
                         const struct silofs_cmeta *cmeta,
                         struct silofs_paddr       *out_paddr,
                         struct silofs_mbr1k       *out_mbr1k);

int silofs_mbr_decode_by(struct silofs_mbr         *mbr,
                         const struct silofs_cmeta *cmeta,
                         const struct silofs_paddr *paddr,
                         const struct silofs_mbr1k *mbr1k);

int silofs_derive_mbr_cmeta(const struct silofs_password *passwd,
                            struct silofs_cmeta          *out_cmeta);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbi_init(struct silofs_mbr_info *mbi, enum silofs_mbr_kind kind);

void silofs_mbi_fini(struct silofs_mbr_info *mbi);

int silofs_mbi_update_cmeta_by(struct silofs_mbr_info       *mbi,
                               const struct silofs_password *pw);

int silofs_mbi_uber_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pmeta          *out_pmeta);

int silofs_mbi_arix_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pmeta          *out_pmeta);

int silofs_mbi_set_root(struct silofs_mbr_info    *mbi,
                        const struct silofs_pmeta *pmeta);

int silofs_mbi_set_sbaddr(struct silofs_mbr_info    *mbi,
                          const struct silofs_uaddr *sb_uaddr);

void silofs_mbi_align_cmeta(struct silofs_mbr_info       *mbi,
                            const struct silofs_mbr_info *other);

int silofs_mbi_stamp_export(struct silofs_mbr_info *mbi,
                            struct silofs_paddr    *out_paddr,
                            struct silofs_mbr1k    *out_mbr1k);

int silofs_mbi_verify_import(struct silofs_mbr_info    *mbi,
                             const struct silofs_paddr *paddr,
                             const struct silofs_mbr1k *mbr1k);

#endif /* SILOFS_MBR_H_ */
