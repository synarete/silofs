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
#ifndef SILOFS_GBR_H_
#define SILOFS_GBR_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"
#include "nodes.h"
#include "bstore.h"

struct silofs_env;

/* a tuple of references (CAS) to global boot-records */
struct silofs_gbrefs {
	struct silofs_paddr main;
	struct silofs_paddr base;
	struct silofs_paddr fork;
};

/* global boot-record, in-memory representation */
struct silofs_gbr {
	struct silofs_pmeta  root;
	struct silofs_uuid   uuid;
	struct silofs_uaddr  sb_addr;
	enum silofs_gbr_kind kind;
	unsigned             flags;
};

/* global boot-records state */
struct silofs_gbrstate {
	struct silofs_gbr   fs_gbr;
	struct silofs_gbr   ar_gbr;
	struct silofs_cmeta cmeta;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_gbr_init(struct silofs_gbr *gbr, enum silofs_gbr_kind kind);

void silofs_gbr_fini(struct silofs_gbr *gbr);

int silofs_gbr_root(const struct silofs_gbr *gbr,
                    struct silofs_pmeta     *out_pmeta);

void silofs_gbr_set_root(struct silofs_gbr         *gbr,
                         const struct silofs_pmeta *pmeta);

void silofs_gbr_set_rootc(struct silofs_gbr         *gbr,
                          const struct silofs_cmeta *cmeta);

void silofs_gbr_set_rootc_by(struct silofs_gbr       *gbr,
                             const struct silofs_gbr *other);

void silofs_gbr_update_sb(struct silofs_gbr         *gbr,
                          const struct silofs_uaddr *sb_uaddr);

int silofs_gbr_encode_by(const struct silofs_gbr   *gbr,
                         const struct silofs_cmeta *cmeta,
                         struct silofs_paddr       *out_paddr,
                         struct silofs_gbr1k       *out_gbr1k);

int silofs_gbr_decode_by(struct silofs_gbr         *gbr,
                         const struct silofs_cmeta *cmeta,
                         const struct silofs_paddr *paddr,
                         const struct silofs_gbr1k *gbr1k);

int silofs_derive_gbr_cmeta(const struct silofs_password *passwd,
                            struct silofs_cmeta          *out_cmeta);

#endif /* SILOFS_GBR_H_ */
