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
#include "pbs.h"

struct silofs_env;

/* a tuple of content-addressable references to main boot-records */
struct silofs_mrefs {
	struct silofs_paddr main;
	struct silofs_paddr base;
	struct silofs_paddr fork;
};

/* global boot-record, in-memory representation */
struct silofs_gbr {
	struct silofs_ivkey  main_ivkey;
	struct silofs_uuid   uuid;
	struct silofs_paddr  root;
	struct silofs_uaddr  sb_addr;
	enum silofs_gbr_kind kind;
	uint32_t             flags;
	int                  cipher_algo;
	int                  cipher_mode;
};

/* global boot records switch */
struct silofs_gbrs {
	struct silofs_gbr     fs_gbr;
	struct silofs_gbr     ar_gbr;
	struct silofs_cipher  cipher;
	struct silofs_mdigest mdigest;
	struct silofs_ivkey   ivkey;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_gbrs_init(struct silofs_gbrs *gbrs);

void silofs_gbrs_fini(struct silofs_gbrs *gbrs);

int silofs_gbrs_derive_ivkey(struct silofs_gbrs           *gbrs,
                             const struct silofs_password *pw);

void silofs_gbrs_update_sb_addr(struct silofs_gbrs        *gbrs,
                                const struct silofs_uaddr *sb_uaddr);

int silofs_gbrs_root(const struct silofs_gbrs *gbrs,
                     enum silofs_gbr_kind      gdr_kind,
                     struct silofs_paddr      *out_paddr);

void silofs_gbrs_set_root(struct silofs_gbrs        *gbrs,
                          enum silofs_gbr_kind       gdr_kind,
                          const struct silofs_paddr *paddr);

int silofs_gbrs_regen(struct silofs_gbrs *gbrs, enum silofs_gbr_kind gdr_kind);

int silofs_gbrs_encode(const struct silofs_gbrs *gbrs,
                       enum silofs_gbr_kind      gdr_kind,
                       struct silofs_paddr      *out_mref,
                       struct silofs_gbr1k      *out_gbr1k);

int silofs_gbrs_decode(struct silofs_gbrs *gbrs, enum silofs_gbr_kind gdr_kind,
                       const struct silofs_paddr *mref,
                       const struct silofs_gbr1k *gbr1k);

int silofs_gbrs_update(struct silofs_gbrs  *gbrs,
                       enum silofs_gbr_kind gdr_kind);

#endif /* SILOFS_GBR_H_ */
