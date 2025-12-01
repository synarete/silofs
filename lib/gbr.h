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

/* a tuple of content-addressable references to main boot-records */
struct silofs_mrefs {
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
struct silofs_gbrinfo {
	struct silofs_gbr     fs_gbr;
	struct silofs_gbr     ar_gbr;
	struct silofs_mdigest mdigest;
	struct silofs_cipher  cipher;
	struct silofs_civkey  civkey;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_gbrinfo_init(struct silofs_gbrinfo *gbrinfo);

void silofs_gbrinfo_fini(struct silofs_gbrinfo *gbrinfo);

int silofs_gbrinfo_derive_civkey(struct silofs_gbrinfo        *gbrinfo,
                                 const struct silofs_password *pw);

void silofs_gbrinfo_update_sb_addr(struct silofs_gbrinfo     *gbrinfo,
                                   const struct silofs_uaddr *sb_uaddr);

int silofs_gbrinfo_fs_root(const struct silofs_gbrinfo *gbrinfo,
                           struct silofs_pmeta         *out_pmeta);

int silofs_gbrinfo_ar_root(const struct silofs_gbrinfo *gbrinfo,
                           struct silofs_pmeta         *out_pmeta);

void silofs_gbrinfo_set_fs_root(struct silofs_gbrinfo     *gbrinfo,
                                const struct silofs_pmeta *pmeta);

void silofs_gbrinfo_set_ar_root(struct silofs_gbrinfo     *gbrinfo,
                                const struct silofs_pmeta *pmeta);

int silofs_gbrinfo_encode(const struct silofs_gbrinfo *gbrinfo,
                          enum silofs_gbr_kind         gdr_kind,
                          struct silofs_paddr         *out_mref,
                          struct silofs_gbr1k         *out_gbr1k);

int silofs_gbrinfo_decode(struct silofs_gbrinfo     *gbrinfo,
                          enum silofs_gbr_kind       gdr_kind,
                          const struct silofs_paddr *mref,
                          const struct silofs_gbr1k *gbr1k);

int silofs_gbrinfo_update(struct silofs_gbrinfo *gbrinfo,
                          enum silofs_gbr_kind   gdr_kind);

#endif /* SILOFS_GBR_H_ */
