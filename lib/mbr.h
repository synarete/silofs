/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include "addr.h"
#include "nodes.h"
#include "obs.h"

struct silofs_env;

/* mbr meta info */
struct silofs_mbr_meta {
	struct silofs_nmeta  nmeta;
	struct silofs_ckey   hmac_key;
	enum silofs_mbr_mode mode;
};

/* main boot-record, in-memory representation */
struct silofs_mbr_info {
	struct silofs_mbr_meta mb_meta;
	struct silofs_mbr1k    mb_mbr1k;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbi_init(struct silofs_mbr_info       *mbi,
                     const struct silofs_mbr_meta *mbr_meta);

void silofs_mbi_fini(struct silofs_mbr_info *mbi);

int silofs_mbi_uber_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pmeta          *out_pmeta);

int silofs_mbi_arix_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pmeta          *out_pmeta);

int silofs_mbi_set_root(struct silofs_mbr_info    *mbi,
                        const struct silofs_pmeta *pmeta);

int silofs_mbi_sbaddr(const struct silofs_mbr_info *mbi,
                      struct silofs_uaddr          *out_sb_uaddr);

int silofs_mbi_set_sbaddr(struct silofs_mbr_info    *mbi,
                          const struct silofs_uaddr *sb_uaddr);

int silofs_mbi_export(const struct silofs_mbr_info *mbi,
                      struct silofs_mbref          *out_mbref,
                      struct silofs_mbr1k          *out_mbr1k);

int silofs_mbi_import(struct silofs_mbr_info    *mbi,
                      const struct silofs_mbref *mbref,
                      const struct silofs_mbr1k *mbr1k);

int silofs_derive_mbr_meta(const struct silofs_password *passwd,
                           struct silofs_mbr_meta       *out_mbr_meta);

#endif /* SILOFS_MBR_H_ */
