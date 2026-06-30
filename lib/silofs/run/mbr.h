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

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

struct silofs_env;

/* mbr meta info */
struct silofs_mbr_meta {
	struct silofs_nmeta nmeta;
	struct silofs_ckey  hmac_key;
};

/* main boot-record, in-memory representation */
struct silofs_mbr_info {
	struct silofs_mbr_meta mb_meta;
	struct silofs_mbr1k    mb_mbr1k;
	struct silofs_mbref    mb_ref;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbi_init(struct silofs_mbr_info *mbi);

void silofs_mbi_fini(struct silofs_mbr_info *mbi);

void silofs_mbi_set_meta(struct silofs_mbr_info       *mbi,
                         const struct silofs_mbr_meta *meta);

int silofs_mbi_uber_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pnptr          *out_pnptr);

void silofs_mbi_set_root(struct silofs_mbr_info    *mbi,
                         const struct silofs_pnptr *pnptr);

int silofs_mbi_export(const struct silofs_mbr_info *mbi,
                      struct silofs_mbref          *out_mbref,
                      struct silofs_mbr1k          *out_mbr1k);

int silofs_derive_mbr_meta(const struct silofs_password *passwd,
                           struct silofs_mbr_meta       *out_mbr_meta);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sense_mbr(struct silofs_dstor       *dstor,
                     const struct silofs_mbref *mbref);

int silofs_commit_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                      struct silofs_mbref *out_mbref);

int silofs_reload_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                      const struct silofs_mbref *mbref);

int silofs_unref_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                     const struct silofs_mbref *mbref);

#endif /* SILOFS_MBR_H_ */
