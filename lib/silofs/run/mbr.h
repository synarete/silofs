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

/* mbr meta info */
struct silofs_mbr_meta {
	struct silofs_nmeta nmeta;
	struct silofs_ckey  hmac_key;
};

/* main boot-record, in-memory representation */
struct silofs_mbr_info {
	struct silofs_mbr1k    mb_mbr1k;
	struct silofs_mbr_meta mb_meta;
	struct silofs_mbref    mb_ref;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_update_mbr(struct silofs_mbr_info       *mbi,
                      const struct silofs_password *passwd);

int silofs_sense_mbr(struct silofs_dstor       *dstor,
                     const struct silofs_mbref *mbref);

int silofs_commit_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                      struct silofs_mbref *out_mbref);

int silofs_reload_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                      const struct silofs_mbref *mbref);

int silofs_unref_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                     const struct silofs_mbref *mbref);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbi_init(struct silofs_mbr_info *mbi);

void silofs_mbi_fini(struct silofs_mbr_info *mbi);

int silofs_get_fsroot(const struct silofs_mbr_info *mbi,
                      struct silofs_pnptr          *out_pnptr,
                      struct silofs_sw_version     *out_swv);

void silofs_set_fsroot(struct silofs_mbr_info         *mbi,
                       const struct silofs_pnptr      *pnptr,
                       const struct silofs_sw_version *swv);

#endif /* SILOFS_MBR_H_ */
