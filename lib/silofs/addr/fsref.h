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
#ifndef SILOFS_FSREF_H_
#define SILOFS_FSREF_H_

#include <silofs/ondisk.h>
#include <silofs/types.h>

/* MBR reference address */
struct silofs_mbref {
	struct silofs_blobidx bx;
};

/* mbr-refs tuple */
struct silofs_mbrefs {
	struct silofs_mbref main;
	struct silofs_mbref base;
	struct silofs_mbref fork;
};

void silofs_mbref_reset(struct silofs_mbref *mbref);

void silofs_mbref_setup(struct silofs_mbref         *mbref,
                        const struct silofs_blobidx *blobidx);

void silofs_mbref_assign(struct silofs_mbref       *mbref,
                         const struct silofs_mbref *other);

void silofs_mbref_derive(struct silofs_mbref            *mbref,
                         const struct silofs_mdigest_hd *md_hd,
                         const struct silofs_paddr      *paddr);

bool silofs_mbref_isequal(const struct silofs_mbref *mbref,
                          const struct silofs_mbref *other);

int silofs_mbref_from_str(struct silofs_mbref *mbref, const char *str,
                          size_t len);

int silofs_mbref_to_str(const struct silofs_mbref *mbref, char *str, size_t n);

void silofs_mbrefs_assign(struct silofs_mbrefs       *mbrefs,
                          const struct silofs_mbrefs *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_fsmeta_setup(struct silofs_fsmeta *fsmeta);

void silofs_fsref_export(struct silofs_fsref       *fsref,
                         const struct silofs_mbref *mbref);

int silofs_fsref_import(const struct silofs_fsref *fsref,
                        struct silofs_mbref       *out_mbref);

void silofs_fsrefs_export(struct silofs_fsrefs       *fsrefs,
                          const struct silofs_mbrefs *mbrefs);

#endif /* SILOFS_FSREF_H_ */
