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
#ifndef SILOFS_MBREF_H_
#define SILOFS_MBREF_H_

#include <silofs/types.h>
#include "paddr.h"

/* MBR reference address */
struct silofs_mbref {
	struct silofs_blobidx bx;
};

/* tuple of mbr-refs */
struct silofs_mbrefs {
	struct silofs_mbref main;
	struct silofs_mbref base;
	struct silofs_mbref fork;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

#endif /* SILOFS_MBREF_H_ */
