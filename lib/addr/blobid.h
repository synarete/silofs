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
#ifndef SILOFS_BLOBID_H_
#define SILOFS_BLOBID_H_

#include <silofs/ondisk.h>

struct silofs_strview;
struct silofs_strspan;
struct silofs_strbuf;

/* a pair of unique blob-id and sub-index */
struct silofs_blobidx {
	struct silofs_blobid blobid;
	uint32_t             index;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobid_generate(struct silofs_blobid *blobid);

void silofs_blobid_reset(struct silofs_blobid *blobid);

void silofs_blobid_assign(struct silofs_blobid       *blobid,
                          const struct silofs_blobid *other);

void silofs_blobid_assign_hash(struct silofs_blobid        *blobid,
                               const struct silofs_hash256 *hash);

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2);

bool silofs_blobid_isequal(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2);

void silofs_blobid_to_sbuf(const struct silofs_blobid *blobid,
                           struct silofs_strbuf       *sbuf);

void silofs_blobid_to_str(const struct silofs_blobid *blobid,
                          struct silofs_strspan      *ss);

int silofs_blobid_from_str(struct silofs_blobid        *blobid,
                           const struct silofs_strview *sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_blobidx *silofs_blobidx_none(void);

void silofs_blobidx_init(struct silofs_blobidx      *blobidx,
                         const struct silofs_blobid *blobid, uint32_t idx);

void silofs_blobidx_fini(struct silofs_blobidx *blobidx);

bool silofs_blobidx_isnull(const struct silofs_blobidx *blobidx);

bool silofs_blobidx_has_blobid(const struct silofs_blobidx *blobidx,
                               const struct silofs_blobid  *blobid);

void silofs_blobidx_generate(struct silofs_blobidx *blobidx);

void silofs_blobidx_reset(struct silofs_blobidx *blobidx);

void silofs_blobidx_assign(struct silofs_blobidx       *blobidx,
                           const struct silofs_blobidx *other);

long silofs_blobidx_compare(const struct silofs_blobidx *blobidx1,
                            const struct silofs_blobidx *blobidx2);

bool silofs_blobidx_isequal(const struct silofs_blobidx *blobidx,
                            const struct silofs_blobidx *other);

uint64_t silofs_blobidx_hash64(const struct silofs_blobidx *blobidx);

void silofs_blobidx_to_str(const struct silofs_blobidx *blobidx,
                           struct silofs_strbuf        *sbuf);

void silofs_blobidx32b_htox(struct silofs_blobidx48b    *blobidx32,
                            const struct silofs_blobidx *blobidx);

void silofs_blobidx32b_xtoh(const struct silofs_blobidx48b *blobidx32,
                            struct silofs_blobidx          *blobidx);

#endif /* SILOFS_BLOBID_H_ */
