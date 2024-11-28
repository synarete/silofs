/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

#define SILOFS_BOLBID_LEN_MAX (40)

struct silofs_blobid {
	uint32_t id_len;
	uint8_t  id[SILOFS_BOLBID_LEN_MAX];
};

void silofs_blobid_setup(struct silofs_blobid *blobid, const void *id,
                         size_t id_len);

void silofs_blobid_assign(struct silofs_blobid       *blobid,
                          const struct silofs_blobid *other);

void silofs_blobid_reset(struct silofs_blobid *blobid);

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2);

uint64_t silofs_blobid_hash64(const struct silofs_blobid *blobid);

#endif /* SILOFS_BLOBID_H_ */
