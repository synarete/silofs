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

#include <stdlib.h>
#include <silofs/ondisk.h>

struct silofs_strview;
struct silofs_strspan;
struct silofs_strbuf;

union silofs_blobidu {
	struct silofs_blobid  bid;
	struct silofs_uuid    uuid[2];
	struct silofs_hash256 hash;
	uint64_t              ui[4];
};

const union silofs_blobidu *silofs_blobid_none(void);

void silofs_blobid_generate(union silofs_blobidu *blobid);

void silofs_blobid_reset(union silofs_blobidu *blobid);

void silofs_blobid_assign(union silofs_blobidu       *blobid,
                          const union silofs_blobidu *other);

void silofs_blobid_assign_hash(union silofs_blobidu        *blobid,
                               const struct silofs_hash256 *hash);

long silofs_blobid_compare(const union silofs_blobidu *blobid1,
                           const union silofs_blobidu *blobid2);

bool silofs_blobid_isequal(const union silofs_blobidu *blobid1,
                           const union silofs_blobidu *blobid2);

bool silofs_blobid_isnone(const union silofs_blobidu *blobid);

int silofs_blobid_to_ascii(const union silofs_blobidu *blobid, char *s,
                           size_t n);

int silofs_blobid_from_ascii(union silofs_blobidu *blobid, const char *s,
                             size_t n);

void silofs_blobid_to_sbuf(const union silofs_blobidu *blobid,
                           struct silofs_strbuf       *sbuf);

int silofs_blobid_to_str(const union silofs_blobidu *blobid,
                         struct silofs_strspan      *ss);

int silofs_blobid_from_str(union silofs_blobidu        *blobid,
                           const struct silofs_strview *sv);

uint64_t
silofs_blobid_hash64(const union silofs_blobidu *blobid, uint64_t seed);

int silofs_blobid_import(union silofs_blobidu       *blobid,
                         const struct silofs_blobid *other);

void silofs_blobid_export(const union silofs_blobidu *blobid,
                          struct silofs_blobid       *other);

#endif /* SILOFS_BLOBID_H_ */
