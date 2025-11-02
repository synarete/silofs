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
#include "str.h"
#include "svolid.h"

const struct silofs_blobid *silofs_blobid_none(void);

void silofs_blobid_setup_raw(struct silofs_blobid       *blobid,
                             const struct silofs_svolid *svolid,
                             enum silofs_mtype           mtype);

void silofs_blobid_setup_raw2(struct silofs_blobid       *blobid,
                              const struct silofs_svolid *svolid,
                              enum silofs_mtype           mtype,
                              enum silofs_mtype           vspace,
                              enum silofs_height          height);

void silofs_blobid_setup_cas(struct silofs_blobid        *blobid,
                             const struct silofs_svolid  *svolid,
                             const struct silofs_hash256 *hash,
                             enum silofs_mtype            mtype);

void silofs_blobid_get_svolid(const struct silofs_blobid *blobid,
                              struct silofs_svolid       *out_svolid);

enum silofs_bmode silofs_blobid_get_bmode(const struct silofs_blobid *blobid);

enum silofs_mtype silofs_blobid_get_mtype(const struct silofs_blobid *blobid);

enum silofs_mtype silofs_blobid_get_vspace(const struct silofs_blobid *blobid);

enum silofs_height
silofs_blobid_get_height(const struct silofs_blobid *blobid);

void silofs_blobid_reset(struct silofs_blobid *blobid);

void silofs_blobid_copyto(const struct silofs_blobid *blobid,
                          struct silofs_blobid       *other);

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2);

bool silofs_blobid_isequal(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2);

bool silofs_blobid_isnone(const struct silofs_blobid *blobid);

int silofs_blobid_to_ascii(const struct silofs_blobid *blobid, char *s,
                           size_t n);

int silofs_blobid_from_ascii(struct silofs_blobid *blobid, const char *s,
                             size_t n);

void silofs_blobid_to_sbuf(const struct silofs_blobid *blobid,
                           struct silofs_strbuf       *sbuf);

int silofs_blobid_to_str(const struct silofs_blobid *blobid,
                         struct silofs_strspan      *ss);

int silofs_blobid_from_str(struct silofs_blobid        *blobid,
                           const struct silofs_strview *sv);

uint64_t
silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t seed);

#endif /* SILOFS_BLOBID_H_ */
