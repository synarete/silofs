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
#ifndef SILOFS_MDIGEST_H_
#define SILOFS_MDIGEST_H_

#include <stdlib.h>
#include <stdint.h>
#include <gcrypt.h>

struct iovec;
struct silofs_hash256;
struct silofs_hash512;

struct silofs_mdigest {
	gcry_md_hd_t md_hd;
};

int silofs_mdigest_init(struct silofs_mdigest *md);

void silofs_mdigest_fini(struct silofs_mdigest *md);

void silofs_blake2s128_of(const struct silofs_mdigest *md, const void *buf,
			  size_t bsz, struct silofs_hash128 *out_hash);

void silofs_sha256_of(const struct silofs_mdigest *md, const void *buf,
		      size_t bsz, struct silofs_hash256 *out_hash);

void silofs_sha256_ofv(const struct silofs_mdigest *md,
		       const struct iovec *iov, size_t cnt,
		       struct silofs_hash256 *out_hash);

void silofs_sha3_256_of(const struct silofs_mdigest *md, const void *buf,
			size_t bsz, struct silofs_hash256 *out_hash);

void silofs_sha3_512_of(const struct silofs_mdigest *md, const void *buf,
			size_t bsz, struct silofs_hash512 *out_hash);

void silofs_crc32_of(const struct silofs_mdigest *md, const void *buf,
		     size_t bsz, uint32_t *out_crc32);

#endif /* SILOFS_MDIGEST_H_ */
