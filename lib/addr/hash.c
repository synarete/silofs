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
#include "configs.h"
#include <uuid/uuid.h>
#include <errno.h>
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "mtype.h"
#include "hash.h"

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other)
{
	return (memcmp(hash->hash, other->hash, sizeof(hash->hash)) == 0);
}

void silofs_hash256_copyto(const struct silofs_hash256 *hash,
                           struct silofs_hash256 *other)
{
	memcpy(other->hash, hash->hash, sizeof(other->hash));
}

void silofs_hash256_to_u64s(const struct silofs_hash256 *hash, uint64_t u[4])
{
	const uint8_t *p = hash->hash;

	SILOFS_STATICASSERT_EQ(sizeof(hash->hash), 4 * sizeof(uint64_t));

	u[0] = silofs_u8b_as_u64(p);
	u[1] = silofs_u8b_as_u64(p + 8);
	u[2] = silofs_u8b_as_u64(p + 16);
	u[3] = silofs_u8b_as_u64(p + 24);
}

void silofs_hash256_from_u64s(struct silofs_hash256 *hash, const uint64_t u[4])
{
	uint8_t *p = hash->hash;

	SILOFS_STATICASSERT_EQ(sizeof(hash->hash), 4 * sizeof(uint64_t));

	silofs_u8b_from_u64(p, u[0]);
	silofs_u8b_from_u64(p + 8, u[1]);
	silofs_u8b_from_u64(p + 16, u[2]);
	silofs_u8b_from_u64(p + 24, u[3]);
}

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf *out_name)
{
	size_t cnt = 0;

	silofs_strbuf_reset(out_name);
	silofs_mem_to_ascii(hash->hash, sizeof(hash->hash), out_name->str,
	                    sizeof(out_name->str) - 1, &cnt);
	return cnt;
}

int silofs_hash256_by_name(struct silofs_hash256 *hash,
                           const struct silofs_strbuf *name)
{
	struct silofs_strview sv;
	size_t cnt = 0;
	int err;

	silofs_strbuf_as_sv(name, &sv);
	err = silofs_ascii_to_mem(hash->hash, sizeof(hash->hash), sv.str,
	                          sv.len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(hash->hash)) {
		return -SILOFS_EILLSTR;
	}
	return 0;
}
