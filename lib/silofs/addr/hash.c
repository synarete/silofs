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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/addr.h>

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other)
{
	return (memcmp(hash->hash, other->hash, sizeof(hash->hash)) == 0);
}

void silofs_hash256_assign(struct silofs_hash256 *hash,
                           const struct silofs_hash256 *other)
{
	silofs_hash256_copyto(other, hash);
}

void silofs_hash256_copyto(const struct silofs_hash256 *hash,
                           struct silofs_hash256 *other)
{
	memcpy(other->hash, hash->hash, sizeof(other->hash));
}

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf *out_name)
{
	size_t cnt = 0;

	silofs_strbuf_reset(out_name);
	silofs_mem_to_ascii(hash->hash, sizeof(hash->hash), out_name->str,
	                    sizeof(out_name->str), &cnt);
	return cnt;
}

int silofs_hash256_to_str(const struct silofs_hash256 *hash, char *str,
                          size_t len)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(hash->hash, sizeof(hash->hash), str, len, &cnt);
	if (cnt != (2 * sizeof(hash->hash))) {
		return -SILOFS_EILLSTR;
	}
	return 0;
}

int silofs_hash256_from_str(struct silofs_hash256 *hash, const char *str,
                            size_t len)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(hash->hash, sizeof(hash->hash), str, len,
	                          &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(hash->hash)) {
		return -SILOFS_EILLSTR;
	}
	return 0;
}
