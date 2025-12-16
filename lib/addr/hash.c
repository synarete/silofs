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
#include "stringx.h"
#include "htox.h"
#include "mtype.h"
#include "hash.h"

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other)
{
	return (memcmp(hash->hash, other->hash, sizeof(hash->hash)) == 0);
}

void silofs_hash256_copyto(const struct silofs_hash256 *hash,
                           struct silofs_hash256       *other)
{
	memcpy(other->hash, hash->hash, sizeof(other->hash));
}

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf        *out_name)
{
	size_t cnt = 0;

	silofs_strbuf_reset(out_name);
	silofs_mem_to_ascii(hash->hash, sizeof(hash->hash), out_name->str,
	                    sizeof(out_name->str) - 1, &cnt);
	return cnt;
}
