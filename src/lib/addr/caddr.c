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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/addr.h>


void silofs_caddr_setup(struct silofs_caddr *caddr,
                        const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&caddr->hash, hash);
}

void silofs_caddr_assign(struct silofs_caddr *caddr,
                         const struct silofs_caddr *other)
{
	silofs_hash256_assign(&caddr->hash, &other->hash);
}

bool silofs_caddr_isnone(const struct silofs_caddr *caddr)
{
	return silofs_hash256_isnil(&caddr->hash);
}

bool silofs_caddr_isequal(const struct silofs_caddr *caddr,
                          const struct silofs_caddr *other)
{
	return silofs_hash256_isequal(&caddr->hash, &other->hash);
}

void silofs_caddr_to_name(const struct silofs_caddr *caddr,
                          struct silofs_strbuf *out_name)
{
	silofs_hash256_to_name(&caddr->hash, out_name);
}

uint32_t silofs_caddr_to_u32(const struct silofs_caddr *caddr)
{
	struct silofs_caddr64b caddr64b;

	silofs_caddr64b_htox(&caddr64b, caddr);
	return silofs_squash_to_u32(&caddr64b, sizeof(caddr64b));
}

void silofs_caddr64b_htox(struct silofs_caddr64b *caddr64b,
                          const struct silofs_caddr *caddr)
{
	silofs_hash256_assign(&caddr64b->hash, &caddr->hash);
	memset(caddr64b->reserved, 0, sizeof(caddr64b->reserved));
}

void silofs_caddr64b_xtoh(const struct silofs_caddr64b *caddr64b,
                          struct silofs_caddr *caddr)
{
	silofs_caddr_setup(caddr, &caddr64b->hash);
}
