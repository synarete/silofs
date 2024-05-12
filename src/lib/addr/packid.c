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


void silofs_packid_setup(struct silofs_packid *packid,
                         const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&packid->hash, hash);
}

void silofs_packid_assign(struct silofs_packid *packid,
                          const struct silofs_packid *other)
{
	silofs_hash256_assign(&packid->hash, &other->hash);
}

bool silofs_packid_isnone(const struct silofs_packid *packid)
{
	return silofs_hash256_isnil(&packid->hash);
}

void silofs_packid_to_name(const struct silofs_packid *packid,
                           struct silofs_strbuf *out_name)
{
	silofs_hash256_to_name(&packid->hash, out_name);
}

uint32_t silofs_packid_to_u32(const struct silofs_packid *packid)
{
	struct silofs_packid64b packid64b;

	silofs_packid64b_htox(&packid64b, packid);
	return silofs_squash_to_u32(&packid64b, sizeof(packid64b));
}

void silofs_packid_to_base64(const struct silofs_packid *packid,
                             struct silofs_strbuf *out_sbuf)
{
	silofs_hash256_to_base64(&packid->hash, out_sbuf);
}


void silofs_packid64b_htox(struct silofs_packid64b *packid64b,
                           const struct silofs_packid *packid)
{
	silofs_hash256_assign(&packid64b->hash, &packid->hash);
	memset(packid64b->reserved, 0, sizeof(packid64b->reserved));
}

void silofs_packid64b_xtoh(const struct silofs_packid64b *packid64b,
                           struct silofs_packid *packid)
{
	silofs_packid_setup(packid, &packid64b->hash);
}
