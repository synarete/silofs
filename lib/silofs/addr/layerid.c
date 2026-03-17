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
#include <silofs/addr/layerid.h>

static const struct silofs_layerid s_silofs_layerid_none;

const struct silofs_layerid *silofs_layerid_none(void)
{
	return &s_silofs_layerid_none;
}

void silofs_layerid_reset(struct silofs_layerid *layerid)
{
	memset(layerid->id, 0, sizeof(layerid->id));
}

void silofs_layerid_assign(struct silofs_layerid *layerid,
                           const struct silofs_layerid *other)
{
	memcpy(layerid->id, other->id, sizeof(layerid->id));
}

void silofs_layerid_assignx(struct silofs_layerid *layerid,
                            const struct silofs_layerid *other)
{
	if (other != nullptr) {
		silofs_layerid_assign(layerid, other);
	} else {
		silofs_layerid_reset(layerid);
	}
}

long silofs_layerid_compare(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other)
{
	return memcmp(layerid->id, other->id, sizeof(layerid->id));
}

bool silofs_layerid_isequal(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other)
{
	return (silofs_layerid_compare(layerid, other) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uniqid_reset(struct silofs_uniqid *uniqid)
{
	memset(uniqid->id, 0, sizeof(uniqid->id));
}

void silofs_uniqid_setup_by(struct silofs_uniqid *uniqid,
                            const struct silofs_hash256 *hash)
{
	STATICASSERT_EQ(2 * sizeof(uniqid->id), sizeof(hash->hash));

	silofs_uniqid_reset(uniqid);
	for (size_t i = 0; i < ARRAY_SIZE(hash->hash); ++i) {
		const size_t j = i % ARRAY_SIZE(uniqid->id);

		uniqid->id[j] ^= hash->hash[i];
	}
}

void silofs_uniqid_assign(struct silofs_uniqid *uniqid,
                          const struct silofs_uniqid *other)
{
	memcpy(uniqid->id, other->id, sizeof(uniqid->id));
}

void silofs_uniqid_assignx(struct silofs_uniqid *uniqid,
                           const struct silofs_uniqid *other)
{
	if (other != nullptr) {
		silofs_uniqid_assign(uniqid, other);
	} else {
		silofs_uniqid_reset(uniqid);
	}
}

long silofs_uniqid_compare(const struct silofs_uniqid *uniqid,
                           const struct silofs_uniqid *other)
{
	return memcmp(uniqid->id, other->id, sizeof(uniqid->id));
}
