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
#include <silofs/macros.h>
#include <uuid/uuid.h>
#include "uuid.h"

void silofs_uuid_generate(struct silofs_uuid *uu)
{
	SILOFS_STATICASSERT_EQ(sizeof(uu->id), sizeof(uuid_t));

	uuid_generate_random(uu->id);
}

void silofs_uuid_assign(struct silofs_uuid *uu,
                        const struct silofs_uuid *other)
{
	silofs_uuid_assign2(uu, other->id);
}

void silofs_uuid_assign2(struct silofs_uuid *uu, const uint8_t u[16])
{
	uuid_copy(uu->id, u);
}

void silofs_uuid_copyto(const struct silofs_uuid *uu, uint8_t u[16])
{
	uuid_copy(u, uu->id);
}

long silofs_uuid_compare(const struct silofs_uuid *uu1,
                         const struct silofs_uuid *uu2)
{
	return uuid_compare(uu1->id, uu2->id);
}
