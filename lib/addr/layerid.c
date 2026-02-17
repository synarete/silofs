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
#include "infra.h"
#include "layerid.h"

static const struct silofs_layerid s_silofs_layerid_none;

const struct silofs_layerid *silofs_layerid_none(void)
{
	return &s_silofs_layerid_none;
}

void silofs_layerid_reset(struct silofs_layerid *layerid)
{
	memset(layerid->id, 0, sizeof(layerid->id));
}

void silofs_layerid_generate(struct silofs_layerid *layerid)
{
	struct silofs_uuid uuid;

	STATICASSERT_EQ(sizeof(uuid.id), sizeof(layerid->id));

	silofs_uuid_generate(&uuid);
	memcpy(layerid->id, uuid.id, sizeof(layerid->id));
}

void silofs_layerid_copyto(const struct silofs_layerid *layerid,
                           struct silofs_layerid *other)
{
	memcpy(other->id, layerid->id, sizeof(other->id));
}

bool silofs_layerid_isequal(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other)
{
	return (memcmp(layerid->id, other->id, sizeof(layerid->id)) == 0);
}
