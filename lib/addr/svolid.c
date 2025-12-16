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
#include <silofs/configs.h>
#include "infra.h"
#include "uuid.h"
#include "svolid.h"

static const struct silofs_svolid s_silofs_svolid_none;

const struct silofs_svolid *silofs_svolid_none(void)
{
	return &s_silofs_svolid_none;
}

void silofs_svolid_reset(struct silofs_svolid *svolid)
{
	memset(svolid->id, 0, sizeof(svolid->id));
}

void silofs_svolid_generate(struct silofs_svolid *svolid)
{
	struct silofs_uuid uuid;

	STATICASSERT_EQ(sizeof(uuid.id), sizeof(svolid->id));

	silofs_uuid_generate(&uuid);
	memcpy(svolid->id, uuid.id, sizeof(svolid->id));
}

void silofs_svolid_copyto(const struct silofs_svolid *svolid,
                          struct silofs_svolid       *other)
{
	memcpy(other->id, svolid->id, sizeof(other->id));
}

bool silofs_svolid_isequal(const struct silofs_svolid *svolid,
                           const struct silofs_svolid *other)
{
	return (memcmp(svolid->id, other->id, sizeof(svolid->id)) == 0);
}
