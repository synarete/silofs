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
#include "infra.h"
#include "meta.h"
#include "volumeid.h"

void silofs_volumeid_generate(struct silofs_volumeid *vid)
{
	silofs_uuid_generate(&vid->id);
}

void silofs_volumeid_assign(struct silofs_volumeid *vid,
                            const struct silofs_volumeid *other)
{
	silofs_uuid_assign(&vid->id, &other->id);
}

void silofs_volumeid_reset(struct silofs_volumeid *vid)
{
	memset(vid, 0, sizeof(*vid));
}

long silofs_volumeid_compare(const struct silofs_volumeid *vid1,
                             const struct silofs_volumeid *vid2)
{
	return silofs_uuid_compare(&vid1->id, &vid2->id);
}

bool silofs_volumeid_isequal(const struct silofs_volumeid *vid1,
                             const struct silofs_volumeid *vid2)
{
	return (silofs_volumeid_compare(vid1, vid2) == 0);
}

void silofs_volumeid_to_str(const struct silofs_volumeid *vid,
                            struct silofs_strbuf *sbuf)
{
	silofs_uuid_unparse(&vid->id, sbuf);
}

int silofs_volumeid_from_str(struct silofs_volumeid *vid,
                             const struct silofs_strview *sv)
{
	return silofs_uuid_parse(&vid->id, sv);
}

void silofs_volumeid_by_uuid(struct silofs_volumeid *vid,
                             const struct silofs_uuid *uuid)
{
	SILOFS_STATICASSERT_EQ(sizeof(vid->id.uu), 16);

	silofs_uuid_assign(&vid->id, uuid);
}
