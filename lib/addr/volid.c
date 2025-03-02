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
#include <silofs/infra.h>
#include "meta.h"
#include "volid.h"

void silofs_volid_generate(struct silofs_volid *volid)
{
	silofs_uuid_generate(&volid->id);
}

void silofs_volid_assign(struct silofs_volid *volid,
                         const struct silofs_volid *other)
{
	silofs_uuid_assign(&volid->id, &other->id);
}

void silofs_volid_reset(struct silofs_volid *volid)
{
	memset(volid, 0, sizeof(*volid));
}

long silofs_volid_compare(const struct silofs_volid *volid1,
                          const struct silofs_volid *volid2)
{
	return silofs_uuid_compare(&volid1->id, &volid2->id);
}

bool silofs_volid_isequal(const struct silofs_volid *volid1,
                          const struct silofs_volid *volid2)
{
	return (silofs_volid_compare(volid1, volid2) == 0);
}

void silofs_volid_to_str(const struct silofs_volid *volid,
                         struct silofs_strbuf *sbuf)
{
	silofs_uuid_unparse(&volid->id, sbuf);
}

int silofs_volid_from_str(struct silofs_volid *volid,
                          const struct silofs_strview *sv)
{
	return silofs_uuid_parse(&volid->id, sv);
}

void silofs_volid_by_uuid(struct silofs_volid *volid,
                          const struct silofs_uuid *uuid)
{
	STATICASSERT_EQ(sizeof(volid->id.uu), 16);

	silofs_uuid_assign(&volid->id, uuid);
}
