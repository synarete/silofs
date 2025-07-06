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
#include "blobid.h"

void silofs_blobid_generate(struct silofs_blobid *blobid)
{
	silofs_uuid_generate(&blobid->id);
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	silofs_uuid_assign(&blobid->id, &other->id);
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
}

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	return silofs_uuid_compare(&blobid1->id, &blobid2->id);
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	return (silofs_blobid_compare(blobid1, blobid2) == 0);
}

void silofs_blobid_to_str(const struct silofs_blobid *blobid,
                          struct silofs_strbuf *sbuf)
{
	silofs_uuid_unparse(&blobid->id, sbuf);
}

int silofs_blobid_from_str(struct silofs_blobid *blobid,
                           const struct silofs_strview *sv)
{
	return silofs_uuid_parse(&blobid->id, sv);
}

void silofs_blobid_by_uuid(struct silofs_blobid *blobid,
                           const struct silofs_uuid *uuid)
{
	SILOFS_STATICASSERT_EQ(sizeof(blobid->id.uu), 16);

	silofs_uuid_assign(&blobid->id, uuid);
}
