/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_UIDGID_H_
#define SILOFS_UIDGID_H_

#include <silofs/defs.h>
#include <unistd.h>

/*
 * TODO-0043: Map uig/gid "nobody" to host values
 *
 * Do not use hard-coded values to uid/gid "nobody" but resolve to host-local
 * values upon boot.
 */
static inline uid_t silofs_uid_nobody(void)
{
	return 65534;
}

static inline gid_t silofs_gid_nobody(void)
{
	return 65534;
}

static inline bool silofs_uid_eq(uid_t uid1, uid_t uid2)
{
	return (uid1 == uid2);
}

static inline bool silofs_uid_isnull(uid_t uid)
{
	return silofs_uid_eq(uid, (uid_t)(-1));
}

static inline bool silofs_uid_isroot(uid_t uid)
{
	return silofs_uid_eq(uid, 0);
}

static inline bool silofs_gid_eq(gid_t gid1, gid_t gid2)
{
	return (gid1 == gid2);
}

static inline bool silofs_gid_isnull(gid_t gid)
{
	return silofs_gid_eq(gid, (gid_t)(-1));
}

#endif /* SILOFS_UIDGID_H_ */
