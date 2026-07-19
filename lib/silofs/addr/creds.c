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
#include <silofs/addr.h>

/*
 * TODO-0043: Map uig/gid "nobody" to host values
 *
 * Do not use hard-coded values to uid/gid "nobody" but resolve to host-local
 * values upon boot.
 */

uid_t silofs_uid_null(void)
{
	return (uid_t)(-1);
}

uid_t silofs_uid_nobody(void)
{
	return 65534;
}

bool silofs_uid_eq(uid_t uid1, uid_t uid2)
{
	return (uid1 == uid2);
}

bool silofs_uid_isnull(uid_t uid)
{
	return silofs_uid_eq(uid, silofs_uid_null());
}

bool silofs_uid_isroot(uid_t uid)
{
	return silofs_uid_eq(uid, 0);
}

gid_t silofs_gid_null(void)
{
	return (uid_t)(-1);
}

gid_t silofs_gid_nobody(void)
{
	return 65534;
}

bool silofs_gid_eq(gid_t gid1, gid_t gid2)
{
	return (gid1 == gid2);
}

bool silofs_gid_isnull(gid_t gid)
{
	return silofs_gid_eq(gid, silofs_gid_null());
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cred_init(struct silofs_cred *cred)
{
	silofs_cred_setup(cred, silofs_uid_null(), silofs_gid_null(), 0);
}

void silofs_cred_fini(struct silofs_cred *cred)
{
	silofs_cred_setup(cred, silofs_uid_null(), silofs_gid_null(),
	                  (mode_t)(-1));
}

void silofs_cred_assign(struct silofs_cred *cred,
                        const struct silofs_cred *other)
{
	silofs_cred_setup(cred, other->uid, other->gid, other->umask);
}

void silofs_cred_setup(struct silofs_cred *cred, uid_t uid, gid_t gid,
                       mode_t umsk)
{
	cred->uid   = uid;
	cred->gid   = gid;
	cred->umask = umsk;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_creds_init(struct silofs_creds *creds)
{
	silofs_cred_init(&creds->fs_cred);
	silofs_cred_init(&creds->host_cred);
}

void silofs_creds_fini(struct silofs_creds *creds)
{
	silofs_cred_fini(&creds->fs_cred);
	silofs_cred_fini(&creds->host_cred);
}
