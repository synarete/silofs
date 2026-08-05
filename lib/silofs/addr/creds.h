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
#ifndef SILOFS_CREDS_H_
#define SILOFS_CREDS_H_

#include <silofs/types.h>

uid_t silofs_uid_null(void);

uid_t silofs_uid_nobody(void);

bool silofs_uid_eq(uid_t uid1, uid_t uid2);

bool silofs_uid_isnull(uid_t uid);

bool silofs_uid_isroot(uid_t uid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

gid_t silofs_gid_null(void);

gid_t silofs_gid_nobody(void);

bool silofs_gid_eq(gid_t gid1, gid_t gid2);

bool silofs_gid_isnull(gid_t gid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cred_init(struct silofs_cred *cred);

void silofs_cred_fini(struct silofs_cred *cred);

void silofs_cred_assign(struct silofs_cred       *cred,
                        const struct silofs_cred *other);

void silofs_cred_setup(struct silofs_cred *cred, //
                       uid_t uid, gid_t gid, mode_t umsk);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_creds_init(struct silofs_creds *creds);

void silofs_creds_fini(struct silofs_creds *creds);

#endif /* SILOFS_CREDS_H_ */
