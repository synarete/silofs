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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/types.h>

struct silofs_env;
struct silofs_task;

/* boot pathname: a pair of repo-directory & boot-record name (optional) */
struct silofs_bootpath {
	struct silofs_strview repodir;
	struct silofs_strview name;
};

/* file-system's boot reference */
struct silofs_bootref {
	struct silofs_caddr caddr;
	const char         *repodir;
	const char         *name;
	const char         *passwd;
	const char         *mntdir;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bp, const char *repodir,
                          const char *name);

void silofs_bootref_init(struct silofs_bootref *bref);

void silofs_bootref_fini(struct silofs_bootref *bref);

void silofs_bootref_assign(struct silofs_bootref       *bref,
                           const struct silofs_bootref *other);

void silofs_bootref_update(struct silofs_bootref     *bref,
                           const struct silofs_caddr *caddr, const char *name);

int silofs_bootref_import(struct silofs_bootref       *bref,
                          const struct silofs_strview *sv);

void silofs_bootref_export(const struct silofs_bootref *bref,
                           struct silofs_strbuf        *sbuf);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_reload_vspace(struct silofs_task *task);

int silofs_reload_rootd(struct silofs_task *task);

#endif /* SILOFS_BOOT_H_ */
