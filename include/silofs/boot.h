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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_xref_reset(struct silofs_xref *ba);

void silofs_xref_setup(struct silofs_xref        *ba,
                       const struct silofs_caddr *caddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bp, const char *repodir,
                          const char *name);

void silofs_bootref_init(struct silofs_boot_args *bref);

void silofs_bootref_assign(struct silofs_boot_args       *bref,
                           const struct silofs_boot_args *other);

int silofs_bootref_import(struct silofs_boot_args     *bref,
                          const struct silofs_strview *sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_reload_vspace(struct silofs_task *task);

int silofs_reload_rootd(struct silofs_task *task);

#endif /* SILOFS_BOOT_H_ */
