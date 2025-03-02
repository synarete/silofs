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
#include <string.h>
#include <limits.h>
#include <silofs/infra.h>
#include <silofs/ioctls.h>
#include "boot.h"
#include "lnodes.h"
#include "task.h"
#include "inode.h"
#include "namei.h"
#include "vstage.h"
#include "claim.h"
#include "alias.h"

void silofs_xref_reset(struct silofs_xref *xref)
{
	memset(xref->s, 0, sizeof(xref->s));
}

bool silofs_xref_isnull(const struct silofs_xref *xref)
{
	return xref->s[0] == '\0';
}

void silofs_xref_from_caddr(struct silofs_xref *xref,
                            const struct silofs_caddr *caddr)
{
	silofs_caddr_to_str(caddr, xref->s, sizeof(xref->s));
}

int silofs_xref_to_caddr(const struct silofs_xref *xref,
                         struct silofs_caddr *out_caddr)
{
	const size_t lim = sizeof(xref->s);
	const size_t n = silofs_str_nlength(xref->s, lim);
	int ret = -SILOFS_EINVAL;

	if (n < lim) {
		ret = silofs_caddr_from_str(out_caddr, xref->s, n);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bpath, const char *repodir,
                          const char *name)
{
	struct silofs_namestr nstr;
	size_t len;

	silofs_memzero(bpath, sizeof(*bpath));
	len = silofs_str_length(repodir);
	if (!len || (len >= SILOFS_REPOPATH_MAX)) {
		return -SILOFS_EINVAL;
	}
	silofs_strview_init(&bpath->repodir, repodir);
	if (name == NULL) {
		return 0; /* boot with repo-dir only */
	}
	silofs_strview_init(&bpath->name, name);
	return silofs_make_namestr(&nstr, name);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_reload_vspace(struct silofs_task *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = silofs_rescan_vspace_of(task, ltype);
		if (err) {
			log_err("failed to reload vspace: ltype=%d err=%d",
			        ltype, err);
			return err;
		}
	}
	return 0;
}

int silofs_reload_rootd(struct silofs_task *task)
{
	struct silofs_inode_info *ii = NULL;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

	err = silofs_stage_inode(task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o", ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}
