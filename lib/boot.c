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
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <limits.h>

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

void silofs_bootref_init(struct silofs_fs_bref *bref)
{
	silofs_caddr_reset(&bref->caddr);
	bref->repodir = NULL;
	bref->name = NULL;
	bref->passwd = NULL;
}

void silofs_bootref_fini(struct silofs_fs_bref *bref)
{
	silofs_caddr_reset(&bref->caddr);
	bref->repodir = NULL;
	bref->name = NULL;
	bref->passwd = NULL;
}

void silofs_bootref_assign(struct silofs_fs_bref *bref,
                           const struct silofs_fs_bref *other)
{
	silofs_caddr_assign(&bref->caddr, &other->caddr);
	bref->repodir = other->repodir;
	bref->name = other->name;
	bref->passwd = other->passwd;
}

void silofs_bootref_update(struct silofs_fs_bref *bref,
                           const struct silofs_caddr *caddr, const char *name)
{
	silofs_caddr_assign(&bref->caddr, caddr);
	bref->name = name;
}

int silofs_bootref_import(struct silofs_fs_bref *bref,
                          const struct silofs_strview *sv)
{
	return silofs_caddr_by_name2(&bref->caddr, sv);
}

void silofs_bootref_export(const struct silofs_fs_bref *bref,
                           struct silofs_strbuf *sbuf)
{
	silofs_caddr_to_name(&bref->caddr, sbuf);
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
