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
#include <silofs/ondisk.h>
#include <silofs/types.h>
#include "infra.h"
#include "addr.h"
#include "fs.h"
#include "exec.h"
#include "env.h"

static int reload_uber(struct silofs_exec_ctx *ectx)
{
	return silofs_env_reload_uber(ectx->ex_env);
}

static int reload_super(struct silofs_exec_ctx *ectx)
{
	int err;

	err = silofs_env_reload_sb_lseg(ectx->ex_env);
	if (err) {
		return err;
	}
	err = silofs_env_reload_super(ectx->ex_env);
	if (err) {
		return err;
	}
	return 0;
}

static int reload_vspace(struct silofs_exec_ctx *ectx)
{
	return silofs_reload_vspace(ectx);
}

static int reload_rootd(struct silofs_exec_ctx *ectx)
{
	struct silofs_inode_info *ii = nullptr;
	const ino_t ino              = SILOFS_INO_ROOT;
	int err;

	err = silofs_stage_inode(ectx, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!silofs_ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o",
		        silofs_ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int
reload_fs_mbr(struct silofs_exec_ctx *ectx, const struct silofs_mbref *mbref)
{
	return silofs_env_reload_fs_mbr(ectx->ex_env, mbref);
}

int silofs_exec_reload_fs(struct silofs_exec_ctx *ectx,
                          const struct silofs_mbref *mbref)
{
	int err;

	err = reload_fs_mbr(ectx, mbref);
	if (err) {
		return err;
	}
	err = reload_uber(ectx);
	if (err) {
		return err;
	}
	err = reload_super(ectx);
	if (err) {
		return err;
	}
	err = reload_vspace(ectx);
	if (err) {
		return err;
	}
	err = reload_rootd(ectx);
	if (err) {
		return err;
	}
	return 0;
}
