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
#include "carve.h"
#include "stage.h"
#include "btnode.h"
#include "btree.h"
#include "space.h"
#include <silofs/exectx.h>
#include <silofs/env.h>

static void update_formatted_uber(struct silofs_task_ctx *task,
                                  struct silofs_uber_info *ubi)
{
	log_dbg("update uber: ubi=%p", (void *)ubi);
	silofs_env_update_uber(task->env, ubi);
	task->ubi = task->env->ubi;
}

static int format_uber(struct silofs_task_ctx *task)
{
	struct silofs_pnptr pnptr    = {};
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_carve_base_ubspace(task, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_spawn_uber(task, &pnptr, &ubi);
	if (err) {
		return err;
	}
	update_formatted_uber(task, ubi);
	return 0;
}

static void
fixup_spawned_btroot(struct silofs_btnode_info *bti, enum silofs_vtype vtype)
{
	silofs_bti_set_vspace(bti, vtype);
	silofs_bti_mark_root(bti);
}

static int
spawn_btroot_of(struct silofs_task_ctx *task, enum silofs_vtype vtype,
                struct silofs_btnode_info **out_bti)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_carve_base_btspace(task, vtype, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_spawn_btnode(task, &pnptr, out_bti);
	if (err) {
		return err;
	}
	fixup_spawned_btroot(*out_bti, vtype);
	return 0;
}

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return silofs_pni_paddr(&bti->btn_pni);
}

static void update_formatted_btroot(struct silofs_task_ctx *task,
                                    const struct silofs_btnode_info *bti)
{
	struct silofs_uber_info *ubi = task->ubi;

	silofs_ubi_set_btroot_by(ubi, bti);
	silofs_ubi_start_spdesc(ubi, bti_paddr(bti));
}

static int
format_btroot_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = spawn_btroot_of(task, vtype, &bti);
	if (err) {
		return err;
	}
	update_formatted_btroot(task, bti);
	return 0;
}

static int
format_vspace_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	struct silofs_paddr paddr = {};
	int err;

	err = silofs_carve_base_vspace(task, vtype, &paddr);
	if (err) {
		return err;
	}
	silofs_ubi_start_spdesc(task->ubi, &paddr);
	return 0;
}

static int format_vspaces(struct silofs_task_ctx *task)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype)) {
			continue;
		}
		err = format_btroot_of(task, vtype);
		if (err) {
			return err;
		}
		err = format_vspace_of(task, vtype);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_format_ps(struct silofs_task_ctx *task)
{
	int err;

	err = format_uber(task);
	if (err) {
		return err;
	}
	err = format_vspaces(task);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_vnode2_at(struct silofs_task_ctx *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_carve_next_vspace(task, vaddr->vtype, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode2(task, vaddr, &pnptr, out_vni);
	if (err) {
		return err;
	}
	err = silofs_insert_vtop(task, vaddr, &pnptr);
	if (err) {
		return err;
	}
	return 0;
}
