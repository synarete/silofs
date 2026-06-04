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
#include <inttypes.h>

#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/pv.h>
#include <silofs/fs.h>

static int
stage_vnode(const struct silofs_task_ctx *task,
            const struct silofs_vaddr *vaddr, struct silofs_inode_info *pii,
            enum silofs_stg_mode stg_mode, struct silofs_vnode_info **out_vni)
{
	struct silofs_pexec_ctx pexec;
	int err;

	silofs_make_pexec(task, &pexec);
	silofs_ii_incref(pii);
	err = silofs_fetch_vnode2(&pexec, vaddr, out_vni);
	silofs_ii_decref(pii);
	silofs_unused(stg_mode);
	return err;
}

static int
spawn_vnode(const struct silofs_task_ctx *task, struct silofs_inode_info *pii,
            enum silofs_vtype vtype, struct silofs_vnode_info **out_vni)
{
	struct silofs_pexec_ctx pexec;
	int err;

	silofs_make_pexec(task, &pexec);
	silofs_ii_incref(pii);
	err = silofs_create_vnode2(&pexec, vtype, out_vni);
	silofs_ii_decref(pii);
	return err;
}

static int remove_vnode_at(const struct silofs_task_ctx *task,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_pexec_ctx pexec;

	silofs_make_pexec(task, &pexec);
	return silofs_reclaim_vnode2_at(&pexec, vaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_xanode_info *vni_to_xai(struct silofs_vnode_info *vni)
{
	struct silofs_xanode_info *xai = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIXPTR, (uintptr_t)vni);
	}
	xai = silofs_xai_from_vni(vni);
	if (unlikely(xai == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIXPTR, (uintptr_t)vni);
	}
	if (unlikely(xai->xan == nullptr)) {
		silofs_panic("missing xanode: xai=%" PRIXPTR, (uintptr_t)xai);
	}
	return xai;
}

int silofs_stage_xanode(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_inode_info *pii,
                        enum silofs_stg_mode stg_mode,
                        struct silofs_xanode_info **out_xai)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_XANODE);
	err = stage_vnode(task, vaddr, pii, stg_mode, &vni);
	if (err) {
		return err;
	}
	*out_xai = vni_to_xai(vni);
	return 0;
}

int silofs_spawn_xanode(struct silofs_task_ctx *task,
                        struct silofs_inode_info *pii,
                        struct silofs_xanode_info **out_xai)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_vnode(task, pii, SILOFS_VTYPE_XANODE, &vni);
	if (err) {
		return err;
	}
	*out_xai = vni_to_xai(vni);
	return 0;
}

int silofs_remove_xanode_at(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_XANODE);
	return remove_vnode_at(task, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_symval_info *vni_to_svi(struct silofs_vnode_info *vni)
{
	struct silofs_symval_info *svi = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIXPTR, (uintptr_t)vni);
	}
	svi = silofs_svi_from_vni(vni);
	if (unlikely(svi == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIXPTR, (uintptr_t)vni);
	}
	if (unlikely(svi->svn == nullptr)) {
		silofs_panic("missing symval: svi=%" PRIXPTR, (uintptr_t)svi);
	}
	return svi;
}

int silofs_stage_symval(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_inode_info *pii,
                        enum silofs_stg_mode stg_mode,
                        struct silofs_symval_info **out_svi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_SYMVAL);
	err = stage_vnode(task, vaddr, pii, stg_mode, &vni);
	if (err) {
		return err;
	}
	*out_svi = vni_to_svi(vni);
	return 0;
}

int silofs_spawn_symval(struct silofs_task_ctx *task,
                        struct silofs_inode_info *pii,
                        struct silofs_symval_info **out_svi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_vnode(task, pii, SILOFS_VTYPE_SYMVAL, &vni);
	if (err) {
		return err;
	}
	*out_svi = vni_to_svi(vni);
	return 0;
}

int silofs_remove_symval_at(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_SYMVAL);
	return remove_vnode_at(task, vaddr);
}
