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

static void
start_pexec(struct silofs_pexec_ctx *pexec, const struct silofs_task_ctx *task,
            struct silofs_inode_info *pii)
{
	silofs_make_pexec(task, pexec);
	silofs_ii_incref(pii);
}

static void
finish_pexec(struct silofs_pexec_ctx *pexec, struct silofs_inode_info *pii)
{
	silofs_ii_decref(pii);
	silofs_memzero(pexec, sizeof(*pexec));
}

static int
probe_vnode(const struct silofs_task_ctx *task,
            const struct silofs_vaddr *vaddr, struct silofs_inode_info *pii)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_probe_vnode2(&pexec, vaddr);
	finish_pexec(&pexec, pii);
	return err;
}

static int
stage_vnode(const struct silofs_task_ctx *task,
            const struct silofs_vaddr *vaddr, struct silofs_inode_info *pii,
            enum silofs_stg_mode stg_mode, struct silofs_vnode_info **out_vni)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_fetch_vnode2(&pexec, vaddr, out_vni);
	finish_pexec(&pexec, pii);
	silofs_unused(stg_mode);
	return err;
}

static int
spawn_vnode(const struct silofs_task_ctx *task, struct silofs_inode_info *pii,
            enum silofs_vtype vtype, struct silofs_vnode_info **out_vni)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_create_vnode2(&pexec, vtype, out_vni);
	finish_pexec(&pexec, pii);
	return err;
}

static int
claim_vnode(const struct silofs_task_ctx *task, enum silofs_vtype vtype,
            struct silofs_inode_info *pii, struct silofs_vaddr *out_vaddr)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_claim_vnode2_space(&pexec, vtype, out_vaddr);
	finish_pexec(&pexec, pii);
	return err;
}

static int
reclaim_vnode(const struct silofs_task_ctx *task,
              const struct silofs_vaddr *vaddr, struct silofs_inode_info *pii)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_reclaim_vnode2_at(&pexec, vaddr);
	finish_pexec(&pexec, pii);
	return err;
}

static int
share_vnode(const struct silofs_task_ctx *task,
            const struct silofs_vaddr *vaddr, struct silofs_inode_info *pii)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_share_vnode2_at(&pexec, vaddr);
	finish_pexec(&pexec, pii);
	return err;
}

static int
unshare_vnode(const struct silofs_task_ctx *task,
              const struct silofs_vaddr *vaddr, struct silofs_inode_info *pii)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_unshare_vnode2_at(&pexec, vaddr);
	finish_pexec(&pexec, pii);
	return err;
}

static int isshared_vnode(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii, bool *out_res)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_isshared_vnode2_at(&pexec, vaddr, out_res);
	finish_pexec(&pexec, pii);
	return err;
}

static int
mark_unwritten(const struct silofs_task_ctx *task,
               const struct silofs_vaddr *vaddr, struct silofs_inode_info *pii)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_mark_unwritten_at2(&pexec, vaddr);
	finish_pexec(&pexec, pii);
	return err;
}

static int clear_unwritten(const struct silofs_task_ctx *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_inode_info *pii)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_clear_unwritten_at2(&pexec, vaddr);
	finish_pexec(&pexec, pii);
	return err;
}

static int test_unwritten(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii, bool *out_unwritten)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_test_unwritten_at2(&pexec, vaddr, out_unwritten);
	finish_pexec(&pexec, pii);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_inode_info *vni_to_ii(struct silofs_vnode_info *vni)
{
	struct silofs_inode_info *ii = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	ii = silofs_ii_from_vni(vni);
	if (unlikely(ii == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(ii->inode == nullptr)) {
		silofs_panic("missing inode: ii=%" PRIxPTR, (uintptr_t)ii);
	}
	return ii;
}

int silofs_probe_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_INODE);
	return probe_vnode(task, vaddr, nullptr);
}

int silofs_stage_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr *vaddr,
                        enum silofs_stg_mode stg_mode,
                        struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_INODE);
	err = stage_vnode(task, vaddr, nullptr, stg_mode, &vni);
	return_if_err(err);

	*out_ii = vni_to_ii(vni);
	return 0;
}

int silofs_spawn_inode2(const struct silofs_task_ctx *task,
                        struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_vnode(task, nullptr, SILOFS_VTYPE_INODE, &vni);
	return_if_err(err);

	*out_ii = vni_to_ii(vni);
	return 0;
}

int silofs_remove_inode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_INODE);
	return reclaim_vnode(task, vaddr, nullptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_xanode_info *vni_to_xai(struct silofs_vnode_info *vni)
{
	struct silofs_xanode_info *xai = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	xai = silofs_xai_from_vni(vni);
	if (unlikely(xai == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(xai->xan == nullptr)) {
		silofs_panic("missing xanode: xai=%" PRIxPTR, (uintptr_t)xai);
	}
	return xai;
}

int silofs_stage_xanode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_xanode_info **out_xai)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_XANODE);

	err = stage_vnode(task, vaddr, pii, stg_mode, &vni);
	return_if_err(err);

	*out_xai = vni_to_xai(vni);
	return 0;
}

int silofs_spawn_xanode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_xanode_info **out_xai)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_vnode(task, pii, SILOFS_VTYPE_XANODE, &vni);
	return_if_err(err);

	*out_xai = vni_to_xai(vni);
	return 0;
}

int silofs_remove_xanode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_XANODE);
	return reclaim_vnode(task, vaddr, pii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_symval_info *vni_to_svi(struct silofs_vnode_info *vni)
{
	struct silofs_symval_info *svi = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	svi = silofs_svi_from_vni(vni);
	if (unlikely(svi == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(svi->svn == nullptr)) {
		silofs_panic("missing symval: svi=%" PRIxPTR, (uintptr_t)svi);
	}
	return svi;
}

int silofs_stage_symval2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_symval_info **out_svi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_SYMVAL);

	err = stage_vnode(task, vaddr, pii, stg_mode, &vni);
	return_if_err(err);

	*out_svi = vni_to_svi(vni);
	return 0;
}

int silofs_spawn_symval2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_symval_info **out_svi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_vnode(task, pii, SILOFS_VTYPE_SYMVAL, &vni);
	return_if_err(err);

	*out_svi = vni_to_svi(vni);
	return 0;
}

int silofs_remove_symval2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_SYMVAL);
	return reclaim_vnode(task, vaddr, pii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dtnode_info *vni_to_dti(struct silofs_vnode_info *vni)
{
	struct silofs_dtnode_info *dti = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	dti = silofs_dti_from_vni(vni);
	if (unlikely(dti == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(dti->dtn == nullptr)) {
		silofs_panic("missing dtnode: dti=%" PRIxPTR, (uintptr_t)dti);
	}
	return dti;
}

int silofs_stage_dtnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_dtnode_info **out_dti)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_DTNODE);
	err = stage_vnode(task, vaddr, pii, stg_mode, &vni);
	return_if_err(err);

	*out_dti = vni_to_dti(vni);
	return 0;
}

int silofs_spawn_dtnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_dtnode_info **out_dti)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_vnode(task, pii, SILOFS_VTYPE_DTNODE, &vni);
	return_if_err(err);

	*out_dti = vni_to_dti(vni);
	return 0;
}

int silofs_remove_dtnode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_DTNODE);

	return reclaim_vnode(task, vaddr, pii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ftnode_info *vni_to_fti(struct silofs_vnode_info *vni)
{
	struct silofs_ftnode_info *fti = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	fti = silofs_fti_from_vni(vni);
	if (unlikely(fti == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(fti->ftn == nullptr)) {
		silofs_panic("missing ftnode: fti=%" PRIxPTR, (uintptr_t)fti);
	}
	return fti;
}

int silofs_stage_ftnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_ftnode_info **out_fti)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_FTNODE);
	err = stage_vnode(task, vaddr, pii, stg_mode, &vni);
	return_if_err(err);

	*out_fti = vni_to_fti(vni);
	return 0;
}

int silofs_spawn_ftnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_ftnode_info **out_fti)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_vnode(task, pii, SILOFS_VTYPE_FTNODE, &vni);
	return_if_err(err);

	*out_fti = vni_to_fti(vni);
	return 0;
}

int silofs_remove_ftnode2(struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_FTNODE);
	return reclaim_vnode(task, vaddr, pii);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_fdnode_info *vni_to_fdi(struct silofs_vnode_info *vni)
{
	struct silofs_fdnode_info *fdi = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	fdi = silofs_fdi_from_vni(vni);
	if (unlikely(fdi == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(fdi->fdn.dn64 == nullptr)) {
		silofs_panic("missing ftleaf: fli=%" PRIxPTR, (uintptr_t)fdi);
	}
	return fdi;
}

int silofs_stage_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_fdnode_info **out_fdi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_assert(silofs_vaddr_isdata(vaddr));

	err = stage_vnode(task, vaddr, pii, stg_mode, &vni);
	return_if_err(err);

	*out_fdi = vni_to_fdi(vni);
	return 0;
}

int silofs_claim_fdnode2(const struct silofs_task_ctx *task,
                         enum silofs_vtype vtype,
                         struct silofs_inode_info *pii,
                         struct silofs_vaddr *out_vaddr)
{
	silofs_assert(silofs_vtype_isdata(vtype));
	return claim_vnode(task, vtype, pii, out_vaddr);
}

int silofs_reclaim_fdnode2(const struct silofs_task_ctx *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_inode_info *pii)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return reclaim_vnode(task, vaddr, pii);
}

int silofs_remove_fdnode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return reclaim_vnode(task, vaddr, pii);
}

int silofs_share_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return share_vnode(task, vaddr, pii);
}

int silofs_unshare_fdnode2(const struct silofs_task_ctx *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_inode_info *pii)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return unshare_vnode(task, vaddr, pii);
}

int silofs_isshared_fdnode2(const struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_inode_info *pii, bool *out_res)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return isshared_vnode(task, vaddr, pii, out_res);
}

int silofs_mark_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_vaddr *vaddr,
                                  struct silofs_inode_info *pii)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return mark_unwritten(task, vaddr, pii);
}

int silofs_clear_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_inode_info *pii)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return clear_unwritten(task, vaddr, pii);
}

int silofs_test_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_vaddr *vaddr,
                                  struct silofs_inode_info *pii,
                                  bool *out_unwritten)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return test_unwritten(task, vaddr, pii, out_unwritten);
}
