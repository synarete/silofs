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

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/pv.h>
#include <silofs/fs.h>

static int verify_lview_of(const struct silofs_lview *lview,
                           const struct silofs_vaddr *vaddr)
{
	int ret;

	switch (vaddr->vtype) {
	case SILOFS_VTYPE_SUPER2:
		ret = silofs_verify_superb_node(&lview->u.sbn);
		break;
	case SILOFS_VTYPE_SPNODE2:
		ret = silofs_verify_space_node(&lview->u.spn);
		break;
	case SILOFS_VTYPE_INODE:
		ret = silofs_verify_inode(&lview->u.in);
		break;
	case SILOFS_VTYPE_XANODE:
		ret = silofs_verify_xattr_node(&lview->u.xan);
		break;
	case SILOFS_VTYPE_SYMVAL:
		ret = silofs_verify_symval_node(&lview->u.svn);
		break;
	case SILOFS_VTYPE_DTNODE:
		ret = silofs_verify_dtree_node(&lview->u.dtn);
		break;
	case SILOFS_VTYPE_FTNODE:
		ret = silofs_verify_ftree_node(&lview->u.ftn);
		break;
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
		ret = 0;
		break;
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		silofs_panic("non vnode: vtype=%d off=%zd", //
		             vaddr->vtype, vaddr->off);
		break;
	}
	return ret;
}

static int verify_staged_vnode(const struct silofs_vnode_info *vni)
{
	const struct silofs_lview *lview = vni->vn_ni.view.lview;
	const struct silofs_vaddr *vaddr = silofs_vni_vaddr(vni);

	return verify_lview_of(lview, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	err = silofs_probe_vnode2_at(&pexec, vaddr);
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
	err = silofs_stage_vnode2_at(&pexec, vaddr, out_vni);
	finish_pexec(&pexec, pii);
	silofs_unused(stg_mode);
	return err;
}

static int stage_verify_vnode(const struct silofs_task_ctx *task,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_inode_info *pii,
                              enum silofs_stg_mode stg_mode,
                              struct silofs_vnode_info **out_vni)
{
	int err;

	err = stage_vnode(task, vaddr, pii, stg_mode, out_vni);
	return err ? err : verify_staged_vnode(*out_vni);
}

static int spawn_vnode_at(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_vnode_info **out_vni)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, nullptr);
	err = silofs_spawn_vnode2_at(&pexec, vaddr, out_vni);
	finish_pexec(&pexec, nullptr);
	return err;
}

static int
spawn_vnode(const struct silofs_task_ctx *task, enum silofs_vtype vtype,
            struct silofs_inode_info *pii, struct silofs_vnode_info **out_vni)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_spawn_vnode2(&pexec, vtype, out_vni);
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

static int reclaim_vnode(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii, bool *out_last)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_reclaim_vnode2_at(&pexec, vaddr, out_last);
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

static int unshare_vnode(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_inode_info *pii, bool *out_last)
{
	struct silofs_pexec_ctx pexec;
	int err;

	start_pexec(&pexec, task, pii);
	err = silofs_unshare_vnode2_at(&pexec, vaddr, out_last);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int get_sbi(const struct silofs_task_ctx *task,
                   struct silofs_sbnode_info **out_sbi)
{
	int err;

	err = silofs_curr_sbi(task, out_sbi);
	return_if_err(err);

	silofs_sbi_incref(*out_sbi);
	return 0;
}

static void put_sbi(struct silofs_sbnode_info *sbi)
{
	if (sbi != nullptr) {
		silofs_sbi_decref(sbi);
	}
}

static void take_vnode(struct silofs_sbnode_info *sbi, enum silofs_vtype vtype)
{
	silofs_sbi_take_vnode(sbi, vtype);
}

static void
give_vnode(struct silofs_sbnode_info *sbi, enum silofs_vtype vtype, bool last)
{
	if (last) {
		silofs_sbi_give_vnode(sbi, vtype);
	}
}

static void give_vnode_of(struct silofs_sbnode_info *sbi,
                          const struct silofs_vaddr *vaddr, bool last)
{
	give_vnode(sbi, vaddr->vtype, last);
}

static int
spawn_take_vnode(const struct silofs_task_ctx *task, enum silofs_vtype vtype,
                 struct silofs_inode_info *pii,
                 struct silofs_vnode_info **out_vni)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = spawn_vnode(task, vtype, pii, out_vni);
	goto_out_if_err(err);

	take_vnode(sbi, vtype);
out:
	put_sbi(sbi);
	return err;
}

static int
claim_take_vnode(const struct silofs_task_ctx *task, enum silofs_vtype vtype,
                 struct silofs_inode_info *pii, struct silofs_vaddr *out_vaddr)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = claim_vnode(task, vtype, pii, out_vaddr);
	goto_out_if_err(err);

	take_vnode(sbi, vtype);
out:
	put_sbi(sbi);
	return err;
}

static int reclaim_give_vnode(const struct silofs_task_ctx *task,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_inode_info *pii)
{
	struct silofs_sbnode_info *sbi = nullptr;
	bool last;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = reclaim_vnode(task, vaddr, pii, &last);
	goto_out_if_err(err);

	give_vnode_of(sbi, vaddr, last);
out:
	put_sbi(sbi);
	return err;
}

static int unshare_give_vnode(const struct silofs_task_ctx *task,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_inode_info *pii)
{
	struct silofs_sbnode_info *sbi = nullptr;
	bool last;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = unshare_vnode(task, vaddr, pii, &last);
	goto_out_if_err(err);

	give_vnode_of(sbi, vaddr, last);
out:
	put_sbi(sbi);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void vaddr_of_super(struct silofs_vaddr *out_vaddr)
{
	const off_t pos = silofs_vtype_ssize(SILOFS_VTYPE_SUPER2);

	silofs_vaddr_setup(out_vaddr, SILOFS_VTYPE_SUPER2, pos);
}

static struct silofs_sbnode_info *vni_to_sbi(struct silofs_vnode_info *vni)
{
	struct silofs_sbnode_info *sbi = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	sbi = silofs_sbi_from_vni(vni);
	if (unlikely(sbi == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(sbi->sbn == nullptr)) {
		silofs_panic("missing sun: sui=%" PRIxPTR, (uintptr_t)sbi);
	}
	return sbi;
}

int silofs_probe_super2(const struct silofs_task_ctx *task)
{
	struct silofs_vaddr vaddr;

	vaddr_of_super(&vaddr);
	return probe_vnode(task, &vaddr, nullptr);
}

int silofs_stage_super2(const struct silofs_task_ctx *task,
                        enum silofs_stg_mode stg_mode,
                        struct silofs_sbnode_info **out_sbi)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vni = nullptr;
	int err;

	vaddr_of_super(&vaddr);
	err = stage_verify_vnode(task, &vaddr, nullptr, stg_mode, &vni);
	return_if_err(err);

	*out_sbi = vni_to_sbi(vni);
	return 0;
}

int silofs_spawn_super2(const struct silofs_task_ctx *task,
                        struct silofs_sbnode_info **out_sbi)
{
	struct silofs_vaddr vaddr     = {};
	struct silofs_vnode_info *vni = nullptr;
	int err;

	vaddr_of_super(&vaddr);
	err = spawn_vnode_at(task, &vaddr, &vni);
	return_if_err(err);

	*out_sbi = vni_to_sbi(vni);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_spnode_info2 *vni_to_spi(struct silofs_vnode_info *vni)
{
	struct silofs_spnode_info2 *spi = nullptr;

	if (unlikely(vni == nullptr)) {
		silofs_panic("nullptr: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	spi = silofs_spi_from_vni(vni);
	if (unlikely(spi == nullptr)) {
		silofs_panic("upcast failure: vni=%" PRIxPTR, (uintptr_t)vni);
	}
	if (unlikely(spi->spn == nullptr)) {
		silofs_panic("missing spnode: spi=%" PRIxPTR, (uintptr_t)spi);
	}
	return spi;
}

int silofs_probe_spnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_SPNODE2);
	return probe_vnode(task, vaddr, nullptr);
}

int silofs_stage_spnode2_of(const struct silofs_task_ctx *task,
                            const struct silofs_vaddr *ref_vaddr,
                            enum silofs_stg_mode stg_mode,
                            struct silofs_spnode_info2 **out_spi)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);

	err = stage_verify_vnode(task, &vaddr, nullptr, stg_mode, &vni);
	return_if_err(err);

	*out_spi = vni_to_spi(vni);
	return 0;
}

int silofs_spawn_spnode2_of(const struct silofs_task_ctx *task,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_spnode_info2 **out_spi)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vni = nullptr;
	int err;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);

	err = spawn_vnode_at(task, &vaddr, &vni);
	return_if_err(err);

	*out_spi = vni_to_spi(vni);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	err = stage_verify_vnode(task, vaddr, nullptr, stg_mode, &vni);
	return_if_err(err);

	*out_ii = vni_to_ii(vni);
	return 0;
}

int silofs_spawn_inode2(const struct silofs_task_ctx *task,
                        struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = spawn_take_vnode(task, SILOFS_VTYPE_INODE, nullptr, &vni);
	return_if_err(err);

	*out_ii = vni_to_ii(vni);
	return 0;
}

int silofs_remove_inode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_INODE);
	return reclaim_give_vnode(task, vaddr, nullptr);
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

	err = stage_verify_vnode(task, vaddr, pii, stg_mode, &vni);
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

	err = spawn_take_vnode(task, SILOFS_VTYPE_XANODE, pii, &vni);
	return_if_err(err);

	*out_xai = vni_to_xai(vni);
	return 0;
}

int silofs_remove_xanode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_XANODE);
	return reclaim_give_vnode(task, vaddr, pii);
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

	err = stage_verify_vnode(task, vaddr, pii, stg_mode, &vni);
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

	err = spawn_take_vnode(task, SILOFS_VTYPE_SYMVAL, pii, &vni);
	return_if_err(err);

	*out_svi = vni_to_svi(vni);
	return 0;
}

int silofs_remove_symval2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_SYMVAL);
	return reclaim_give_vnode(task, vaddr, pii);
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
	err = stage_verify_vnode(task, vaddr, pii, stg_mode, &vni);
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

	err = spawn_take_vnode(task, SILOFS_VTYPE_DTNODE, pii, &vni);
	return_if_err(err);

	*out_dti = vni_to_dti(vni);
	return 0;
}

int silofs_remove_dtnode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_DTNODE);
	return reclaim_give_vnode(task, vaddr, pii);
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
	err = stage_verify_vnode(task, vaddr, pii, stg_mode, &vni);
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

	err = spawn_take_vnode(task, SILOFS_VTYPE_FTNODE, pii, &vni);
	return_if_err(err);

	*out_fti = vni_to_fti(vni);
	return 0;
}

int silofs_remove_ftnode2(struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(vaddr->vtype, SILOFS_VTYPE_FTNODE);
	return reclaim_give_vnode(task, vaddr, pii);
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

	err = stage_verify_vnode(task, vaddr, pii, stg_mode, &vni);
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
	return claim_take_vnode(task, vtype, pii, out_vaddr);
}

int silofs_remove_fdnode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert(silofs_vaddr_isdata(vaddr));
	return reclaim_give_vnode(task, vaddr, pii);
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
	return unshare_give_vnode(task, vaddr, pii);
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
