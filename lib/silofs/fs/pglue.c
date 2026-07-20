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
#include <silofs/pstor.h>
#include <silofs/fs.h>

static int verify_lview_of(const struct silofs_lview *lview,
                           const struct silofs_laddr *laddr)
{
	int ret;

	switch (laddr->ltype) {
	case SILOFS_LTYPE_SUPER:
		ret = silofs_verify_superb_node(&lview->u.sbn);
		break;
	case SILOFS_LTYPE_SPNODE:
		ret = silofs_verify_space_node(&lview->u.spn);
		break;
	case SILOFS_LTYPE_INODE:
		ret = silofs_verify_inode(&lview->u.in);
		break;
	case SILOFS_LTYPE_XANODE:
		ret = silofs_verify_xattr_node(&lview->u.xan);
		break;
	case SILOFS_LTYPE_SYMVAL:
		ret = silofs_verify_symval_node(&lview->u.svn);
		break;
	case SILOFS_LTYPE_DTNODE:
		ret = silofs_verify_dtree_node(&lview->u.dtn);
		break;
	case SILOFS_LTYPE_FTNODE:
		ret = silofs_verify_ftree_node(&lview->u.ftn);
		break;
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATA64K:
		ret = 0;
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		silofs_panic("non lnode: ltype=%d off=%zd", //
		             laddr->ltype, laddr->off);
		break;
	}
	return ret;
}

static int verify_staged_lnode(const struct silofs_lnode_info *lni)
{
	const struct silofs_lview *lview = lni->ln_ni.view.lview;
	const struct silofs_laddr *laddr = silofs_lni_laddr(lni);

	return verify_lview_of(lview, laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pii_incref(struct silofs_inode_info *pii)
{
	if (pii != nullptr) {
		silofs_ii_incref(pii);
	}
}

static void pii_decref(struct silofs_inode_info *pii)
{
	if (pii != nullptr) {
		silofs_ii_decref(pii);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
probe_lnode(const struct silofs_task_ctx *task,
            const struct silofs_laddr *laddr, struct silofs_inode_info *pii)
{
	struct silofs_pnptr pnptr;
	int err;

	pii_incref(pii);
	err = silofs_resolve_ltop_mapping(task->corefs, laddr, &pnptr);
	pii_decref(pii);
	return err;
}

static int do_stage_lnode(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_lnode_info **out_lni)
{
	enum silofs_lspacef lspf;
	int err;

	err = silofs_probe_lspacef_at(task, laddr, &lspf);
	return_if_err(err);

	err = silofs_stage_lnode_by_mapping(task->corefs, laddr, lspf,
	                                    out_lni);
	return_if_err(err);

	return 0;
}

static int
stage_lnode(const struct silofs_task_ctx *task,
            const struct silofs_laddr *laddr, struct silofs_inode_info *pii,
            enum silofs_stg_mode stg_mode, struct silofs_lnode_info **out_lni)
{
	int err;

	pii_incref(pii);
	err = do_stage_lnode(task, laddr, out_lni);
	pii_decref(pii);
	silofs_unused(stg_mode);
	return err;
}

static int stage_verify_lnode(const struct silofs_task_ctx *task,
                              const struct silofs_laddr *laddr,
                              struct silofs_inode_info *pii,
                              enum silofs_stg_mode stg_mode,
                              struct silofs_lnode_info **out_lni)
{
	int err;

	err = stage_lnode(task, laddr, pii, stg_mode, out_lni);
	return_if_err(err);

	err = verify_staged_lnode(*out_lni);
	return_if_err(err);

	return 0;
}

static int spawn_lnode_at(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_lnode_info **out_lni)
{
	return silofs_spawn_lnode_by_mapping(task->corefs, laddr, out_lni);
}

static int
claim_free_lspace(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
                  struct silofs_laddr *out_laddr)
{
	return silofs_claim_free_lspace(task, ltype, out_laddr);
}

static int do_claim_spawn_lnode(const struct silofs_task_ctx *task,
                                enum silofs_ltype ltype,
                                struct silofs_lnode_info **out_lni)
{
	struct silofs_laddr laddr = { .off = -1 };
	int err;

	err = claim_free_lspace(task, ltype, &laddr);
	return_if_err(err);

	err = spawn_lnode_at(task, &laddr, out_lni);
	return_if_err(err);

	return 0;
}

static int
claim_spawn_lnode(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
                  struct silofs_inode_info *pii,
                  struct silofs_lnode_info **out_lni)
{
	int err;

	pii_incref(pii);
	err = do_claim_spawn_lnode(task, ltype, out_lni);
	pii_decref(pii);
	return err;
}

static int
do_claim_lspace(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
                struct silofs_laddr *out_laddr)
{
	int err;

	err = claim_free_lspace(task, ltype, out_laddr);
	return_if_err(err);

	err = silofs_claim_lnode_mapping(task->corefs, out_laddr);
	return_if_err(err);

	return 0;
}

static int
claim_lnode(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
            struct silofs_inode_info *pii, struct silofs_laddr *out_laddr)
{
	int err;

	pii_incref(pii);
	err = do_claim_lspace(task, ltype, out_laddr);
	pii_decref(pii);
	return err;
}

static int
share_lnode(const struct silofs_task_ctx *task,
            const struct silofs_laddr *laddr, struct silofs_inode_info *pii)
{
	int err;

	pii_incref(pii);
	err = silofs_share_lnode_at(task, laddr);
	pii_decref(pii);
	return err;
}

static int
unshare_lnode(const struct silofs_task_ctx *task,
              const struct silofs_laddr *laddr, struct silofs_inode_info *pii)
{
	int err;

	pii_incref(pii);
	err = silofs_unshare_lnode_at(task, laddr);
	pii_decref(pii);
	return err;
}

static int isshared_lnode(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info *pii, bool *out_res)
{
	int err;

	pii_incref(pii);
	err = silofs_isshared_lnode_at(task, laddr, out_res);
	pii_decref(pii);
	return err;
}

static int do_reclaim_mapping(const struct silofs_task_ctx *task,
                              const struct silofs_laddr *laddr)
{
	int err;

	err = silofs_reclaim_lnode_mapping(task->corefs, laddr);
	return_if_err(err);

	silofs_lspools_push(task->corefs->lspools, laddr);
	return 0;
}

static int reclaim_mapping(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           struct silofs_inode_info *pii)
{
	int err;

	pii_incref(pii);
	err = do_reclaim_mapping(task, laddr);
	pii_decref(pii);
	return err;
}

static int reclaim_lnode(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr,
                         struct silofs_inode_info *pii, bool *out_last)
{
	int err;
	bool shared = false;

	err = isshared_lnode(task, laddr, pii, &shared);
	return_if_err(err);

	err = unshare_lnode(task, laddr, pii);
	return_if_err(err);

	if (!shared) {
		err = reclaim_mapping(task, laddr, pii);
		return_if_err(err);
	}

	*out_last = !shared;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
mark_unwritten(const struct silofs_task_ctx *task,
               const struct silofs_laddr *laddr, struct silofs_inode_info *pii)
{
	int err;

	pii_incref(pii);
	err = silofs_mark_unwritten_at(task, laddr);
	pii_decref(pii);
	return err;
}

static int clear_unwritten(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           struct silofs_inode_info *pii)
{
	int err;

	pii_incref(pii);
	err = silofs_clear_unwritten_at(task, laddr);
	pii_decref(pii);
	return err;
}

static int test_unwritten(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info *pii, bool *out_unwritten)
{
	int err;

	pii_incref(pii);
	err = silofs_test_unwritten_at(task, laddr, out_unwritten);
	pii_decref(pii);
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

static void take_lnode(struct silofs_sbnode_info *sbi, enum silofs_ltype ltype)
{
	silofs_sbi_take_lnode(sbi, ltype);
}

static void give_lnode(struct silofs_sbnode_info *sbi, enum silofs_ltype ltype)
{
	silofs_sbi_give_lnode(sbi, ltype);
}

static void
give_lnode_of(struct silofs_sbnode_info *sbi, const struct silofs_laddr *laddr)
{
	give_lnode(sbi, laddr->ltype);
}

static int
check_take_lnode(const struct silofs_sbnode_info *sbi, enum silofs_ltype ltype)
{
	return silofs_sbi_check_avail(sbi, ltype);
}

static int
spawn_take_lnode(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
                 struct silofs_inode_info *pii,
                 struct silofs_lnode_info **out_lni)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = check_take_lnode(sbi, ltype);
	goto_out_if_err(err);

	err = claim_spawn_lnode(task, ltype, pii, out_lni);
	goto_out_if_err(err);

	take_lnode(sbi, ltype);
out:
	put_sbi(sbi);
	return err;
}

static int
claim_take_lnode(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
                 struct silofs_inode_info *pii, struct silofs_laddr *out_laddr)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = check_take_lnode(sbi, ltype);
	goto_out_if_err(err);

	err = claim_lnode(task, ltype, pii, out_laddr);
	goto_out_if_err(err);

	take_lnode(sbi, ltype);
out:
	put_sbi(sbi);
	return err;
}

static void try_forget_cached_lni(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr *laddr)
{
	struct silofs_lcache *lcache  = task->corefs->lcache;
	struct silofs_lnode_info *lni = nullptr;
	;

	/*
	 * Special case where data-node has been unmapped via forget, yet it
	 * still has a live ref-count due to on-going I/O operation.
	 */
	lni = silofs_lcache_lookup_lnode(lcache, laddr);
	if ((lni != nullptr) && !silofs_lni_refcnt(lni)) {
		silofs_lcache_forget_lnode(lcache, lni);
	}
}

static int reclaim_give_lnode(const struct silofs_task_ctx *task,
                              const struct silofs_laddr *laddr,
                              struct silofs_inode_info *pii)
{
	struct silofs_sbnode_info *sbi = nullptr;
	bool last;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = reclaim_lnode(task, laddr, pii, &last);
	goto_out_if_err(err);

	if (last) {
		give_lnode_of(sbi, laddr);
		try_forget_cached_lni(task, laddr);
	}
out:
	put_sbi(sbi);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void laddr_of_super(struct silofs_laddr *out_laddr)
{
	const off_t pos = silofs_ltype_ssize(SILOFS_LTYPE_SUPER);

	silofs_laddr_setup(out_laddr, SILOFS_LTYPE_SUPER, pos);
}

static struct silofs_sbnode_info *lni_to_sbi(struct silofs_lnode_info *lni)
{
	struct silofs_sbnode_info *sbi = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	sbi = silofs_sbi_from_lni(lni);
	if (unlikely(sbi == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(sbi->sbn == nullptr)) {
		silofs_panic("missing sun: sui=%" PRIxPTR, (uintptr_t)sbi);
	}
	return sbi;
}

int silofs_probe_super(const struct silofs_task_ctx *task)
{
	struct silofs_laddr laddr;

	laddr_of_super(&laddr);
	return probe_lnode(task, &laddr, nullptr);
}

int silofs_stage_super(const struct silofs_task_ctx *task,
                       enum silofs_stg_mode stg_mode,
                       struct silofs_sbnode_info **out_sbi)
{
	struct silofs_laddr laddr;
	struct silofs_lnode_info *lni = nullptr;
	int err;

	laddr_of_super(&laddr);
	err = stage_verify_lnode(task, &laddr, nullptr, stg_mode, &lni);
	return_if_err(err);

	*out_sbi = lni_to_sbi(lni);
	return 0;
}

int silofs_spawn_super(const struct silofs_task_ctx *task,
                       struct silofs_sbnode_info **out_sbi)
{
	struct silofs_laddr laddr     = {};
	struct silofs_lnode_info *lni = nullptr;
	int err;

	laddr_of_super(&laddr);
	err = spawn_lnode_at(task, &laddr, &lni);
	return_if_err(err);

	*out_sbi = lni_to_sbi(lni);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_spnode_info *lni_to_spi(struct silofs_lnode_info *lni)
{
	struct silofs_spnode_info *spi = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	spi = silofs_spi_from_lni(lni);
	if (unlikely(spi == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(spi->spn == nullptr)) {
		silofs_panic("missing spnode: spi=%" PRIxPTR, (uintptr_t)spi);
	}
	return spi;
}

int silofs_probe_spnode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr *laddr)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_SPNODE);
	return probe_lnode(task, laddr, nullptr);
}

int silofs_stage_spnode_at(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           enum silofs_stg_mode stg_mode,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = stage_verify_lnode(task, laddr, nullptr, stg_mode, &lni);
	return_if_err(err);

	*out_spi = lni_to_spi(lni);
	return 0;
}

int silofs_spawn_spnode_at(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = spawn_lnode_at(task, laddr, &lni);
	return_if_err(err);

	*out_spi = lni_to_spi(lni);
	return 0;
}

int silofs_stage_spnode_of(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *ref_laddr,
                           enum silofs_stg_mode stg_mode,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	return silofs_stage_spnode_at(task, &laddr, stg_mode, out_spi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_info *lni_to_ii(struct silofs_lnode_info *lni)
{
	struct silofs_inode_info *ii = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	ii = silofs_ii_from_lni(lni);
	if (unlikely(ii == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(ii->inode == nullptr)) {
		silofs_panic("missing inode: ii=%" PRIxPTR, (uintptr_t)ii);
	}
	return ii;
}

int silofs_probe_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_laddr *laddr)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_INODE);
	return probe_lnode(task, laddr, nullptr);
}

int silofs_stage_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_laddr *laddr,
                        enum silofs_stg_mode stg_mode,
                        struct silofs_inode_info **out_ii)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_INODE);
	err = stage_verify_lnode(task, laddr, nullptr, stg_mode, &lni);
	return_if_err(err);

	*out_ii = lni_to_ii(lni);
	return 0;
}

int silofs_spawn_inode2(const struct silofs_task_ctx *task,
                        struct silofs_inode_info **out_ii)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = spawn_take_lnode(task, SILOFS_LTYPE_INODE, nullptr, &lni);
	return_if_err(err);

	*out_ii = lni_to_ii(lni);
	return 0;
}

int silofs_remove_inode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_INODE);
	return reclaim_give_lnode(task, laddr, nullptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_xanode_info *lni_to_xai(struct silofs_lnode_info *lni)
{
	struct silofs_xanode_info *xai = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	xai = silofs_xai_from_lni(lni);
	if (unlikely(xai == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(xai->xan == nullptr)) {
		silofs_panic("missing xanode: xai=%" PRIxPTR, (uintptr_t)xai);
	}
	return xai;
}

int silofs_stage_xanode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_xanode_info **out_xai)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_XANODE);

	err = stage_verify_lnode(task, laddr, pii, stg_mode, &lni);
	return_if_err(err);

	*out_xai = lni_to_xai(lni);
	return 0;
}

int silofs_spawn_xanode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_xanode_info **out_xai)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = spawn_take_lnode(task, SILOFS_LTYPE_XANODE, pii, &lni);
	return_if_err(err);

	*out_xai = lni_to_xai(lni);
	return 0;
}

int silofs_remove_xanode2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_XANODE);
	return reclaim_give_lnode(task, laddr, pii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_symval_info *lni_to_svi(struct silofs_lnode_info *lni)
{
	struct silofs_symval_info *svi = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	svi = silofs_svi_from_lni(lni);
	if (unlikely(svi == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(svi->svn == nullptr)) {
		silofs_panic("missing symval: svi=%" PRIxPTR, (uintptr_t)svi);
	}
	return svi;
}

int silofs_stage_symval2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_symval_info **out_svi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_SYMVAL);

	err = stage_verify_lnode(task, laddr, pii, stg_mode, &lni);
	return_if_err(err);

	*out_svi = lni_to_svi(lni);
	return 0;
}

int silofs_spawn_symval2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_symval_info **out_svi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = spawn_take_lnode(task, SILOFS_LTYPE_SYMVAL, pii, &lni);
	return_if_err(err);

	*out_svi = lni_to_svi(lni);
	return 0;
}

int silofs_remove_symval2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_SYMVAL);
	return reclaim_give_lnode(task, laddr, pii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dtnode_info *lni_to_dti(struct silofs_lnode_info *lni)
{
	struct silofs_dtnode_info *dti = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	dti = silofs_dti_from_lni(lni);
	if (unlikely(dti == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(dti->dtn == nullptr)) {
		silofs_panic("missing dtnode: dti=%" PRIxPTR, (uintptr_t)dti);
	}
	return dti;
}

int silofs_stage_dtnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_dtnode_info **out_dti)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_DTNODE);
	err = stage_verify_lnode(task, laddr, pii, stg_mode, &lni);
	return_if_err(err);

	*out_dti = lni_to_dti(lni);
	return 0;
}

int silofs_spawn_dtnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_dtnode_info **out_dti)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = spawn_take_lnode(task, SILOFS_LTYPE_DTNODE, pii, &lni);
	return_if_err(err);

	*out_dti = lni_to_dti(lni);
	return 0;
}

int silofs_remove_dtnode2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_DTNODE);
	return reclaim_give_lnode(task, laddr, pii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ftnode_info *lni_to_fti(struct silofs_lnode_info *lni)
{
	struct silofs_ftnode_info *fti = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	fti = silofs_fti_from_lni(lni);
	if (unlikely(fti == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(fti->ftn == nullptr)) {
		silofs_panic("missing ftnode: fti=%" PRIxPTR, (uintptr_t)fti);
	}
	return fti;
}

int silofs_stage_ftnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_ftnode_info **out_fti)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_FTNODE);
	err = stage_verify_lnode(task, laddr, pii, stg_mode, &lni);
	return_if_err(err);

	*out_fti = lni_to_fti(lni);
	return 0;
}

int silofs_spawn_ftnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *pii,
                         struct silofs_ftnode_info **out_fti)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = spawn_take_lnode(task, SILOFS_LTYPE_FTNODE, pii, &lni);
	return_if_err(err);

	*out_fti = lni_to_fti(lni);
	return 0;
}

int silofs_remove_ftnode2(struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_FTNODE);
	return reclaim_give_lnode(task, laddr, pii);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_fdnode_info *lni_to_fdi(struct silofs_lnode_info *lni)
{
	struct silofs_fdnode_info *fdi = nullptr;

	if (unlikely(lni == nullptr)) {
		silofs_panic("nullptr: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	fdi = silofs_fdi_from_lni(lni);
	if (unlikely(fdi == nullptr)) {
		silofs_panic("upcast failure: lni=%" PRIxPTR, (uintptr_t)lni);
	}
	if (unlikely(fdi->fdn.dn64 == nullptr)) {
		silofs_panic("missing ftleaf: fli=%" PRIxPTR, (uintptr_t)fdi);
	}
	return fdi;
}

int silofs_stage_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr,
                         struct silofs_inode_info *pii,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_fdnode_info **out_fdi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	silofs_assert(silofs_laddr_isdata(laddr));

	err = stage_verify_lnode(task, laddr, pii, stg_mode, &lni);
	return_if_err(err);

	*out_fdi = lni_to_fdi(lni);
	return 0;
}

int silofs_claim_fdnode2(const struct silofs_task_ctx *task,
                         enum silofs_ltype ltype,
                         struct silofs_inode_info *pii,
                         struct silofs_laddr *out_laddr)
{
	silofs_assert(silofs_ltype_isdata(ltype));
	return claim_take_lnode(task, ltype, pii, out_laddr);
}

int silofs_remove_fdnode2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info *pii)
{
	silofs_assert(silofs_laddr_isdata(laddr));
	return reclaim_give_lnode(task, laddr, pii);
}

int silofs_share_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr *laddr,
                         struct silofs_inode_info *pii)
{
	silofs_assert(silofs_laddr_isdata(laddr));
	return share_lnode(task, laddr, pii);
}

int silofs_unshare_fdnode2(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           struct silofs_inode_info *pii)
{
	silofs_assert(silofs_laddr_isdata(laddr));
	return reclaim_give_lnode(task, laddr, pii);
}

int silofs_isshared_fdnode2(const struct silofs_task_ctx *task,
                            const struct silofs_laddr *laddr,
                            struct silofs_inode_info *pii, bool *out_res)
{
	silofs_assert(silofs_laddr_isdata(laddr));
	return isshared_lnode(task, laddr, pii, out_res);
}

int silofs_mark_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr *laddr,
                                  struct silofs_inode_info *pii)
{
	silofs_assert(silofs_laddr_isdata(laddr));
	return mark_unwritten(task, laddr, pii);
}

int silofs_clear_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                   const struct silofs_laddr *laddr,
                                   struct silofs_inode_info *pii)
{
	silofs_assert(silofs_laddr_isdata(laddr));
	return clear_unwritten(task, laddr, pii);
}

int silofs_test_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr *laddr,
                                  struct silofs_inode_info *pii,
                                  bool *out_unwritten)
{
	silofs_assert(silofs_laddr_isdata(laddr));
	return test_unwritten(task, laddr, pii, out_unwritten);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_take_lnode(const struct silofs_task_ctx *task,
                            enum silofs_ltype ltype,
                            struct silofs_lnode_info **out_lni)
{
	silofs_assert(silofs_ltype_usespmap(ltype));

	return spawn_take_lnode(task, ltype, nullptr, out_lni);
}

static void
laddr_of(const struct silofs_lnode_info *lni, struct silofs_laddr *out_laddr)
{
	silofs_laddr_assign(out_laddr, silofs_lni_laddr(lni));
}

int silofs_remove_give_lnode(const struct silofs_task_ctx *task,
                             const struct silofs_lnode_info *lni)
{
	struct silofs_laddr laddr;

	laddr_of(lni, &laddr);
	return reclaim_give_lnode(task, &laddr, nullptr);
}

int silofs_stage_curr_lnode(const struct silofs_task_ctx *task,
                            const struct silofs_laddr *laddr,
                            struct silofs_lnode_info **out_lni)
{
	return stage_lnode(task, laddr, nullptr, SILOFS_STG_CUR, out_lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_curr_sbi(const struct silofs_task_ctx *task,
                    struct silofs_sbnode_info **out_sbi)
{
	return silofs_stage_super(task, SILOFS_STG_CUR, out_sbi);
}

int silofs_flush_dirty_now(const struct silofs_task_ctx *task)
{
	return silofs_destage_dirty_nodes(task->corefs);
}

static bool need_flush(const struct silofs_task_ctx *task, int flags)
{
	bool ret = false;

	if (flags & SILOFS_CTLF_IDLE) {
		ret = true;
	} else {
		const uint32_t mempress = silofs_mempress(task->corefs->alloc);

		if (flags & (SILOFS_CTLF_OPSTART | SILOFS_CTLF_INTERN)) {
			ret = (mempress > 25);
		} else {
			ret = (mempress > 50);
		}
	}
	return ret;
}

int silofs_try_flush_dirty(const struct silofs_task_ctx *task, int flags)
{
	int ret = 0;

	if (need_flush(task, flags)) {
		ret = silofs_flush_dirty_now(task);
	}
	return ret;
}
