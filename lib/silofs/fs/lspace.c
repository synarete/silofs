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

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>

static int resolve_spnode_mapping(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr *laddr,
                                  struct silofs_pnptr *out_pnptr)
{
	silofs_assert_eq(laddr->ltype, SILOFS_LTYPE_SPNODE);

	return silofs_resolve_ltop_mapping(&task->pexec, laddr, out_pnptr);
}

static int stage_spnode_with(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *laddr,
                             const struct silofs_pnptr *pnptr,
                             struct silofs_spnode_info **out_spi)
{
	constexpr enum silofs_lspacef lspf = SILOFS_LSPACEF_NONE;
	struct silofs_lnode_info *lni      = nullptr;
	int err;

	err = silofs_stage_lnode_with(&task->pexec, laddr, pnptr, lspf, &lni);
	return_if_err(err);

	*out_spi = silofs_spi_from_lni(lni);
	silofs_spi_setup_staged(*out_spi);

	return 0;
}

static int stage_spnode_at(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_pnptr pnptr;
	int err;

	err = resolve_spnode_mapping(task, laddr, &pnptr);
	return_if_err(err);

	err = stage_spnode_with(task, laddr, &pnptr, out_spi);
	return_if_err(err);

	return 0;
}

static int stage_spnode_by(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *ref_laddr,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	return stage_spnode_at(task, &laddr, out_spi);
}

static int probe_lspace_ref(const struct silofs_task_ctx *task,
                            const struct silofs_laddr *ref_laddr,
                            struct silofs_lspace_ref *out_lspref)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = stage_spnode_by(task, ref_laddr, &spi);
	return_if_err(err);

	silofs_spi_lspace_ref(spi, ref_laddr, out_lspref);
	return 0;
}

static int check_lspace_ref(const struct silofs_laddr *ref_laddr,
                            const struct silofs_lspace_ref *lspref,
                            size_t refcnt_min, size_t refcnt_max)
{
	if ((lspref->refcnt < refcnt_min) || (lspref->refcnt > refcnt_max)) {
		log_err("illegal lspace ref: ltype=%d off=%zd refcnt=%zu",
		        ref_laddr->ltype, ref_laddr->off, lspref->refcnt);
		return -SILOFS_EBUG;
	}
	return 0;
}

#define REFCNT_MAX (UINT64_MAX >> 4)

static int probe_check_lspace_ref(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr *ref_laddr,
                                  struct silofs_lspace_ref *out_lspref)
{
	int err;

	err = probe_lspace_ref(task, ref_laddr, out_lspref);
	return_if_err(err);

	err = check_lspace_ref(ref_laddr, out_lspref, 0, REFCNT_MAX);
	return_if_err(err);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_mark_unwritten_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *ref_laddr)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = stage_spnode_by(task, ref_laddr, &spi);
	return_if_err(err);

	silofs_spi_mark_unwritten(spi, ref_laddr);
	return 0;
}

int silofs_clear_unwritten_at(const struct silofs_task_ctx *task,
                              const struct silofs_laddr *ref_laddr)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = stage_spnode_by(task, ref_laddr, &spi);
	return_if_err(err);

	silofs_spi_clear_unwritten(spi, ref_laddr);
	return 0;
}

int silofs_test_unwritten_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *ref_laddr,
                             bool *out_unwritten)
{
	struct silofs_lspace_ref lspref = {};
	int err;

	err = probe_check_lspace_ref(task, ref_laddr, &lspref);
	return_if_err(err);

	*out_unwritten = (lspref.flags & SILOFS_LSPACEF_UNWRITTEN) > 0;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_isshared_lnode_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *laddr, bool *out_res)
{
	struct silofs_lspace_ref lspref = {};
	int err;

	err = probe_check_lspace_ref(task, laddr, &lspref);
	return_if_err(err);

	*out_res = (lspref.refcnt > 1);
	return 0;
}

int silofs_share_lnode_at(const struct silofs_task_ctx *task,
                          const struct silofs_laddr *laddr)
{
	struct silofs_lspace_ref lspref;
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = stage_spnode_by(task, laddr, &spi);
	return_if_err(err);

	silofs_spi_lspace_ref(spi, laddr, &lspref);

	err = check_lspace_ref(laddr, &lspref, 1, REFCNT_MAX);
	return_if_err(err);

	silofs_spi_inc_allocated(spi, laddr);
	return 0;
}

int silofs_unshare_lnode_at(const struct silofs_task_ctx *task,
                            const struct silofs_laddr *laddr)
{
	struct silofs_lspace_ref lspref;
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = stage_spnode_by(task, laddr, &spi);
	return_if_err(err);

	silofs_spi_lspace_ref(spi, laddr, &lspref);

	err = check_lspace_ref(laddr, &lspref, 1, REFCNT_MAX);
	return_if_err(err);

	silofs_spi_dec_allocated(spi, laddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stage_spnode_of(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *ref_laddr,
                           enum silofs_stg_mode stg_mode,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	return silofs_stage_spnode_at(task, &laddr, stg_mode, out_spi);
}

static int spawn_spnode_of(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *ref_laddr,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;
	int err;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	err = silofs_spawn_spnode_at(task, &laddr, out_spi);
	return_if_err(err);

	silofs_spi_setup_spawned(*out_spi, ref_laddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
apex_laddr_of(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
              struct silofs_laddr *out_laddr)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = silofs_curr_sbi(task, &sbi);
	return_if_err(err);

	silofs_sbi_apex_of(sbi, ltype, out_laddr);
	return 0;
}

static void next_apex_laddr(struct silofs_laddr *ref_laddr)
{
	constexpr ssize_t nrefs  = SILOFS_SPNODE_NREFS;
	const ssize_t ltype_size = silofs_ltype_ssize(ref_laddr->ltype);

	ref_laddr->off = silofs_off_next(ref_laddr->off, ltype_size * nrefs);
}

static int update_apex_laddr(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *laddr)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = silofs_curr_sbi(task, &sbi);
	return_if_err(err);

	silofs_sbi_update_apex(sbi, laddr);
	return 0;
}

static int
claim_free_by_lspool(const struct silofs_task_ctx *task,
                     enum silofs_ltype ltype, struct silofs_laddr *out_laddr)
{
	struct silofs_lspace_ref lspref;
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = silofs_lspools_pull(task->lspools, ltype, out_laddr);
	return_if_err(err);

	err = stage_spnode_by(task, out_laddr, &spi);
	return_if_err(err);

	silofs_spi_lspace_ref(spi, out_laddr, &lspref);

	err = check_lspace_ref(out_laddr, &lspref, 0, 0);
	return_if_err(err);

	silofs_spi_inc_allocated(spi, out_laddr);
	return 0;
}

static int claim_free_by_ref(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *ref_laddr,
                             struct silofs_laddr *out_laddr)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = stage_spnode_of(task, ref_laddr, SILOFS_STG_CUR, &spi);
	return_if_err(err);

	err = silofs_spi_find_free(spi, out_laddr);
	return_if_err(err);

	silofs_spi_inc_allocated(spi, out_laddr);
	return 0;
}

static int
claim_free_by_apex(const struct silofs_task_ctx *task, enum silofs_ltype ltype,
                   struct silofs_laddr *out_laddr)
{
	struct silofs_laddr ref_laddr;
	int err;

	err = apex_laddr_of(task, ltype, &ref_laddr);
	return_if_err(err);

	err = claim_free_by_ref(task, &ref_laddr, out_laddr);
	return_if_err(err);

	return 0;
}

static int
advance_free_apex(const struct silofs_task_ctx *task, enum silofs_ltype ltype)
{
	struct silofs_laddr ref_laddr;
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = apex_laddr_of(task, ltype, &ref_laddr);
	return_if_err(err);

	next_apex_laddr(&ref_laddr);

	err = spawn_spnode_of(task, &ref_laddr, &spi);
	return_if_err(err);

	err = update_apex_laddr(task, &ref_laddr);
	return_if_err(err);

	return 0;
}

/*
 * TODO-0065: Define niter limit based on available space.
 *
 * Try to consume free space based of actual usage and total file-system size.
 * Define proper formula and derive 'niter' accordingly.
 */
static int
claim_free_by_spnode(const struct silofs_task_ctx *task,
                     enum silofs_ltype ltype, struct silofs_laddr *out_laddr)
{
	constexpr size_t niter = 1024;
	int err;

	for (size_t i = 0; i < niter; ++i) {
		err = claim_free_by_apex(task, ltype, out_laddr);
		if (err != -SILOFS_ENOSPC) {
			break; /* OK or I/O error */
		}
		err = advance_free_apex(task, ltype);
		if (err) {
			break;
		}
	}
	return err;
}

int silofs_claim_free_lspace(const struct silofs_task_ctx *task,
                             enum silofs_ltype ltype,
                             struct silofs_laddr *out_laddr)
{
	int err;

	/* fast: try to allocated from in-memory pool */
	err = claim_free_by_lspool(task, ltype, out_laddr);
	goto_out_if_not_err(err);

	/* slow: try to allocate using space-mapping nodes */
	err = claim_free_by_spnode(task, ltype, out_laddr);
	goto_out_if_not_err(err);

	/* failure */
	log_err("failed to claim free space: ltype=%d err=%d", ltype, err);
out:
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_stage_apex_spnode_of(const struct silofs_task_ctx *task,
                                enum silofs_ltype ltype,
                                struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr apex_laddr;
	int err;

	err = apex_laddr_of(task, ltype, &apex_laddr);
	return_if_err(err);

	err = stage_spnode_of(task, &apex_laddr, SILOFS_STG_CUR, out_spi);
	return_if_err(err);

	return 0;
}

int silofs_spawn_apex_spnode_of(const struct silofs_task_ctx *task,
                                enum silofs_ltype ltype,
                                struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr apex_laddr;
	int err;

	err = apex_laddr_of(task, ltype, &apex_laddr);
	return_if_err(err);

	err = spawn_spnode_of(task, &apex_laddr, out_spi);
	return_if_err(err);

	return 0;
}
