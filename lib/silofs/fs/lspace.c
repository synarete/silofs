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

static int stage_spnode_at(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = silofs_stage_lnode_at(&task->pexec, laddr, &lni);
	return_if_err(err);

	*out_spi = silofs_spi_from_lni(lni);
	silofs_spi_setup_staged(*out_spi);
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

static int
check_lspace_ref(const struct silofs_laddr *ref_laddr,
                 const struct silofs_lspace_ref *lspref, size_t refcnt_min)
{
	constexpr size_t refcnt_max = UINT64_MAX >> 4;

	if ((lspref->refcnt < refcnt_min) || (lspref->refcnt > refcnt_max)) {
		log_err("illegal lspace ref: ltype=%d off=%zd refcnt=%zu",
		        ref_laddr->ltype, ref_laddr->off, lspref->refcnt);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int probe_check_lspace_ref(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr *ref_laddr,
                                  struct silofs_lspace_ref *out_lspref)
{
	int err;

	err = probe_lspace_ref(task, ref_laddr, out_lspref);
	return_if_err(err);

	err = check_lspace_ref(ref_laddr, out_lspref, 0);
	return_if_err(err);

	return 0;
}

#if 0
static int decref_used_lspace(struct silofs_vspace_ctx *vs_ctx,
				  const struct silofs_laddr *ref_laddr)
{
	struct silofs_lspace_ref lspref;
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = stage_spnode_by(vs_ctx, laddr, &spi);
	return_if_err(err);

	silofs_spi_vspace_ref(spi, laddr, &lspref);

	err = check_lspace_ref(ref_laddr, out_lspref);
	return_if_err(err);

	silofs_spi_dec_allocated(spi, ref_laddr);
	return 0;
}
#endif

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

	err = check_lspace_ref(laddr, &lspref, 1);
	return_if_err(err);

	silofs_spi_inc_allocated(spi, laddr);
	return 0;
}
