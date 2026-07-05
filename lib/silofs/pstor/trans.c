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
#include <silofs/nodes.h>
#include <silofs/pstor.h>

static void lni_setdirty(struct silofs_lnode_info *lni)
{
	silofs_lni_setdirty(lni, nullptr);
}

int silofs_probe_lnode2_at(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr *laddr)
{
	struct silofs_pnptr pnptr;

	return silofs_resolve_ltop_mapping(pexec, laddr, &pnptr);
}

static bool uses_spmap(const struct silofs_laddr *laddr)
{
	return silofs_ltype_usespmap(laddr->ltype);
}

static int resolve_spacef_of(const struct silofs_pexec_ctx *pexec,
                             const struct silofs_laddr *laddr,
                             enum silofs_lspacef *out_spacef)
{
	struct silofs_lspace_ref vspref = {
		.flags = SILOFS_LSPACEF_NONE,
	};
	int ret = 0;

	if (uses_spmap(laddr)) {
		ret = silofs_probe_lspace_ref(pexec, laddr, &vspref);
	}
	*out_spacef = vspref.flags;
	return ret;
}

int silofs_stage_lnode_at(const struct silofs_pexec_ctx *pexec,
                          const struct silofs_laddr *laddr,
                          struct silofs_lnode_info **out_lni)
{
	struct silofs_pnptr pnptr;
	enum silofs_lspacef spacef;
	int err;

	err = silofs_resolve_ltop_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = resolve_spacef_of(pexec, laddr, &spacef);
	return_if_err(err);

	err = silofs_stage_lnode2_with(pexec, laddr, &pnptr, spacef, out_lni);
	return_if_err(err);

	return 0;
}

static int carve_ltop_mapping(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr *laddr,
                              struct silofs_pnptr *out_pnptr)
{
	int err;

	err = silofs_carve_vspace(pexec, laddr->ltype, out_pnptr);
	return_if_err(err);

	err = silofs_require_paddr(pexec, &out_pnptr->paddr);
	return_if_err(err);

	err = silofs_create_ltop_mapping(pexec, laddr, out_pnptr);
	return_if_err(err);

	return 0;
}

int silofs_spawn_lnode2(const struct silofs_pexec_ctx *pexec,
                        enum silofs_ltype ltype,
                        struct silofs_lnode_info **out_lni)
{
	struct silofs_laddr laddr;
	int err;

	err = silofs_claim_free_vspace(pexec, ltype, &laddr);
	return err ? err : silofs_spawn_lnode2_at(pexec, &laddr, out_lni);
}

int silofs_spawn_lnode2_at(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr *laddr,
                           struct silofs_lnode_info **out_lni)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = carve_ltop_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_spawn_lnode2_with(pexec, laddr, &pnptr, out_lni);
	return_if_err(err);

	lni_setdirty(*out_lni);
	return 0;
}

int silofs_claim_lnode2_space(const struct silofs_pexec_ctx *pexec,
                              enum silofs_ltype ltype,
                              struct silofs_laddr *out_laddr)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_claim_free_vspace(pexec, ltype, out_laddr);
	return_if_err(err);

	err = carve_ltop_mapping(pexec, out_laddr, &pnptr);
	return_if_err(err);

	err = silofs_claim_lnode2_space2(pexec, out_laddr, &pnptr);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void retain_free_space(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr *laddr,
                              const struct silofs_paddr *paddr)
{
	silofs_lspools_push(pexec->lspools, laddr);
	silofs_pspools_push(pexec->pspools, paddr);
}

static int decref_used_vspace(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr *laddr)
{
	return silofs_update_used_vspace(pexec, laddr, false);
}

static int reclaim_lnode_at(const struct silofs_pexec_ctx *pexec,
                            const struct silofs_laddr *laddr, bool *out_last)
{
	struct silofs_pnptr pnptr;
	struct silofs_lspace_ref vspref;
	int err;

	err = silofs_probe_lspace_ref(pexec, laddr, &vspref);
	return_if_err(err);

	silofs_assert_gt(vspref.refcnt, 0);

	*out_last = (vspref.refcnt == 1);
	if (*out_last == false) {
		silofs_assert(silofs_laddr_isdata(laddr));
		goto out; /* shared data node: dec-ref only */
	}

	err = silofs_resolve_ltop_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_detach_lnode2_at(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_remove_ltop_mapping(pexec, laddr);
	return_if_err(err);

	retain_free_space(pexec, laddr, &pnptr.paddr);
out:
	return decref_used_vspace(pexec, laddr);
}

static struct silofs_lnode_info *
lookup_cached_lni(const struct silofs_pexec_ctx *pexec,
                  const struct silofs_laddr *laddr)
{
	return silofs_lcache_lookup_lnode(pexec->lcache, laddr);
}

static void forget_cached_lni(const struct silofs_pexec_ctx *pexec,
                              struct silofs_lnode_info *lni)
{
	silofs_lcache_forget_lnode(pexec->lcache, lni);
}

static void try_forget_cached_lni(const struct silofs_pexec_ctx *pexec,
                                  struct silofs_lnode_info *lni)
{
	/*
	 * Special case where data-node has been unmapped due to forget, yet it
	 * still has a live ref-count due to on-going I/O operation.
	 */
	if ((lni != nullptr) && !silofs_lni_refcnt(lni)) {
		forget_cached_lni(pexec, lni);
	}
}

int silofs_reclaim_lnode2_at(const struct silofs_pexec_ctx *pexec,
                             const struct silofs_laddr *laddr, bool *out_last)
{
	struct silofs_lnode_info *lni;
	int err;

	lni = lookup_cached_lni(pexec, laddr);
	err = reclaim_lnode_at(pexec, laddr, out_last);
	if (!err && *out_last) {
		try_forget_cached_lni(pexec, lni);
	}
	return err;
}

int silofs_unshare_lnode2_at(const struct silofs_pexec_ctx *pexec,
                             const struct silofs_laddr *laddr, bool *out_last)
{
	struct silofs_lspace_ref vspref;
	int err;

	err = silofs_probe_lspace_ref(pexec, laddr, &vspref);
	return_if_err(err);

	err = reclaim_lnode_at(pexec, laddr, out_last);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int claim_spawn_spnode2_at(const struct silofs_pexec_ctx *pexec,
                                  const struct silofs_laddr *laddr,
                                  const struct silofs_laddr *ref_laddr,
                                  struct silofs_spnode_info **out_spi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = silofs_spawn_lnode2_at(pexec, laddr, &lni);
	return_if_err(err);

	*out_spi = silofs_spi_from_lni(lni);
	silofs_spi_setup_spawned(*out_spi, ref_laddr);
	return 0;
}

static int resolve_stage_spnode2_at(const struct silofs_pexec_ctx *pexec,
                                    const struct silofs_laddr *laddr,
                                    struct silofs_spnode_info **out_spi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = silofs_stage_lnode_at(pexec, laddr, &lni);
	return_if_err(err);

	*out_spi = silofs_spi_from_lni(lni);
	silofs_spi_setup_staged(*out_spi);
	return 0;
}

int silofs_stage_spnode_by(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr *ref_laddr,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	return resolve_stage_spnode2_at(pexec, &laddr, out_spi);
}

int silofs_spawn_spnode2_by(const struct silofs_pexec_ctx *pexec,
                            const struct silofs_laddr *ref_laddr,
                            struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	return claim_spawn_spnode2_at(pexec, &laddr, ref_laddr, out_spi);
}

static int
test_ltop_mapping(const struct silofs_pexec_ctx *pexec,
                  const struct silofs_laddr *laddr, bool *out_exists)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_ltop_mapping(pexec, laddr, &pnptr);

	*out_exists = (err == 0);
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

int silofs_require_spnode2_by(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr *ref_laddr,
                              struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;
	int err;
	bool exists;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	err = test_ltop_mapping(pexec, &laddr, &exists);
	if (!err) {
		if (exists) {
			err = resolve_stage_spnode2_at(pexec, &laddr, out_spi);
		} else {
			err = claim_spawn_spnode2_at(pexec, &laddr, //
			                             ref_laddr, out_spi);
		}
	}
	return err;
}
