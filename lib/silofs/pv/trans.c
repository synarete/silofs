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
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>

static void vni_setdirty(struct silofs_vnode_info *vni)
{
	silofs_vni_setdirty(vni, nullptr);
}

int silofs_probe_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_pnptr pnptr;

	return silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);
}

static bool uses_spmap(const struct silofs_vaddr *vaddr)
{
	return silofs_vtype_usespmap(vaddr->vtype);
}

static int resolve_spacef_of(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_spacef *out_spacef)
{
	struct silofs_vspace_ref vspref = {
		.flags = SILOFS_SPACEF_NONE,
	};
	int ret = 0;

	if (uses_spmap(vaddr)) {
		ret = silofs_probe_vspace_ref(pexec, vaddr, &vspref);
	}
	*out_spacef = vspref.flags;
	return ret;
}

int silofs_stage_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr;
	enum silofs_spacef spacef;
	int err;

	err = silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);
	return_if_err(err);

	err = resolve_spacef_of(pexec, vaddr, &spacef);
	return_if_err(err);

	err = silofs_stage_vnode2_with(pexec, vaddr, &pnptr, spacef, out_vni);
	return_if_err(err);

	return 0;
}

static int carve_vtop_mapping(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_pnptr *out_pnptr)
{
	int err;

	err = silofs_carve_vspace(pexec, vaddr->vtype, out_pnptr);
	return_if_err(err);

	err = silofs_require_paddr(pexec, &out_pnptr->paddr);
	return_if_err(err);

	err = silofs_create_vtop_mapping(pexec, vaddr, out_pnptr);
	return_if_err(err);

	return 0;
}

int silofs_spawn_vnode2(struct silofs_pexec_ctx *pexec,
                        enum silofs_vtype vtype,
                        struct silofs_vnode_info **out_vni)
{
	struct silofs_vaddr vaddr;
	int err;

	err = silofs_claim_free_vspace(pexec, vtype, &vaddr);
	return err ? err : silofs_spawn_vnode2_at(pexec, &vaddr, out_vni);
}

int silofs_spawn_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = carve_vtop_mapping(pexec, vaddr, &pnptr);
	return_if_err(err);

	err = silofs_spawn_vnode2_with(pexec, vaddr, &pnptr, out_vni);
	return_if_err(err);

	vni_setdirty(*out_vni);
	return 0;
}

int silofs_claim_vnode2_space(struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype vtype,
                              struct silofs_vaddr *out_vaddr)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_claim_free_vspace(pexec, vtype, out_vaddr);
	return_if_err(err);

	err = carve_vtop_mapping(pexec, out_vaddr, &pnptr);
	return_if_err(err);

	err = silofs_claim_vnode2_space2(pexec, out_vaddr, &pnptr);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void retain_free_space(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *vaddr,
                              const struct silofs_paddr *paddr)
{
	silofs_freevsqs_push(pexec->fvsqs, vaddr);
	silofs_freepaqs_push(pexec->fpaqs, paddr);
}

static int incref_used_vspace(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *vaddr)
{
	return silofs_update_used_vspace(pexec, vaddr, true);
}

static int decref_used_vspace(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *vaddr)
{
	return silofs_update_used_vspace(pexec, vaddr, false);
}

static int reclaim_vnode2_at(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr, bool *out_last)
{
	struct silofs_pnptr pnptr;
	struct silofs_vspace_ref vspref;
	int err;

	err = silofs_probe_vspace_ref(pexec, vaddr, &vspref);
	return_if_err(err);

	silofs_assert_gt(vspref.refcnt, 0);

	*out_last = (vspref.refcnt == 1);
	if (*out_last == false) {
		silofs_assert(silofs_vaddr_isdata(vaddr));
		goto out; /* shared data node: dec-ref only */
	}

	err = silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);
	return_if_err(err);

	err = silofs_detach_vnode2_at(pexec, vaddr, &pnptr);
	return_if_err(err);

	err = silofs_remove_vtop_mapping(pexec, vaddr);
	return_if_err(err);

	retain_free_space(pexec, vaddr, &pnptr.paddr);
out:
	return decref_used_vspace(pexec, vaddr);
}

static struct silofs_vnode_info *
lookup_cached_vni(struct silofs_pexec_ctx *pexec,
                  const struct silofs_vaddr *vaddr)
{
	return silofs_vcache_lookup_vnode(pexec->vcache, vaddr);
}

static void forget_cached_vni(struct silofs_pexec_ctx *pexec,
                              struct silofs_vnode_info *vni)
{
	silofs_vcache_forget_vnode(pexec->vcache, vni);
}

static void try_forget_cached_vni(struct silofs_pexec_ctx *pexec,
                                  struct silofs_vnode_info *vni)
{
	/*
	 * Special case where data-node has been unmapped due to forget, yet it
	 * still has a live ref-count due to on-going I/O operation.
	 */
	if ((vni != nullptr) && !silofs_vni_refcnt(vni)) {
		forget_cached_vni(pexec, vni);
	}
}

int silofs_reclaim_vnode2_at(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr, bool *out_last)
{
	struct silofs_vnode_info *vni;
	int err;

	vni = lookup_cached_vni(pexec, vaddr);
	err = reclaim_vnode2_at(pexec, vaddr, out_last);
	if (!err && *out_last) {
		try_forget_cached_vni(pexec, vni);
	}
	return err;
}

int silofs_isshared_vnode2_at(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_vspace_ref vspref;
	int err;

	err = silofs_probe_vspace_ref(pexec, vaddr, &vspref);
	return_if_err(err);

	*out_res = (vspref.refcnt > 1);
	return 0;
}

int silofs_share_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vspace_ref vspref;
	int err;

	err = silofs_probe_vspace_ref(pexec, vaddr, &vspref);
	return_if_err(err);

	err = incref_used_vspace(pexec, vaddr);
	return_if_err(err);

	return 0;
}

int silofs_unshare_vnode2_at(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr, bool *out_last)
{
	struct silofs_vspace_ref vspref;
	int err;

	err = silofs_probe_vspace_ref(pexec, vaddr, &vspref);
	return_if_err(err);

	err = reclaim_vnode2_at(pexec, vaddr, out_last);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int claim_spawn_spnode2_at(struct silofs_pexec_ctx *pexec,
                                  const struct silofs_vaddr *vaddr,
                                  const struct silofs_vaddr *ref_vaddr,
                                  struct silofs_spnode_info2 **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_spawn_vnode2_at(pexec, vaddr, &vni);
	return_if_err(err);

	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_spawned(*out_spi, ref_vaddr);
	return 0;
}

static int resolve_stage_spnode2_at(struct silofs_pexec_ctx *pexec,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_spnode_info2 **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_stage_vnode2_at(pexec, vaddr, &vni);
	return_if_err(err);

	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_staged(*out_spi);
	return 0;
}

int silofs_stage_spnode2_by(struct silofs_pexec_ctx *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_spnode_info2 **out_spi)
{
	struct silofs_vaddr vaddr;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);
	return resolve_stage_spnode2_at(pexec, &vaddr, out_spi);
}

int silofs_spawn_spnode2_by(struct silofs_pexec_ctx *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_spnode_info2 **out_spi)
{
	struct silofs_vaddr vaddr;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);
	return claim_spawn_spnode2_at(pexec, &vaddr, ref_vaddr, out_spi);
}

int silofs_test_vtop_mapping(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr,
                             bool *out_exists)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);

	*out_exists = (err == 0);
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

int silofs_require_spnode2_by(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *ref_vaddr,
                              struct silofs_spnode_info2 **out_spi)
{
	struct silofs_vaddr vaddr;
	int err;
	bool exists;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);
	err = silofs_test_vtop_mapping(pexec, &vaddr, &exists);
	if (!err) {
		if (exists) {
			err = resolve_stage_spnode2_at(pexec, &vaddr, out_spi);
		} else {
			err = claim_spawn_spnode2_at(pexec, &vaddr, //
			                             ref_vaddr, out_spi);
		}
	}
	return err;
}

int silofs_mark_unwritten_at2(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *ref_vaddr)
{
	struct silofs_spnode_info2 *spi = nullptr;
	int err;

	err = silofs_stage_spnode2_by(pexec, ref_vaddr, &spi);
	return_if_err(err);

	silofs_spi_mark_unwritten(spi, ref_vaddr);
	return 0;
}

int silofs_clear_unwritten_at2(struct silofs_pexec_ctx *pexec,
                               const struct silofs_vaddr *ref_vaddr)
{
	struct silofs_spnode_info2 *spi = nullptr;
	int err;

	err = silofs_stage_spnode2_by(pexec, ref_vaddr, &spi);
	return_if_err(err);

	silofs_spi_clear_unwritten(spi, ref_vaddr);
	return 0;
}

int silofs_test_unwritten_at2(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *ref_vaddr,
                              bool *out_unwritten)
{
	struct silofs_vspace_ref vspref = {};
	int err;

	err = silofs_probe_vspace_ref(pexec, ref_vaddr, &vspref);
	return_if_err(err);

	*out_unwritten = (vspref.flags & SILOFS_SPACEF_UNWRITTEN) > 0;
	return 0;
}
