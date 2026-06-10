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

static void
vaddr_of(const struct silofs_vnode_info *vni, struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr_assign(out_vaddr, silofs_vni_vaddr(vni));
}

static void vni_markdirty(struct silofs_vnode_info *vni)
{
	silofs_vni_markdirty(vni, nullptr);
}

int silofs_probe_vnode2(struct silofs_pexec_ctx *pexec,
                        const struct silofs_vaddr *vaddr)
{
	struct silofs_pnptr pnptr;

	return silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);
}

int silofs_fetch_vnode2(struct silofs_pexec_ctx *pexec,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	err = silofs_stage_vnode2(pexec, vaddr, &pnptr, out_vni);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	return 0;
}

static int carve_vtop_mapping(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_pnptr *out_pnptr)
{
	int err;

	err = silofs_carve_next_vspace(pexec, vaddr->vtype, out_pnptr);
	if (err) {
		return err;
	}
	err = silofs_create_vtop_mapping(pexec, vaddr, out_pnptr);
	if (err) {
		return err;
	}
	return 0;
}

static int carve_spawn_vnode2_at(struct silofs_pexec_ctx *pexec,
                                 const struct silofs_vaddr *vaddr,
                                 struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = carve_vtop_mapping(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode2(pexec, vaddr, &pnptr, out_vni);
	if (err) {
		return err;
	}
	vni_markdirty(*out_vni);
	return 0;
}

int silofs_create_vnode2(struct silofs_pexec_ctx *pexec,
                         enum silofs_vtype vtype,
                         struct silofs_vnode_info **out_vni)
{
	struct silofs_vaddr vaddr;
	int err;

	err = silofs_claim_free_vspace(pexec, vtype, &vaddr);
	if (err) {
		return err;
	}
	err = carve_spawn_vnode2_at(pexec, &vaddr, out_vni);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_carve_vnode2_space(struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype vtype,
                              struct silofs_vaddr *out_vaddr)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_claim_free_vspace(pexec, vtype, out_vaddr);
	if (err) {
		return err;
	}
	err = carve_vtop_mapping(pexec, out_vaddr, &pnptr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void retain_free_vspace(struct silofs_pexec_ctx *pexec,
                               const struct silofs_vaddr *vaddr)
{
	silofs_vspmaps_push(pexec->vspmaps, vaddr);
}

static int reclaim_vnode2_at(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_pnptr pnptr;
	struct silofs_vspace_ref vspref;
	int err;

	err = silofs_probe_vspace_ref(pexec, vaddr, &vspref);
	if (err) {
		return err;
	}
	if (vspref.refcnt > 1) {
		goto reclaim; /* dec-ref only */
	}
	err = silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_detach_vnode2(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_remove_vtop_mapping(pexec, vaddr);
	if (err) {
		return err;
	}
	retain_free_vspace(pexec, vaddr);
reclaim:
	err = silofs_update_used_vspace(pexec, vaddr, true);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_reclaim_vnode2(struct silofs_pexec_ctx *pexec,
                          struct silofs_vnode_info *vni)
{
	struct silofs_vaddr vaddr;

	vaddr_of(vni, &vaddr);
	return silofs_reclaim_vnode2_at(pexec, &vaddr);
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
	if (vni != nullptr) {
		silofs_vcache_forget_vnode(pexec->vcache, vni);
	}
}

int silofs_reclaim_vnode2_at(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni;
	int err;

	vni = lookup_cached_vni(pexec, vaddr);
	err = reclaim_vnode2_at(pexec, vaddr);
	if (err) {
		return err;
	}
	forget_cached_vni(pexec, vni);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int claim_spawn_spnode2_at(struct silofs_pexec_ctx *pexec,
                                  const struct silofs_vaddr *vaddr,
                                  const struct silofs_vaddr *ref_vaddr,
                                  struct silofs_space_info **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = carve_spawn_vnode2_at(pexec, vaddr, &vni);
	if (err) {
		return err;
	}
	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_spawned(*out_spi, ref_vaddr);
	return 0;
}

static int resolve_stage_spnode2_at(struct silofs_pexec_ctx *pexec,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_space_info **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_fetch_vnode2(pexec, vaddr, &vni);
	if (err) {
		return err;
	}
	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_staged(*out_spi);
	return 0;
}

int silofs_fetch_spnode2_of(struct silofs_pexec_ctx *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_space_info **out_spi)
{
	struct silofs_vaddr vaddr;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);
	return resolve_stage_spnode2_at(pexec, &vaddr, out_spi);
}

static int
test_vtop_mapping(struct silofs_pexec_ctx *pexec,
                  const struct silofs_vaddr *vaddr, bool *out_exists)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_vtop_mapping(pexec, vaddr, &pnptr);

	*out_exists = (err == 0);
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

int silofs_require_spnode2_of(struct silofs_pexec_ctx *pexec,
                              const struct silofs_vaddr *ref_vaddr,
                              struct silofs_space_info **out_spi)
{
	struct silofs_vaddr vaddr;
	int err;
	bool exists;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);
	err = test_vtop_mapping(pexec, &vaddr, &exists);
	if (!err) {
		if (exists) {
			err = resolve_stage_spnode2_at(pexec, &vaddr, out_spi);
		} else {
			err = claim_spawn_spnode2_at(pexec, &vaddr, ref_vaddr,
			                             out_spi);
		}
	}
	return err;
}
