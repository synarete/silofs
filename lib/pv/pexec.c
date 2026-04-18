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

static void vni_markdirty(struct silofs_vnode_info *vni)
{
	silofs_vni_markdirty(vni, nullptr);
}

int silofs_spawn_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_carve_next_vspace(pexec, vaddr->vtype, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode2(pexec, vaddr, &pnptr, out_vni);
	if (err) {
		return err;
	}
	err = silofs_insert_vtop(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	vni_markdirty(*out_vni);
	return 0;
}

int silofs_stage_vnode2_at(struct silofs_pexec_ctx *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_vtop(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_stage_vnode2(pexec, vaddr, &pnptr, out_vni);
	if (err) {
		return err;
	}
	return 0;
}

static int
test_vtop_mapping(struct silofs_pexec_ctx *pexec,
                  const struct silofs_vaddr *vaddr, bool *out_exists)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_vtop(pexec, vaddr, &pnptr);

	*out_exists = (err == 0);
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

int silofs_require_vnode2_at(struct silofs_pexec_ctx *pexec,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_vnode_info **out_vni)
{
	int err;
	bool exists;

	err = test_vtop_mapping(pexec, vaddr, &exists);
	if (!err) {
		if (exists) {
			err = silofs_stage_vnode2_at(pexec, vaddr, out_vni);
		} else {
			err = silofs_spawn_vnode2_at(pexec, vaddr, out_vni);
		}
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int silofs_spawn_spnode2_at(struct silofs_pexec_ctx *pexec,
                                   const struct silofs_vaddr *vaddr,
                                   const struct silofs_vaddr *ref_vaddr,
                                   struct silofs_space_info **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_spawn_vnode2_at(pexec, vaddr, &vni);
	if (err) {
		return err;
	}
	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_spawned(*out_spi, ref_vaddr);
	return 0;
}

static int silofs_stage_spnode2_at(struct silofs_pexec_ctx *pexec,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_space_info **out_spi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_stage_vnode2_at(pexec, vaddr, &vni);
	if (err) {
		return err;
	}
	*out_spi = silofs_spi_from_vni(vni);
	silofs_spi_setup_staged(*out_spi);
	return 0;
}

int silofs_stage_spnode2_of(struct silofs_pexec_ctx *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_space_info **out_spi)
{
	struct silofs_vaddr vaddr;

	silofs_resolve_spnode2_vaddr(ref_vaddr, &vaddr);
	return silofs_stage_spnode2_at(pexec, &vaddr, out_spi);
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
			err = silofs_stage_spnode2_at(pexec, &vaddr, out_spi);
		} else {
			err = silofs_spawn_spnode2_at(pexec, &vaddr, ref_vaddr,
			                              out_spi);
		}
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_detach_vnode2_at(struct silofs_pexec_ctx *pexec,
                            const struct silofs_vaddr *vaddr)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_vtop(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_detach_vnode2(pexec, vaddr, &pnptr);
	if (err) {
		return err;
	}
	err = silofs_remove_vtop(pexec, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_detach_forget_vnode2(struct silofs_pexec_ctx *pexec,
                                struct silofs_vnode_info *vni)
{
	const struct silofs_vaddr *vaddr;
	int err;

	vaddr = silofs_vni_vaddr(vni);
	err   = silofs_detach_vnode2_at(pexec, vaddr);
	if (err) {
		return err;
	}
	silofs_vcache_forget_vnode(pexec->vcache, vni);
	return 0;
}
