/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_SPMAPS_H_
#define SILOFS_SPMAPS_H_

#include <silofs/defs.h>
#include "addr/laddr.h"

struct silofs_spnode_info;

struct silofs_spmap_lmap {
	struct silofs_laddr laddr[SILOFS_SPMAP_NCHILDS];
	size_t              len[SILOFS_SPMAP_NCHILDS];
	uint32_t            cnt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

loff_t silofs_sni_base_voff(const struct silofs_spnode_info *sni);

enum silofs_height silofs_sni_height(const struct silofs_spnode_info *sni);

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni);

const struct silofs_laddr *
silofs_sni_laddr(const struct silofs_spnode_info *sni);

void silofs_sni_incref(struct silofs_spnode_info *sni);

void silofs_sni_decref(struct silofs_spnode_info *sni);

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni,
                              const struct silofs_uaddr *parent, loff_t voff);

void silofs_sni_update_nactive(struct silofs_spnode_info *sni);

void silofs_sni_clone_from(struct silofs_spnode_info       *sni,
                           const struct silofs_spnode_info *sni_other);

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_lrange            *lrange);

void silofs_sni_active_lrange(const struct silofs_spnode_info *sni,
                              struct silofs_lrange            *out_lrange);

void silofs_sni_main_lseg(const struct silofs_spnode_info *sni,
                          struct silofs_lsid              *out_lsid);

void silofs_sni_bind_main_lseg(struct silofs_spnode_info *sni,
                               const struct silofs_lsid  *lsid);

void silofs_sni_resolve_main(const struct silofs_spnode_info *sni, loff_t voff,
                             struct silofs_uaddr *out_uaddr);

void silofs_sni_bind_child(struct silofs_spnode_info *sni, loff_t voff,
                           const struct silofs_uaddr *uaddr);

int silofs_sni_resolve_child(const struct silofs_spnode_info *sni, loff_t voff,
                             struct silofs_uaddr *out_uaddr);

void silofs_sni_resolve_lmap(const struct silofs_spnode_info *sni,
                             struct silofs_spmap_lmap        *out_lmap);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_laddr *
silofs_sli_laddr(const struct silofs_spleaf_info *sli);

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli);

enum silofs_ltype silofs_sli_refltype(const struct silofs_spleaf_info *sli);

void silofs_sli_incref(struct silofs_spleaf_info *sli);

void silofs_sli_decref(struct silofs_spleaf_info *sli);

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_uaddr *parent,
                              enum silofs_ltype refltype, loff_t voff);

void silofs_sli_update_nused(struct silofs_spleaf_info *sli);

void silofs_sli_get_lrange(const struct silofs_spleaf_info *sli,
                           struct silofs_lrange            *out_lrange);

loff_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli);

void silofs_sli_update_off_hint(struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr);

void silofs_sli_mark_allocated_at(struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr);

void silofs_sli_reref_allocated_at(struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr *vaddr);

void silofs_sli_unref_allocated_at(struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr *vaddr);

bool silofs_sli_has_allocated_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr       *vaddr);

bool silofs_sli_has_allocated_with(const struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr       *vaddr);

void silofs_sli_vaddrs_at(const struct silofs_spleaf_info *sli,
                          const struct silofs_vaddr       *vaddr,
                          struct silofs_vaddrs            *out_vaddrs);

void silofs_sli_lbk_vaddrs_at(const struct silofs_spleaf_info *sli,
                              const struct silofs_vaddr       *vaddr,
                              struct silofs_vaddrs            *out_vaddrs);

void silofs_sli_main_lseg(const struct silofs_spleaf_info *sli,
                          struct silofs_lsid              *out_lsid);

void silofs_sli_bind_main_lseg(struct silofs_spleaf_info *sli,
                               const struct silofs_lsid  *lsid);

void silofs_sli_bind_child(struct silofs_spleaf_info *sli, loff_t voff,
                           const struct silofs_laddr *laddr);

void silofs_sli_clone_from(struct silofs_spleaf_info       *sli,
                           const struct silofs_spleaf_info *sli_other);

int silofs_sli_resolve_main_lbk(const struct silofs_spleaf_info *sli,
                                loff_t voff, struct silofs_laddr *out_laddr);

bool silofs_sli_has_child_lbk_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr       *vaddr);

int silofs_sli_resolve_child(const struct silofs_spleaf_info *sli, loff_t voff,
                             struct silofs_laddr *out_laddr);

int silofs_sli_require_child(struct silofs_spleaf_info *sli,
                             const struct silofs_vaddr *vaddr, bool *out_new);

void silofs_sli_resolve_lmap(const struct silofs_spleaf_info *sli,
                             struct silofs_spmap_lmap        *out_lmaps);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn);

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl);

#endif /* SILOFS_SPMAPS_H_ */
