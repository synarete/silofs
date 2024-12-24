/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/types.h>

struct silofs_spnode_info;

struct silofs_spmap_lmap {
	struct silofs_laddr laddr[SILOFS_SPMAP_NCHILDS];
	uint32_t            cnt;
};

void silofs_bk_state_init(struct silofs_bk_state *bk_st);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

loff_t silofs_sni_base_voff(const struct silofs_spnode_info *sni);

enum silofs_height silofs_sni_height(const struct silofs_spnode_info *sni);

const struct silofs_ulink *
silofs_sni_ulink(const struct silofs_spnode_info *sni);

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni);

void silofs_sni_incref(struct silofs_spnode_info *sni);

void silofs_sni_decref(struct silofs_spnode_info *sni);

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni,
                              const struct silofs_uaddr *parent, loff_t voff);

void silofs_sni_update_nactive(struct silofs_spnode_info *sni);

void silofs_sni_clone_from(struct silofs_spnode_info       *sni,
                           const struct silofs_spnode_info *sni_other);

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_vrange            *vrange);

void silofs_sni_active_vrange(const struct silofs_spnode_info *sni,
                              struct silofs_vrange            *out_vrange);

void silofs_sni_main_lseg(const struct silofs_spnode_info *sni,
                          struct silofs_lsid              *out_lsid);

void silofs_sni_bind_main_lseg(struct silofs_spnode_info *sni,
                               const struct silofs_lsid  *lsid);

void silofs_sni_resolve_main(const struct silofs_spnode_info *sni, loff_t voff,
                             struct silofs_ulink *out_ulink);

void silofs_sni_bind_child(struct silofs_spnode_info *sni, loff_t voff,
                           const struct silofs_ulink *ulink);

int silofs_sni_resolve_child(const struct silofs_spnode_info *sni, loff_t voff,
                             struct silofs_ulink *out_ulink);

void silofs_sni_resolve_lmap(const struct silofs_spnode_info *sni,
                             struct silofs_spmap_lmap        *out_lmap);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_ulink *
silofs_sli_ulink(const struct silofs_spleaf_info *sli);

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli);

void silofs_sli_incref(struct silofs_spleaf_info *sli);

void silofs_sli_decref(struct silofs_spleaf_info *sli);

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_uaddr *parent, loff_t voff);

void silofs_sli_update_nused(struct silofs_spleaf_info *sli);

void silofs_sli_vspace_range(const struct silofs_spleaf_info *sli,
                             struct silofs_vrange            *out_vrange);

loff_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli);

int silofs_sli_find_free_space(const struct silofs_spleaf_info *sli,
                               loff_t voff_from, enum silofs_ltype ltype,
                               struct silofs_vaddr *out_vaddr);

void silofs_sli_mark_allocated_space(struct silofs_spleaf_info *sli,
                                     const struct silofs_vaddr *vaddr);

void silofs_sli_reref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr);

void silofs_sli_unref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr);

bool silofs_sli_has_allocated_space(const struct silofs_spleaf_info *sli,
                                    const struct silofs_vaddr       *vaddr);

bool silofs_sli_has_allocated_with(const struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr       *vaddr);

bool silofs_sli_is_last_allocated(const struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr       *vaddr);

bool silofs_sli_has_unwritten_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr       *vaddr);

void silofs_sli_clear_unwritten_at(struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr *vaddr);

void silofs_sli_mark_unwritten_at(struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr);

size_t silofs_sli_dbkref_at(const struct silofs_spleaf_info *sli,
                            const struct silofs_vaddr       *vaddr);

void silofs_sli_vaddrs_at(const struct silofs_spleaf_info *sli,
                          enum silofs_ltype ltype, silofs_lba_t lba,
                          struct silofs_vaddrs *vas);

void silofs_sli_main_lseg(const struct silofs_spleaf_info *sli,
                          struct silofs_lsid              *out_lsid);

void silofs_sli_bind_main_lseg(struct silofs_spleaf_info *sli,
                               const struct silofs_lsid  *lsid);

void silofs_sli_clone_from(struct silofs_spleaf_info       *sli,
                           const struct silofs_spleaf_info *sli_other);

void silofs_sli_resolve_main_lbk(const struct silofs_spleaf_info *sli,
                                 loff_t voff, struct silofs_llink *out_llink);

void silofs_sli_bind_child(struct silofs_spleaf_info *sli, loff_t voff,
                           const struct silofs_llink *llink);

int silofs_sli_resolve_child(const struct silofs_spleaf_info *sli, loff_t voff,
                             struct silofs_llink *out_llink);

void silofs_sli_resolve_lmap(const struct silofs_spleaf_info *sli,
                             struct silofs_spmap_lmap        *out_lmaps);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn);

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl);

#endif /* SILOFS_SPMAPS_H_ */
