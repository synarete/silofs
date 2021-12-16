/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

#include <silofs/fs/defs.h>
#include <silofs/fs/types.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_spr_initn(struct silofs_spmap_ref *spr, size_t n);


void silofs_spr_ulink(const struct silofs_spmap_ref *spr,
                      struct silofs_ulink *out_ulink);

void silofs_spr_set_ulink(struct silofs_spmap_ref *spr,
                          const struct silofs_ulink *ulink,
                          enum silofs_stype stype_sub);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

loff_t silofs_sni_base_voff(const struct silofs_spnode_info *sni);

loff_t silofs_sni_last_voff(const struct silofs_spnode_info *sni);

size_t silofs_sni_height(const struct silofs_spnode_info *sni);

size_t silofs_sni_child_height(const struct silofs_spnode_info *sni);

enum silofs_stype silofs_sni_child_stype(const struct silofs_spnode_info *sni);

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni);

void silofs_sni_incref(struct silofs_spnode_info *sni);

void silofs_sni_decref(struct silofs_spnode_info *sni);

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni, size_t height,
                              const struct silofs_vrange *vrange);

void silofs_sni_update_staged(struct silofs_spnode_info *sni);

void silofs_sni_update_nused(struct silofs_spnode_info *sni,
                             const struct silofs_vaddr *vaddr, int take);

void silofs_sni_clone_subrefs(struct silofs_spnode_info *sni,
                              const struct silofs_spnode_info *sni_other);

int silofs_sni_resolve_subref(const struct silofs_spnode_info *sni,
                              loff_t voff, struct silofs_ulink *out_ulink);

void silofs_sni_setup_parent(struct silofs_spnode_info *sni,
                             const struct silofs_unode_info *ui);

void silofs_sni_bind_child_spleaf(struct silofs_spnode_info *sni,
                                  const struct silofs_spleaf_info *sli);

void silofs_sni_bind_child_spnode(struct silofs_spnode_info *sni,
                                  const struct silofs_spnode_info *sni_child);

bool silofs_sni_has_child_at(const struct silofs_spnode_info *sni, loff_t off);

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_vrange *vrange);

void silofs_sni_formatted_vrange(const struct silofs_spnode_info *sni,
                                 struct silofs_vrange *out_vrange);

int silofs_sni_check_may_alloc(const struct silofs_spnode_info *sni,
                               const enum silofs_stype stype);

int silofs_sni_search_spleaf(const struct silofs_spnode_info *sni,
                             const struct silofs_vrange *range,
                             enum silofs_stype stype, loff_t *out_voff);

void silofs_sni_main_blob(const struct silofs_spnode_info *sni,
                          struct silofs_blobid *out_bid);

void silofs_sni_bind_main_blob(struct silofs_spnode_info *sni,
                               const struct silofs_blobid *bid);

bool silofs_sni_has_main_blob(const struct silofs_spnode_info *sni);

void silofs_sni_resolve_main_child(const struct silofs_spnode_info *sni,
                                   loff_t voff, struct silofs_uaddr *out_ua);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli);

void silofs_sli_incref(struct silofs_spleaf_info *sli);

void silofs_sli_decref(struct silofs_spleaf_info *sli);

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_vrange *vrange,
                              enum silofs_stype stype_sub);

void silofs_sli_setup_parent(struct silofs_spleaf_info *sli,
                             const struct silofs_spnode_info *sni);

void silofs_sli_update_staged(struct silofs_spleaf_info *sli);

void silofs_sli_update_voff_last(struct silofs_spleaf_info *sli, loff_t voff);

void silofs_sli_vspace_range(const struct silofs_spleaf_info *sli,
                             struct silofs_vrange *out_vrange);

enum silofs_stype silofs_sli_stype_sub(const struct silofs_spleaf_info *sli);

loff_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli);

loff_t silofs_sli_last_voff(const struct silofs_spleaf_info *sli);

int silofs_sli_find_free_space(const struct silofs_spleaf_info *sli,
                               enum silofs_stype stype,
                               struct silofs_vaddr *out_vaddr);

void silofs_sli_mark_allocated_space(struct silofs_spleaf_info *sli,
                                     const struct silofs_vaddr *vaddr);

void silofs_sli_clear_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr);

bool silofs_sli_has_refs_at(const struct silofs_spleaf_info *sli, loff_t voff);

bool silofs_sli_has_last_refcnt(const struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr);

bool silofs_sli_has_unwritten_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr *vaddr);

void silofs_sli_clear_unwritten_at(struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr *vaddr);

void silofs_sli_mark_unwritten_at(struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr);

void silofs_sli_main_blob(const struct silofs_spleaf_info *sli,
                          struct silofs_blobid *out_bid);

void silofs_sli_bind_main_blob(struct silofs_spleaf_info *sli,
                               const struct silofs_blobid *bid);

bool silofs_sli_has_main_blob(const struct silofs_spleaf_info *sli,
                              const struct silofs_metaid *tree_id);

int silofs_sli_check_stable_at(const struct silofs_spleaf_info *sli,
                               const struct silofs_vaddr *vaddr);

void silofs_sli_clone_childs(struct silofs_spleaf_info *sli,
                             const struct silofs_spleaf_info *sli_other);


void silofs_sli_resolve_child(const struct silofs_spleaf_info *sli,
                              loff_t voff, struct silofs_uaddr *out_uaddr);

void silofs_sli_resolve_main_at(const struct silofs_spleaf_info *sli,
                                loff_t voff, struct silofs_uaddr *out_uaddr);

void silofs_sli_rebind_main_at(struct silofs_spleaf_info *sli, loff_t voff);


int silofs_verify_spmap_node(const struct silofs_spmap_node *sn);

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl);

#endif /* SILOFS_SPMAPS_H_ */
