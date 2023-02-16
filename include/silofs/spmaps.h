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

#include <silofs/fsdef.h>
#include <silofs/types.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

loff_t silofs_sni_base_voff(const struct silofs_spnode_info *sni);

enum silofs_height silofs_sni_height(const struct silofs_spnode_info *sni);

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni);

void silofs_sni_incref(struct silofs_spnode_info *sni);

void silofs_sni_decref(struct silofs_spnode_info *sni);

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni,
                              const struct silofs_uaddr *parent, loff_t voff);

void silofs_sni_update_staged(struct silofs_spnode_info *sni);

void silofs_sni_clone_subrefs(struct silofs_spnode_info *sni,
                              const struct silofs_spnode_info *sni_other);

bool silofs_sni_has_child_at(const struct silofs_spnode_info *sni, loff_t off);

int silofs_sni_subref_of(const struct silofs_spnode_info *sni, loff_t voff,
                         struct silofs_uaddr *out_ulink);

void silofs_sni_bind_child_spleaf(struct silofs_spnode_info *sni,
                                  const struct silofs_spleaf_info *sli);

void silofs_sni_bind_child_spnode(struct silofs_spnode_info *sni,
                                  const struct silofs_spnode_info *sni_child);

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_vrange *vrange);

void silofs_sni_active_vrange(const struct silofs_spnode_info *sni,
                              struct silofs_vrange *out_vrange);

void silofs_sni_main_blob(const struct silofs_spnode_info *sni,
                          struct silofs_blobid *out_blobid);

void silofs_sni_bind_main_blob(struct silofs_spnode_info *sni,
                               const struct silofs_blobid *blobid);

bool silofs_sni_has_main_blob(const struct silofs_spnode_info *sni);

void silofs_sni_resolve_main_at(const struct silofs_spnode_info *sni,
                                loff_t voff, struct silofs_uaddr *out_ua);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli);

void silofs_sli_incref(struct silofs_spleaf_info *sli);

void silofs_sli_decref(struct silofs_spleaf_info *sli);

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_uaddr *parent, loff_t voff);

void silofs_sli_update_staged(struct silofs_spleaf_info *sli);

void silofs_sli_vspace_range(const struct silofs_spleaf_info *sli,
                             struct silofs_vrange *out_vrange);

loff_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli);

int silofs_sli_find_free_space(const struct silofs_spleaf_info *sli,
                               loff_t voff_from, enum silofs_stype stype,
                               struct silofs_vaddr *out_vaddr);

void silofs_sli_mark_allocated_space(struct silofs_spleaf_info *sli,
                                     const struct silofs_vaddr *vaddr);

void silofs_sli_reref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr);

void silofs_sli_unref_allocated_space(struct silofs_spleaf_info *sli,
                                      const struct silofs_vaddr *vaddr);

bool silofs_sli_has_allocated_space(const struct silofs_spleaf_info *sli,
                                    const struct silofs_vaddr *vaddr);

size_t silofs_sli_nallocated_at(const struct silofs_spleaf_info *sli,
                                const silofs_lba_t lba);


bool silofs_sli_has_shared_refcnt(const struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr);

bool silofs_sli_has_refs_at(const struct silofs_spleaf_info *sli,
                            const struct silofs_vaddr *vaddr);

bool silofs_sli_has_last_refcnt(const struct silofs_spleaf_info *sli,
                                const struct silofs_vaddr *vaddr);

bool silofs_sli_has_unwritten_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr *vaddr);

void silofs_sli_clear_unwritten_at(struct silofs_spleaf_info *sli,
                                   const struct silofs_vaddr *vaddr);

void silofs_sli_mark_unwritten_at(struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr);

void silofs_sli_vaddrs_at(const struct silofs_spleaf_info *sli,
                          enum silofs_stype stype, silofs_lba_t lba,
                          struct silofs_vaddrs *vas);

void silofs_sli_main_blob(const struct silofs_spleaf_info *sli,
                          struct silofs_blobid *out_blobid);

void silofs_sli_bind_main_blob(struct silofs_spleaf_info *sli,
                               const struct silofs_blobid *blobid);

bool silofs_sli_has_main_blob(const struct silofs_spleaf_info *sli,
                              const struct silofs_treeid *treeid);

void silofs_sli_clone_subrefs(struct silofs_spleaf_info *sli,
                              const struct silofs_spleaf_info *sli_other);


void silofs_sli_resolve_main_ubk(const struct silofs_spleaf_info *sli,
                                 loff_t voff, struct silofs_bkaddr *out_bka);

int silofs_sli_resolve_ubk(const struct silofs_spleaf_info *sli,
                           loff_t voff, struct silofs_bkaddr *out_bkaddr);

void silofs_sli_rebind_ubk(struct silofs_spleaf_info *sli, loff_t voff,
                           const struct silofs_bkaddr *bkaddr);

void silofs_sli_seal_meta(struct silofs_spleaf_info *sli);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn);

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl);

#endif /* SILOFS_SPMAPS_H_ */
