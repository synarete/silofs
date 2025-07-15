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
#ifndef SILOFS_LSMAP_H_
#define SILOFS_LSMAP_H_

struct silofs_lsmap_info *silofs_lsi_from_vni(struct silofs_vnode_info *vni);

void silofs_lsi_incref(struct silofs_lsmap_info *lsi);

void silofs_lsi_decref(struct silofs_lsmap_info *lsi);

enum silofs_mtype silofs_lsi_refmtype(const struct silofs_lsmap_info *lsi);

void silofs_lsi_get_lrange(const struct silofs_lsmap_info *lsi,
                           struct silofs_lrange           *out_lrange);

void silofs_lsi_setup_spawned(struct silofs_lsmap_info *lsi,
                              enum silofs_mtype refmtype, loff_t beg);

void silofs_lsi_update_nused(struct silofs_lsmap_info *lsi);

size_t silofs_lsi_refcnt_at(const struct silofs_lsmap_info *lsi,
                            const struct silofs_vaddr      *vaddr);

int silofs_lsi_find_free_space(const struct silofs_lsmap_info *lsi,
                               struct silofs_vaddr            *out_vaddr);

void silofs_lsi_update_off_hint(struct silofs_lsmap_info  *lsi,
                                const struct silofs_vaddr *vaddr);

void silofs_lsi_mark_allocated_at(struct silofs_lsmap_info  *lsi,
                                  const struct silofs_vaddr *vaddr);

void silofs_lsi_unref_allocated_at(struct silofs_lsmap_info  *lsi,
                                   const struct silofs_vaddr *vaddr);

void silofs_lsi_reref_allocated_at(struct silofs_lsmap_info  *lsi,
                                   const struct silofs_vaddr *vaddr);

bool silofs_lsi_has_allocated_with(const struct silofs_lsmap_info *lsi,
                                   const struct silofs_vaddr      *vaddr);

bool silofs_lsi_is_last_allocated(const struct silofs_lsmap_info *lsi,
                                  const struct silofs_vaddr      *vaddr);

bool silofs_lsi_has_allocated_at(const struct silofs_lsmap_info *lsi,
                                 const struct silofs_vaddr      *vaddr);

bool silofs_lsi_has_unwritten_at(const struct silofs_lsmap_info *lsi,
                                 const struct silofs_vaddr      *vaddr);

void silofs_lsi_clear_unwritten_at(struct silofs_lsmap_info  *lsi,
                                   const struct silofs_vaddr *vaddr);

void silofs_lsi_mark_unwritten_at(struct silofs_lsmap_info  *lsi,
                                  const struct silofs_vaddr *vaddr);

int silofs_lsi_resolve_key(const struct silofs_lsmap_info *lsi,
                           const struct silofs_vaddr      *vaddr,
                           struct silofs_key              *out_key);

int silofs_lsi_rebind_key(struct silofs_lsmap_info  *lsi,
                          const struct silofs_vaddr *vaddr,
                          const struct silofs_key   *key);

void silofs_lsi_vaddrs_at(const struct silofs_lsmap_info *lsi,
                          const struct silofs_vaddr      *vaddr,
                          struct silofs_vaddrs           *out_vaddrs);

void silofs_lsi_clone_from(struct silofs_lsmap_info *lsi,
                           struct silofs_lsmap_info *lsi_other);

int silofs_verify_lsmap(const struct silofs_lsmap *lsm);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#endif /* SILOFS_LSMAP_H_ */
