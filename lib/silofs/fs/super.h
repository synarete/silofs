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
#ifndef SILOFS_SUPER_H_
#define SILOFS_SUPER_H_

int silofs_verify_superb_node(const struct silofs_superb_node *sbn);

void silofs_sbi_incref(struct silofs_sbnode_info *sbi);

void silofs_sbi_decref(struct silofs_sbnode_info *sbi);

void silofs_sbi_setdirty(struct silofs_sbnode_info *sbi);

void silofs_sbi_setup_spawned(struct silofs_sbnode_info *sbi, size_t fscap);

int silofs_sbi_check_iavail(const struct silofs_sbnode_info *sbi);

int silofs_sbi_check_avail(const struct silofs_sbnode_info *sbi,
                           enum silofs_vtype                vtype);

void silofs_sbi_take_vnode(struct silofs_sbnode_info *sbi,
                           enum silofs_vtype          vtype);

void silofs_sbi_give_vnode(struct silofs_sbnode_info *sbi,
                           enum silofs_vtype          vtype);

void silofs_sbi_apex_of(const struct silofs_sbnode_info *sbi,
                        enum silofs_vtype                vtype,
                        struct silofs_vaddr             *out_vaddr);

void silofs_sbi_update_apex(struct silofs_sbnode_info *sbi,
                            const struct silofs_vaddr *vaddr);

uint64_t silofs_sbi_next_igen(struct silofs_sbnode_info *sbi);

void silofs_sbi_calc_statvfs(const struct silofs_sbnode_info *sbi,
                             struct statvfs                  *out_stv);

#endif /* SILOFS_SUPER_H_ */
