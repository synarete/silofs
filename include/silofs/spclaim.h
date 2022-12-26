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
#ifndef SILOFS_SPCLAIM_H_
#define SILOFS_SPCLAIM_H_


int silofs_claim_vspace(const struct silofs_task *task,
                        enum silofs_stype stype, silofs_dqid_t dqid,
                        struct silofs_voaddr *out_voa);

int silofs_reclaim_vspace(const struct silofs_task *task,
                          const struct silofs_vaddr *vaddr);

int silofs_claim_vnode(const struct silofs_task *task,
                       enum silofs_stype stype, silofs_dqid_t dqid,
                       struct silofs_vnode_info **out_vi);

int silofs_claim_inode(const struct silofs_task *task,
                       struct silofs_inode_info **out_ii);

int silofs_addref_vspace(const struct silofs_task *task,
                         const struct silofs_vaddr *vaddr);

int silofs_rescan_vspace_of(const struct silofs_task *task,
                            enum silofs_stype stype);

int silofs_recache_vspace(const struct silofs_task *task,
                          const struct silofs_vaddr *vaddr);

#endif /* SILOFS_SPCLAIM_H_ */
