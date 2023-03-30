/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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


int silofs_claim_vspace(struct silofs_task *task,
                        struct silofs_inode_info *pii,
                        enum silofs_stype stype,
                        struct silofs_voaddr *out_voa);

int silofs_reclaim_vspace(struct silofs_task *task,
                          const struct silofs_vaddr *vaddr);

int silofs_claim_vnode(struct silofs_task *task,
                       struct silofs_inode_info *pii,
                       enum silofs_stype stype,
                       struct silofs_vnode_info **out_vi);

int silofs_claim_inode(struct silofs_task *task,
                       struct silofs_inode_info **out_ii);

int silofs_addref_vspace(struct silofs_task *task,
                         const struct silofs_vaddr *vaddr);

int silofs_rescan_vspace_of(struct silofs_task *task, enum silofs_stype stype);

#endif /* SILOFS_SPCLAIM_H_ */