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
#ifndef SILOFS_USTAGE_H_
#define SILOFS_USTAGE_H_

int silofs_spawn_super(struct silofs_fsenv       *fsenv,
                       const struct silofs_ulink *ulink,
                       struct silofs_sb_info    **out_sbi);

int silofs_stage_super(struct silofs_fsenv       *fsenv,
                       const struct silofs_ulink *ulink,
                       struct silofs_sb_info    **out_sbi);

int silofs_spawn_spnode(struct silofs_fsenv        *fsenv,
                        const struct silofs_ulink  *ulink,
                        struct silofs_spnode_info **out_sni);

int silofs_stage_spnode(struct silofs_fsenv        *fsenv,
                        const struct silofs_ulink  *ulink,
                        struct silofs_spnode_info **out_sni);

int silofs_spawn_spleaf(struct silofs_fsenv        *fsenv,
                        const struct silofs_ulink  *ulink,
                        struct silofs_spleaf_info **out_sli);

int silofs_stage_spleaf(struct silofs_fsenv        *fsenv,
                        const struct silofs_ulink  *ulink,
                        struct silofs_spleaf_info **out_sli);

int silofs_spawn_lseg(struct silofs_fsenv      *fsenv,
                      const struct silofs_lsid *lsid);

int silofs_stage_lseg(struct silofs_fsenv      *fsenv,
                      const struct silofs_lsid *lsid);

#endif /* SILOFS_USTAGE_H_ */
