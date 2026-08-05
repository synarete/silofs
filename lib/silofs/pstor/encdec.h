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
#ifndef SILOFS_ENCDEC_H_
#define SILOFS_ENCDEC_H_

#include <silofs/ondisk.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

int silofs_encrypt_pnode(const struct silofs_core_refs  *corefs,
                         const struct silofs_pnode_info *pni,
                         struct silofs_ctag             *out_ctag);

int silofs_decrypt_pnode(const struct silofs_core_refs  *corefs,
                         const struct silofs_pnode_info *pni,
                         const struct silofs_ctag       *ctag);

int silofs_encrypt_lnode(const struct silofs_core_refs  *corefs,
                         const struct silofs_lnode_info *lni,
                         const struct silofs_pnptr      *pnptr,
                         struct silofs_ctag             *out_ctag);

int silofs_decrypt_lnode(const struct silofs_core_refs  *corefs,
                         const struct silofs_lnode_info *lni,
                         const struct silofs_pnptr      *pnptr,
                         const struct silofs_ctag       *ctag);

#endif /* SILOFS_ENCDEC_H_ */
