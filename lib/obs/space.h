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
#ifndef SILOFS_SPACE_H_
#define SILOFS_SPACE_H_

#include <silofs/types.h>
#include "addr.h"
#include "crypto.h"

void silofs_make_uniq_blobid(struct silofs_prandgen *prng,
                             enum silofs_mtype       mtype,
                             struct silofs_blobid   *out_blobid);

void silofs_make_base_paddr(struct silofs_prandgen *prng,
                            enum silofs_mtype       mtype,
                            struct silofs_paddr    *out_paddr);

void silofs_make_base_pnodeptr(struct silofs_prandgen *prng,
                               enum silofs_mtype       mtype,
                               struct silofs_pnodeptr *out_pnodeptr);

#endif /* SILOFS_SPACE_H_ */
