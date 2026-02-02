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

void silofs_make_base_nodeptr(struct silofs_prandgen *prng,
                              enum silofs_mtype       mtype,
                              struct silofs_nodeptr  *out_nodeptr);

void silofs_make_next_nodeptr(struct silofs_prandgen    *prng,
                              const struct silofs_paddr *paddr,
                              struct silofs_nodeptr     *out_nodeptr);

#endif /* SILOFS_SPACE_H_ */
