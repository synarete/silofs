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
#ifndef SILOFS_GENID_H_
#define SILOFS_GENID_H_

#include "crypto.h"

void silofs_generate_civkey(struct silofs_prandgen *prng,
                            struct silofs_civkey   *out_civkey);

void silofs_generate_uniqid(struct silofs_prandgen *prng,
                            struct silofs_uniqid   *out_uniqid);

#endif /* SILOFS_RANDOM_H_ */
