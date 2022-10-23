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
#ifndef SILOFS_PACK_H_
#define SILOFS_PACK_H_

#include <silofs/infra.h>
#include <silofs/types.h>


int silofs_uber_pack_fs(struct silofs_fs_uber *uber,
                        const struct silofs_kivam *kivam,
                        const struct silofs_bootsec *warm_bsec,
                        struct silofs_bootsec *out_cold_bsec);

int silofs_uber_unpack_fs(struct silofs_fs_uber *uber,
                          const struct silofs_kivam *kivam,
                          const struct silofs_bootsec *cold_bsec,
                          struct silofs_bootsec *out_warm_bsec);

#endif /* SILOFS_PACK_H_ */
