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
#ifndef SILOFS_LAYERID_H_
#define SILOFS_LAYERID_H_

#include <silofs/ondisk.h>

const struct silofs_layerid *silofs_layerid_none(void);

void silofs_layerid_reset(struct silofs_layerid *layerid);

void silofs_layerid_copyto(const struct silofs_layerid *layerid,
                           struct silofs_layerid       *other);

bool silofs_layerid_isequal(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other);

#endif /* SILOFS_LAYERID_H_ */
