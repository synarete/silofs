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
#ifndef SILOFS_UUID_H_
#define SILOFS_UUID_H_

#include <stdint.h>

struct silofs_uuid;

void silofs_uuid_generate(struct silofs_uuid *uu);

void silofs_uuid_assign(struct silofs_uuid       *uu,
                        const struct silofs_uuid *other);

void silofs_uuid_assign2(struct silofs_uuid *uu, const uint8_t u[16]);

void silofs_uuid_copyto(const struct silofs_uuid *uu, uint8_t u[16]);

long silofs_uuid_compare(const struct silofs_uuid *uu1,
                         const struct silofs_uuid *uu2);

#endif /* SILOFS_UUID_H_ */
