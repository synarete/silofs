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

struct silofs_task_ctx;

void silofs_ignite_ubspace(const struct silofs_task_ctx *task,
                           struct silofs_pnodeptr       *out_pnodeptr);

void silofs_ignite_btspace(const struct silofs_task_ctx *task,
                           struct silofs_pnodeptr       *out_pnodeptr);

#endif /* SILOFS_SPACE_H_ */
