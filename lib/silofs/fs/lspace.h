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
#ifndef SILOFS_LSPACE_H_
#define SILOFS_LSPACE_H_

#include <silofs/ondisk.h>
#include <silofs/addr.h>

struct silofs_task_ctx;

int silofs_require_lsmap_of(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_lsmap_info **out_lsi);

#endif /* SILOFS_LSPACE_H_ */
