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

int silofs_mark_unwritten_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr    *ref_laddr);

int silofs_clear_unwritten_at(const struct silofs_task_ctx *task,
                              const struct silofs_laddr    *ref_laddr);

int silofs_test_unwritten_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr    *ref_laddr,
                             bool                         *out_unwritten);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_isshared_lnode_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *laddr, bool *out_res);

int silofs_share_lnode_at(const struct silofs_task_ctx *task,
                          const struct silofs_laddr    *laddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_claim_free_lspace(const struct silofs_task_ctx *task,
                             enum silofs_ltype             ltype,
                             struct silofs_laddr          *out_laddr);

#endif /* SILOFS_LSPACE_H_ */
