/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

struct silofs_task;

#define SILOFS_CATALOG_SIZE_MIN SILOFS_LBK_SIZE
#define SILOFS_CATALOG_SIZE_MAX (256 * SILOFS_MEGA)


int silofs_fs_pack(struct silofs_task *task,
                   struct silofs_caddr *out_caddr);

int silofs_fs_unpack(struct silofs_task *task,
                     const struct silofs_caddr *caddr);

#endif /* SILOFS_PACK_H_ */
