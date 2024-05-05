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
#ifndef SILOFS_EXPORT_H_
#define SILOFS_EXPORT_H_

struct silofs_task;

struct silofs_pack_args {
	const char *remotedir;
};

int silofs_fs_export(struct silofs_task *task,
                     const struct silofs_pack_args *args,
                     struct silofs_hash256 *out_cat_hash);

#endif /* SILOFS_EXPORT_H_ */
