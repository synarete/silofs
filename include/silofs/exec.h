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
#ifndef SILOFS_EXEC_H_
#define SILOFS_EXEC_H_


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fse_new(const struct silofs_fs_args *args,
                   struct silofs_fs_env **out_fse);

void silofs_fse_del(struct silofs_fs_env *fse);

int silofs_fse_format_repo(struct silofs_fs_env *fse);

int silofs_fse_open_repo(struct silofs_fs_env *fse);

int silofs_fse_close_repo(struct silofs_fs_env *fse);

int silofs_fse_format_fs(struct silofs_fs_env *fse,
                         struct silofs_uuid *out_uuid);

int silofs_fse_boot_fs(struct silofs_fs_env *fse,
                       const struct silofs_uuid *uuid);

int silofs_fse_open_fs(struct silofs_fs_env *fse);

int silofs_fse_poke_fs(struct silofs_fs_env *fse,
                       const struct silofs_uuid *uuid);

int silofs_fse_close_fs(struct silofs_fs_env *fse);

int silofs_fse_exec_fs(struct silofs_fs_env *fse);

int silofs_fse_fork_fs(struct silofs_fs_env *fse,
                       struct silofs_uuid *out_new,
                       struct silofs_uuid *out_alt);

int silofs_fse_inspect_fs(struct silofs_fs_env *fse);

int silofs_fse_unref_fs(struct silofs_fs_env *fse,
                        const struct silofs_uuid *uuid);

void silofs_fse_halt(struct silofs_fs_env *fse, int signum);

int silofs_fse_sync_drop(struct silofs_fs_env *fse);

void silofs_fse_stats(const struct silofs_fs_env *fse,
                      struct silofs_fs_stats *st);

bool silofs_fse_served_clean(const struct silofs_fs_env *fse);

#endif /* SILOFS_EXEC_H_ */
