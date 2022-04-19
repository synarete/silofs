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


struct silofs_fs_stats {
	size_t nalloc_bytes;
	size_t ncache_ublocks;
	size_t ncache_vblocks;
	size_t ncache_unodes;
	size_t ncache_vnodes;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fse_new(const struct silofs_fs_args *args,
                   struct silofs_fs_env **out_fse);

void silofs_fse_del(struct silofs_fs_env *fse);

int silofs_fse_reopen(struct silofs_fs_env *fse,
                      const struct silofs_bootsec *bsec);

int silofs_fse_reload(struct silofs_fs_env *fse,
                      const struct silofs_bootsec *bsec);

int silofs_fse_format_repos(struct silofs_fs_env *fse);

int silofs_fse_format_fs(struct silofs_fs_env *fse,
                         struct silofs_bootsec *out_bsec);

int silofs_fse_serve(struct silofs_fs_env *fse,
                     const struct silofs_bootsec *bsec);

int silofs_fse_archive(struct silofs_fs_env *fse,
                       const struct silofs_bootsec *src_bsec,
                       struct silofs_bootsec *dst_bsec);

int silofs_fse_restore(struct silofs_fs_env *fse,
                       const struct silofs_bootsec *src_bsec,
                       struct silofs_bootsec *dst_bsec);

int silofs_fse_snap(struct silofs_fs_env *fse,
                    const struct silofs_bootsec *src_bsec,
                    struct silofs_bootsec *out_bsec);

int silofs_fse_verify(struct silofs_fs_env *fse,
                      const struct silofs_bootsec *bsec);

int silofs_fse_resolve(const struct silofs_fs_env *fse,
                       struct silofs_bootsec *out_bsec);

int silofs_fse_shut(struct silofs_fs_env *fse);

int silofs_fse_term(struct silofs_fs_env *fse);

void silofs_fse_halt(struct silofs_fs_env *fse, int signum);

int silofs_fse_sync_drop(struct silofs_fs_env *fse);

void silofs_fse_stats(const struct silofs_fs_env *fse,
                      struct silofs_fs_stats *st);

bool silofs_fse_served_clean(const struct silofs_fs_env *fse);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fse_open_repos(struct silofs_fs_env *fse);

int silofs_fse_close_repos(struct silofs_fs_env *fse);

#endif /* SILOFS_EXEC_H_ */
