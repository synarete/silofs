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
#ifndef SILOFS_APEX_H_
#define SILOFS_APEX_H_

#include <stdlib.h>
#include <silofs/fs/types.h>

int silofs_apex_init(struct silofs_fs_apex *apex,
                     struct silofs_repo *repo, struct silofs_crypto *crypto);

void silofs_apex_fini(struct silofs_fs_apex *apex);

void silofs_apex_shut(struct silofs_fs_apex *apex);

int silofs_apex_flush_dirty(struct silofs_fs_apex *apex, int flags);

int silofs_apex_spawn_blob(const struct silofs_fs_apex *apex,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli);

int silofs_apex_stage_blob(const struct silofs_fs_apex *apex,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli);


int silofs_apex_spawn_super(struct silofs_fs_apex *apex, size_t cap_want,
                            const struct silofs_namestr *name,
                            struct silofs_sb_info **out_sbi);

int silofs_apex_stage_super(struct silofs_fs_apex *apex,
                            const struct silofs_namestr *name,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi);

void silofs_apex_bind_to_sbi(struct silofs_fs_apex *apex,
                             struct silofs_sb_info *sbi_new);


int silofs_apex_forkfs(struct silofs_fs_apex *apex,
                       const struct silofs_namestr *name);

int silofs_apex_prune_space(struct silofs_fs_apex *apex);

bool silofs_apex_has_bootsec(const struct silofs_fs_apex *apex,
                             const struct silofs_namestr *name);

int silofs_apex_load_bootsec(const struct silofs_fs_apex *apex,
                             struct silofs_bootsec *out_bsec);

int silofs_apex_lock_bootsec(struct silofs_fs_apex *apex);

int silofs_apex_unlock_bootsec(struct silofs_fs_apex *apex);


int silofs_apex_kcopy(struct silofs_fs_apex *apex,
                      const struct silofs_fiovec *fiov_src,
                      const struct silofs_fiovec *fiov_dst, size_t len);

#endif /* SILOFS_APEX_H_ */
