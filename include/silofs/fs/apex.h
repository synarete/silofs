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

#include <silofs/fs/types.h>

int silofs_apex_init(struct silofs_fs_apex *apex,
                     struct silofs_alloc_if *alif,
                     struct silofs_crypto *crypto,
                     struct silofs_repo *mrepo,
                     struct silofs_repo *crepo);

void silofs_apex_fini(struct silofs_fs_apex *apex);

void silofs_apex_shut(struct silofs_fs_apex *apex);

int silofs_apex_flush_dirty(const struct silofs_fs_apex *apex, int flags);

void silofs_apex_relax_caches(const struct silofs_fs_apex *apex, int flags);

int silofs_apex_spawn_super(struct silofs_fs_apex *apex, size_t capacity,
                            struct silofs_sb_info **out_sbi);

int silofs_apex_stage_super(struct silofs_fs_apex *apex,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi);

void silofs_apex_bind_to_sbi(struct silofs_fs_apex *apex,
                             struct silofs_sb_info *sbi_new);


int silofs_apex_forkfs(struct silofs_fs_apex *apex,
                       const struct silofs_namestr *name);



int silofs_apex_boot_name(const struct silofs_fs_apex *apex,
                          struct silofs_namestr *out_name);

int silofs_apex_save_boot(const struct silofs_fs_apex *apex,
                          const struct silofs_bootsec *bsec,
                          const struct silofs_namestr *name);

int silofs_apex_load_boot(const struct silofs_fs_apex *apex,
                          const struct silofs_namestr *name,
                          struct silofs_bootsec *out_bsec);

int silofs_apex_lock_boot(struct silofs_fs_apex *apex);

int silofs_apex_unlock_boot(struct silofs_fs_apex *apex);


int silofs_apex_kcopy(struct silofs_fs_apex *apex,
                      const struct silofs_xiovec *xiov_src,
                      const struct silofs_xiovec *xiov_dst, size_t len);

void silofs_apex_main_fsname(const struct silofs_fs_apex *apex,
                             struct silofs_namestr *out_name);

#endif /* SILOFS_APEX_H_ */
