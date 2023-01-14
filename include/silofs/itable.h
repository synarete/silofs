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
#ifndef SILOFS_ITABLE_H_
#define SILOFS_ITABLE_H_

#include <unistd.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_inomap_init(struct silofs_inomap *imap,
                       struct silofs_alloc *alloc);

void silofs_inomap_fini(struct silofs_inomap *imap);

int silofs_inomap_lookup(struct silofs_inomap *imap,
                         ino_t ino, loff_t *out_voff);

int silofs_inomap_insert(struct silofs_inomap *imap, ino_t ino, loff_t voff);

int silofs_inomap_remove(struct silofs_inomap *imap, ino_t ino);

int silofs_inomap_update(struct silofs_inomap *imap, ino_t ino, loff_t voff);

void silofs_inomap_relax(struct silofs_inomap *imap, int flags);

void silofs_inomap_clear(struct silofs_inomap *imap);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_itbi_init(struct silofs_itable_info *itbi,
                     struct silofs_alloc *alloc);

void silofs_itbi_reinit(struct silofs_itable_info *itbi);

void silofs_itbi_fini(struct silofs_itable_info *itbi);

void silofs_itbi_update_by(struct silofs_itable_info *itbi,
                           const struct silofs_itable_info *itbi_other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_acquire_ino(struct silofs_task *task,
                       const struct silofs_vaddr *vaddr,
                       struct silofs_iaddr *out_iaddr);

int silofs_discard_ino(struct silofs_task *task, ino_t ino);

int silofs_resolve_iaddr(struct silofs_task *task,
                         ino_t xino, struct silofs_iaddr *out_iaddr);

int silofs_format_itable_root(struct silofs_task *task,
                              struct silofs_vaddr *out_vaddr);

int silofs_bind_rootdir_to(struct silofs_task *task,
                           const struct silofs_inode_info *ii);

int silofs_reload_itable_at(struct silofs_task *task,
                            const struct silofs_vaddr *vaddr);

void silofs_drop_itable_cache(struct silofs_task *task);

void silofs_relax_inomap(struct silofs_task *task, int flags);

int silofs_verify_itable_node(const struct silofs_itable_node *itn);



#endif /* SILOFS_ITABLE_H_ */
