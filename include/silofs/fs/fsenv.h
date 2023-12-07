/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_FSENV_H_
#define SILOFS_FSENV_H_


/* base members of fsenv-block (provided) */
struct silofs_fsenv_base {
	const struct silofs_fs_args    *fs_args;
	const struct silofs_bootpath   *bootpath;
	const struct silofs_ivkey      *boot_ivkey;
	const struct silofs_ivkey      *main_ivkey;
	struct silofs_alloc            *alloc;
	struct silofs_cache            *cache;
	struct silofs_repo             *repo;
	struct silofs_submitq          *submitq;
	struct silofs_flusher          *flusher;
	struct silofs_idsmap           *idsmap;
};

/* top-level pseudo meta node */
struct silofs_fsenv {
	struct silofs_fsenv_base        fse;
	struct silofs_mutex             fse_mutex;
	struct silofs_rwlock            fse_rwlock;
	struct silofs_mdigest           fse_mdigest;
	struct silofs_cipher            fse_cipher;
	struct silofs_oper_stat         fse_op_stat;
	struct silofs_lsegid            fse_sb_lsegid;
	struct silofs_sb_info          *fse_sbi;
	struct silofs_ulink             fse_sb_ulink;
	struct silofs_cred              fse_owner;
	unsigned long                   fse_ctl_flags;
	unsigned long                   fse_ms_flags;
	iconv_t                         fse_iconv;
	time_t                          fse_init_time;
	uint64_t                        fse_commit_id;
} silofs_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fsenv_init(struct silofs_fsenv *fsenv,
                      const struct silofs_fsenv_base *base);

void silofs_fsenv_fini(struct silofs_fsenv *fsenv);

void silofs_fsenv_lock(struct silofs_fsenv *fsenv);

void silofs_fsenv_unlock(struct silofs_fsenv *fsenv);

void silofs_fsenv_rwlock(struct silofs_fsenv *fsenv, bool ex);

void silofs_fsenv_rwunlock(struct silofs_fsenv *fsenv);

void silofs_fsenv_shut(struct silofs_fsenv *fsenv);

void silofs_fsenv_bind_child(struct silofs_fsenv *fsenv,
                             const struct silofs_ulink *ulink);

int silofs_fsenv_format_super(struct silofs_fsenv *fsenv, size_t capacity);

int silofs_fsenv_reload_super(struct silofs_fsenv *fsenv);

int silofs_fsenv_reload_sb_lseg(struct silofs_fsenv *fsenv);

int silofs_fsenv_forkfs(struct silofs_fsenv *fsenv,
                        struct silofs_bootrecs *out_brecs);

time_t silofs_fsenv_uptime(const struct silofs_fsenv *fsenv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_super_at(struct silofs_fsenv *fsenv,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi);

int silofs_stage_super_at(struct silofs_fsenv *fsenv,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi);


int silofs_spawn_spnode_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni);

int silofs_stage_spnode_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni);


int silofs_spawn_spleaf_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli);

int silofs_stage_spleaf_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_lseg_at(struct silofs_fsenv *fsenv,
                         const struct silofs_lsegid *lsegid);

int silofs_stage_lseg_at(struct silofs_fsenv *fsenv,
                         const struct silofs_lsegid *lsegid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_relax_caches(const struct silofs_task *task, int flags);

#endif /* SILOFS_FSENV_H_ */
