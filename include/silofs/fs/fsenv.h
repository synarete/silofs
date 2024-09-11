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
#ifndef SILOFS_FSENV_H_
#define SILOFS_FSENV_H_

#include <silofs/ps.h>
#include <silofs/fs/types.h>
#include <silofs/fs/boot.h>


/* fs-env control flags */
enum silofs_env_flags {
	SILOFS_ENVF_WITHFUSE    = SILOFS_BIT(0),
	SILOFS_ENVF_NLOOKUP     = SILOFS_BIT(1),
	SILOFS_ENVF_WRITEBACK   = SILOFS_BIT(2),
	SILOFS_ENVF_MAYSPLICE   = SILOFS_BIT(3),
	SILOFS_ENVF_ALLOWOTHER  = SILOFS_BIT(4),
	SILOFS_ENVF_ALLOWADMIN  = SILOFS_BIT(5),
	SILOFS_ENVF_ALLOWXACL   = SILOFS_BIT(6),
	SILOFS_ENVF_ASYNCWR     = SILOFS_BIT(7),
};

/* operations counters */
struct silofs_oper_stat {
	size_t op_iopen_max;
	size_t op_iopen;
	time_t op_time;
	size_t op_count;
	/* TODO: Have counter per-operation */
};

/* base members of fsenv-block (provided) */
struct silofs_fsenv_base {
	struct silofs_alloc            *alloc;
	struct silofs_lcache           *lcache;
	struct silofs_repo             *repo;
	struct silofs_submitq          *submitq;
	struct silofs_flusher          *flusher;
	struct silofs_idsmap           *idsmap;
	struct silofs_pstore           *pstore;
	struct silofs_fuseq            *fuseq;
};

/* fs two-layers locking */
struct silofs_fsenv_locks {
	struct silofs_mutex             mutex;
	struct silofs_rwlock            rwlock;
};

/* top-level boot state */
struct silofs_fsenv_boot {
	struct silofs_ivkey             ivkey;
	struct silofs_caddr             caddr;
	struct silofs_cipher            cipher;
	struct silofs_bootrec           brec;
};

/* top-level environment object */
struct silofs_fsenv {
	struct silofs_fs_args           fse_args;
	struct silofs_fsenv_base        fse;
	struct silofs_fsenv_locks       fse_locks;
	struct silofs_fsenv_boot        fse_boot;
	struct silofs_cipher            fse_enc_cipher;
	struct silofs_cipher            fse_dec_cipher;
	struct silofs_mdigest           fse_mdigest;
	struct silofs_caddr             fse_pack_caddr;
	struct silofs_oper_stat         fse_op_stat;
	struct silofs_lsid              fse_sb_lsid;
	struct silofs_sb_info          *fse_sbi;
	struct silofs_ulink             fse_sb_ulink;
	struct silofs_cred              fse_owner;
	unsigned long                   fse_ms_flags;
	enum silofs_env_flags           fse_ctl_flags;
	iconv_t                         fse_iconv;
	time_t                          fse_init_time;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fsenv_init(struct silofs_fsenv *fsenv,
                      const struct silofs_fs_args *args,
                      const struct silofs_fsenv_base *base);

void silofs_fsenv_fini(struct silofs_fsenv *fsenv);

int silofs_fsenv_setup(struct silofs_fsenv *fsenv,
                       const struct silofs_password *pw);

void silofs_fsenv_lock(struct silofs_fsenv *fsenv);

void silofs_fsenv_unlock(struct silofs_fsenv *fsenv);

void silofs_fsenv_rwlock(struct silofs_fsenv *fsenv, bool ex);

void silofs_fsenv_rwunlock(struct silofs_fsenv *fsenv);

int silofs_fsenv_shut(struct silofs_fsenv *fsenv);

int silofs_fsenv_format_super(struct silofs_fsenv *fsenv, size_t capacity);

int silofs_fsenv_reload_super(struct silofs_fsenv *fsenv);

int silofs_fsenv_reload_sb_lseg(struct silofs_fsenv *fsenv);

int silofs_fsenv_forkfs(struct silofs_fsenv *fsenv,
                        struct silofs_bootrecs *out_brecs);

void silofs_fsenv_relax_caches(const struct silofs_fsenv *fsenv, int flags);

void silofs_fsenv_uptime(const struct silofs_fsenv *fsenv, time_t *out_uptime);

void silofs_fsenv_allocstat(const struct silofs_fsenv *fsenv,
                            struct silofs_alloc_stat *out_alst);

void silofs_fsenv_bootpath(const struct silofs_fsenv *fsenv,
                           struct silofs_bootpath *out_bootpath);

int silofs_fsenv_update_by(struct silofs_fsenv *fsenv,
                           const struct silofs_bootrec *brec);

void silofs_fsenv_set_boot_caddr(struct silofs_fsenv *fsenv,
                                 const struct silofs_caddr *caddr);

void silofs_fsenv_set_pack_caddr(struct silofs_fsenv *fsenv,
                                 const struct silofs_caddr *caddr);

void silofs_fsenv_set_sb_ulink(struct silofs_fsenv *fsenv,
                               const struct silofs_ulink *ulink);


#endif /* SILOFS_FSENV_H_ */
