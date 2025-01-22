/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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

#include <silofs/macros.h>
#include <silofs/types.h>
#include <silofs/boot.h>

/* top-level control flags */
enum silofs_env_flags {
	SILOFS_F_PEDANTIC     = SILOFS_BIT(0),
	SILOFS_F_RDONLY       = SILOFS_BIT(1),
	SILOFS_F_NOEXEC       = SILOFS_BIT(2),
	SILOFS_F_NOSUID       = SILOFS_BIT(3),
	SILOFS_F_NODEV        = SILOFS_BIT(4),
	SILOFS_F_WITHFUSE     = SILOFS_BIT(5),
	SILOFS_F_NLOOKUP      = SILOFS_BIT(6),
	SILOFS_F_WRITEBACK    = SILOFS_BIT(7),
	SILOFS_F_MAYSPLICE    = SILOFS_BIT(8),
	SILOFS_F_ALLOWOTHER   = SILOFS_BIT(9),
	SILOFS_F_ALLOWADMIN   = SILOFS_BIT(10),
	SILOFS_F_ALLOWXACL    = SILOFS_BIT(11),
	SILOFS_F_ALLOWHOSTIDS = SILOFS_BIT(12),
	SILOFS_F_ASYNCWR      = SILOFS_BIT(13),
	SILOFS_F_LAZYTIME     = SILOFS_BIT(14),
	SILOFS_F_STDALLOC     = SILOFS_BIT(15),
};

/* input arguments */
struct silofs_env_args {
	struct silofs_bootref bref;
	struct silofs_fs_ids  ids;
	const char           *mntdir;
	enum silofs_env_flags flags;
	uid_t                 uid;
	gid_t                 gid;
	pid_t                 pid;
	mode_t                umask;
	size_t                capacity;
	size_t                memwant;
};

/* top-level operations counters/stats */
struct silofs_env_opstat {
	size_t op_iopen_max;
	size_t op_iopen;
	time_t op_time;
	size_t op_count;
	/* TODO: Have counter per-operation */
};

/* base members of env-block (provided) */
struct silofs_env_base {
	struct silofs_alloc   *alloc;
	struct silofs_repo    *repo;
	struct silofs_pcache  *pcache;
	struct silofs_lcache  *lcache;
	struct silofs_submitq *submitq;
	struct silofs_flusher *flusher;
	struct silofs_idsmap  *idsmap;
	struct silofs_bstore  *bstore;
	struct silofs_fuseq   *fuseq;
};

/* top-level boot state */
struct silofs_env_boot {
	struct silofs_ivkey  ivkey;
	struct silofs_caddr  caddr;
	struct silofs_cipher cipher;
	struct silofs_uber   uber;
};

/* fs two-layers locking */
struct silofs_env_locks {
	struct silofs_rwlock rwlock;
	struct silofs_mutex  mutex;
};

/* top-level environment object */
struct silofs_env {
	struct silofs_env_args   args;
	struct silofs_env_base   base;
	struct silofs_env_boot   boot;
	struct silofs_env_locks  locks;
	struct silofs_cipher     enc_cipher;
	struct silofs_cipher     dec_cipher;
	struct silofs_mdigest    mdigest;
	struct silofs_caddr      pack_caddr;
	struct silofs_env_opstat opstat;
	struct silofs_lsid       sb_lsid;
	struct silofs_sb_info   *sbi;
	struct silofs_ulink      sb_ulink;
	struct silofs_cred       owner_cred;
	unsigned long            ms_flags;
	iconv_t                  iconv;
	time_t                   init_time;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_init(struct silofs_env *env, const struct silofs_env_args *args,
                    const struct silofs_env_base *base);

void silofs_env_fini(struct silofs_env *env);

bool silofs_env_hasflag(const struct silofs_env *env, enum silofs_env_flags f);

int silofs_env_setup(struct silofs_env *env, const struct silofs_password *pw);

void silofs_env_lock(struct silofs_env *env);

void silofs_env_unlock(struct silofs_env *env);

void silofs_env_rwlock(struct silofs_env *env, bool ex);

void silofs_env_rwunlock(struct silofs_env *env);

int silofs_env_shut(struct silofs_env *env);

int silofs_env_format_super(struct silofs_env *env, size_t capacity);

int silofs_env_reload_super(struct silofs_env *env);

int silofs_env_reload_sb_lseg(struct silofs_env *env);

int silofs_env_forkfs(struct silofs_env *env, struct silofs_ubers *out_ubers);

void silofs_env_relax_caches(const struct silofs_env *env, int flags);

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime);

void silofs_env_allocstat(const struct silofs_env  *env,
                          struct silofs_alloc_stat *out_alst);

int silofs_env_update_by(struct silofs_env        *env,
                         const struct silofs_uber *uber);

void silofs_env_drop_caches(struct silofs_env *env);

void silofs_env_set_boot_caddr(struct silofs_env         *env,
                               const struct silofs_caddr *caddr);

void silofs_env_set_pack_caddr(struct silofs_env         *env,
                               const struct silofs_caddr *caddr);

void silofs_env_set_sb_ulink(struct silofs_env         *env,
                             const struct silofs_ulink *ulink);

#endif /* SILOFS_FSENV_H_ */
