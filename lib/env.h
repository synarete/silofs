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
#ifndef SILOFS_ENV_H_
#define SILOFS_ENV_H_

#include <iconv.h>
#include <silofs/appexec.h>
#include "infra.h"
#include "crypt.h"
#include "addr.h"
#include "uidgid.h"
#include "uber.h"

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
	struct silofs_args    *args;
	struct silofs_alloc   *alloc;
	struct silofs_repo    *repo;
	struct silofs_pcache  *pcache;
	struct silofs_bstore  *bstore;
	struct silofs_lcache  *lcache;
	struct silofs_submitq *submitq;
	struct silofs_flusher *flusher;
	struct silofs_idsmap  *idsmap;
	struct silofs_fuseq   *fuseq;
};

/* top-level environment object */
struct silofs_env {
	struct silofs_env_base   base;
	struct silofs_rwlock     rwlock;
	struct silofs_mutex      mutex;
	struct silofs_cipher     uber_cipher;
	struct silofs_cipher     enc_cipher;
	struct silofs_cipher     dec_cipher;
	struct silofs_mdigest    mdigest;
	struct silofs_ivkey      uber_ivkey;
	struct silofs_caddr      uber_caddr;
	struct silofs_caddr      uber_base_caddr;
	struct silofs_caddr      uber_fork_caddr;
	struct silofs_caddr      pack_caddr;
	struct silofs_uber       uber;
	struct silofs_env_opstat opstat;
	struct silofs_sb_info   *sbi;
	struct silofs_cred       owner_cred;
	unsigned long            ms_flags;
	iconv_t                  iconv;
	time_t                   init_time;
	bool                     iconv_set;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_require_proper_defs(void);

int silofs_env_init(struct silofs_env            *env,
                    const struct silofs_env_base *base);

void silofs_env_fini(struct silofs_env *env);

int silofs_env_setup(struct silofs_env *env, const struct silofs_password *pw);

void silofs_env_lock(struct silofs_env *env);

void silofs_env_unlock(struct silofs_env *env);

void silofs_env_rwlock(struct silofs_env *env, bool ex);

void silofs_env_rwunlock(struct silofs_env *env);

int silofs_env_shut(struct silofs_env *env);

int silofs_env_format_bstore(struct silofs_env *env);

int silofs_env_setup_uber(struct silofs_env *env);

int silofs_env_commit_uber(struct silofs_env *env);

int silofs_env_sense_uber(struct silofs_env *env);

int silofs_env_reload_uber(struct silofs_env *env);

int silofs_env_unlink_uber(struct silofs_env *env);

int silofs_env_format_super(struct silofs_env *env, size_t capacity);

int silofs_env_reload_super(struct silofs_env *env);

int silofs_env_reload_sb_lseg(struct silofs_env *env);

int silofs_env_forkfs(struct silofs_env *env);

void silofs_env_relax_caches(const struct silofs_env *env, int flags);

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime);

void silofs_env_allocstat(const struct silofs_env  *env,
                          struct silofs_alloc_stat *out_alst);

int silofs_env_update_by(struct silofs_env        *env,
                         const struct silofs_uber *uber);

int silofs_env_sense_pack(struct silofs_env *env);

void silofs_env_drop_caches(struct silofs_env *env);

bool silofs_env_hasflag(const struct silofs_env *env, enum silofs_flags f);

int silofs_env_uber_caddr(const struct silofs_env *env,
                          struct silofs_caddr     *out_caddr);

int silofs_env_set_uber_caddr(struct silofs_env         *env,
                              const struct silofs_caddr *caddr);

int silofs_env_base_caddr(const struct silofs_env *env,
                          struct silofs_caddr     *out_caddr);

int silofs_env_fork_caddr(const struct silofs_env *env,
                          struct silofs_caddr     *out_caddr);

int silofs_env_pack_caddr(const struct silofs_env *env,
                          struct silofs_caddr     *out_caddr);

int silofs_env_set_pack_caddr(struct silofs_env         *env,
                              const struct silofs_caddr *caddr);

#endif /* SILOFS_ENV_H_ */
