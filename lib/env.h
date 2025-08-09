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
#include "mbr.h"

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
	const struct silofs_env_args *args;
	struct silofs_alloc          *alloc;
	struct silofs_repo           *repo;
	struct silofs_pcache         *pcache;
	struct silofs_bstore         *bstore;
	struct silofs_lcache         *lcache;
	struct silofs_submitq        *submitq;
	struct silofs_flusher        *flusher;
	struct silofs_idsmap         *idsmap;
	struct silofs_fuseq          *fuseq;
};

/* top-level environment object */
struct silofs_env {
	struct silofs_env_base   base;
	struct silofs_mbrctl     mbrctl;
	struct silofs_rwlock     rwlock;
	struct silofs_mutex      mutex;
	struct silofs_cipher     enc_cipher;
	struct silofs_cipher     dec_cipher;
	struct silofs_mdigest    mdigest;
	struct silofs_caddr      arix_addr;
	struct silofs_env_opstat opstat;
	struct silofs_sb_info   *sbi;
	struct silofs_cred       owner_cred;
	unsigned long            ms_flags;
	iconv_t                  iconv;
	time_t                   init_time;
	bool                     iconv_set;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_affirm_ondisk_format(void);

int silofs_env_init(struct silofs_env            *env,
                    const struct silofs_env_base *base);

void silofs_env_fini(struct silofs_env *env);

int silofs_env_setup_passwd(struct silofs_env            *env,
                            const struct silofs_password *pw);

void silofs_env_lock(struct silofs_env *env);

void silofs_env_unlock(struct silofs_env *env);

void silofs_env_rwlock(struct silofs_env *env, bool ex);

void silofs_env_rwunlock(struct silofs_env *env);

int silofs_env_shut(struct silofs_env *env);

int silofs_env_format_bstore(struct silofs_env *env);

int silofs_env_setup_mbr(struct silofs_env *env);

int silofs_env_commit_mbr(struct silofs_env *env);

int silofs_env_sense_mbr(struct silofs_env         *env,
                         const struct silofs_caddr *caddr);

int silofs_env_reload_mbr(struct silofs_env         *env,
                          const struct silofs_caddr *caddr);

int silofs_env_unlink_mbr(struct silofs_env *env);

int silofs_env_format_super(struct silofs_env *env, size_t capacity);

int silofs_env_reload_super(struct silofs_env *env);

int silofs_env_reload_sb_lseg(struct silofs_env *env);

int silofs_env_forkfs(struct silofs_env *env, struct silofs_mrefs *out_mrefs);

void silofs_env_relax_caches(const struct silofs_env *env, int flags);

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime);

void silofs_env_allocstat(const struct silofs_env  *env,
                          struct silofs_alloc_stat *out_alst);

int silofs_env_sense_ar(struct silofs_env *env);

void silofs_env_drop_caches(struct silofs_env *env);

bool silofs_env_hasflag(const struct silofs_env *env, enum silofs_flags f);

int silofs_env_mbr_addr(const struct silofs_env *env,
                        struct silofs_caddr     *out_caddr);

int silofs_env_set_mbr_addr(struct silofs_env         *env,
                            const struct silofs_caddr *caddr);

int silofs_env_arix_addr(const struct silofs_env *env,
                         struct silofs_caddr     *out_caddr);

int silofs_env_set_arix_addr(struct silofs_env         *env,
                             const struct silofs_caddr *caddr);

#endif /* SILOFS_ENV_H_ */
