/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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

#include <silofs/appexec.h>
#include <silofs/infra.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>

/* env initialization-state flags */
enum silofs_env_initf {
	SILOFS_ENVF_QALLOC   = SILOFS_BIT(0),
	SILOFS_ENVF_STDALLOC = SILOFS_BIT(1),
	SILOFS_ENVF_PRANDGEN = SILOFS_BIT(2),
	SILOFS_ENVF_LOCKS    = SILOFS_BIT(3),
	SILOFS_ENVF_CRYPT    = SILOFS_BIT(4),
	SILOFS_ENVF_UCONV    = SILOFS_BIT(5),
	SILOFS_ENVF_REPO     = SILOFS_BIT(6),
	SILOFS_ENVF_PCACHE   = SILOFS_BIT(7),
	SILOFS_ENVF_LCACHE   = SILOFS_BIT(8),
	SILOFS_ENVF_FREESQS  = SILOFS_BIT(9),
	SILOFS_ENVF_IDSMAP   = SILOFS_BIT(10),
	SILOFS_ENVF_MBR      = SILOFS_BIT(11),
	SILOFS_ENVF_UBREF    = SILOFS_BIT(12),
	SILOFS_ENVF_FUSEQ    = SILOFS_BIT(13),
};

/* memory allocator of choice */
union silofs_alloc_u {
	struct silofs_qalloc   qalloc;
	struct silofs_stdalloc stdalloc;
};

/* top-level envronment object */
struct silofs_env {
	struct silofs_prandgen         prandgen;
	union silofs_alloc_u           alloc_u;
	struct silofs_alloc           *alloc;
	struct silofs_repo             repo;
	struct silofs_pcache           pcache;
	struct silofs_lcache           lcache;
	struct silofs_lspools          lspools;
	struct silofs_pspools          pspools;
	struct silofs_idsmap           idsmap;
	struct silofs_fsroot           fsroot;
	struct silofs_uber_ref         ubref;
	struct silofs_fuseq           *fuseq;
	const struct silofs_vfs_hooks *vfs_hooks;
	struct silofs_mutex            mutex;
	struct silofs_cipher_hd        enc_ci_hd;
	struct silofs_cipher_hd        dec_ci_hd;
	struct silofs_mdigest_hd       md_hd;
	struct silofs_opstat           opstat;
	struct silofs_cred             owner_cred;
	struct silofs_uconv            uconv;
	struct silofs_strbuf           name;
	char                          *repodir;
	long                           initf;
	size_t                         fscap;
	time_t                         init_time;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_setup(struct silofs_env *env, const struct silofs_spec *spec);

void silofs_env_bind_fuseq(struct silofs_env *env, struct silofs_fuseq *fq);

void silofs_env_lock(struct silofs_env *env);

void silofs_env_unlock(struct silofs_env *env);

void silofs_env_refresh_root(struct silofs_env         *env,
                             const struct silofs_pnptr *pnptr);

void silofs_env_relax_caches(struct silofs_env *env, int flags);

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime);

void silofs_env_allocstat(const struct silofs_env  *env,
                          struct silofs_alloc_stat *out_alst);

void silofs_env_drop_caches(struct silofs_env *env);

int silofs_env_shut(struct silofs_env *env);

int silofs_env_forkfs(struct silofs_env    *env,
                      struct silofs_mbrefs *out_mbrefs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_sense_mbr(struct silofs_env         *env,
                         const struct silofs_mbref *mbr);

int silofs_env_reinit_ciphers(struct silofs_env *env);

int silofs_env_commit_mbr(struct silofs_env   *env,
                          struct silofs_mbref *out_mbref);

int silofs_env_reload_mbr(struct silofs_env         *env,
                          const struct silofs_mbref *mbref);

int silofs_env_unref_mbr(struct silofs_env         *env,
                         const struct silofs_mbref *mbref);

#endif /* SILOFS_ENV_H_ */
