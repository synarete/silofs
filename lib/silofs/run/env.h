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
	struct silofs_lblock          *nilbk;
	struct silofs_repo             repo;
	struct silofs_pcache           pcache;
	struct silofs_lcache           lcache;
	struct silofs_lspools          lspools;
	struct silofs_pspools          pspools;
	struct silofs_idsmap           idsmap;
	struct silofs_fsroot           fsroot;
	struct silofs_fuseq           *fuseq;
	const struct silofs_vfs_hooks *vfs_hooks;
	struct silofs_cipher_hd        enc_ci_hd;
	struct silofs_cipher_hd        dec_ci_hd;
	struct silofs_mdigest_hd       md_hd;
	struct silofs_cred             owner_cred;
	struct silofs_uconv            uconv;
	struct silofs_exec_refs        xrefs;
	struct silofs_strbuf           name;
	char                          *repodir;
	long                           initf;
	size_t                         fscap;
	time_t                         init_time;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_setup(struct silofs_env *env, const struct silofs_spec *spec);

void silofs_env_bind_fuseq(struct silofs_env *env, struct silofs_fuseq *fq);

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime);

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
