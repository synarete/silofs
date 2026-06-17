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
#include <silofs/base.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/run/mbr.h>

/* top-level operations counters/stats */
struct silofs_env_opstat {
	size_t op_iopen_max;
	size_t op_iopen;
	size_t op_count;
	/* TODO: Have counter per-operation */
};

/* environment meta settings */
struct silofs_env_base {
	struct silofs_prandgen *prng;
	struct silofs_lblock   *nilbk;
	struct silofs_repo     *repo;
	struct silofs_dstor    *dstor;
	struct silofs_pcache   *pcache;
	struct silofs_lcache   *lcache;
	struct silofs_vspmaps  *vspmaps;
	struct silofs_spamaps  *spamaps;
	struct silofs_submitq  *submitq;
	struct silofs_flusher  *flusher;
	struct silofs_idsmap   *idsmap;
};

/* main boot-records info */
struct silofs_env_mbis {
	struct silofs_mbr_info fs_mbi;
	struct silofs_mbr_info ar_mbi;
};

/* top-level environment object */
struct silofs_env {
	struct silofs_strbuf           name;
	struct silofs_alloc           *alloc;
	struct silofs_env_base         base;
	struct silofs_env_mbis         mbis;
	struct silofs_rwlock           rwlock;
	struct silofs_mutex            mutex;
	struct silofs_cipher_hd        enc_ci_hd;
	struct silofs_cipher_hd        dec_ci_hd;
	struct silofs_mdigest_hd       md_hd;
	struct silofs_env_opstat       opstat;
	struct silofs_uber_ref         ubref;
	struct silofs_sb_info         *sbi;
	struct silofs_fuseq           *fuseq;
	const struct silofs_vfs_hooks *vfs_hooks;
	struct silofs_cred             owner_cred;
	struct silofs_uconv            uconv;
	char                          *repodir;
	size_t                         fscap;
	time_t                         init_time;
	bool                           iconv_set;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_init(struct silofs_env *env, struct silofs_alloc *alloc);

void silofs_env_fini(struct silofs_env *env);

void silofs_env_use(struct silofs_env            *env,
                    const struct silofs_env_base *base);

int silofs_env_setup(struct silofs_env *env, const struct silofs_spec *spec);

void silofs_env_bind_fuseq(struct silofs_env *env, struct silofs_fuseq *fq);

void silofs_env_bind_hooks(struct silofs_env *env);

void silofs_env_lock(struct silofs_env *env);

void silofs_env_unlock(struct silofs_env *env);

void silofs_env_rwlock(struct silofs_env *env, bool ex);

void silofs_env_rwunlock(struct silofs_env *env);

void silofs_env_refresh_root(struct silofs_env         *env,
                             const struct silofs_pnptr *pnptr);

int silofs_env_format_super(struct silofs_env *env, size_t capacity);

int silofs_env_reload_super(struct silofs_env *env);

int silofs_env_reload_sb_lseg(struct silofs_env *env);

void silofs_env_relax_caches(const struct silofs_env *env, int flags);

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime);

void silofs_env_allocstat(const struct silofs_env  *env,
                          struct silofs_alloc_stat *out_alst);

void silofs_env_drop_caches(struct silofs_env *env);

bool silofs_env_hasflag(const struct silofs_env *env, enum silofs_flags f);

int silofs_env_shut(struct silofs_env *env);

int silofs_env_forkfs(struct silofs_env    *env,
                      struct silofs_mbrefs *out_mbrefs);

int silofs_env_export_ar_mbr(struct silofs_env   *env,
                             struct silofs_mbref *out_mbref,
                             struct silofs_mbr1k *out_mbr1k);

bool silofs_env_isrdonlyfs(const struct silofs_env *env);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_sense_mbr(struct silofs_env         *env,
                         const struct silofs_mbref *mbr);

int silofs_env_reinit_ciphers(struct silofs_env *env);

int silofs_env_commit_fs_mbr(struct silofs_env   *env,
                             struct silofs_mbref *out_mbref);

int silofs_env_reload_fs_mbr(struct silofs_env         *env,
                             const struct silofs_mbref *mbref);

int silofs_env_reload_ar_mbr(struct silofs_env         *env,
                             const struct silofs_mbref *mbref);

int silofs_env_unref_fs_mbr(struct silofs_env         *env,
                            const struct silofs_mbref *mbref);

#endif /* SILOFS_ENV_H_ */
