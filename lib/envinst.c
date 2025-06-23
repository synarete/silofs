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
#include "configs.h"
#include <sys/resource.h>
#include <silofs/ioctls.h>
#include "repo.h"
#include "pnodes.h"
#include "pcache.h"
#include "bstore.h"
#include "fs.h"
#include "bootrec.h"
#include "env.h"
#include "fuseq.h"
#include "private.h"

/* env initialization-state flags */
enum silofs_env_initf {
	SILOFS_ENVIF_QALLOC = SILOFS_BIT(0),
	SILOFS_ENVIF_STDALLOC = SILOFS_BIT(1),
	SILOFS_ENVIF_REPO = SILOFS_BIT(2),
	SILOFS_ENVIF_PCACHE = SILOFS_BIT(3),
	SILOFS_ENVIF_LCACHE = SILOFS_BIT(4),
	SILOFS_ENVIF_BOOTREC = SILOFS_BIT(5),
	SILOFS_ENVIF_SUBMITQ = SILOFS_BIT(6),
	SILOFS_ENVIF_IDSMAP = SILOFS_BIT(7),
	SILOFS_ENVIF_BSTORE = SILOFS_BIT(8),
	SILOFS_ENVIF_FLUSHER = SILOFS_BIT(9),
	SILOFS_ENVIF_FUSEQ = SILOFS_BIT(10),
	SILOFS_ENVIF_ENV = SILOFS_BIT(11),
};

/* memory allocator of choice */
union silofs_alloc_u {
	struct silofs_qalloc qalloc;
	struct silofs_stdalloc stdalloc;
};

/* actual environment instance object (internal) */
struct silofs_env_inst {
	struct silofs_password passwd;
	struct silofs_args args;
	union silofs_alloc_u alloc_u;
	struct silofs_repo repo;
	struct silofs_pcache pcache;
	struct silofs_lcache lcache;
	struct silofs_idsmap idsmap;
	struct silofs_bstore bstore;
	struct silofs_bootrec bootrec;
	struct silofs_submitq submitq;
	struct silofs_flusher flusher;
	struct silofs_env env;
	struct silofs_alloc *alloc;
	struct silofs_fuseq *fuseq;
	long initf;
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t align_down(size_t sz, size_t align)
{
	return (sz / align) * align;
}

static uint64_t minu64(uint64_t x, uint64_t y, uint64_t z)
{
	return silofs_min(silofs_min(x, y), z);
}

static int calc_mem_size(size_t mem_want, size_t *out_mem_size)
{
	const size_t mem_floor = SILOFS_UGIGA / 4;
	const size_t mem_glim = 64 * SILOFS_UGIGA;
	size_t mem_total = 0;
	size_t mem_rlim = 0;
	size_t mem_ceil = 0;
	size_t mem_uget = 0;
	int err;

	/* zero implies default value */
	if (mem_want == 0) {
		mem_want = 4 * SILOFS_GIGA;
	}

	err = silofs_memlimits(&mem_total, &mem_rlim);
	if (err) {
		return err;
	}
	if (mem_total < mem_floor) {
		return -SILOFS_ENOMEM;
	}
	if (mem_rlim < mem_floor) {
		return -SILOFS_ENOMEM;
	}
	mem_ceil = minu64(mem_glim, mem_rlim, mem_total / 4);
	mem_uget = silofs_clamp_u64(mem_want, mem_floor, mem_ceil);
	*out_mem_size = align_down(mem_uget, 2 * SILOFS_UMEGA);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int check_bootpath(const struct silofs_args *args)
{
	struct silofs_namestr nstr;
	const struct silofs_boot_args *boot_args = &args->boot;
	const size_t len = silofs_str_length(boot_args->repodir);
	int err;

	if (!len || (len >= SILOFS_REPOPATH_MAX)) {
		log_dbg("illegal repodir length: %s", boot_args->repodir);
		return -SILOFS_EINVAL;
	}
	if (boot_args->fsname != NULL) {
		err = silofs_make_namestr(&nstr, boot_args->fsname);
		if (err) {
			log_dbg("illegal fsname: %s", boot_args->fsname);
			return err;
		}
	}
	if (boot_args->arname != NULL) {
		err = silofs_make_namestr(&nstr, boot_args->arname);
		if (err) {
			log_dbg("illegal arname: %s", boot_args->arname);
			return err;
		}
	}
	return 0;
}

static int check_password(const struct silofs_args *args)
{
	struct silofs_password passwd;

	return silofs_password_setup(&passwd, args->boot.passwd);
}

static int check_args(const struct silofs_args *args)
{
	int err;

	err = check_bootpath(args);
	if (err) {
		return err;
	}
	err = check_password(args);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool
envi_has_flag(const struct silofs_env_inst *envi, enum silofs_flags f)
{
	return ((envi->args.flags & f) == f);
}

static int envi_init_qalloc(struct silofs_env_inst *envi)
{
	struct silofs_qalloc *qalloc = NULL;
	size_t memsize = 0;
	enum silofs_qallocf qaflags = SILOFS_QALLOCF_NOFAIL;
	int err;

	err = calc_mem_size(envi->args.memwant, &memsize);
	if (err) {
		return err;
	}
	if (envi->args.flags & SILOFS_F_PEDANTIC) {
		qaflags |= SILOFS_QALLOCF_DEMASK;
	}
	qalloc = &envi->alloc_u.qalloc;
	err = silofs_qalloc_init(qalloc, memsize, qaflags);
	if (err) {
		return err;
	}
	envi->alloc = &qalloc->alloc;
	envi->initf |= SILOFS_ENVIF_QALLOC;
	return 0;
}

static void envi_fini_qalloc(struct silofs_env_inst *envi)
{
	struct silofs_qalloc *qalloc = NULL;

	if (envi->initf & SILOFS_ENVIF_QALLOC) {
		qalloc = &envi->alloc_u.qalloc;
		silofs_qalloc_fini(qalloc);
		envi->alloc = NULL;
		envi->initf &= ~SILOFS_ENVIF_QALLOC;
	}
}

static int envi_init_stdalloc(struct silofs_env_inst *envi)
{
	struct silofs_stdalloc *stdalloc = NULL;
	size_t memsize = 0;
	int err;

	err = calc_mem_size(envi->args.memwant, &memsize);
	if (err) {
		return err;
	}
	stdalloc = &envi->alloc_u.stdalloc;
	err = silofs_stdalloc_init(stdalloc, memsize);
	if (err) {
		return err;
	}
	envi->alloc = &stdalloc->alloc;
	envi->initf |= SILOFS_ENVIF_STDALLOC;
	return 0;
}

static void envi_fini_stdalloc(struct silofs_env_inst *envi)
{
	struct silofs_stdalloc *stdalloc = NULL;

	if (envi->initf & SILOFS_ENVIF_STDALLOC) {
		stdalloc = &envi->alloc_u.stdalloc;
		silofs_stdalloc_fini(stdalloc);
		envi->alloc = NULL;
		envi->initf &= ~SILOFS_ENVIF_STDALLOC;
	}
}

static int envi_init_alloc(struct silofs_env_inst *envi)
{
	int ret;

	if (envi->args.flags & SILOFS_F_STDALLOC) {
		ret = envi_init_stdalloc(envi);
	} else {
		ret = envi_init_qalloc(envi);
	}
	return ret;
}

static void envi_fini_alloc(struct silofs_env_inst *envi)
{
	if (envi->args.flags & SILOFS_F_STDALLOC) {
		envi_fini_stdalloc(envi);
	} else {
		envi_fini_qalloc(envi);
	}
}

static void envi_make_repo_base(const struct silofs_env_inst *envi,
				struct silofs_repo_base *re_base)
{
	silofs_memzero(re_base, sizeof(*re_base));
	re_base->alloc = envi->alloc;
	if (envi->args.flags & SILOFS_F_RDONLY) {
		re_base->flags |= SILOFS_REPOF_RDONLY;
	}
	silofs_strview_init(&re_base->repodir, envi->args.boot.repodir);
}

static int envi_init_repo(struct silofs_env_inst *envi)
{
	struct silofs_repo_base re_base = { .flags = 0 };
	struct silofs_repo *repo = &envi->repo;
	int err;

	envi_make_repo_base(envi, &re_base);
	err = silofs_repo_init(repo, &re_base);
	if (err) {
		return err;
	}
	envi->initf |= SILOFS_ENVIF_REPO;
	return 0;
}

static void envi_fini_repo(struct silofs_env_inst *envi)
{
	struct silofs_repo *repo = &envi->repo;

	if (envi->initf & SILOFS_ENVIF_REPO) {
		silofs_repo_fini(repo);
		envi->initf &= ~SILOFS_ENVIF_REPO;
	}
}

static int envi_init_pcache(struct silofs_env_inst *envi)
{
	struct silofs_pcache *pcache = &envi->pcache;
	int err;

	err = silofs_pcache_init(pcache, envi->alloc);
	if (err) {
		return err;
	}
	envi->initf |= SILOFS_ENVIF_PCACHE;
	return 0;
}

static void envi_fini_pcache(struct silofs_env_inst *envi)
{
	struct silofs_pcache *pcache = &envi->pcache;

	if (envi->initf & SILOFS_ENVIF_PCACHE) {
		silofs_pcache_fini(pcache);
		envi->initf &= ~SILOFS_ENVIF_PCACHE;
	}
}

static int envi_init_bstore(struct silofs_env_inst *envi)
{
	struct silofs_bstore *bstore = &envi->bstore;
	int err;

	err = silofs_bstore_init(bstore, &envi->pcache, &envi->repo);
	if (err) {
		return err;
	}
	envi->initf |= SILOFS_ENVIF_BSTORE;
	return 0;
}

static void envi_fini_bstore(struct silofs_env_inst *envi)
{
	struct silofs_bstore *bstore = &envi->bstore;

	if (envi->initf & SILOFS_ENVIF_BSTORE) {
		silofs_bstore_fini(bstore);
		envi->initf &= ~SILOFS_ENVIF_BSTORE;
	}
}

static int envi_init_lcache(struct silofs_env_inst *envi)
{
	struct silofs_lcache *lcache = &envi->lcache;
	int err;

	err = silofs_lcache_init(lcache, envi->alloc);
	if (err) {
		return err;
	}
	envi->initf |= SILOFS_ENVIF_LCACHE;
	return 0;
}

static void envi_fini_lcache(struct silofs_env_inst *envi)
{
	struct silofs_lcache *lcache = &envi->lcache;

	if (envi->initf & SILOFS_ENVIF_LCACHE) {
		silofs_lcache_fini(lcache);
		envi->initf &= ~SILOFS_ENVIF_LCACHE;
	}
}

static int envi_init_bootrec(struct silofs_env_inst *envi)
{
	silofs_bootrec_init(&envi->bootrec);
	envi->initf |= SILOFS_ENVIF_BOOTREC;
	return 0;
}

static void envi_fini_bootrec(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_LCACHE) {
		silofs_bootrec_fini(&envi->bootrec);
		envi->initf &= ~SILOFS_ENVIF_BOOTREC;
	}
}

static int envi_init_submitq(struct silofs_env_inst *envi)
{
	struct silofs_submitq *submitq = &envi->submitq;
	int err;

	err = silofs_submitq_init(submitq, envi->alloc);
	if (err) {
		return err;
	}
	envi->initf |= SILOFS_ENVIF_SUBMITQ;
	return 0;
}

static void envi_fini_submitq(struct silofs_env_inst *envi)
{
	struct silofs_submitq *submitq = &envi->submitq;

	if (envi->initf & SILOFS_ENVIF_SUBMITQ) {
		silofs_submitq_fini(submitq);
		envi->initf &= ~SILOFS_ENVIF_SUBMITQ;
	}
}

static int envi_init_flusher(struct silofs_env_inst *envi)
{
	struct silofs_flusher *flusher = &envi->flusher;
	int err;

	err = silofs_flusher_init(flusher, &envi->bootrec, &envi->submitq);
	if (err) {
		return err;
	}
	envi->initf |= SILOFS_ENVIF_FLUSHER;
	return 0;
}

static void envi_fini_flusher(struct silofs_env_inst *envi)
{
	struct silofs_flusher *flusher = &envi->flusher;

	if (envi->initf & SILOFS_ENVIF_FLUSHER) {
		silofs_flusher_fini(flusher);
		envi->initf &= ~SILOFS_ENVIF_FLUSHER;
	}
}

static int envi_init_idsmap(struct silofs_env_inst *envi)
{
	const struct silofs_ugids *ids = &envi->args.ugids;
	struct silofs_idsmap *idsmap = &envi->idsmap;
	bool allow_hostids;
	int err;

	allow_hostids = envi_has_flag(envi, SILOFS_F_ALLOWHOSTIDS);
	err = silofs_idsmap_init(idsmap, envi->alloc, allow_hostids);
	if (err) {
		return err;
	}
	err = silofs_idsmap_populate_uids(idsmap, ids);
	if (err) {
		silofs_idsmap_fini(idsmap);
		return err;
	}
	err = silofs_idsmap_populate_gids(idsmap, ids);
	if (err) {
		silofs_idsmap_fini(idsmap);
		return err;
	}
	envi->initf |= SILOFS_ENVIF_IDSMAP;
	return 0;
}

static void envi_fini_idsmap(struct silofs_env_inst *envi)
{
	struct silofs_idsmap *idsmap = &envi->idsmap;

	if (envi->initf & SILOFS_ENVIF_IDSMAP) {
		silofs_idsmap_clear(idsmap);
		silofs_idsmap_fini(idsmap);
		envi->initf &= ~SILOFS_ENVIF_IDSMAP;
	}
}

static bool envi_with_fuse(const struct silofs_env_inst *envi)
{
	const enum silofs_flags flags = envi->args.flags;

	return (flags & SILOFS_F_WITHFUSE) > 0;
}

static void
envi_update_fuseq(const struct silofs_env_inst *envi, struct silofs_fuseq *fq)
{
	const enum silofs_flags flags = envi->args.flags;

	fq->fq_writeback_cache = (flags & SILOFS_F_WRITEBACK) > 0;
	fq->fq_may_splice = (flags & SILOFS_F_MAYSPLICE) > 0;
}

static int envi_init_fuseq(struct silofs_env_inst *envi)
{
	struct silofs_fuseq *fq = NULL;
	int err;

	if (!envi_with_fuse(envi)) {
		return 0;
	}
	err = silofs_fuseq_new(envi->alloc, &fq);
	if (err) {
		return err;
	}
	envi_update_fuseq(envi, fq);

	envi->initf |= SILOFS_ENVIF_FUSEQ;
	envi->fuseq = fq;
	return 0;
}

static void envi_fini_fuseq(struct silofs_env_inst *envi)
{
	struct silofs_fuseq *fq = envi->fuseq;

	if (envi->initf & SILOFS_ENVIF_FUSEQ) {
		silofs_fuseq_del(fq, envi->alloc);
		envi->fuseq = NULL;
		envi->initf &= ~SILOFS_ENVIF_FUSEQ;
	}
}

static int envi_init_env(struct silofs_env_inst *envi)
{
	const struct silofs_env_base env_base = {
		.args = &envi->args,
		.alloc = envi->alloc,
		.repo = &envi->repo,
		.pcache = &envi->pcache,
		.bstore = &envi->bstore,
		.lcache = &envi->lcache,
		.bootrec = &envi->bootrec,
		.submitq = &envi->submitq,
		.flusher = &envi->flusher,
		.idsmap = &envi->idsmap,
		.fuseq = envi->fuseq,
	};
	struct silofs_env *env = &envi->env;
	int err;

	err = silofs_env_init(env, &env_base);
	if (err) {
		return err;
	}
	envi->initf |= SILOFS_ENVIF_ENV;
	err = silofs_env_setup(env, &envi->passwd);
	if (err) {
		return err;
	}
	return 0;
}

static void envi_fini_env(struct silofs_env_inst *envi)
{
	struct silofs_env *env = &envi->env;

	if (envi->initf & SILOFS_ENVIF_ENV) {
		silofs_env_fini(env);
		envi->initf &= ~SILOFS_ENVIF_ENV;
	}
}

static int envi_init_passwd(struct silofs_env_inst *envi)
{
	return silofs_password_setup(&envi->passwd, envi->args.boot.passwd);
}

static void envi_fini_passwd(struct silofs_env_inst *envi)
{
	silofs_password_reset(&envi->passwd);
}

static void envi_fini(struct silofs_env_inst *envi)
{
	envi_fini_env(envi);
	envi_fini_fuseq(envi);
	envi_fini_idsmap(envi);
	envi_fini_flusher(envi);
	envi_fini_submitq(envi);
	envi_fini_bootrec(envi);
	envi_fini_lcache(envi);
	envi_fini_bstore(envi);
	envi_fini_pcache(envi);
	envi_fini_repo(envi);
	envi_fini_alloc(envi);
	envi_fini_passwd(envi);
}

static int
envi_init_args(struct silofs_env_inst *envi, const struct silofs_args *args)
{
	int err;

	err = check_args(args);
	if (err) {
		return err;
	}
	memcpy(&envi->args, args, sizeof(envi->args));
	return 0;
}

static int
envi_init(struct silofs_env_inst *envi, const struct silofs_args *args)
{
	int err;

	err = envi_init_args(envi, args);
	if (err) {
		goto out_err;
	}
	err = envi_init_passwd(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_alloc(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_repo(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_pcache(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_bstore(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_lcache(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_bootrec(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_submitq(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_flusher(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_idsmap(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_fuseq(envi);
	if (err) {
		goto out_err;
	}
	err = envi_init_env(envi);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	envi_fini(envi);
	return err;
}

static size_t envi_memsize(const struct silofs_env_inst *envi)
{
	const size_t pgsz = (size_t)silofs_sc_page_size();
	const size_t ensz = sizeof(*envi);

	return silofs_div_round_up(ensz, pgsz) * pgsz;
}

static int
envi_new(const struct silofs_args *args, struct silofs_env_inst **out_envi)
{
	struct silofs_env_inst *envi = NULL;
	const size_t msz = envi_memsize(envi);
	void *mem = NULL;
	int err;

	err = silofs_zmalloc(msz, &mem);
	if (err) {
		return err;
	}
	envi = mem;
	err = envi_init(envi, args);
	if (err) {
		silofs_zfree(mem, msz);
		return err;
	}
	*out_envi = envi;
	return 0;
}

static void envi_del(struct silofs_env_inst *envi)
{
	const size_t msz = envi_memsize(envi);
	void *mem = envi;

	envi_fini(envi);
	silofs_zfree(mem, msz);
}

int silofs_create_env(const struct silofs_args *args,
		      struct silofs_env **out_env)
{
	struct silofs_env_inst *envi = NULL;
	int err = 0;

	STATICASSERT_LE(sizeof(*envi), 16 * SILOFS_KILO);

	err = check_args(args);
	if (err) {
		goto out;
	}
	err = envi_new(args, &envi);
	if (err) {
		goto out;
	}
	*out_env = &envi->env;
out:
	silofs_burnstack();
	return err;
}

static struct silofs_env_inst *env_inst_of(struct silofs_env *env)
{
	return container_of(env, struct silofs_env_inst, env);
}

void silofs_destroy_env(struct silofs_env *env)
{
	struct silofs_env_inst *envi = NULL;

	envi = env_inst_of(env);
	envi_del(envi);
	silofs_burnstack();
}
