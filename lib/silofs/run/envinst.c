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
#include <silofs/configs.h>
#include <sys/resource.h>

#include <silofs/ioctls.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/fuseq.h>
#include <silofs/run.h>

/* env initialization-state flags */
enum silofs_env_initf {
	SILOFS_ENVIF_PRANDGEN = SILOFS_BIT(0),
	SILOFS_ENVIF_QALLOC   = SILOFS_BIT(1),
	SILOFS_ENVIF_STDALLOC = SILOFS_BIT(2),
	SILOFS_ENVIF_REPO     = SILOFS_BIT(3),
	SILOFS_ENVIF_PCACHE   = SILOFS_BIT(4),
	SILOFS_ENVIF_VCACHE   = SILOFS_BIT(5),
	SILOFS_ENVIF_FREESQS  = SILOFS_BIT(6),
	SILOFS_ENVIF_SPAMAPS  = SILOFS_BIT(7),
	SILOFS_ENVIF_IDSMAP   = SILOFS_BIT(9),
	SILOFS_ENVIF_FUSEQ    = SILOFS_BIT(11),
	SILOFS_ENVIF_ENV      = SILOFS_BIT(12),
};

/* memory allocator of choice */
union silofs_alloc_u {
	struct silofs_qalloc qalloc;
	struct silofs_stdalloc stdalloc;
};

/* actual environment instance object (internal) */
struct silofs_env_inst {
	struct silofs_prandgen prandgen;
	union silofs_alloc_u alloc_u;
	struct silofs_repo repo;
	struct silofs_pcache pcache;
	struct silofs_vcache vcache;
	struct silofs_freevsqs fvsqs;
	struct silofs_freepaqs fpaqs;
	struct silofs_spamaps spamaps;
	struct silofs_idsmap idsmap;
	struct silofs_env env;
	struct silofs_alloc *alloc;
	struct silofs_lblock *nilbk;
	struct silofs_fuseq *fuseq;
	long initf;
};

/* Local functions */
static void envi_unbind_fuseq(struct silofs_env_inst *envi);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t align_down(size_t sz, size_t align)
{
	return (sz / align) * align;
}

static uint64_t min3_u64(uint64_t x, uint64_t y, uint64_t z)
{
	return silofs_min(silofs_min(x, y), z);
}

static uint64_t clamp_u64(uint64_t v, uint64_t lo, uint64_t hi)
{
	return silofs_clamp_u64(v, lo, hi);
}

static int calc_mem_size(size_t mem_want, size_t *out_mem_size)
{
	const size_t mem_floor = SILOFS_UGIGA / 4;
	const size_t mem_glim  = 64 * SILOFS_UGIGA;
	size_t mem_total       = 0;
	size_t mem_rlim        = 0;
	size_t mem_ceil        = 0;
	size_t mem_uget        = 0;
	int err;

	/* zero implies default value */
	if (mem_want == 0) {
		mem_want = 4 * SILOFS_GIGA;
	}

	err = silofs_memlimits(&mem_total, &mem_rlim);
	if (err) {
		return err;
	}
	if ((mem_total < mem_floor) || (mem_rlim < mem_floor)) {
		return -SILOFS_ENOMEM;
	}

	mem_ceil = min3_u64(mem_glim, mem_rlim, mem_total / 4);
	mem_uget = clamp_u64(mem_want, mem_floor, mem_ceil);

	*out_mem_size = align_down(mem_uget, 2 * SILOFS_UMEGA);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int check_baseref_repodir(const struct silofs_baseref *baseref)
{
	size_t len;
	int ret = 0;

	len = silofs_str_length(baseref->repodir);
	if (len >= SILOFS_REPOPATH_MAX) {
		log_dbg("repodir too-long: %s", baseref->repodir);
		ret = -SILOFS_EINVAL;
	}
	return ret;
}

static int check_baseref_refname(const struct silofs_baseref *baseref)
{
	struct silofs_namestr nstr;
	int ret = 0;

	if (baseref->refname != nullptr) {
		ret = silofs_namestr_init(&nstr, baseref->refname);
		if (ret) {
			log_dbg("illegal refname: %s", baseref->refname);
		}
	}
	return ret;
}

static int check_baseref(const struct silofs_baseref *baseref)
{
	int err;

	err = check_baseref_repodir(baseref);
	if (err) {
		return err;
	}
	err = check_baseref_refname(baseref);
	if (err) {
		return err;
	}
	return 0;
}

static int check_baserefs(const struct silofs_spec *spec)
{
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(spec->bref); ++i) {
		err = check_baseref(&spec->bref[i]);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int check_password(const struct silofs_spec *spec)
{
	int ret = 0;

	if ((spec->flags & SILOFS_F_NOPASSWD) == 0) {
		ret = silofs_password_recheck(&spec->passwd);
	}
	return ret;
}

static int check_spec(const struct silofs_spec *spec)
{
	int err;

	err = check_baserefs(spec);
	if (err) {
		return err;
	}
	err = check_password(spec);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int envi_init_qalloc(struct silofs_env_inst *envi, size_t memwant,
                            enum silofs_flags flags)
{
	struct silofs_qalloc *qalloc = nullptr;
	enum silofs_qallocf qaflags  = SILOFS_QALLOCF_NOFAIL;
	size_t memsize;
	int err;

	err = calc_mem_size(memwant, &memsize);
	if (err) {
		return err;
	}
	if (flags & SILOFS_F_PEDANTIC) {
		qaflags |= SILOFS_QALLOCF_DEMASK;
	}
	qalloc = &envi->alloc_u.qalloc;
	err    = silofs_qalloc_init(qalloc, memsize, qaflags);
	if (err) {
		return err;
	}
	envi->alloc = &qalloc->alloc;
	envi->initf |= SILOFS_ENVIF_QALLOC;
	return 0;
}

static void envi_fini_qalloc(struct silofs_env_inst *envi)
{
	struct silofs_qalloc *qalloc = nullptr;

	if (envi->initf & SILOFS_ENVIF_QALLOC) {
		qalloc = &envi->alloc_u.qalloc;
		silofs_qalloc_fini(qalloc);
		envi->alloc = nullptr;
		envi->initf &= ~SILOFS_ENVIF_QALLOC;
	}
}

static int envi_init_stdalloc(struct silofs_env_inst *envi, size_t memwant)
{
	struct silofs_stdalloc *stdalloc = nullptr;
	size_t memsize;
	int err;

	err = calc_mem_size(memwant, &memsize);
	if (err) {
		return err;
	}
	stdalloc = &envi->alloc_u.stdalloc;
	err      = silofs_stdalloc_init(stdalloc, memsize);
	if (err) {
		return err;
	}
	envi->alloc = &stdalloc->alloc;
	envi->initf |= SILOFS_ENVIF_STDALLOC;
	return 0;
}

static void envi_fini_stdalloc(struct silofs_env_inst *envi)
{
	struct silofs_stdalloc *stdalloc = nullptr;

	if (envi->initf & SILOFS_ENVIF_STDALLOC) {
		stdalloc = &envi->alloc_u.stdalloc;
		silofs_stdalloc_fini(stdalloc);
		envi->alloc = nullptr;
		envi->initf &= ~SILOFS_ENVIF_STDALLOC;
	}
}

static int envi_init_alloc(struct silofs_env_inst *envi, size_t memwant,
                           enum silofs_flags flags)
{
	int ret;

	if (flags & SILOFS_F_STDALLOC) {
		ret = envi_init_stdalloc(envi, memwant);
	} else {
		ret = envi_init_qalloc(envi, memwant, flags);
	}
	return ret;
}

static void envi_fini_alloc(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_STDALLOC) {
		envi_fini_stdalloc(envi);
	} else if (envi->initf & SILOFS_ENVIF_QALLOC) {
		envi_fini_qalloc(envi);
	}
}

static int envi_init_nil_bk(struct silofs_env_inst *envi)
{
	struct silofs_lblock *lbk;

	lbk = silofs_memalloc(envi->alloc, sizeof(*lbk), SILOFS_ALLOCF_BZERO);
	if (lbk == nullptr) {
		return -SILOFS_ENOMEM;
	}
	envi->nilbk = lbk;
	return 0;
}

static void envi_fini_nil_bk(struct silofs_env_inst *envi)
{
	struct silofs_lblock *nilbk = envi->nilbk;

	if (nilbk != nullptr) {
		silofs_memfree(envi->alloc, nilbk, sizeof(*nilbk),
		               SILOFS_ALLOCF_TRYPUNCH);
		envi->nilbk = nullptr;
	}
}

static int envi_init_repo(struct silofs_env_inst *envi)
{
	int err;

	err = silofs_repo_init(&envi->repo, envi->alloc);
	return_if_err(err);

	envi->initf |= SILOFS_ENVIF_REPO;
	return 0;
}

static void envi_fini_repo(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_REPO) {
		silofs_repo_fini(&envi->repo);
		envi->initf &= ~SILOFS_ENVIF_REPO;
	}
}

static int envi_init_pcache(struct silofs_env_inst *envi)
{
	int err;

	err = silofs_pcache_init(&envi->pcache, envi->alloc);
	return_if_err(err);

	envi->initf |= SILOFS_ENVIF_PCACHE;
	return 0;
}

static void envi_fini_pcache(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_PCACHE) {
		silofs_pcache_fini(&envi->pcache);
		envi->initf &= ~SILOFS_ENVIF_PCACHE;
	}
}

static int envi_init_vcache(struct silofs_env_inst *envi)
{
	int err;

	err = silofs_vcache_init(&envi->vcache, envi->alloc);
	return_if_err(err);

	envi->initf |= SILOFS_ENVIF_VCACHE;
	return 0;
}

static void envi_fini_vcache(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_VCACHE) {
		silofs_vcache_fini(&envi->vcache);
		envi->initf &= ~SILOFS_ENVIF_VCACHE;
	}
}

static int envi_init_freesqs(struct silofs_env_inst *envi)
{
	int err;

	err = silofs_freevsqs_init(&envi->fvsqs, envi->alloc);
	return_if_err(err);

	silofs_freepaqs_init(&envi->fpaqs, envi->alloc);
	envi->initf |= SILOFS_ENVIF_FREESQS;
	return 0;
}

static void envi_fini_freesqs(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_FREESQS) {
		silofs_freepaqs_fini(&envi->fpaqs);
		silofs_freevsqs_fini(&envi->fvsqs);
		envi->initf &= ~SILOFS_ENVIF_FREESQS;
	}
}

static int envi_init_spamaps(struct silofs_env_inst *envi)
{
	int err;

	err = silofs_spamaps_init(&envi->spamaps, envi->alloc);
	return_if_err(err);

	envi->initf |= SILOFS_ENVIF_SPAMAPS;
	return 0;
}

static void envi_fini_spamaps(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_SPAMAPS) {
		silofs_spamaps_fini(&envi->spamaps);
		envi->initf &= ~SILOFS_ENVIF_SPAMAPS;
	}
}

static int envi_init_idsmap(struct silofs_env_inst *envi)
{
	struct silofs_idsmap *idsmap = &envi->idsmap;
	int err;

	err = silofs_idsmap_init(idsmap, envi->alloc);
	return_if_err(err);

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

static int envi_init_env(struct silofs_env_inst *envi)
{
	const struct silofs_env_base env_base = {
		.prng    = &envi->prandgen,
		.nilbk   = envi->nilbk,
		.repo    = &envi->repo,
		.dstor   = &envi->repo.re_dstor,
		.pcache  = &envi->pcache,
		.vcache  = &envi->vcache,
		.fvsqs   = &envi->fvsqs,
		.fpaqs   = &envi->fpaqs,
		.spamaps = &envi->spamaps,
		.idsmap  = &envi->idsmap,
	};
	struct silofs_env *env = &envi->env;
	int err;

	err = silofs_env_init(env, envi->alloc);
	return_if_err(err);

	silofs_env_use(env, &env_base);
	envi->initf |= SILOFS_ENVIF_ENV;
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

static int envi_init_prandgen(struct silofs_env_inst *envi)
{
	int err;

	err = silofs_prandgen_init(&envi->prandgen);
	return_if_err(err);

	envi->initf |= SILOFS_ENVIF_PRANDGEN;
	return 0;
}

static void envi_fini_prandgen(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_PRANDGEN) {
		silofs_prandgen_fini(&envi->prandgen);
		envi->initf &= ~SILOFS_ENVIF_PRANDGEN;
	}
}

static void envi_fini(struct silofs_env_inst *envi)
{
	envi_unbind_fuseq(envi);
	envi_fini_env(envi);
	envi_fini_idsmap(envi);
	envi_fini_spamaps(envi);
	envi_fini_freesqs(envi);
	envi_fini_vcache(envi);
	envi_fini_pcache(envi);
	envi_fini_repo(envi);
	envi_fini_nil_bk(envi);
	envi_fini_alloc(envi);
	envi_fini_prandgen(envi);
}

static int envi_init(struct silofs_env_inst *envi, size_t memwant,
                     enum silofs_flags flags)
{
	int err;

	err = envi_init_prandgen(envi);
	goto_out_if_err(err);

	err = envi_init_alloc(envi, memwant, flags);
	goto_out_if_err(err);

	err = envi_init_nil_bk(envi);
	goto_out_if_err(err);

	err = envi_init_repo(envi);
	goto_out_if_err(err);

	err = envi_init_pcache(envi);
	goto_out_if_err(err);

	err = envi_init_vcache(envi);
	goto_out_if_err(err);

	err = envi_init_freesqs(envi);
	goto_out_if_err(err);

	err = envi_init_spamaps(envi);
	goto_out_if_err(err);

	err = envi_init_idsmap(envi);
	goto_out_if_err(err);

	err = envi_init_env(envi);
	goto_out_if_err(err);

	return 0;
out:
	envi_fini(envi);
	return err;
}

static size_t envi_memsize(const struct silofs_env_inst *envi)
{
	constexpr size_t ensz = sizeof(*envi);
	const size_t pgsz     = (size_t)silofs_sc_page_size();
	const size_t npgs     = silofs_div_round_up(ensz, pgsz);

	return npgs * pgsz;
}

static int envi_new(size_t memwant, enum silofs_flags flags,
                    struct silofs_env_inst **out_envi)

{
	struct silofs_env_inst *envi = nullptr;
	size_t msz;
	void *mem;
	int err;

	msz = envi_memsize(envi);
	err = silofs_zmalloc(msz, &mem);
	if (err) {
		return err;
	}
	envi = mem;
	err  = envi_init(envi, memwant, flags);
	if (err) {
		return err;
	}
	*out_envi = envi;
	return 0;
}

static void envi_del(struct silofs_env_inst *envi)
{
	const size_t msz = envi_memsize(envi);
	void *mem        = envi;

	envi_fini(envi);
	silofs_zfree(mem, msz);
}

int silofs_create_env(size_t memwant, enum silofs_flags flags,
                      struct silofs_env **out_env)
{
	struct silofs_env_inst *envi;
	int err;

	STATICASSERT_LE(sizeof(*envi), 64 * SILOFS_KILO);

	err = envi_new(memwant, flags, &envi);
	if (!err) {
		*out_env = &envi->env;
	}
	silofs_burnstack();

	return err;
}

static struct silofs_env_inst *env_inst_of(struct silofs_env *env)
{
	return mut_container_of(env, struct silofs_env_inst, env);
}

void silofs_destroy_env(struct silofs_env *env)
{
	struct silofs_env_inst *envi = nullptr;

	envi = env_inst_of(env);
	envi_del(envi);
	silofs_burnstack();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int envi_populate_idsmap(struct silofs_env_inst *envi,
                                const struct silofs_spec *spec)
{
	struct silofs_idsmap *idsmap = &envi->idsmap;
	bool allow_hostids;

	allow_hostids = (spec->flags & SILOFS_F_ALLOW_HOSTIDS) > 0;
	return silofs_idsmap_populate(idsmap, &spec->fsids, allow_hostids);
}

static int
envi_attach_fuseq(struct silofs_env_inst *envi, const struct silofs_spec *spec)
{
	struct silofs_fuseq *fuseq;

	fuseq = silofs_fuseq_new(envi->alloc, spec->flags);
	if (fuseq == nullptr) {
		log_warn("failed to create fuseq: flags=0x%x", spec->flags);
		return -SILOFS_ENOMEM;
	}
	envi->initf |= SILOFS_ENVIF_FUSEQ;
	envi->fuseq = fuseq;

	silofs_env_bind_fuseq(&envi->env, fuseq);
	return 0;
}

static void envi_unbind_fuseq(struct silofs_env_inst *envi)
{
	if (envi->initf & SILOFS_ENVIF_FUSEQ) {
		silofs_fuseq_del(envi->fuseq, envi->alloc);
		envi->fuseq = envi->env.fuseq = nullptr;
		envi->initf &= ~SILOFS_ENVIF_FUSEQ;
	}
}

static bool with_fuse(const struct silofs_spec *args)
{
	return (args->flags & SILOFS_F_WITH_FUSE) > 0;
}

static int envi_update_by_spec(struct silofs_env_inst *envi,
                               const struct silofs_spec *spec)
{
	return silofs_env_setup(&envi->env, spec);
}

int silofs_open_env(struct silofs_env *env, const struct silofs_spec *spec)
{
	struct silofs_env_inst *envi = env_inst_of(env);
	int err;

	err = check_spec(spec);
	if (err) {
		return err;
	}
	err = envi_update_by_spec(envi, spec);
	if (err) {
		return err;
	}
	err = envi_populate_idsmap(envi, spec);
	if (err) {
		return err;
	}
	if (!with_fuse(spec)) {
		return 0;
	}
	err = envi_attach_fuseq(envi, spec);
	if (err) {
		return err;
	}
	return 0;
}
