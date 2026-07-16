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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <silofs/pstor.h>
#include <silofs/fs.h>
#include <silofs/bridge.h>
#include <silofs/run.h>

/* env initialization-state flags */
enum silofs_env_initf {
	SILOFS_ENVF_QALLOC   = SILOFS_BIT(0),
	SILOFS_ENVF_STDALLOC = SILOFS_BIT(1),
	SILOFS_ENVF_NILBK    = SILOFS_BIT(2),
	SILOFS_ENVF_PRANDGEN = SILOFS_BIT(3),
	SILOFS_ENVF_CRYPT    = SILOFS_BIT(4),
	SILOFS_ENVF_UCONV    = SILOFS_BIT(5),
	SILOFS_ENVF_REPO     = SILOFS_BIT(6),
	SILOFS_ENVF_PCACHE   = SILOFS_BIT(7),
	SILOFS_ENVF_LCACHE   = SILOFS_BIT(8),
	SILOFS_ENVF_FREESQS  = SILOFS_BIT(9),
	SILOFS_ENVF_IDSMAP   = SILOFS_BIT(10),
	SILOFS_ENVF_FSROOT   = SILOFS_BIT(11),
	SILOFS_ENVF_FUSEQ    = SILOFS_BIT(12),
};

/* Local functions */
static void env_unbind_fuseq(struct silofs_env *env);

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
	return_if_err(err);

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
	return_if_err(err);

	err = check_baseref_refname(baseref);
	return_if_err(err);

	return 0;
}

static int check_baserefs(const struct silofs_spec *spec)
{
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(spec->bref); ++i) {
		err = check_baseref(&spec->bref[i]);
		return_if_err(err);
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
	return_if_err(err);

	err = check_password(spec);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_qallocf qaflags_by(enum silofs_flags flags)
{
	enum silofs_qallocf qaflags = SILOFS_QALLOCF_NOFAIL;

	if (flags & SILOFS_F_PEDANTIC) {
		qaflags |= SILOFS_QALLOCF_DEMASK;
	}
	return qaflags;
}

static int env_init_qalloc(struct silofs_env *env, size_t memwant,
                           enum silofs_flags flags)
{
	struct silofs_qalloc *qalloc = &env->alloc_u.qalloc;
	size_t memsize;
	int err;

	err = calc_mem_size(memwant, &memsize);
	return_if_err(err);

	err = silofs_qalloc_init(qalloc, memsize, qaflags_by(flags));
	return_if_err(err);

	env->alloc = &qalloc->alloc;
	env->initf |= SILOFS_ENVF_QALLOC;
	return 0;
}

static void env_fini_qalloc(struct silofs_env *env)
{
	struct silofs_qalloc *qalloc = nullptr;

	if (env->initf & SILOFS_ENVF_QALLOC) {
		qalloc = &env->alloc_u.qalloc;
		silofs_qalloc_fini(qalloc);
		env->alloc = nullptr;
		env->initf &= ~SILOFS_ENVF_QALLOC;
	}
}

static int env_init_stdalloc(struct silofs_env *env, size_t memwant)
{
	struct silofs_stdalloc *stdalloc = &env->alloc_u.stdalloc;
	size_t memsize;
	int err;

	err = calc_mem_size(memwant, &memsize);
	return_if_err(err);

	err = silofs_stdalloc_init(stdalloc, memsize);
	return_if_err(err);

	env->alloc = &stdalloc->alloc;
	env->initf |= SILOFS_ENVF_STDALLOC;
	return 0;
}

static void env_fini_stdalloc(struct silofs_env *env)
{
	struct silofs_stdalloc *stdalloc = nullptr;

	if (env->initf & SILOFS_ENVF_STDALLOC) {
		stdalloc = &env->alloc_u.stdalloc;
		silofs_stdalloc_fini(stdalloc);
		env->alloc = nullptr;
		env->initf &= ~SILOFS_ENVF_STDALLOC;
	}
}

static int
env_init_alloc(struct silofs_env *env, size_t memwant, enum silofs_flags flags)
{
	int ret;

	if (flags & SILOFS_F_STDALLOC) {
		ret = env_init_stdalloc(env, memwant);
	} else {
		ret = env_init_qalloc(env, memwant, flags);
	}
	return ret;
}

static void env_fini_alloc(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_STDALLOC) {
		env_fini_stdalloc(env);
	} else if (env->initf & SILOFS_ENVF_QALLOC) {
		env_fini_qalloc(env);
	}
}

static int env_init_fsroot(struct silofs_env *env)
{
	int err;

	err = silofs_fsroot_init(&env->fsroot);
	return_if_err(err);

	env->initf |= SILOFS_ENVF_FSROOT;
	return 0;
}

static void env_fini_fsroot(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_FSROOT) {
		silofs_fsroot_fini(&env->fsroot);
		env->initf &= ~SILOFS_ENVF_FSROOT;
	}
}

static int env_init_crypt(struct silofs_env *env)
{
	int err;

	err = silofs_mdigest_init(&env->md_hd);
	return_if_err(err);

	err = silofs_cipher_init(&env->enc_ci_hd);
	goto_if_err(err, out_err);

	err = silofs_cipher_init(&env->dec_ci_hd);
	goto_if_err(err, out_err);

	env->initf |= SILOFS_ENVF_CRYPT;
	return 0;
out_err:
	silofs_cipher_fini(&env->dec_ci_hd);
	silofs_cipher_fini(&env->enc_ci_hd);
	silofs_mdigest_fini(&env->md_hd);
	return err;
}

static void env_fini_crypt(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_CRYPT) {
		silofs_cipher_fini(&env->dec_ci_hd);
		silofs_cipher_fini(&env->enc_ci_hd);
		silofs_mdigest_fini(&env->md_hd);
		env->initf &= ~SILOFS_ENVF_CRYPT;
	}
}

static int env_init_uconv(struct silofs_env *env)
{
	return silofs_uconv_init(&env->uconv);
}

static void env_fini_uconv(struct silofs_env *env)
{
	silofs_uconv_fini(&env->uconv);
}

static int env_init_repo(struct silofs_env *env)
{
	int err;

	err = silofs_repo_init(&env->repo, env->alloc);
	return_if_err(err);

	env->initf |= SILOFS_ENVF_REPO;
	return 0;
}

static void env_fini_repo(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_REPO) {
		silofs_repo_fini(&env->repo);
		env->initf &= ~SILOFS_ENVF_REPO;
	}
}

static int env_init_pcache(struct silofs_env *env)
{
	int err;

	err = silofs_pcache_init(&env->pcache, env->alloc);
	return_if_err(err);

	env->initf |= SILOFS_ENVF_PCACHE;
	return 0;
}

static void env_fini_pcache(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_PCACHE) {
		silofs_pcache_fini(&env->pcache);
		env->initf &= ~SILOFS_ENVF_PCACHE;
	}
}

static int env_init_lcache(struct silofs_env *env)
{
	int err;

	err = silofs_lcache_init(&env->lcache, env->alloc);
	return_if_err(err);

	env->initf |= SILOFS_ENVF_LCACHE;
	return 0;
}

static void env_fini_lcache(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_LCACHE) {
		silofs_lcache_fini(&env->lcache);
		env->initf &= ~SILOFS_ENVF_LCACHE;
	}
}

static int env_init_freesqs(struct silofs_env *env)
{
	int err;

	err = silofs_lspools_init(&env->lspools, env->alloc);
	return_if_err(err);

	silofs_pspools_init(&env->pspools, env->alloc);
	env->initf |= SILOFS_ENVF_FREESQS;
	return 0;
}

static void env_fini_freesqs(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_FREESQS) {
		silofs_pspools_fini(&env->pspools);
		silofs_lspools_fini(&env->lspools);
		env->initf &= ~SILOFS_ENVF_FREESQS;
	}
}

static int env_init_idsmap(struct silofs_env *env)
{
	struct silofs_idsmap *idsmap = &env->idsmap;
	int err;

	err = silofs_idsmap_init(idsmap, env->alloc);
	return_if_err(err);

	env->initf |= SILOFS_ENVF_IDSMAP;
	return 0;
}

static void env_fini_idsmap(struct silofs_env *env)
{
	struct silofs_idsmap *idsmap = &env->idsmap;

	if (env->initf & SILOFS_ENVF_IDSMAP) {
		silofs_idsmap_clear(idsmap);
		silofs_idsmap_fini(idsmap);
		env->initf &= ~SILOFS_ENVF_IDSMAP;
	}
}

static void env_init_commons(struct silofs_env *env)
{
	silofs_strbuf_reset(&env->name);
	silofs_cred_init(&env->owner_cred);
	env->init_time = silofs_time_mono_now();
	env->alloc     = nullptr;
	env->repodir   = nullptr;
	env->fuseq     = nullptr;
	env->vfs_hooks = nullptr;
}

static void env_fini_commons(struct silofs_env *env)
{
	silofs_cred_fini(&env->owner_cred);
}

static int env_init_nilbk(struct silofs_env *env)
{
	struct silofs_lblock *nilbk = nullptr;

	nilbk = silofs_memalloc(env->alloc, sizeof(*nilbk),
	                        SILOFS_ALLOCF_BZERO);
	if (nilbk == nullptr) {
		return -SILOFS_ENOMEM;
	}
	env->nilbk = nilbk;
	env->initf |= SILOFS_ENVF_NILBK;
	return 0;
}

static void env_fini_nilbk(struct silofs_env *env)
{
	struct silofs_lblock *nilbk = env->nilbk;

	if (env->initf & SILOFS_ENVF_NILBK) {
		silofs_memfree(env->alloc, nilbk, sizeof(*nilbk),
		               SILOFS_ALLOCF_TRYPUNCH);
		env->nilbk = nullptr;
		env->initf &= ~SILOFS_ENVF_NILBK;
	}
}

static int env_init_prandgen(struct silofs_env *env)
{
	int err;

	err = silofs_prandgen_init(&env->prandgen);
	return_if_err(err);

	env->initf |= SILOFS_ENVF_PRANDGEN;
	return 0;
}

static void env_fini_prandgen(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_PRANDGEN) {
		silofs_prandgen_fini(&env->prandgen);
		env->initf &= ~SILOFS_ENVF_PRANDGEN;
	}
}

static void env_fini(struct silofs_env *env)
{
	env_unbind_fuseq(env);
	env_fini_fsroot(env);
	env_fini_idsmap(env);
	env_fini_freesqs(env);
	env_fini_lcache(env);
	env_fini_pcache(env);
	env_fini_repo(env);
	env_fini_uconv(env);
	env_fini_crypt(env);
	env_fini_prandgen(env);
	env_fini_nilbk(env);
	env_fini_alloc(env);
	env_fini_commons(env);
}

static void env_init_ectx(struct silofs_env *env)
{
	env->ectx.alloc     = env->alloc;
	env->ectx.nilbk     = env->nilbk;
	env->ectx.prng      = &env->prandgen;
	env->ectx.dstor     = &env->repo.re_dstor;
	env->ectx.pcache    = &env->pcache;
	env->ectx.pspools   = &env->pspools;
	env->ectx.md_hd     = &env->md_hd;
	env->ectx.enc_ci_hd = &env->enc_ci_hd;
	env->ectx.dec_ci_hd = &env->dec_ci_hd;
	env->ectx.fsroot    = &env->fsroot;
	env->ectx.lcache    = &env->lcache;
	env->ectx.lspools   = &env->lspools;
	env->ectx.ubi       = nullptr;
}

static int
env_init(struct silofs_env *env, size_t memwant, enum silofs_flags flags)
{
	int err;

	env_init_commons(env);

	err = env_init_alloc(env, memwant, flags);
	goto_out_if_err(err);

	err = env_init_nilbk(env);
	goto_out_if_err(err);

	err = env_init_prandgen(env);
	goto_out_if_err(err);

	err = env_init_crypt(env);
	goto_out_if_err(err);

	err = env_init_uconv(env);
	goto_out_if_err(err);

	err = env_init_repo(env);
	goto_out_if_err(err);

	err = env_init_pcache(env);
	goto_out_if_err(err);

	err = env_init_lcache(env);
	goto_out_if_err(err);

	err = env_init_freesqs(env);
	goto_out_if_err(err);

	err = env_init_idsmap(env);
	goto_out_if_err(err);

	err = env_init_fsroot(env);
	goto_out_if_err(err);

	env_init_ectx(env);

	return 0;
out:
	env_fini(env);
	return err;
}

static size_t page_size(void)
{
	return (size_t)silofs_sc_page_size();
}

static size_t env_memsize(const struct silofs_env *env)
{
	constexpr size_t ensz = sizeof(*env);
	const size_t pgsz     = page_size();
	const size_t npgs     = silofs_div_round_up(ensz, pgsz);

	STATICASSERT_LT(sizeof(*env), 65536);

	return npgs * pgsz;
}

static int env_malloc_mlock(struct silofs_env **out_env)
{
	const size_t msz = env_memsize(*out_env);
	void *mem        = nullptr;
	int err;

	err = posix_memalign(&mem, page_size(), msz);
	if (err) {
		log_err("posix_memalign failed: msz=%zu err=%d", msz, err);
		return -abs(err);
	}
	err = silofs_sys_mlock(mem, msz);
	if (err) {
		free(mem);
		log_err("mlock failed: msz=%zu err=%d", msz, err);
		return err;
	}
	explicit_bzero(mem, msz);
	*out_env = mem;
	return 0;
}

static void env_munlock_free(struct silofs_env *env)
{
	const size_t msz = env_memsize(env);
	void *mem        = env;

	explicit_bzero(mem, msz);
	silofs_sys_munlock(mem, msz);
	free(mem);
}

static int
env_new(size_t memwant, enum silofs_flags flags, struct silofs_env **out_env)

{
	struct silofs_env *env = nullptr;
	int err;

	err = env_malloc_mlock(&env);
	if (err) {
		return err;
	}
	err = env_init(env, memwant, flags);
	if (err) {
		env_munlock_free(env);
		return err;
	}
	*out_env = env;
	silofs_burnstack();
	return 0;
}

static void env_del(struct silofs_env *env)
{
	env_fini(env);
	env_munlock_free(env);
	silofs_burnstack();
}

int silofs_create_env(size_t memwant, enum silofs_flags flags,
                      struct silofs_env **out_env)
{
	int err;

	STATICASSERT_LT(sizeof(**out_env), 64 * SILOFS_KILO);

	err = env_new(memwant, flags, out_env);
	silofs_burnstack();

	return err;
}

void silofs_destroy_env(struct silofs_env *env)
{
	env_del(env);
	silofs_burnstack();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
env_populate_idsmap(struct silofs_env *env, const struct silofs_spec *spec)
{
	struct silofs_idsmap *idsmap = &env->idsmap;
	bool allow_hostids;

	allow_hostids = (spec->flags & SILOFS_F_ALLOW_HOSTIDS) > 0;
	return silofs_idsmap_populate(idsmap, &spec->fsids, allow_hostids);
}

static int
env_attach_fuseq(struct silofs_env *env, const struct silofs_spec *spec)
{
	struct silofs_fuseq *fuseq;

	fuseq = silofs_fuseq_new(env->alloc, spec->flags);
	if (fuseq == nullptr) {
		log_warn("failed to create fuseq: flags=0x%x", spec->flags);
		return -SILOFS_ENOMEM;
	}
	env->initf |= SILOFS_ENVF_FUSEQ;
	env->fuseq = fuseq;

	silofs_env_bind_fuseq(env, fuseq);
	return 0;
}

static void env_unbind_fuseq(struct silofs_env *env)
{
	if (env->initf & SILOFS_ENVF_FUSEQ) {
		silofs_fuseq_del(env->fuseq, env->alloc);
		env->fuseq = nullptr;
		env->initf &= ~SILOFS_ENVF_FUSEQ;
	}
}

static bool with_fuse(const struct silofs_spec *args)
{
	return (args->flags & SILOFS_F_WITH_FUSE) > 0;
}

static int
env_update_by_spec(struct silofs_env *env, const struct silofs_spec *spec)
{
	return silofs_env_setup(env, spec);
}

int silofs_open_env(struct silofs_env *env, const struct silofs_spec *spec)
{
	int err;

	err = check_spec(spec);
	return_if_err(err);

	err = env_update_by_spec(env, spec);
	return_if_err(err);

	err = env_populate_idsmap(env, spec);
	return_if_err(err);

	if (with_fuse(spec)) {
		err = env_attach_fuseq(env, spec);
		return_if_err(err);
	}

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int env_update_repodir(struct silofs_env *env, const char *repodir)
{
	struct silofs_alloc *alloc = env->alloc;
	size_t len;

	if (env->repodir != nullptr) {
		len = silofs_str_length(env->repodir);
		silofs_memfree(alloc, env->repodir, len + 1, 0);
		env->repodir                = nullptr;
		env->fsroot.baseref.repodir = nullptr;
	}
	if (repodir != nullptr) {
		len          = silofs_str_length(repodir);
		env->repodir = silofs_memdup(alloc, repodir, len + 1, 0);
		if (env->repodir == nullptr) {
			return -SILOFS_ENOMEM;
		}
		env->fsroot.baseref.repodir = env->repodir;
	}
	return 0;
}

static int
env_setup_owner(struct silofs_env *env, const struct silofs_cred *cred)
{
	if (silofs_uid_isnull(cred->uid)) {
		log_dbg("illegal owner uid: %u", cred->uid);
		return -SILOFS_EINVAL;
	}
	if (silofs_gid_isnull(cred->gid)) {
		log_dbg("illegal owner gid: %u", cred->gid);
		return -SILOFS_EINVAL;
	}
	if (cred->umask == 0) {
		log_dbg("zero umask: uid=%u gid=%u", cred->uid, cred->gid);
		return -SILOFS_EINVAL;
	}
	silofs_cred_assign(&env->owner_cred, cred);
	return 0;
}

static int
env_use_password(struct silofs_env *env, const struct silofs_password *pw,
                 enum silofs_flags flags)
{
	int err;

	if ((flags & SILOFS_F_NOPASSWD) != SILOFS_F_NOPASSWD) {
		err = silofs_fsroot_derive_meta(&env->fsroot, pw);
		return_if_err(err);
	}
	return 0;
}

static int env_update_fscap(struct silofs_env *env, size_t cap_want)
{
	const size_t align_size = SILOFS_MEGA;
	const size_t fscap      = (cap_want / align_size) * align_size;

	if (cap_want == 0) {
		return 0; /* no-op */
	}
	if ((fscap < SILOFS_CAPACITY_SIZE_MIN) ||
	    (fscap > SILOFS_CAPACITY_SIZE_MAX)) {
		return -SILOFS_EINVAL;
	}
	env->fscap = fscap;
	return 0;
}

static void env_setup_ctlflags(struct silofs_env *env, enum silofs_flags flags)
{
	silofs_update_main_ctlflags(&env->fsroot, flags);
}

static int env_update_name(struct silofs_env *env, const char *fsname)
{
	int err;

	silofs_strbuf_reset(&env->name);
	if (fsname != nullptr) {
		struct silofs_namestr nstr;

		err = silofs_namestr_init(&nstr, fsname);
		return_if_err(err);

		err = silofs_check_fsname(&nstr);
		return_if_err(err);

		silofs_strbuf_setup(&env->name, &nstr.sv);
	}
	env->fsroot.baseref.refname = env->name.str;
	return 0;
}

static size_t env_calc_iopen_limit(const struct silofs_env *env)
{
	struct silofs_alloc_stat st;
	const size_t align = 128;
	size_t lim;

	silofs_memstat(env->alloc, &st);
	lim = (st.nbytes_max / (2 * SILOFS_LBK_SIZE));
	return silofs_div_round_up(lim, align) * align;
}

static void env_update_iopen_max(struct silofs_env *env)
{
	env->fsroot.opstat.op_iopen_max = env_calc_iopen_limit(env);
}

static void env_bind_vfs_hooks(struct silofs_env *env)
{
	env->vfs_hooks = silofs_vfswrap_hooks();
}

int silofs_env_setup(struct silofs_env *env, const struct silofs_spec *spec)
{
	int err;

	err = env_update_repodir(env, spec->bref[0].repodir);
	return_if_err(err);

	err = env_update_name(env, spec->bref[0].refname);
	return_if_err(err);

	err = env_setup_owner(env, &spec->fsowner);
	return_if_err(err);

	err = env_use_password(env, &spec->passwd, spec->flags);
	return_if_err(err);

	err = env_update_fscap(env, spec->fscap);
	return_if_err(err);

	env_setup_ctlflags(env, spec->flags);
	env_update_iopen_max(env);

	env_bind_vfs_hooks(env);

	return 0;
}

void silofs_env_bind_fuseq(struct silofs_env *env, struct silofs_fuseq *fq)
{
	if (fq != nullptr) {
		fq->fq_env       = env;
		fq->fq_vfs_hooks = env->vfs_hooks;
	}
	env->fuseq = fq;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime)
{
	const time_t now = silofs_time_mono_now();

	*out_uptime = now - env->init_time;
}

#if 0
static int env_fork_rebind_super(struct silofs_env *env,
				 const struct silofs_sb_info *sbi_cur,
				 struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = nullptr;
	int err;

	env_drop_uamap(env);
	err = env_spawn_super(env, 0, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_make_fork_of(sbi, sbi_cur);
	env_update_sb(env, sbi);

	*out_sbi = sbi;
	return 0;
}

static void sbi_mark_fossil(struct silofs_sb_info *sbi)
{
	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_FOSSIL);
}

static void
env_curr_fs_mbref(const struct silofs_env *env, struct silofs_mbref *out_mbref)
{
	silofs_mbref_assign(out_mbref, &env->mbi.mb_ref);
}

static int
env_do_forkfs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs)
{
	struct silofs_sb_info *sbi_alt = nullptr;
	struct silofs_sb_info *sbi_new = nullptr;
	struct silofs_sb_info *sbi_cur = env->sbi;
	int err;

	env_curr_fs_mbref(env, &out_mbrefs->base);

	err = env_fork_rebind_super(env, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}

	err = silofs_env_commit_mbr(env, &out_mbrefs->fork);
	if (err) {
		return err;
	}

	err = env_fork_rebind_super(env, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}

	err = silofs_env_commit_mbr(env, &out_mbrefs->main);
	if (err) {
		return err;
	}

	sbi_mark_fossil(sbi_cur);
	return 0;
}
#endif

int silofs_env_forkfs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs)
{
	int err;

	silofs_memzero(out_mbrefs, sizeof(*out_mbrefs));
	err = -1; /* env_do_forkfs(env, out_mbrefs); */
	(void)env;
	return err;
}

static int
env_reinit_ciphers(struct silofs_env *env, const struct silofs_ciargs *ciargs)
{
	int err;

	err = silofs_cipher_reinit(&env->enc_ci_hd, ciargs);
	return_if_err(err);

	err = silofs_cipher_reinit(&env->dec_ci_hd, ciargs);
	return_if_err(err);

	return 0;
}

int silofs_env_reinit_ciphers(struct silofs_env *env)
{
	return env_reinit_ciphers(env, &env->fsroot.mbr_meta.nmeta.ciargs);
}
