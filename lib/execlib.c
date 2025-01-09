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
#include <silofs/configs.h>
#include <silofs/fs.h>
#include <silofs/fuseq.h>
#include <silofs/execlib.h>
#include <sys/resource.h>

#define ROUND_TO_4K(n) SILOFS_ROUND_TO(n, (4 * SILOFS_KILO))

union silofs_alloc_u {
	struct silofs_qalloc qalloc;
	struct silofs_calloc calloc;
};

struct silofs_fs_core {
	struct silofs_password passwd;
	union silofs_alloc_u alloc_u;
	struct silofs_repo repo;
	struct silofs_pcache pcache;
	struct silofs_lcache lcache;
	struct silofs_submitq submitq;
	struct silofs_idsmap idsmap;
	struct silofs_bstore bstore;
	struct silofs_env env;
	struct silofs_flusher flusher;
};

union silofs_fs_core_u {
	struct silofs_fs_core c;
	uint8_t dat[ROUND_TO_4K(sizeof(struct silofs_fs_core))];
};

struct silofs_fs_inst {
	union silofs_fs_core_u fs_core;
};

struct silofs_fs_ctx {
	struct silofs_fs_args args;
	struct silofs_fs_inst *inst;
	struct silofs_password *password;
	struct silofs_alloc *alloc;
	struct silofs_repo *repo;
	struct silofs_pcache *pcache;
	struct silofs_lcache *lcache;
	struct silofs_submitq *submitq;
	struct silofs_flusher *flusher;
	struct silofs_idsmap *idsmap;
	struct silofs_bstore *bstore;
	struct silofs_env *env;
	struct silofs_fuseq *fuseq;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

	err = silofs_memory_limits(&mem_total, &mem_rlim);
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

static struct silofs_fs_inst *fs_inst_of(struct silofs_env *env)
{
	struct silofs_fs_core *fs_core;
	union silofs_fs_core_u *fs_core_u;

	fs_core = container_of(env, struct silofs_fs_core, env);
	fs_core_u = container_of(fs_core, union silofs_fs_core_u, c);

	return container_of(fs_core_u, struct silofs_fs_inst, fs_core);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_bootpath(const struct silofs_fs_args *fs_args)
{
	const struct silofs_fs_bref *bref = &fs_args->bref;
	struct silofs_bootpath bootpath;

	return silofs_bootpath_setup(&bootpath, bref->repodir, bref->name);
}

static int check_password(const struct silofs_fs_args *fs_args)
{
	struct silofs_password passwd;

	return silofs_password_setup(&passwd, fs_args->bref.passwd);
}

static int check_fs_args(const struct silofs_fs_args *fs_args)
{
	int err;

	err = check_bootpath(fs_args);
	if (err) {
		return err;
	}
	err = check_password(fs_args);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_qalloc *fs_ctx_qalloc_of(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_alloc *alloc = fs_ctx->alloc;
	struct silofs_qalloc *qalloc = NULL;

	if ((alloc != NULL) && !fs_ctx->args.cflags.stdalloc) {
		qalloc = container_of(alloc, struct silofs_qalloc, alloc);
	}
	return qalloc;
}

static struct silofs_calloc *fs_ctx_calloc_of(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_alloc *alloc = fs_ctx->alloc;
	struct silofs_calloc *calloc = NULL;

	if ((alloc != NULL) && fs_ctx->args.cflags.stdalloc) {
		calloc = container_of(alloc, struct silofs_calloc, alloc);
	}
	return calloc;
}

static int fs_ctx_setup_qalloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_qalloc *qalloc = NULL;
	size_t memsize = 0;
	enum silofs_qallocf qaflags = SILOFS_QALLOCF_NOFAIL;
	int err;

	err = calc_mem_size(fs_ctx->args.memwant, &memsize);
	if (err) {
		return err;
	}
	if (fs_ctx->args.cflags.pedantic) {
		qaflags |= SILOFS_QALLOCF_DEMASK;
	}
	qalloc = &fs_ctx->inst->fs_core.c.alloc_u.qalloc;
	err = silofs_qalloc_init(qalloc, memsize, qaflags);
	if (err) {
		return err;
	}
	fs_ctx->alloc = &qalloc->alloc;
	return 0;
}

static void fs_ctx_destroy_qalloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_qalloc *qalloc = NULL;

	if (fs_ctx->alloc != NULL) {
		qalloc = fs_ctx_qalloc_of(fs_ctx);
		silofs_qalloc_fini(qalloc);
		fs_ctx->alloc = NULL;
	}
}

static int fs_ctx_setup_calloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_calloc *calloc = NULL;
	size_t memsize = 0;
	int err;

	err = calc_mem_size(fs_ctx->args.memwant, &memsize);
	if (err) {
		return err;
	}
	calloc = &fs_ctx->inst->fs_core.c.alloc_u.calloc;
	err = silofs_calloc_init(calloc, memsize);
	if (err) {
		return err;
	}
	fs_ctx->alloc = &calloc->alloc;
	return 0;
}

static void fs_ctx_destroy_calloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_calloc *calloc;

	if (fs_ctx->alloc != NULL) {
		calloc = fs_ctx_calloc_of(fs_ctx);
		silofs_calloc_fini(calloc);
		fs_ctx->alloc = NULL;
	}
}

static int fs_ctx_setup_alloc(struct silofs_fs_ctx *fs_ctx)
{
	int ret;

	if (fs_ctx->args.cflags.stdalloc) {
		ret = fs_ctx_setup_calloc(fs_ctx);
	} else {
		ret = fs_ctx_setup_qalloc(fs_ctx);
	}
	return ret;
}

static void fs_ctx_destroy_alloc(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->args.cflags.stdalloc) {
		fs_ctx_destroy_calloc(fs_ctx);
	} else {
		fs_ctx_destroy_qalloc(fs_ctx);
	}
}

static void fs_ctx_make_repo_base(const struct silofs_fs_ctx *fs_ctx,
                                  struct silofs_repo_base *re_base)
{
	silofs_memzero(re_base, sizeof(*re_base));
	re_base->alloc = fs_ctx->alloc;
	if (fs_ctx->args.cflags.rdonly) {
		re_base->flags |= SILOFS_REPOF_RDONLY;
	}
	silofs_strview_init(&re_base->repodir, fs_ctx->args.bref.repodir);
}

static int fs_ctx_setup_repo(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_repo_base re_base = { .flags = 0 };
	struct silofs_repo *repo = NULL;
	int err;

	repo = &fs_ctx->inst->fs_core.c.repo;
	fs_ctx_make_repo_base(fs_ctx, &re_base);
	err = silofs_repo_init(repo, &re_base);
	if (err) {
		return err;
	}
	fs_ctx->repo = repo;
	return 0;
}

static void fs_ctx_destroy_repo(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->repo != NULL) {
		silofs_repo_fini(fs_ctx->repo);
		fs_ctx->repo = NULL;
	}
}

static int fs_ctx_setup_pcache(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_pcache *pcache = NULL;
	int err;

	pcache = &fs_ctx->inst->fs_core.c.pcache;
	err = silofs_pcache_init(pcache, fs_ctx->alloc);
	if (err) {
		return err;
	}
	fs_ctx->pcache = pcache;
	return 0;
}

static void fs_ctx_destroy_pcache(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->pcache != NULL) {
		silofs_pcache_fini(fs_ctx->pcache);
		fs_ctx->pcache = NULL;
	}
}

static int fs_ctx_setup_lcache(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_lcache *lcache = NULL;
	int err;

	lcache = &fs_ctx->inst->fs_core.c.lcache;
	err = silofs_lcache_init(lcache, fs_ctx->alloc);
	if (err) {
		return err;
	}
	fs_ctx->lcache = lcache;
	return 0;
}

static void fs_ctx_destroy_lcache(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->lcache != NULL) {
		silofs_lcache_fini(fs_ctx->lcache);
		fs_ctx->lcache = NULL;
	}
}

static int fs_ctx_setup_submitq(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_submitq *submitq = NULL;
	int err;

	submitq = &fs_ctx->inst->fs_core.c.submitq;
	err = silofs_submitq_init(submitq, fs_ctx->alloc);
	if (err) {
		return err;
	}
	fs_ctx->submitq = submitq;
	return 0;
}

static void fs_ctx_destroy_submitq(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->submitq != NULL) {
		silofs_submitq_fini(fs_ctx->submitq);
		fs_ctx->submitq = NULL;
	}
}

static int fs_ctx_setup_flusher(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_flusher *flusher = NULL;
	int err;

	flusher = &fs_ctx->inst->fs_core.c.flusher;
	err = silofs_flusher_init(flusher, fs_ctx->submitq);
	if (err) {
		return err;
	}
	fs_ctx->flusher = flusher;
	return 0;
}

static void fs_ctx_destroy_flusher(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->flusher != NULL) {
		silofs_flusher_fini(fs_ctx->flusher);
		fs_ctx->flusher = NULL;
	}
}

static int fs_ctx_setup_idsmap(struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_fs_ids *ids = &fs_ctx->args.ids;
	const struct silofs_fs_cflags *cflags = &fs_ctx->args.cflags;
	struct silofs_idsmap *idsmap = NULL;
	int err;

	idsmap = &fs_ctx->inst->fs_core.c.idsmap;
	err = silofs_idsmap_init(idsmap, fs_ctx->alloc, cflags->allow_hostids);
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
	fs_ctx->idsmap = idsmap;
	return 0;
}

static void fs_ctx_destroy_idsmap(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->idsmap != NULL) {
		silofs_idsmap_clear(fs_ctx->idsmap);
		silofs_idsmap_fini(fs_ctx->idsmap);
		fs_ctx->idsmap = NULL;
	}
}

static int fs_ctx_setup_bstore(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_bstore *bstore;
	int err;

	bstore = &fs_ctx->inst->fs_core.c.bstore;
	err = silofs_bstore_init(bstore, fs_ctx->pcache, fs_ctx->repo);
	if (err) {
		return err;
	}
	fs_ctx->bstore = bstore;
	return 0;
}

static void fs_ctx_destroy_bstore(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->bstore != NULL) {
		silofs_bstore_fini(fs_ctx->bstore);
		fs_ctx->bstore = NULL;
	}
}

static int fs_ctx_setup_env(struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_env_base fse_base = {
		.alloc = fs_ctx->alloc,
		.pcache = fs_ctx->pcache,
		.lcache = fs_ctx->lcache,
		.repo = fs_ctx->repo,
		.submitq = fs_ctx->submitq,
		.flusher = fs_ctx->flusher,
		.idsmap = fs_ctx->idsmap,
		.bstore = fs_ctx->bstore,
		.fuseq = NULL,
	};
	struct silofs_env *env;
	int err;

	env = &fs_ctx->inst->fs_core.c.env;
	err = silofs_env_init(env, &fs_ctx->args, &fse_base);
	if (err) {
		return err;
	}
	err = silofs_env_setup(env, fs_ctx->password);
	if (err) {
		return err;
	}
	fs_ctx->env = env;
	return 0;
}

static void fs_ctx_destroy_env(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->env != NULL) {
		silofs_env_fini(fs_ctx->env);
		fs_ctx->env = NULL;
	}
}

static bool has_with_fuse(const struct silofs_env *env)
{
	const enum silofs_env_flags mask = SILOFS_ENVF_WITHFUSE;

	return (env->ctl_flags & mask) == mask;
}

static bool run_with_fuse(const struct silofs_env *env)
{
	const struct silofs_fuseq *fuseq = env->base.fuseq;

	return (fuseq != NULL) && has_with_fuse(env);
}

static bool has_ctlf(const struct silofs_env *env, enum silofs_env_flags mask)
{
	return (env->ctl_flags & mask) == mask;
}

static void
fs_ctx_bind_fuseq(struct silofs_fs_ctx *fs_ctx, struct silofs_fuseq *fuseq)
{
	struct silofs_env *env = fs_ctx->env;

	fs_ctx->fuseq = fuseq;
	if (env == NULL) {
		return;
	}
	env->base.fuseq = fuseq;
	if (fuseq == NULL) {
		return;
	}
	fuseq->fq_writeback_cache = has_ctlf(env, SILOFS_ENVF_WRITEBACK);
	fuseq->fq_may_splice = has_ctlf(env, SILOFS_ENVF_MAYSPLICE);
}

static int fs_ctx_setup_fuseq(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_fuseq *fq = NULL;
	int err;

	if (!has_with_fuse(fs_ctx->env)) {
		return 0;
	}
	err = silofs_fuseq_new(fs_ctx->alloc, &fq);
	if (err) {
		return err;
	}
	fs_ctx_bind_fuseq(fs_ctx, fq);
	return 0;
}

static void fs_ctx_destroy_fuseq(struct silofs_fs_ctx *fs_ctx)
{

	if (fs_ctx->fuseq != NULL) {
		silofs_fuseq_del(fs_ctx->fuseq, fs_ctx->alloc);
		fs_ctx_bind_fuseq(fs_ctx, NULL);
	}
}

static int fs_ctx_setup_password(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_password *passwd;
	int err;

	passwd = &fs_ctx->inst->fs_core.c.passwd;
	err = silofs_password_setup(passwd, fs_ctx->args.bref.passwd);
	if (err) {
		return err;
	}
	fs_ctx->password = passwd;
	return 0;
}

static void fs_ctx_destroy_passwd(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->password != NULL) {
		silofs_password_reset(fs_ctx->password);
		fs_ctx->password = NULL;
	}
}

static void fs_ctx_destroy(struct silofs_fs_ctx *fs_ctx)
{
	fs_ctx_destroy_fuseq(fs_ctx);
	fs_ctx_destroy_env(fs_ctx);
	fs_ctx_destroy_idsmap(fs_ctx);
	fs_ctx_destroy_flusher(fs_ctx);
	fs_ctx_destroy_submitq(fs_ctx);
	fs_ctx_destroy_lcache(fs_ctx);
	fs_ctx_destroy_bstore(fs_ctx);
	fs_ctx_destroy_pcache(fs_ctx);
	fs_ctx_destroy_repo(fs_ctx);
	fs_ctx_destroy_alloc(fs_ctx);
	fs_ctx_destroy_passwd(fs_ctx);
}

static int fs_ctx_setup(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = fs_ctx_setup_password(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_alloc(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_repo(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_pcache(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_bstore(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_lcache(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_submitq(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_flusher(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_idsmap(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_env(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_fuseq(fs_ctx);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	fs_ctx_destroy(fs_ctx);
	return err;
}

static void
fs_ctx_init(struct silofs_fs_ctx *fs_ctx, struct silofs_fs_inst *fs_inst,
            const struct silofs_fs_args *fs_args)
{
	memset(fs_ctx, 0, sizeof(*fs_ctx));
	memcpy(&fs_ctx->args, fs_args, sizeof(fs_ctx->args));
	fs_ctx->inst = fs_inst;
}

static void
fs_ctx_init_from(struct silofs_fs_ctx *fs_ctx, struct silofs_fs_inst *fs_inst)
{
	struct silofs_env *env = &fs_inst->fs_core.c.env;

	fs_ctx_init(fs_ctx, fs_inst, &env->args);
	fs_ctx->password = &fs_inst->fs_core.c.passwd;
	fs_ctx->alloc = env->base.alloc;
	fs_ctx->repo = env->base.repo;
	fs_ctx->pcache = env->base.pcache;
	fs_ctx->lcache = env->base.lcache;
	fs_ctx->submitq = env->base.submitq;
	fs_ctx->flusher = env->base.flusher;
	fs_ctx->idsmap = env->base.idsmap;
	fs_ctx->bstore = env->base.bstore;
	fs_ctx->env = env;
	fs_ctx->fuseq = env->base.fuseq;
}

static int new_fs_inst(const struct silofs_fs_args *fs_args,
                       struct silofs_fs_inst **out_fs_inst)
{
	struct silofs_fs_ctx fs_ctx = { .inst = NULL };
	const size_t msz = sizeof(*fs_ctx.inst);
	void *mem = NULL;
	int err;

	err = silofs_zmalloc(msz, &mem);
	if (err) {
		return err;
	}

	fs_ctx_init(&fs_ctx, mem, fs_args);
	err = fs_ctx_setup(&fs_ctx);
	if (err) {
		silofs_zfree(mem, msz);
		return err;
	}
	*out_fs_inst = fs_ctx.inst;
	return 0;
}

int silofs_new_env(const struct silofs_fs_args *fs_args,
                   struct silofs_env **out_env)
{
	struct silofs_fs_inst *fs_inst = NULL;
	int err = 0;

	STATICASSERT_LE(sizeof(*fs_inst), 64 * SILOFS_KILO);

	err = check_fs_args(fs_args);
	if (err) {
		goto out;
	}
	err = new_fs_inst(fs_args, &fs_inst);
	if (err) {
		goto out;
	}
	*out_env = &fs_inst->fs_core.c.env;
out:
	silofs_burnstack();
	return err;
}

static void del_fs_inst(struct silofs_fs_inst *fs_inst)
{
	struct silofs_fs_ctx fs_ctx = { .inst = NULL };
	const size_t msz = sizeof(*fs_inst);
	void *mem = fs_inst;

	fs_ctx_init_from(&fs_ctx, fs_inst);
	fs_ctx_destroy(&fs_ctx);
	silofs_zfree(mem, msz);
}

void silofs_del_env(struct silofs_env *env)
{
	struct silofs_fs_inst *fs_inst = NULL;

	fs_inst = fs_inst_of(env);
	del_fs_inst(fs_inst);
	silofs_burnstack();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_post_exec_fs(struct silofs_env *env)
{
	const struct silofs_fuseq *fuseq = env->base.fuseq;
	int ret = 0;

	if ((fuseq != NULL) && fuseq->fq_got_init) {
		ret = fuseq->fq_got_destroy ? 0 : -SILOFS_ENOTDONE;
	}
	return ret;
}

static int map_task_creds(struct silofs_task *task)
{
	const struct silofs_idsmap *idsm = task_idsmap(task);
	const struct silofs_cred *xcred = &task->t_oper.op_creds.host_cred;
	struct silofs_cred *icred = &task->t_oper.op_creds.fs_cred;
	int ret = 0;

	if (idsm->idm_usize || idsm->idm_gsize) {
		ret = silofs_idsmap_map_uidgid(idsm, xcred->uid, xcred->gid,
		                               &icred->uid, &icred->gid);
	}
	return ret;
}

static int make_task(struct silofs_env *env, struct silofs_task *task)
{
	const struct silofs_fs_args *args = &env->args;

	silofs_task_init(task, env);
	silofs_task_set_ts(task, true);
	silofs_task_set_creds(task, args->uid, args->gid, args->umask);
	task->t_uber_op = true;
	return map_task_creds(task);
}

static int term_task(struct silofs_task *task, int status)
{
	int err;

	err = silofs_task_submit(task, true);
	silofs_task_fini(task);
	silofs_burnstack();
	return status ? status : err;
}

static void drop_caches(const struct silofs_env *env)
{
	silofs_lcache_drop(env->base.lcache);
	silofs_pcache_drop(env->base.pcache);
	silofs_repo_drop_some(env->base.repo);
}

static int exec_stage_rootdir_inode(struct silofs_env *env,
                                    struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_inode(&task, SILOFS_INO_ROOT, SILOFS_STG_CUR,
	                         out_ii);
	return term_task(&task, err);
}

static int reload_rootdir_inode(struct silofs_env *env)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = exec_stage_rootdir_inode(env, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o", ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int
exec_rescan_vspace_of(struct silofs_env *env, enum silofs_ltype ltype)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_rescan_vspace_of(&task, ltype);
	return term_task(&task, err);
}

static int reload_free_vspace(struct silofs_env *env)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = exec_rescan_vspace_of(env, ltype);
		if (err && (err != -SILOFS_ENOSPC) &&
		    (err != -SILOFS_ENOENT)) {
			log_err("failed to reload free vspace: err=%d", err);
			return err;
		}
	}
	return 0;
}

static int reload_fs_meta(struct silofs_env *env)
{
	int err;

	err = reload_rootdir_inode(env);
	if (err) {
		log_err("failed to reload root dir: err=%d", err);
		return err;
	}
	drop_caches(env);
	return 0;
}

static int exec_flush_dirty_now(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_flush_dirty_now(&task);
	return term_task(&task, err);
}

static int flush_dirty(struct silofs_env *env)
{
	int err;

	err = exec_flush_dirty_now(env);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
	}
	return err;
}

static int fsync_lsegs(const struct silofs_env *env)
{
	int err;

	err = silofs_repo_fsync_all(env->base.repo);
	if (err) {
		log_err("failed to fsync lsegs: err=%d", err);
	}
	return err;
}

static int shutdown_fs(struct silofs_env *env)
{
	return silofs_env_shut(env);
}

int silofs_close_repo(struct silofs_env *env)
{
	int ret;

	silofs_env_lock(env);
	ret = silofs_repo_close(env->base.repo);
	silofs_env_unlock(env);
	return ret;
}

static int do_mount_and_exec(struct silofs_env *env)
{
	struct silofs_fuseq *fuseq = env->base.fuseq;
	int err;

	err = silofs_fuseq_mount(fuseq, env, env->args.mntdir);
	if (err) {
		return err;
	}
	err = silofs_fuseq_exec(fuseq);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_exec_fs(struct silofs_env *env)
{
	struct silofs_fuseq *fuseq = env->base.fuseq;
	int err = -SILOFS_EINVAL;

	if (run_with_fuse(env)) {
		err = silofs_fuseq_update(fuseq);
		if (!err) {
			err = do_mount_and_exec(env);
			silofs_fuseq_term(fuseq);
		}
	}
	return err;
}

void silofs_halt_fs(struct silofs_env *env)
{
	silofs_env_lock(env);
	if (env->base.fuseq != NULL) {
		env->base.fuseq->fq_active = 0;
	}
	silofs_env_unlock(env);
}

static int flush_and_drop_cache(struct silofs_env *env)
{
	int err;

	err = flush_dirty(env);
	if (err) {
		return err;
	}
	drop_caches(env);
	return 0;
}

static int do_sync_fs(struct silofs_env *env, bool drop)
{
	int err;

	err = flush_dirty(env);
	if (!err && drop) {
		drop_caches(env);
	}
	return err;
}

int silofs_sync_fs(struct silofs_env *env, bool drop)
{
	int cnt = 3;
	int err = 0;

	silofs_env_lock(env);
	while ((cnt-- > 0) && !err) {
		err = do_sync_fs(env, drop);
	}
	silofs_env_unlock(env);
	return err;
}

void silofs_stat_fs(const struct silofs_env *env,
                    struct silofs_cachestats *cst)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0 };
	const struct silofs_alloc *alloc = env->base.alloc;
	const struct silofs_lcache *lcache = env->base.lcache;

	silofs_memzero(cst, sizeof(*cst));
	silofs_memstat(alloc, &alst);
	cst->nalloc_bytes = alst.nbytes_use;
	cst->ncache_unodes += lcache->lc_uni_hmapq.hmq_htbl_size;
	cst->ncache_vnodes += lcache->lc_vni_hmapq.hmq_htbl_size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Try to add some pseudo-randomness for the rare (yet, possible) case where
 * '/dev/urandom' does not provide good-enough random  bits stream.
 */
static void make_prandom_ivkey(const struct silofs_env *env,
                               struct silofs_ivkey *out_ivkey)
{
	struct silofs_password pw = { .passlen = 0 };

	silofs_password_mkrand(&pw);
	silofs_derive_boot_ivkey(&env->mdigest, &pw, out_ivkey);
}

static void
xrandom_ivkey(const struct silofs_env *env, struct silofs_ivkey *ivkey)
{
	struct silofs_ivkey ivkey2;

	make_prandom_ivkey(env, &ivkey2);
	silofs_ivkey_xor_with(ivkey, &ivkey2);
}

static void
generate_main_ivkey(const struct silofs_env *env, struct silofs_bootrec *brec)
{
	silofs_bootrec_gen_ivkey(brec);
	xrandom_ivkey(env, &brec->main_ivkey);
}

static void
update_pvasd(const struct silofs_env *env, struct silofs_bootrec *brec)
{
	struct silofs_pvasd pvasd;

	silofs_bstore_curr_pvasd(env->base.bstore, &pvasd);
	silofs_bootrec_set_pvasd(brec, &pvasd);
}

static int check_superblock(const struct silofs_env *env)
{
	const struct silofs_sb_info *sbi = env->sbi;
	const struct silofs_super_block *sb = sbi->sb;
	int fossil;
	int err;

	err = silofs_sb_check_version(sb);
	if (err) {
		log_err("bad sb: magic=%lx version:=%ld err=%d", sb->sb_magic,
		        sb->sb_version, err);
		return err;
	}
	fossil = silofs_sb_test_flags(sb, SILOFS_SUPERF_FOSSIL);
	if (fossil && !env->args.cflags.rdonly) {
		log_warn("read-only fs: sb-flags=%08x", (int)sb->sb_flags);
		return -SILOFS_EROFS;
	}
	return 0;
}

static int reload_super(struct silofs_env *env)
{
	int err;

	err = silofs_env_reload_super(env);
	if (err) {
		log_err("failed to reload super: err=%d", err);
		return err;
	}
	err = check_superblock(env);
	if (err) {
		log_warn("bad super-block: err=%d", err);
		return err;
	}
	return 0;
}

static int exec_require_spmaps_of(struct silofs_env *env,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	enum silofs_stg_mode stg_mode = SILOFS_STG_COW;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_require_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int format_base_vspmaps_of(struct silofs_env *env,
                                  const struct silofs_vaddr *vaddr)
{
	int err;

	err = exec_require_spmaps_of(env, vaddr);
	if (err) {
		log_err("failed to format base spmaps: "
		        "ltype=%d err=%d",
		        vaddr->ltype, err);
		return err;
	}
	err = do_sync_fs(env, false);
	if (err) {
		return err;
	}
	log_dbg("format base spmaps of: ltype=%d err=%d", vaddr->ltype, err);
	return 0;
}

static int format_base_vspmaps(struct silofs_env *env)
{
	struct silofs_vaddr vaddr;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		vaddr_setup(&vaddr, ltype, 0);
		err = format_base_vspmaps_of(env, &vaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_claim_vspace(struct silofs_env *env, enum silofs_ltype ltype,
                             struct silofs_vaddr *out_vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_claim_vspace(&task, ltype, out_vaddr);
	return term_task(&task, err);
}

static int
exec_reclaim_vspace(struct silofs_env *env, const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(&task, vaddr);
	return term_task(&task, err);
}

static int
claim_reclaim_vspace_of(struct silofs_env *env, enum silofs_ltype vspace)
{
	struct silofs_vaddr vaddr;
	const loff_t voff_exp = 0;
	int err;

	drop_caches(env);
	err = exec_claim_vspace(env, vspace, &vaddr);
	if (err) {
		log_err("failed to claim: vspace=%d err=%d", vspace, err);
		return err;
	}

	if (vaddr.off != voff_exp) {
		log_err("wrong first voff: vspace=%d expected-voff=%ld "
		        "got-voff=%ld",
		        vspace, voff_exp, vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}

	drop_caches(env);
	err = exec_reclaim_vspace(env, &vaddr);
	if (err) {
		log_err("failed to reclaim space: vspace=%d voff=%ld err=%d",
		        vspace, vaddr.off, err);
	}
	return 0;
}

static int claim_reclaim_vspace(struct silofs_env *env)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = claim_reclaim_vspace_of(env, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(env);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int
exec_stage_spmaps_at(struct silofs_env *env, const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stg_mode stg_mode = SILOFS_STG_CUR;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int
reload_base_vspace_of(struct silofs_env *env, enum silofs_ltype vspace)
{
	struct silofs_vaddr vaddr;
	int err;

	vaddr_setup(&vaddr, vspace, 0);
	err = exec_stage_spmaps_at(env, &vaddr);
	if (err) {
		log_err("failed to reload: vspace=%d err=%d", vspace, err);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int reload_base_vspace(struct silofs_env *env)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err = 0;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = reload_base_vspace_of(env, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(env);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_spawn_vnode(struct silofs_env *env, enum silofs_ltype ltype,
                            struct silofs_vnode_info **out_vni)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode(&task, NULL, ltype, out_vni);
	if (!err) {
		vni_dirtify(*out_vni, NULL);
	}
	return term_task(&task, err);
}

static int
format_zero_vspace_of(struct silofs_env *env, enum silofs_ltype vspace)
{
	struct silofs_vnode_info *vni = NULL;
	const struct silofs_vaddr *vaddr = NULL;
	int err;

	err = exec_spawn_vnode(env, vspace, &vni);
	if (err) {
		log_err("failed to spawn: vspace=%d err=%d", vspace, err);
		return err;
	}
	vaddr = vni_vaddr(vni);
	if (vaddr->off != 0) {
		log_err("bad offset: vspace=%d off=%ld", vspace, vaddr->off);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int format_zero_vspace(struct silofs_env *env)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = format_zero_vspace_of(env, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(env);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int
do_spawn_rootdir(struct silofs_task *task, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp;

	silofs_inew_params_of(&inp, task_creds(task), NULL, S_IFDIR | 0755, 0);
	return silofs_spawn_inode(task, &inp, out_ii);
}

static int
exec_spawn_rootdir(struct silofs_env *env, struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = do_spawn_rootdir(&task, out_ii);
	return term_task(&task, err);
}

static int do_format_rootdir(struct silofs_env *env)
{
	struct silofs_inode_info *root_ii = NULL;
	int err;

	err = exec_spawn_rootdir(env, &root_ii);
	if (err) {
		return err;
	}
	if (root_ii->i_ino != SILOFS_INO_ROOT) {
		log_err("format root-dir failed: ino=%ld", root_ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_ii_fixup_as_rootdir(root_ii);
	return 0;
}

static int format_rootdir(struct silofs_env *env)
{
	int err;

	err = do_format_rootdir(env);
	if (!err) {
		err = flush_and_drop_cache(env);
	}
	return err;
}

static int check_fs_capacity(size_t cap_size)
{
	if (cap_size < SILOFS_CAPACITY_SIZE_MIN) {
		return -SILOFS_EINVAL;
	}
	if (cap_size > SILOFS_CAPACITY_SIZE_MAX) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int check_want_capacity(const struct silofs_env *env)
{
	const size_t cap_want = env->args.capacity;
	int err;

	err = check_fs_capacity(cap_want);
	if (err) {
		log_err("illegal file-system capacity: "
		        "cap=%lu err=%d",
		        cap_want, err);
		return err;
	}
	return 0;
}

static int check_owner_ids(const struct silofs_env *env)
{
	const uid_t owner_uid = env->args.uid;
	const gid_t owner_gid = env->args.gid;
	uid_t suid;
	gid_t sgid;
	int err;

	err = silofs_idsmap_map_uidgid(env->base.idsmap, owner_uid, owner_gid,
	                               &suid, &sgid);
	if (err) {
		log_err("unable to map owner credentials: uid=%ld gid=%ld",
		        (long)owner_uid, (long)owner_gid);
		return err;
	}
	return 0;
}

static size_t calc_aligned_fs_cap(size_t cap_want)
{
	const size_t align_size = SILOFS_LSEG_SIZE_MAX;

	return (cap_want / align_size) * align_size;
}

static int format_umeta(struct silofs_env *env)
{
	size_t fs_cap;
	int err;

	err = check_want_capacity(env);
	if (err) {
		return err;
	}
	fs_cap = calc_aligned_fs_cap(env->args.capacity);
	err = silofs_env_format_super(env, fs_cap);
	if (err) {
		return err;
	}
	err = check_superblock(env);
	if (err) {
		return err;
	}
	err = flush_dirty(env);
	if (err) {
		return err;
	}
	return 0;
}

static int format_vmeta(struct silofs_env *env)
{
	int err;

	err = format_base_vspmaps(env);
	if (err) {
		return err;
	}
	err = claim_reclaim_vspace(env);
	if (err) {
		return err;
	}
	err = format_zero_vspace(env);
	if (err) {
		return err;
	}
	err = flush_dirty(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_format_repo(struct silofs_env *env)
{
	int ret;

	silofs_env_lock(env);
	ret = silofs_repo_format(env->base.repo);
	silofs_env_unlock(env);
	return ret;
}

int silofs_open_repo(struct silofs_env *env)
{
	int ret;

	silofs_env_lock(env);
	ret = silofs_repo_open(env->base.repo);
	silofs_env_unlock(env);
	return ret;
}

static int reload_bootrec_of(const struct silofs_env *env,
                             const struct silofs_caddr *caddr,
                             struct silofs_bootrec *out_brec)
{
	int err;

	err = silofs_stat_bootrec(env, caddr);
	if (err) {
		return err;
	}
	err = silofs_load_bootrec(env, caddr, out_brec);
	if (err) {
		return err;
	}
	return 0;
}

static int
reload_bootrec(struct silofs_env *env, const struct silofs_caddr *caddr,
               struct silofs_bootrec *out_brec)
{
	int err;

	err = reload_bootrec_of(env, caddr, out_brec);
	if (err) {
		return err;
	}
	err = silofs_env_update_by(env, out_brec);
	if (err) {
		return err;
	}
	return 0;
}

static int
update_by_bootrec(struct silofs_env *env, const struct silofs_bootrec *brec)
{
	return silofs_env_update_by(env, brec);
}

static void
ref_super_by(const struct silofs_env *env, struct silofs_bootrec *brec)
{
	const struct silofs_ulink *sb_ulink = sbi_ulink(env->sbi);

	silofs_bootrec_set_sb_ulink(brec, sb_ulink);
}

static int commit_bootrec(struct silofs_env *env, struct silofs_bootrec *brec)
{
	struct silofs_caddr caddr;
	int err;

	ref_super_by(env, brec);
	err = silofs_save_bootrec(env, brec, &caddr);
	if (err) {
		return err;
	}
	err = update_by_bootrec(env, brec);
	if (err) {
		return err;
	}
	return 0;
}

static void resolve_bootrec_caddr(const struct silofs_env *env,
                                  struct silofs_caddr *out_caddr)
{
	caddr_assign(out_caddr, &env->boot.caddr);
}

static int format_bstore(struct silofs_env *env)
{
	return silofs_bstore_format(env->base.bstore);
}

static int
format_bootrec(const struct silofs_env *env, struct silofs_bootrec *brec)
{
	silofs_bootrec_setup(brec);
	generate_main_ivkey(env, brec);
	update_pvasd(env, brec);
	return 0;
}

static int do_format_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	struct silofs_bootrec brec = { .flags = SILOFS_BOOTF_NONE };
	int err;

	err = format_bstore(env);
	if (err) {
		return err;
	}
	err = format_bootrec(env, &brec);
	if (err) {
		return err;
	}
	err = update_by_bootrec(env, &brec);
	if (err) {
		return err;
	}
	err = check_want_capacity(env);
	if (err) {
		return err;
	}
	err = check_owner_ids(env);
	if (err) {
		return err;
	}
	err = format_umeta(env);
	if (err) {
		return err;
	}
	err = format_vmeta(env);
	if (err) {
		return err;
	}
	err = format_rootdir(env);
	if (err) {
		return err;
	}
	err = commit_bootrec(env, &brec);
	if (err) {
		return err;
	}
	resolve_bootrec_caddr(env, out_caddr);
	return 0;
}

int silofs_format_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	int ret;

	silofs_env_lock(env);
	ret = do_format_fs(env, out_caddr);
	silofs_env_unlock(env);
	return ret;
}

static int
reload_root_lseg(struct silofs_env *env, const struct silofs_bootrec *brec)
{
	silofs_env_set_sb_ulink(env, &brec->sb_ulink);
	return silofs_env_reload_sb_lseg(env);
}

static int
reload_bstore(struct silofs_env *env, const struct silofs_bootrec *brec)
{
	bool xxx_ready = false; /* XXX-1 */
	int err = 0;

	if (xxx_ready) {
		err = silofs_bstore_reload(env->base.bstore, &brec->pvasd);
	}
	return err;
}

static int do_open_fs(struct silofs_env *env, const struct silofs_caddr *caddr)
{
	struct silofs_bootrec brec = { .flags = SILOFS_BOOTF_NONE };
	int err;

	err = reload_bootrec(env, caddr, &brec);
	if (err) {
		return err;
	}
	err = reload_bstore(env, &brec);
	if (err) {
		return err;
	}
	err = reload_root_lseg(env, &brec);
	if (err) {
		return err;
	}
	err = reload_super(env);
	if (err) {
		return err;
	}
	err = reload_base_vspace(env);
	if (err) {
		return err;
	}
	err = reload_free_vspace(env);
	if (err) {
		return err;
	}
	err = reload_fs_meta(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_open_fs(struct silofs_env *env, const struct silofs_caddr *caddr)
{
	int ret;

	silofs_env_lock(env);
	ret = do_open_fs(env, caddr);
	silofs_env_unlock(env);
	return ret;
}

static int do_close_fs(struct silofs_env *env)
{
	int err;

	err = flush_dirty(env);
	if (err) {
		return err;
	}
	err = fsync_lsegs(env);
	if (err) {
		return err;
	}
	err = shutdown_fs(env);
	if (err) {
		return err;
	}
	drop_caches(env);
	return err;
}

int silofs_close_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = do_close_fs(env);
	silofs_env_unlock(env);
	return err;
}

int silofs_poke_fs(struct silofs_env *env, const struct silofs_caddr *caddr)
{
	struct silofs_bootrec brec = { .flags = SILOFS_BOOTF_NONE };
	int err;

	silofs_env_lock(env);
	err = reload_bootrec(env, caddr, &brec);
	silofs_env_unlock(env);
	return err;
}

static int stat_archive_index(const struct silofs_env *env,
                              const struct silofs_caddr *caddr)
{
	ssize_t sz = -1;

	return silofs_repo_stat_pack(env->base.repo, caddr, &sz);
}

int silofs_poke_archive(struct silofs_env *env,
                        const struct silofs_caddr *caddr)
{
	int err;

	silofs_env_lock(env);
	err = stat_archive_index(env, caddr);
	silofs_env_unlock(env);
	return err;
}

static int
exec_clone_fs(struct silofs_env *env, struct silofs_bootrecs *out_brecs)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_clone(&task, SILOFS_INO_ROOT, 0, out_brecs);
	if (err) {
		return err;
	}
	return term_task(&task, err);
}

int silofs_fork_fs(struct silofs_env *env, struct silofs_caddr *out_boot_new,
                   struct silofs_caddr *out_boot_alt)
{
	struct silofs_bootrecs brecs;
	int err;

	silofs_env_lock(env);
	err = exec_clone_fs(env, &brecs);
	if (!err) {
		caddr_assign(out_boot_new, &brecs.caddr_new);
		caddr_assign(out_boot_alt, &brecs.caddr_alt);
	}
	silofs_env_unlock(env);
	return err;
}

static int exec_unref_fs(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_unrefs(&task);
	return term_task(&task, err);
}

static int unlink_bootrec_of(const struct silofs_env *env,
                             const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_stat_bootrec(env, caddr);
	if (err) {
		return err;
	}
	err = silofs_unlink_bootrec(env, caddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_unref_fs(struct silofs_env *env, const struct silofs_caddr *caddr)
{
	struct silofs_bootrec brec = { .flags = SILOFS_BOOTF_NONE };
	int err;

	err = reload_bootrec(env, caddr, &brec);
	if (err) {
		return err;
	}
	err = reload_root_lseg(env, &brec);
	if (err) {
		return err;
	}
	err = reload_super(env);
	if (err) {
		return err;
	}
	err = exec_unref_fs(env);
	if (err) {
		return err;
	}
	err = unlink_bootrec_of(env, caddr);
	if (err) {
		return err;
	}
	err = do_close_fs(env);
	if (err) {
		return err;
	}
	return 0;
}

static int exec_inspect_fs(struct silofs_env *env, silofs_visit_laddr_fn cb,
                           void *user_ctx)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_inspect(&task, cb, user_ctx);
	return term_task(&task, err);
}

int silofs_inspect_fs(struct silofs_env *env, silofs_visit_laddr_fn cb,
                      void *user_ctx)
{
	int err;

	silofs_env_lock(env);
	err = exec_inspect_fs(env, cb, user_ctx);
	silofs_env_unlock(env);
	return err;
}

static int exec_pack_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_pack(&task, out_caddr);
	return term_task(&task, err);
}

int silofs_archive_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	int err;

	silofs_env_lock(env);
	err = exec_pack_fs(env, out_caddr);
	silofs_env_unlock(env);
	return err;
}

static int
exec_unpack_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_unpack(&task, out_caddr);
	return term_task(&task, err);
}

int silofs_restore_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	int err;

	silofs_env_lock(env);
	err = exec_unpack_fs(env, out_caddr);
	silofs_env_unlock(env);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define SILOFS_NOFILES_MIN (512)

static int errno_or_errnum(int errnum)
{
	return (errno > 0) ? -errno : -abs(errnum);
}

static int check_endianess32(uint32_t val, const char *str)
{
	char buf[16] = "";
	const uint32_t val_le = htole32(val);

	for (size_t i = 0; i < 4; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess64(uint64_t val, const char *str)
{
	char buf[16] = "";
	const uint64_t val_le = htole64(val);

	for (size_t i = 0; i < 8; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess(void)
{
	int err;

	err = check_endianess64(SILOFS_REPO_META_MAGIC, "#SILOFS#");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_BOOT_RECORD_MAGIC, "@SILOFS@");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_PAR_INDEX_MAGIC, "%silofs%");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_SUPER_MAGIC, "@silofs@");
	if (err) {
		return err;
	}
	err = check_endianess32(SILOFS_FSID_MAGIC, "SILO");
	if (err) {
		return err;
	}
	err = check_endianess32(SILOFS_META_MAGIC, "silo");
	if (err) {
		return err;
	}
	return 0;
}

static int check_sysconf(void)
{
	long val;
	long page_shift = 0;
	const long page_size_min = SILOFS_PAGE_SIZE_MIN;
	const long page_shift_min = SILOFS_PAGE_SHIFT_MIN;
	const long page_shift_max = SILOFS_PAGE_SHIFT_MAX;
	const long cl_size_min = SILOFS_CACHELINE_SIZE_MIN;
	const long cl_size_max = SILOFS_CACHELINE_SIZE_MAX;

	errno = 0;
	val = silofs_sc_phys_pages();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEM);
	}
	val = silofs_sc_avphys_pages();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEM);
	}
	val = silofs_sc_l1_dcache_linesize();
	if ((val < cl_size_min) || (val > cl_size_max)) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	val = silofs_sc_page_size();
	if ((val < page_size_min) || (val % page_size_min)) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	for (long shift = page_shift_min; shift <= page_shift_max; ++shift) {
		if (val == (1L << shift)) {
			page_shift = val;
			break;
		}
	}
	if (page_shift == 0) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	val = silofs_sc_nproc_onln();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEDIUM);
	}
	val = silofs_sc_iov_max();
	if (val < SILOFS_IOV_MAX) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	return 0;
}

static int check_system_page_size(void)
{
	long page_size;
	const size_t page_shift[] = { 12, 13, 14, 16 };

	page_size = silofs_sc_page_size();
	if (page_size > SILOFS_LBK_SIZE) {
		return -SILOFS_EOPNOTSUPP;
	}
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(page_shift); ++i) {
		if (page_size == (1L << page_shift[i])) {
			return 0;
		}
	}
	return -SILOFS_EOPNOTSUPP;
}

static int check_proc_rlimits(void)
{
	struct rlimit rlim;
	int err;

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < SILOFS_MEGA) {
		return -SILOFS_ENOMEM;
	}
	err = silofs_sys_getrlimit(RLIMIT_NOFILE, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < SILOFS_NOFILES_MIN) {
		return -SILOFS_ENFILE;
	}
	return 0;
}

static int check_and_init_lib(void)
{
	int err;

	err = check_endianess();
	if (err) {
		return err;
	}
	err = check_sysconf();
	if (err) {
		return err;
	}
	err = check_system_page_size();
	if (err) {
		return err;
	}
	err = check_proc_rlimits();
	if (err) {
		return err;
	}
	err = silofs_init_time();
	if (err) {
		return err;
	}
	err = silofs_init_gcrypt();
	if (err) {
		return err;
	}
	return 0;
}

static bool g_initlib_once_done;

int silofs_initlib_once(void)
{
	int ret = 0;

	if (g_initlib_once_done) {
		goto out;
	}
	ret = check_and_init_lib();
	if (ret != 0) {
		goto out;
	}
	silofs_require_proper_defs();
	g_initlib_once_done = true;
out:
	return ret;
}
