/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/fs/fuseq.h>
#include <silofs/execlib.h>


#define ROUND_TO_4K(n)  SILOFS_ROUND_TO(n, (4 * SILOFS_KILO))

union silofs_alloc_u {
	struct silofs_qalloc    qalloc;
	struct silofs_calloc    calloc;
};

struct silofs_fs_core {
	struct silofs_password  passwd;
	union silofs_alloc_u    alloc_u;
	struct silofs_lcache    lcache;
	struct silofs_repo      repo;
	struct silofs_submitq   submitq;
	struct silofs_idsmap    idsmap;
	struct silofs_fsenv     fsenv;
	struct silofs_flusher   flusher;
};

union silofs_fs_core_u {
	struct silofs_fs_core c;
	uint8_t dat[ROUND_TO_4K(sizeof(struct silofs_fs_core))];
};

union silofs_fuseq_page {
	struct silofs_fuseq     fuseq;
	uint8_t page[SILOFS_PAGE_SIZE_MIN];
};

struct silofs_fs_inst {
	union silofs_fs_core_u  fs_core;
};

struct silofs_fs_ctx {
	struct silofs_fs_args   args;
	struct silofs_fs_inst  *inst;
	struct silofs_password *password;
	struct silofs_alloc    *alloc;
	struct silofs_lcache   *lcache;
	struct silofs_repo     *repo;
	struct silofs_submitq  *submitq;
	struct silofs_flusher  *flusher;
	struct silofs_idsmap   *idsmap;
	struct silofs_fsenv    *fsenv;
	struct silofs_fuseq    *fuseq;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t align_down(size_t sz, size_t align)
{
	return (sz / align) * align;
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
	mem_ceil = silofs_min3(mem_glim, mem_rlim, mem_total / 4);
	mem_uget = silofs_clamp(mem_want, mem_floor, mem_ceil);
	*out_mem_size = align_down(mem_uget, 2 * SILOFS_UMEGA);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_fs_inst *fs_inst_of(struct silofs_fsenv *fsenv)
{
	struct silofs_fs_core *fs_core;
	union silofs_fs_core_u *fs_core_u;

	fs_core = container_of(fsenv, struct silofs_fs_core, fsenv);
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

static int fs_ctx_setup_fsenv(struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_fsenv_base fse_base = {
		.passwd = fs_ctx->password,
		.alloc = fs_ctx->alloc,
		.lcache = fs_ctx->lcache,
		.repo = fs_ctx->repo,
		.submitq = fs_ctx->submitq,
		.flusher = fs_ctx->flusher,
		.idsmap = fs_ctx->idsmap,
		.fuseq = NULL,
	};
	struct silofs_fsenv *fsenv;
	int err;

	fsenv = &fs_ctx->inst->fs_core.c.fsenv;
	err = silofs_fsenv_init(fsenv, &fs_ctx->args, &fse_base);
	if (err) {
		return err;
	}
	fs_ctx->fsenv = fsenv;
	return 0;
}

static void fs_ctx_destroy_fsenv(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->fsenv != NULL) {
		silofs_fsenv_fini(fs_ctx->fsenv);
		fs_ctx->fsenv = NULL;
	}
}

static union silofs_fuseq_page *fuseq_to_page(struct silofs_fuseq *fuseq)
{
	const union silofs_fuseq_page *fqp = NULL;

	STATICASSERT_EQ(sizeof(*fqp), SILOFS_PAGE_SIZE_MIN);

	fqp = container_of(fuseq, union silofs_fuseq_page, fuseq);
	return unconst(fqp);
}

static bool has_with_fuse(const struct silofs_fsenv *fsenv)
{
	const enum silofs_env_flags mask = SILOFS_ENVF_WITHFUSE;

	return (fsenv->fse_ctl_flags & mask) == mask;
}

static bool run_with_fuse(const struct silofs_fsenv *fsenv)
{
	const struct silofs_fuseq *fuseq = fsenv->fse.fuseq;

	return (fuseq != NULL) && has_with_fuse(fsenv);
}

static bool has_ctlf(const struct silofs_fsenv *fsenv,
                     enum silofs_env_flags mask)
{
	return (fsenv->fse_ctl_flags & mask) == mask;
}

static void fs_ctx_bind_fuseq(struct silofs_fs_ctx *fs_ctx,
                              struct silofs_fuseq *fuseq)
{
	struct silofs_fsenv *fsenv = fs_ctx->fsenv;

	fs_ctx->fuseq = fuseq;
	if (fsenv == NULL) {
		return;
	}
	fsenv->fse.fuseq = fuseq;
	if (fuseq == NULL) {
		return;
	}
	fuseq->fq_writeback_cache = has_ctlf(fsenv, SILOFS_ENVF_WRITEBACK);
	fuseq->fq_may_splice = has_ctlf(fsenv, SILOFS_ENVF_MAYSPLICE);
}

static int fs_ctx_setup_fuseq(struct silofs_fs_ctx *fs_ctx)
{
	union silofs_fuseq_page *fqp = NULL;
	const size_t fuseq_pg_size = sizeof(*fqp);
	void *mem = NULL;
	int err;

	if (!has_with_fuse(fs_ctx->fsenv)) {
		return 0;
	}
	mem = silofs_memalloc(fs_ctx->alloc, fuseq_pg_size, 0);
	if (mem == NULL) {
		log_warn("failed to allocate fuseq: size=%lu", fuseq_pg_size);
		return -SILOFS_ENOMEM;
	}
	fqp = mem;
	err = silofs_fuseq_init(&fqp->fuseq, fs_ctx->alloc);
	if (err) {
		silofs_memfree(fs_ctx->alloc, mem, fuseq_pg_size, 0);
		return err;
	}
	fs_ctx_bind_fuseq(fs_ctx, &fqp->fuseq);
	return 0;
}

static void fs_ctx_destroy_fuseq(struct silofs_fs_ctx *fs_ctx)
{
	union silofs_fuseq_page *fuseq_pg = NULL;

	if (fs_ctx->fuseq != NULL) {
		fuseq_pg = fuseq_to_page(fs_ctx->fuseq);

		silofs_fuseq_fini(fs_ctx->fuseq);
		fs_ctx_bind_fuseq(fs_ctx, NULL);

		silofs_memfree(fs_ctx->alloc, fuseq_pg,
		               sizeof(*fuseq_pg), 0);
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
	fs_ctx_destroy_fsenv(fs_ctx);
	fs_ctx_destroy_idsmap(fs_ctx);
	fs_ctx_destroy_flusher(fs_ctx);
	fs_ctx_destroy_submitq(fs_ctx);
	fs_ctx_destroy_repo(fs_ctx);
	fs_ctx_destroy_lcache(fs_ctx);
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
	err = fs_ctx_setup_lcache(fs_ctx);
	if (err) {
		goto out_err;
	}
	err = fs_ctx_setup_repo(fs_ctx);
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
	err = fs_ctx_setup_fsenv(fs_ctx);
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

static void fs_ctx_init(struct silofs_fs_ctx *fs_ctx,
                        struct silofs_fs_inst *fs_inst,
                        const struct silofs_fs_args *fs_args)
{
	memset(fs_ctx, 0, sizeof(*fs_ctx));
	memcpy(&fs_ctx->args, fs_args, sizeof(fs_ctx->args));
	fs_ctx->inst = fs_inst;
}

static void fs_ctx_init_from(struct silofs_fs_ctx *fs_ctx,
                             struct silofs_fs_inst *fs_inst)
{
	struct silofs_fsenv *fsenv = &fs_inst->fs_core.c.fsenv;

	fs_ctx_init(fs_ctx, fs_inst, &fsenv->fse_args);
	fs_ctx->password = &fs_inst->fs_core.c.passwd;
	fs_ctx->fsenv = fsenv;
	fs_ctx->alloc = fsenv->fse.alloc;
	fs_ctx->lcache = fsenv->fse.lcache;
	fs_ctx->repo = fsenv->fse.repo;
	fs_ctx->submitq = fsenv->fse.submitq;
	fs_ctx->flusher = fsenv->fse.flusher;
	fs_ctx->idsmap = fsenv->fse.idsmap;
	fs_ctx->fuseq = fsenv->fse.fuseq;
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

int silofs_new_fsenv(const struct silofs_fs_args *fs_args,
                     struct silofs_fsenv **out_fsenv)
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
	*out_fsenv = &fs_inst->fs_core.c.fsenv;
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

void silofs_del_fsenv(struct silofs_fsenv *fsenv)
{
	struct silofs_fs_inst *fs_inst = NULL;

	fs_inst = fs_inst_of(fsenv);
	del_fs_inst(fs_inst);
	silofs_burnstack();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_post_exec_fs(struct silofs_fsenv *fsenv)
{
	const struct silofs_fuseq *fuseq = fsenv->fse.fuseq;
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

static int make_task(struct silofs_fsenv *fsenv, struct silofs_task *task)
{
	const struct silofs_fs_args *args = &fsenv->fse_args;

	silofs_task_init(task, fsenv);
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

static void drop_caches(const struct silofs_fsenv *fsenv)
{
	silofs_lcache_drop(fsenv->fse.lcache);
	silofs_repo_drop_some(fsenv->fse.repo);
}

static int exec_stage_rootdir_inode(struct silofs_fsenv *fsenv,
                                    struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_inode(&task, SILOFS_INO_ROOT,
	                         SILOFS_STG_CUR, out_ii);
	return term_task(&task, err);
}

static int reload_rootdir_inode(struct silofs_fsenv *fsenv)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = exec_stage_rootdir_inode(fsenv, &ii);
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

static int exec_rescan_vspace_of(struct silofs_fsenv *fsenv,
                                 enum silofs_ltype ltype)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_rescan_vspace_of(&task, ltype);
	return term_task(&task, err);
}

static int reload_free_vspace(struct silofs_fsenv *fsenv)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = exec_rescan_vspace_of(fsenv, ltype);
		if (err && (err != -SILOFS_ENOSPC) &&
		    (err != -SILOFS_ENOENT)) {
			log_err("failed to reload free vspace: err=%d", err);
			return err;
		}
	}
	return 0;
}

static int reload_fs_meta(struct silofs_fsenv *fsenv)
{
	int err;

	err = reload_rootdir_inode(fsenv);
	if (err) {
		log_err("failed to reload root dir: err=%d", err);
		return err;
	}
	drop_caches(fsenv);
	return 0;
}

static int exec_flush_dirty_now(struct silofs_fsenv *fsenv)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_flush_dirty_now(&task);
	return term_task(&task, err);
}

static int flush_dirty(struct silofs_fsenv *fsenv)
{
	int err;

	err = exec_flush_dirty_now(fsenv);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
	}
	return err;
}

static int fsync_lsegs(const struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_repo_fsync_all(fsenv->fse.repo);
	if (err) {
		log_err("failed to fsync lsegs: err=%d", err);
	}
	return err;
}

static int shutdown_fsenv(struct silofs_fsenv *fsenv)
{
	return silofs_fsenv_shut(fsenv);
}

int silofs_close_repo(struct silofs_fsenv *fsenv)
{
	int ret;

	silofs_fsenv_lock(fsenv);
	ret = silofs_repo_close(fsenv->fse.repo);
	silofs_fsenv_unlock(fsenv);
	return ret;
}

static int do_mount_and_exec(struct silofs_fsenv *fsenv)
{
	struct silofs_fuseq *fuseq = fsenv->fse.fuseq;
	int err;

	err = silofs_fuseq_mount(fuseq, fsenv, fsenv->fse_args.mntdir);
	if (err) {
		return err;
	}
	err = silofs_fuseq_exec(fuseq);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_exec_fs(struct silofs_fsenv *fsenv)
{
	struct silofs_fuseq *fuseq = fsenv->fse.fuseq;
	int err = -SILOFS_EINVAL;

	if (run_with_fuse(fsenv)) {
		err = silofs_fuseq_update(fuseq);
		if (!err) {
			err = do_mount_and_exec(fsenv);
			silofs_fuseq_term(fuseq);
		}
	}
	return err;
}

void silofs_halt_fs(struct silofs_fsenv *fsenv)
{
	silofs_fsenv_lock(fsenv);
	if (fsenv->fse.fuseq != NULL) {
		fsenv->fse.fuseq->fq_active = 0;
	}
	silofs_fsenv_unlock(fsenv);
}

static int flush_and_drop_cache(struct silofs_fsenv *fsenv)
{
	int err;

	err = flush_dirty(fsenv);
	if (err) {
		return err;
	}
	drop_caches(fsenv);
	return 0;
}

static int do_sync_fs(struct silofs_fsenv *fsenv, bool drop)
{
	int err;

	err = flush_dirty(fsenv);
	if (!err && drop) {
		drop_caches(fsenv);
	}
	return err;
}

int silofs_sync_fs(struct silofs_fsenv *fsenv, bool drop)
{
	int cnt = 3;
	int err = 0;

	silofs_fsenv_lock(fsenv);
	while ((cnt-- > 0) && !err) {
		err = do_sync_fs(fsenv, drop);
	}
	silofs_fsenv_unlock(fsenv);
	return err;
}

void silofs_stat_fs(const struct silofs_fsenv *fsenv,
                    struct silofs_cachestats *cst)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0 };
	const struct silofs_alloc *alloc = fsenv->fse.alloc;
	const struct silofs_lcache *lcache = fsenv->fse.lcache;

	silofs_memzero(cst, sizeof(*cst));
	silofs_memstat(alloc, &alst);
	cst->nalloc_bytes = alst.nbytes_use;
	cst->ncache_unodes += lcache->lc_ui_hmapq.hmq_htbl_size;
	cst->ncache_vnodes += lcache->lc_vi_hmapq.hmq_htbl_size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int derive_main_ivkey(struct silofs_fsenv *fsenv,
                             const struct silofs_bootrec *brec)
{
	return silofs_fsenv_derive_main_ivkey(fsenv, brec);
}

static int check_superblock(const struct silofs_fsenv *fsenv)
{
	const struct silofs_sb_info *sbi = fsenv->fse_sbi;
	const struct silofs_super_block *sb = sbi->sb;
	int fossil;
	int err;

	err = silofs_sb_check_version(sb);
	if (err) {
		log_err("bad sb: magic=%lx version:=%ld err=%d",
		        sb->sb_magic, sb->sb_version, err);
		return err;
	}
	fossil = silofs_sb_test_flags(sb, SILOFS_SUPERF_FOSSIL);
	if (fossil && !fsenv->fse_args.cflags.rdonly) {
		log_warn("read-only fs: sb-flags=%08x", (int)sb->sb_flags);
		return -SILOFS_EROFS;
	}
	return 0;
}

static int reload_super(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_fsenv_reload_super(fsenv);
	if (err) {
		log_err("failed to reload super: err=%d", err);
		return err;
	}
	err = check_superblock(fsenv);
	if (err) {
		log_warn("bad super-block: err=%d", err);
		return err;
	}
	return 0;
}

static int exec_require_spmaps_of(struct silofs_fsenv *fsenv,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	enum silofs_stg_mode stg_mode = SILOFS_STG_COW;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_require_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int format_base_vspmaps_of(struct silofs_fsenv *fsenv,
                                  const struct silofs_vaddr *vaddr)
{
	int err;

	err = exec_require_spmaps_of(fsenv, vaddr);
	if (err) {
		log_err("failed to format base spmaps: "
		        "ltype=%d err=%d", vaddr->ltype, err);
		return err;
	}
	err = do_sync_fs(fsenv, false);
	if (err) {
		return err;
	}
	log_dbg("format base spmaps of: ltype=%d err=%d", vaddr->ltype, err);
	return 0;
}

static int format_base_vspmaps(struct silofs_fsenv *fsenv)
{
	struct silofs_vaddr vaddr;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		vaddr_setup(&vaddr, ltype, 0);
		err = format_base_vspmaps_of(fsenv, &vaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_claim_vspace(struct silofs_fsenv *fsenv,
                             enum silofs_ltype ltype,
                             struct silofs_vaddr *out_vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_claim_vspace(&task, ltype, out_vaddr);
	return term_task(&task, err);
}

static int exec_reclaim_vspace(struct silofs_fsenv *fsenv,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(&task, vaddr);
	return term_task(&task, err);
}

static int claim_reclaim_vspace_of(struct silofs_fsenv *fsenv,
                                   enum silofs_ltype vspace)
{
	struct silofs_vaddr vaddr;
	const loff_t voff_exp = 0;
	int err;

	drop_caches(fsenv);
	err = exec_claim_vspace(fsenv, vspace, &vaddr);
	if (err) {
		log_err("failed to claim: vspace=%d err=%d", vspace, err);
		return err;
	}

	if (vaddr.off != voff_exp) {
		log_err("wrong first voff: vspace=%d expected-voff=%ld "
		        "got-voff=%ld", vspace, voff_exp, vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}

	drop_caches(fsenv);
	err = exec_reclaim_vspace(fsenv, &vaddr);
	if (err) {
		log_err("failed to reclaim space: vspace=%d voff=%ld err=%d",
		        vspace, vaddr.off, err);
	}
	return 0;
}

static int claim_reclaim_vspace(struct silofs_fsenv *fsenv)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = claim_reclaim_vspace_of(fsenv, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fsenv);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_stage_spmaps_at(struct silofs_fsenv *fsenv,
                                const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stg_mode stg_mode = SILOFS_STG_CUR;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int reload_base_vspace_of(struct silofs_fsenv *fsenv,
                                 enum silofs_ltype vspace)
{
	struct silofs_vaddr vaddr;
	int err;

	vaddr_setup(&vaddr, vspace, 0);
	err = exec_stage_spmaps_at(fsenv, &vaddr);
	if (err) {
		log_err("failed to reload: vspace=%d err=%d", vspace, err);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int reload_base_vspace(struct silofs_fsenv *fsenv)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err = 0;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = reload_base_vspace_of(fsenv, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fsenv);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_spawn_vnode(struct silofs_fsenv *fsenv,
                            enum silofs_ltype ltype,
                            struct silofs_vnode_info **out_vi)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode(&task, NULL, ltype, out_vi);
	if (!err) {
		vi_dirtify(*out_vi, NULL);
	}
	return term_task(&task, err);
}

static int format_zero_vspace_of(struct silofs_fsenv *fsenv,
                                 enum silofs_ltype vspace)
{
	struct silofs_vnode_info *vi = NULL;
	const struct silofs_vaddr *vaddr = NULL;
	int err;

	err = exec_spawn_vnode(fsenv, vspace, &vi);
	if (err) {
		log_err("failed to spawn: vspace=%d err=%d", vspace, err);
		return err;
	}
	vaddr = vi_vaddr(vi);
	if (vaddr->off != 0) {
		log_err("bad offset: vspace=%d off=%ld", vspace, vaddr->off);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int format_zero_vspace(struct silofs_fsenv *fsenv)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = format_zero_vspace_of(fsenv, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fsenv);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int do_spawn_rootdir(struct silofs_task *task,
                            struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp;

	silofs_inew_params_of(&inp, task_creds(task), NULL, S_IFDIR | 0755, 0);
	return silofs_spawn_inode(task, &inp, out_ii);
}

static int exec_spawn_rootdir(struct silofs_fsenv *fsenv,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = do_spawn_rootdir(&task, out_ii);
	return term_task(&task, err);
}

static int do_format_rootdir(struct silofs_fsenv *fsenv)
{
	struct silofs_inode_info *root_ii = NULL;
	int err;

	err = exec_spawn_rootdir(fsenv, &root_ii);
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

static int format_rootdir(struct silofs_fsenv *fsenv)
{
	int err;

	err = do_format_rootdir(fsenv);
	if (!err) {
		err = flush_and_drop_cache(fsenv);
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

static int check_want_capacity(const struct silofs_fsenv *fsenv)
{
	const size_t cap_want = fsenv->fse_args.capacity;
	int err;

	err = check_fs_capacity(cap_want);
	if (err) {
		log_err("illegal file-system capacity: "
		        "cap=%lu err=%d", cap_want, err);
		return err;
	}
	return 0;
}

static int check_owner_ids(const struct silofs_fsenv *fsenv)
{
	const uid_t owner_uid = fsenv->fse_args.uid;
	const gid_t owner_gid = fsenv->fse_args.gid;
	uid_t suid;
	gid_t sgid;
	int err;

	err = silofs_idsmap_map_uidgid(fsenv->fse.idsmap, owner_uid,
	                               owner_gid, &suid, &sgid);
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

static int format_umeta(struct silofs_fsenv *fsenv)
{
	size_t fs_cap;
	int err;

	err = check_want_capacity(fsenv);
	if (err) {
		return err;
	}
	fs_cap = calc_aligned_fs_cap(fsenv->fse_args.capacity);
	err = silofs_fsenv_format_super(fsenv, fs_cap);
	if (err) {
		return err;
	}
	err = check_superblock(fsenv);
	if (err) {
		return err;
	}
	err = flush_dirty(fsenv);
	if (err) {
		return err;
	}
	return 0;
}

static int format_vmeta(struct silofs_fsenv *fsenv)
{
	int err;

	err = format_base_vspmaps(fsenv);
	if (err) {
		return err;
	}
	err = claim_reclaim_vspace(fsenv);
	if (err) {
		return err;
	}
	err = format_zero_vspace(fsenv);
	if (err) {
		return err;
	}
	err = flush_dirty(fsenv);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_format_repo(struct silofs_fsenv *fsenv)
{
	int ret;

	silofs_fsenv_lock(fsenv);
	ret = silofs_repo_format(fsenv->fse.repo);
	silofs_fsenv_unlock(fsenv);
	return ret;
}

int silofs_open_repo(struct silofs_fsenv *fsenv)
{
	int ret;

	silofs_fsenv_lock(fsenv);
	ret = silofs_repo_open(fsenv->fse.repo);
	silofs_fsenv_unlock(fsenv);
	return ret;
}

static int reload_bootrec(const struct silofs_fsenv *fsenv,
                          const struct silofs_caddr *caddr,
                          struct silofs_bootrec *out_brec)
{
	int err;

	err = silofs_stat_bootrec(fsenv, caddr);
	if (err) {
		return err;
	}
	err = silofs_load_bootrec(fsenv, caddr, out_brec);
	if (err) {
		return err;
	}
	return 0;
}

static int unlink_bootrec_of(const struct silofs_fsenv *fsenv,
                             const struct silofs_caddr *caddr)
{
	return silofs_unlink_bootrec(fsenv, caddr);
}

static void update_bootrec(const struct silofs_fsenv *fsenv,
                           struct silofs_bootrec *brec)
{
	const struct silofs_sb_info *sbi = fsenv->fse_sbi;
	const struct silofs_ulink *sb_ulink = sbi_ulink(sbi);

	silofs_bootrec_set_sb_ulink(brec, sb_ulink);
}

static int commit_bootrec(struct silofs_fsenv *fsenv,
                          struct silofs_bootrec *brec)
{
	update_bootrec(fsenv, brec);
	return silofs_resave_bootrec(fsenv, brec);
}

static void resolve_bootrec_caddr(const struct silofs_fsenv *fsenv,
                                  struct silofs_caddr *out_caddr)
{
	caddr_assign(out_caddr, &fsenv->fse_boot_caddr);
}

static int do_format_fs(struct silofs_fsenv *fsenv,
                        struct silofs_caddr *out_caddr)
{
	struct silofs_bootrec brec;
	int err;

	silofs_bootrec_setup(&brec);
	err = check_want_capacity(fsenv);
	if (err) {
		return err;
	}
	err = check_owner_ids(fsenv);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fsenv, &brec);
	if (err) {
		return err;
	}
	err = format_umeta(fsenv);
	if (err) {
		return err;
	}
	err = format_vmeta(fsenv);
	if (err) {
		return err;
	}
	err = format_rootdir(fsenv);
	if (err) {
		return err;
	}
	err = commit_bootrec(fsenv, &brec);
	if (err) {
		return err;
	}
	resolve_bootrec_caddr(fsenv, out_caddr);
	return 0;
}

int silofs_format_fs(struct silofs_fsenv *fsenv,
                     struct silofs_caddr *out_caddr)
{
	int ret;

	silofs_fsenv_lock(fsenv);
	ret = do_format_fs(fsenv, out_caddr);
	silofs_fsenv_unlock(fsenv);
	return ret;
}

static int reload_root_lseg(struct silofs_fsenv *fsenv,
                            const struct silofs_bootrec *brec)
{
	silofs_fsenv_set_sb_ulink(fsenv, &brec->sb_ulink);
	return silofs_fsenv_reload_sb_lseg(fsenv);
}

static int do_boot_fs(struct silofs_fsenv *fsenv,
                      const struct silofs_caddr *caddr)
{
	struct silofs_bootrec brec;
	int err;

	err = reload_bootrec(fsenv, caddr, &brec);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fsenv, &brec);
	if (err) {
		return err;
	}
	err = reload_root_lseg(fsenv, &brec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_boot_fs(struct silofs_fsenv *fsenv,
                   const struct silofs_caddr *boot_ref)
{
	int ret;

	silofs_fsenv_lock(fsenv);
	ret = do_boot_fs(fsenv, boot_ref);
	silofs_fsenv_unlock(fsenv);
	return ret;
}

static int do_open_fs(struct silofs_fsenv *fsenv)
{
	int err;

	err = reload_super(fsenv);
	if (err) {
		return err;
	}
	err = reload_base_vspace(fsenv);
	if (err) {
		return err;
	}
	err = reload_free_vspace(fsenv);
	if (err) {
		return err;
	}
	err = reload_fs_meta(fsenv);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_open_fs(struct silofs_fsenv *fsenv)
{
	int ret;

	silofs_fsenv_lock(fsenv);
	ret = do_open_fs(fsenv);
	silofs_fsenv_unlock(fsenv);
	return ret;
}

static int do_close_fs(struct silofs_fsenv *fsenv)
{
	int err;

	err = flush_dirty(fsenv);
	if (err) {
		return err;
	}
	err = fsync_lsegs(fsenv);
	if (err) {
		return err;
	}
	err = shutdown_fsenv(fsenv);
	if (err) {
		return err;
	}
	drop_caches(fsenv);
	return err;
}

int silofs_close_fs(struct silofs_fsenv *fsenv)
{
	int err;

	silofs_fsenv_lock(fsenv);
	err = do_close_fs(fsenv);
	silofs_fsenv_unlock(fsenv);
	return err;
}

int silofs_poke_fs(struct silofs_fsenv *fsenv,
                   const struct silofs_caddr *caddr,
                   struct silofs_bootrec *out_brec)
{
	int err;

	silofs_fsenv_lock(fsenv);
	err = reload_bootrec(fsenv, caddr, out_brec);
	silofs_fsenv_unlock(fsenv);
	return err;
}

static int stat_archive_index(const struct silofs_fsenv *fsenv,
                              const struct silofs_caddr *caddr)
{
	ssize_t sz = -1;

	return silofs_repo_stat_pack(fsenv->fse.repo, caddr, &sz);
}

int silofs_poke_archive(struct silofs_fsenv *fsenv,
                        const struct silofs_caddr *caddr)
{
	int err;

	silofs_fsenv_lock(fsenv);
	err = stat_archive_index(fsenv, caddr);
	silofs_fsenv_unlock(fsenv);
	return err;
}

static int exec_clone_fs(struct silofs_fsenv *fsenv,
                         struct silofs_bootrecs *out_brecs)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_clone(&task, SILOFS_INO_ROOT, 0, out_brecs);
	if (err) {
		return err;
	}
	return term_task(&task, err);
}

int silofs_fork_fs(struct silofs_fsenv *fsenv,
                   struct silofs_caddr *out_boot_new,
                   struct silofs_caddr *out_boot_alt)
{
	struct silofs_bootrecs brecs;
	int err;

	silofs_fsenv_lock(fsenv);
	err = exec_clone_fs(fsenv, &brecs);
	if (!err) {
		caddr_assign(out_boot_new, &brecs.caddr_new);
		caddr_assign(out_boot_alt, &brecs.caddr_alt);
	}
	silofs_fsenv_unlock(fsenv);
	return err;
}

static int exec_unref_fs(struct silofs_fsenv *fsenv)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_unrefs(&task);
	return term_task(&task, err);
}

int silofs_unref_fs(struct silofs_fsenv *fsenv,
                    const struct silofs_caddr *caddr)
{
	struct silofs_bootrec brec;
	int err;

	err = reload_bootrec(fsenv, caddr, &brec);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fsenv, &brec);
	if (err) {
		return err;
	}
	err = reload_root_lseg(fsenv, &brec);
	if (err) {
		return err;
	}
	err = reload_super(fsenv);
	if (err) {
		return err;
	}
	err = exec_unref_fs(fsenv);
	if (err) {
		return err;
	}
	err = unlink_bootrec_of(fsenv, caddr);
	if (err) {
		return err;
	}
	err = do_close_fs(fsenv);
	if (err) {
		return err;
	}
	return 0;
}

static int exec_inspect_fs(struct silofs_fsenv *fsenv,
                           silofs_visit_laddr_fn cb, void *user_ctx)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_inspect(&task, cb, user_ctx);
	return term_task(&task, err);
}

int silofs_inspect_fs(struct silofs_fsenv *fsenv,
                      silofs_visit_laddr_fn cb, void *user_ctx)
{
	int err;

	silofs_fsenv_lock(fsenv);
	err = exec_inspect_fs(fsenv, cb, user_ctx);
	silofs_fsenv_unlock(fsenv);
	return err;
}

static int exec_pack_fs(struct silofs_fsenv *fsenv,
                        struct silofs_caddr *out_caddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_pack(&task, out_caddr);
	return term_task(&task, err);
}

int silofs_archive_fs(struct silofs_fsenv *fsenv,
                      struct silofs_caddr *out_caddr)
{
	int err;

	silofs_fsenv_lock(fsenv);
	err = exec_pack_fs(fsenv, out_caddr);
	silofs_fsenv_unlock(fsenv);
	return err;
}

static int exec_unpack_fs(struct silofs_fsenv *fsenv,
                          struct silofs_caddr *out_caddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fsenv, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_unpack(&task, out_caddr);
	return term_task(&task, err);
}

int silofs_restore_fs(struct silofs_fsenv *fsenv,
                      struct silofs_caddr *out_caddr)
{
	int err;

	silofs_fsenv_lock(fsenv);
	err = exec_unpack_fs(fsenv, out_caddr);
	silofs_fsenv_unlock(fsenv);
	return err;
}
