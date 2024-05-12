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
#include <silofs/pack.h>
#include <silofs/execlib.h>


#define ROUND_TO_4K(n)  SILOFS_ROUND_TO(n, (4 * SILOFS_KILO))

union silofs_fs_alloc_u {
	struct silofs_qalloc    qalloc;
	struct silofs_calloc    calloc;
};

struct silofs_fs_core {
	struct silofs_password  passwd;
	union silofs_fs_alloc_u alloc_u;
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
	uint8_t page[4096];
};

struct silofs_fs_ctx_obj {
	union silofs_fs_core_u  fs_core;
	struct silofs_fs_ctx    fs_ctx;
};

/* local functions */
static void fs_ctx_fini(struct silofs_fs_ctx *fs_ctx);


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

static struct silofs_fs_ctx_obj *fs_ctx_obj_of(struct silofs_fs_ctx *fs_ctx)
{
	return container_of(fs_ctx, struct silofs_fs_ctx_obj, fs_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fs_args_assign(struct silofs_fs_args *fs_args,
                           const struct silofs_fs_args *other)
{
	memcpy(fs_args, other, sizeof(*fs_args));
}

static void fs_ctx_init_commons(struct silofs_fs_ctx *fs_ctx,
                                const struct silofs_fs_args *fs_args)
{
	silofs_memzero(fs_ctx, sizeof(*fs_ctx));
	silofs_ivkey_init(&fs_ctx->boot_ivkey);
	silofs_ivkey_init(&fs_ctx->main_ivkey);
	fs_args_assign(&fs_ctx->fs_args, fs_args);
	fs_ctx->signum = 0;
}

static struct silofs_qalloc *fs_ctx_qalloc_of(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_alloc *alloc = fs_ctx->alloc;
	struct silofs_qalloc *qalloc = NULL;

	if ((alloc != NULL) && !fs_ctx->fs_args.cflags.stdalloc) {
		qalloc = container_of(alloc, struct silofs_qalloc, alloc);
	}
	return qalloc;
}

static struct silofs_calloc *fs_ctx_calloc_of(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_alloc *alloc = fs_ctx->alloc;
	struct silofs_calloc *calloc = NULL;

	if ((alloc != NULL) && fs_ctx->fs_args.cflags.stdalloc) {
		calloc = container_of(alloc, struct silofs_calloc, alloc);
	}
	return calloc;
}

static int fs_ctx_init_qalloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_qalloc *qalloc = NULL;
	size_t memsize = 0;
	enum silofs_qallocf qaflags = SILOFS_QALLOCF_NOFAIL;
	int err;

	err = calc_mem_size(fs_ctx->fs_args.memwant, &memsize);
	if (err) {
		return err;
	}
	if (fs_ctx->fs_args.cflags.pedantic) {
		qaflags |= SILOFS_QALLOCF_DEMASK;
	}
	qalloc = &fs_ctx_obj_of(fs_ctx)->fs_core.c.alloc_u.qalloc;
	err = silofs_qalloc_init(qalloc, memsize, qaflags);
	if (err) {
		return err;
	}
	fs_ctx->alloc = &qalloc->alloc;
	return 0;
}

static void fs_ctx_fini_qalloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_qalloc *qalloc;

	if (fs_ctx->alloc != NULL) {
		qalloc = fs_ctx_qalloc_of(fs_ctx);
		silofs_qalloc_fini(qalloc);
		fs_ctx->alloc = NULL;
	}
}

static int fs_ctx_init_calloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_calloc *calloc;
	size_t memsize = 0;
	int err;

	err = calc_mem_size(fs_ctx->fs_args.memwant, &memsize);
	if (err) {
		return err;
	}
	calloc = &fs_ctx_obj_of(fs_ctx)->fs_core.c.alloc_u.calloc;
	err = silofs_calloc_init(calloc, memsize);
	if (err) {
		return err;
	}
	fs_ctx->alloc = &calloc->alloc;
	return 0;
}

static void fs_ctx_fini_calloc(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_calloc *calloc;

	if (fs_ctx->alloc != NULL) {
		calloc = fs_ctx_calloc_of(fs_ctx);
		silofs_calloc_fini(calloc);
		fs_ctx->alloc = NULL;
	}
}

static int fs_ctx_init_alloc(struct silofs_fs_ctx *fs_ctx)
{
	int ret;

	if (fs_ctx->fs_args.cflags.stdalloc) {
		ret = fs_ctx_init_calloc(fs_ctx);
	} else {
		ret = fs_ctx_init_qalloc(fs_ctx);
	}
	return ret;
}

static void fs_ctx_fini_alloc(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->fs_args.cflags.stdalloc) {
		fs_ctx_fini_calloc(fs_ctx);
	} else {
		fs_ctx_fini_qalloc(fs_ctx);
	}
}

static int fs_ctx_init_bootpath(struct silofs_fs_ctx *fs_ctx)
{
	return silofs_bootpath_setup(&fs_ctx->bootpath,
	                             fs_ctx->fs_args.repodir,
	                             fs_ctx->fs_args.name);
}

static int fs_ctx_init_lcache(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_lcache *lcache;
	int err;

	lcache = &fs_ctx_obj_of(fs_ctx)->fs_core.c.lcache;
	err = silofs_lcache_init(lcache, fs_ctx->alloc);
	if (err) {
		return err;
	}
	fs_ctx->lcache = lcache;
	return 0;
}

static void fs_ctx_fini_lcache(struct silofs_fs_ctx *fs_ctx)
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
	if (fs_ctx->fs_args.cflags.rdonly) {
		re_base->flags |= SILOFS_REPOF_RDONLY;
	}
	silofs_substr_clone(&fs_ctx->bootpath.repodir, &re_base->repodir);
}

static int fs_ctx_init_repo(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_repo_base re_base = { .flags = 0 };
	struct silofs_repo *repo;
	int err;

	repo = &fs_ctx_obj_of(fs_ctx)->fs_core.c.repo;
	fs_ctx_make_repo_base(fs_ctx, &re_base);
	err = silofs_repo_init(repo, &re_base);
	if (err) {
		return err;
	}
	fs_ctx->repo = repo;
	return 0;
}

static void fs_ctx_fini_repo(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->repo != NULL) {
		silofs_repo_fini(fs_ctx->repo);
		fs_ctx->repo = NULL;
	}
}

static int fs_ctx_init_submitq(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_submitq *submitq;
	int err;

	submitq = &fs_ctx_obj_of(fs_ctx)->fs_core.c.submitq;
	err = silofs_submitq_init(submitq, fs_ctx->alloc);
	if (err) {
		return err;
	}
	fs_ctx->submitq = submitq;
	return 0;
}

static void fs_ctx_fini_submitq(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->submitq != NULL) {
		silofs_submitq_fini(fs_ctx->submitq);
		fs_ctx->submitq = NULL;
	}
}

static int fs_ctx_init_flusher(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_flusher *flusher;
	int err;

	flusher = &fs_ctx_obj_of(fs_ctx)->fs_core.c.flusher;
	err = silofs_flusher_init(flusher, fs_ctx->submitq);
	if (err) {
		return err;
	}
	fs_ctx->flusher = flusher;
	return 0;
}

static void fs_ctx_fini_flusher(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->flusher != NULL) {
		silofs_flusher_fini(fs_ctx->flusher);
		fs_ctx->flusher = NULL;
	}
}

static int fs_ctx_init_idsmap(struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_fs_bconf *bconf = &fs_ctx->fs_args.bconf;
	struct silofs_idsmap *idsmap = NULL;
	const bool allow_hostids = fs_ctx->fs_args.cflags.allow_hostids;
	int err;

	idsmap = &fs_ctx_obj_of(fs_ctx)->fs_core.c.idsmap;
	err = silofs_idsmap_init(idsmap, fs_ctx->alloc, allow_hostids);
	if (err) {
		return err;
	}
	err = silofs_idsmap_populate_uids(idsmap, &bconf->users_ids);
	if (err) {
		silofs_idsmap_fini(idsmap);
		return err;
	}
	err = silofs_idsmap_populate_gids(idsmap, &bconf->groups_ids);
	if (err) {
		silofs_idsmap_fini(idsmap);
		return err;
	}
	fs_ctx->idsmap = idsmap;
	return 0;
}

static void fs_ctx_fini_idsmap(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->idsmap != NULL) {
		silofs_idsmap_clear(fs_ctx->idsmap);
		silofs_idsmap_fini(fs_ctx->idsmap);
		fs_ctx->idsmap = NULL;
	}
}

static int fs_ctx_init_fsenv(struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_fsenv_base fse_base = {
		.fs_args = &fs_ctx->fs_args,
		.bootpath = &fs_ctx->bootpath,
		.boot_ivkey = &fs_ctx->boot_ivkey,
		.main_ivkey = &fs_ctx->main_ivkey,
		.alloc = fs_ctx->alloc,
		.lcache = fs_ctx->lcache,
		.repo = fs_ctx->repo,
		.submitq = fs_ctx->submitq,
		.flusher = fs_ctx->flusher,
		.idsmap = fs_ctx->idsmap,
	};
	struct silofs_fsenv *fsenv;
	int err;

	fsenv = &fs_ctx_obj_of(fs_ctx)->fs_core.c.fsenv;
	err = silofs_fsenv_init(fsenv, &fse_base);
	if (err) {
		return err;
	}
	fs_ctx->fsenv = fsenv;
	return 0;
}

static void fs_ctx_fini_fsenv(struct silofs_fs_ctx *fs_ctx)
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

static bool fs_ctx_with_fuse(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_fsenv *fsenv = fs_ctx->fsenv;
	const enum silofs_env_flags mask = SILOFS_ENVF_WITHFUSE;

	silofs_assert_not_null(fsenv);
	return (fsenv->fse_ctl_flags & mask) == mask;
}

static bool fs_ctx_with_writeback(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_fsenv *fsenv = fs_ctx->fsenv;
	const enum silofs_env_flags mask = SILOFS_ENVF_WRITEBACK;

	silofs_assert_not_null(fsenv);
	return (fsenv->fse_ctl_flags & mask) == mask;
}

static void fs_ctx_bind_fuseq(struct silofs_fs_ctx *fs_ctx,
                              struct silofs_fuseq *fuseq)
{
	fs_ctx->fuseq = fuseq;
	if (fuseq != NULL) {
		fuseq->fq_writeback_cache = fs_ctx_with_writeback(fs_ctx);
	}
}

static int fs_ctx_init_fuseq(struct silofs_fs_ctx *fs_ctx)
{
	union silofs_fuseq_page *fqp = NULL;
	const size_t fuseq_pg_size = sizeof(*fqp);
	void *mem = NULL;
	int err;

	if (!fs_ctx_with_fuse(fs_ctx)) {
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

static void fs_ctx_fini_fuseq(struct silofs_fs_ctx *fs_ctx)
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

static int fs_ctx_init_passwd(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_password *passwd;
	int err;

	passwd = &fs_ctx_obj_of(fs_ctx)->fs_core.c.passwd;
	err = silofs_password_setup(passwd, fs_ctx->fs_args.passwd);
	if (err) {
		return err;
	}
	fs_ctx->password = passwd;
	return 0;
}

static void fs_ctx_fini_passwd(struct silofs_fs_ctx *fs_ctx)
{
	if (fs_ctx->password != NULL) {
		silofs_password_reset(fs_ctx->password);
		fs_ctx->password = NULL;
	}
}

static int fs_ctx_init_boot_ivkey(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_mdigest md;
	int err;

	if (!fs_ctx->password->passlen) {
		return 0;
	}
	err = silofs_mdigest_init(&md);
	if (err) {
		return err;
	}
	err = silofs_ivkey_for_bootrec(&fs_ctx->boot_ivkey,
	                               fs_ctx->password, &md);
	silofs_mdigest_fini(&md);
	if (err) {
		return err;
	}
	return 0;
}

static int fs_ctx_init_passwd_boot_ivkey(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = fs_ctx_init_passwd(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_boot_ivkey(fs_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int fs_ctx_init_subs(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = fs_ctx_init_alloc(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_lcache(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_repo(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_submitq(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_flusher(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_idsmap(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_fsenv(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_fuseq(fs_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int fs_ctx_init(struct silofs_fs_ctx *fs_ctx,
                       const struct silofs_fs_args *fs_args)
{
	int err;

	fs_ctx_init_commons(fs_ctx, fs_args);
	err = fs_ctx_init_bootpath(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_passwd_boot_ivkey(fs_ctx);
	if (err) {
		return err;
	}
	err = fs_ctx_init_subs(fs_ctx);
	if (err) {
		fs_ctx_fini(fs_ctx);
		return err;
	}
	return 0;
}

static void fs_ctx_fini_commons(struct silofs_fs_ctx *fs_ctx)
{
	silofs_ivkey_fini(&fs_ctx->boot_ivkey);
	silofs_ivkey_fini(&fs_ctx->main_ivkey);
	fs_ctx->fsenv = NULL;
}

static void fs_ctx_fini(struct silofs_fs_ctx *fs_ctx)
{
	fs_ctx_fini_fuseq(fs_ctx);
	fs_ctx_fini_fsenv(fs_ctx);
	fs_ctx_fini_idsmap(fs_ctx);
	fs_ctx_fini_flusher(fs_ctx);
	fs_ctx_fini_submitq(fs_ctx);
	fs_ctx_fini_repo(fs_ctx);
	fs_ctx_fini_lcache(fs_ctx);
	fs_ctx_fini_alloc(fs_ctx);
	fs_ctx_fini_passwd(fs_ctx);
	fs_ctx_fini_commons(fs_ctx);
}

static void fs_ctx_lock(struct silofs_fs_ctx *fs_ctx)
{
	silofs_fsenv_lock(fs_ctx->fsenv);
}

static void fs_ctx_unlock(struct silofs_fs_ctx *fs_ctx)
{
	silofs_fsenv_unlock(fs_ctx->fsenv);
}

static int check_fs_args(const struct silofs_fs_args *fs_args)
{
	struct silofs_password passwd;

	return silofs_password_setup(&passwd, fs_args->passwd);
}

int silofs_new_ctx(const struct silofs_fs_args *fs_args,
                   struct silofs_fs_ctx **out_fs_ctx)
{
	struct silofs_fs_ctx *fs_ctx = NULL;
	struct silofs_fs_ctx_obj *fs_ctx_obj = NULL;
	size_t msz;
	void *mem = NULL;
	int err;

	STATICASSERT_LE(sizeof(*fs_ctx_obj), 64 * SILOFS_KILO);

	err = check_fs_args(fs_args);
	if (err) {
		return err;
	}
	msz = sizeof(*fs_ctx_obj);
	err = silofs_zmalloc(msz, &mem);
	if (err) {
		return err;
	}
	fs_ctx_obj = mem;
	fs_ctx = &fs_ctx_obj->fs_ctx;

	err = fs_ctx_init(fs_ctx, fs_args);
	if (err) {
		fs_ctx_fini(fs_ctx);
		free(mem);
		return err;
	}
	*out_fs_ctx = fs_ctx;
	silofs_burnstack();
	return 0;
}

void silofs_del_ctx(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_fs_ctx_obj *fs_ctx_obj = fs_ctx_obj_of(fs_ctx);

	fs_ctx_fini(fs_ctx);
	silofs_zfree(fs_ctx_obj, sizeof(*fs_ctx_obj));
	silofs_burnstack();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_post_exec_fs(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_fuseq *fq = fs_ctx->fuseq;
	int ret = 0;

	if (fq && fq->fq_got_init) {
		ret = fq->fq_got_destroy ? 0 : -SILOFS_ENOTDONE;
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

static int make_task(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_task *task)
{
	const struct silofs_fs_args *args = &fs_ctx->fs_args;

	silofs_task_init(task, fs_ctx->fsenv);
	silofs_task_set_ts(task, true);
	silofs_task_set_creds(task, args->uid, args->gid, args->umask);
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

static void drop_caches(const struct silofs_fs_ctx *fs_ctx)
{
	silofs_lcache_drop(fs_ctx->lcache);
	silofs_repo_drop_some(fs_ctx->repo);
}

static int exec_stage_rootdir_inode(const struct silofs_fs_ctx *fs_ctx,
                                    struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_inode(&task, SILOFS_INO_ROOT,
	                         SILOFS_STG_CUR, out_ii);
	return term_task(&task, err);
}

static int reload_rootdir_inode(const struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = exec_stage_rootdir_inode(fs_ctx, &ii);
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

static int exec_rescan_vspace_of(const struct silofs_fs_ctx *fs_ctx,
                                 enum silofs_ltype ltype)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_rescan_vspace_of(&task, ltype);
	return term_task(&task, err);
}

static int reload_free_vspace(const struct silofs_fs_ctx *fs_ctx)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = exec_rescan_vspace_of(fs_ctx, ltype);
		if (err && (err != -SILOFS_ENOSPC) &&
		    (err != -SILOFS_ENOENT)) {
			log_err("failed to reload free vspace: err=%d", err);
			return err;
		}
	}
	return 0;
}

static int reload_fs_meta(const struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = reload_rootdir_inode(fs_ctx);
	if (err) {
		log_err("failed to reload root dir: err=%d", err);
		return err;
	}
	drop_caches(fs_ctx);
	return 0;
}

static int exec_flush_dirty_now(const struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_flush_dirty_now(&task);
	return term_task(&task, err);
}

static int flush_dirty(const struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = exec_flush_dirty_now(fs_ctx);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
	}
	return err;
}

static int fsync_lsegs(const struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = silofs_repo_fsync_all(fs_ctx->repo);
	if (err) {
		log_err("failed to fsync lsegs: err=%d", err);
	}
	return err;
}

static int shutdown_fsenv(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_fsenv *fsenv = fs_ctx->fsenv;
	int err;

	if (fsenv == NULL) {
		return 0;
	}
	err = silofs_sbi_shut(fsenv->fse_sbi);
	if (err) {
		return err;
	}
	silofs_fsenv_shut(fsenv);
	return 0;
}

static int do_close_repo(const struct silofs_fs_ctx *fs_ctx)
{
	return silofs_repo_close(fs_ctx->repo);
}

int silofs_close_repo(struct silofs_fs_ctx *fs_ctx)
{
	int ret;

	fs_ctx_lock(fs_ctx);
	ret = do_close_repo(fs_ctx);
	fs_ctx_unlock(fs_ctx);
	return ret;
}

int silofs_exec_fs(struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_fuseq *fuseq = fs_ctx->fuseq;
	int err;

	if (!fs_ctx_with_fuse(fs_ctx) || (fuseq == NULL)) {
		return -SILOFS_EINVAL;
	}
	err = silofs_fuseq_mount(fuseq, fs_ctx->fsenv, fs_ctx->fs_args.mntdir);
	if (!err) {
		err = silofs_fuseq_exec(fuseq);
	}
	silofs_fuseq_term(fuseq);
	return err;
}

void silofs_halt_fs(struct silofs_fs_ctx *fs_ctx, int signum)
{
	fs_ctx->signum = signum;
	if (fs_ctx->fuseq != NULL) {
		fs_ctx->fuseq->fq_active = 0;
	}
}

static int flush_and_drop_cache(const struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = flush_dirty(fs_ctx);
	if (err) {
		return err;
	}
	drop_caches(fs_ctx);
	return 0;
}

static int do_sync_fs(const struct silofs_fs_ctx *fs_ctx, bool drop)
{
	int err;

	err = flush_dirty(fs_ctx);
	if (!err && drop) {
		drop_caches(fs_ctx);
	}
	return err;
}

int silofs_sync_fs(struct silofs_fs_ctx *fs_ctx, bool drop)
{
	int err = 0;

	fs_ctx_lock(fs_ctx);
	for (size_t i = 0; !err && (i < 3); ++i) {
		err = do_sync_fs(fs_ctx, drop);
	}
	fs_ctx_unlock(fs_ctx);
	return err;
}

void silofs_stat_fs(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_cachestats *cst)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0 };
	const struct silofs_lcache *lcache = fs_ctx->lcache;

	silofs_memzero(cst, sizeof(*cst));
	silofs_memstat(fs_ctx->alloc, &alst);
	cst->nalloc_bytes = alst.nbytes_use;
	cst->ncache_unodes += lcache->lc_ui_hmapq.hmq_htbl_size;
	cst->ncache_vnodes += lcache->lc_vi_hmapq.hmq_htbl_size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int derive_main_ivkey(struct silofs_fs_ctx *fs_ctx,
                             const struct silofs_bootrec *brec)
{
	struct silofs_mdigest mdigest = { .md_hd = NULL };
	struct silofs_cipher_args cip_args = { .cipher_algo = 0 };
	const struct silofs_password *passwd = fs_ctx->password;
	struct silofs_ivkey *ivkey = &fs_ctx->main_ivkey;
	int err = 0;

	if (!passwd->passlen) {
		return 0;
	}
	err = silofs_mdigest_init(&mdigest);
	if (err) {
		return err;
	}
	silofs_bootrec_cipher_args(brec, &cip_args);
	err = silofs_derive_ivkey(&cip_args, passwd, &mdigest, ivkey);
	silofs_mdigest_fini(&mdigest);
	if (err) {
		log_err("failed to derive main-key: err=%d", err);
		return err;
	}
	return 0;
}

static int check_superblock(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_sb_info *sbi = fs_ctx->fsenv->fse_sbi;
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
	if (fossil && !fs_ctx->fs_args.cflags.rdonly) {
		log_warn("read-only fs: sb-flags=%08x", (int)sb->sb_flags);
		return -SILOFS_EROFS;
	}
	return 0;
}

static int reload_super(const struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = silofs_fsenv_reload_super(fs_ctx->fsenv);
	if (err) {
		log_err("failed to reload super: err=%d", err);
		return err;
	}
	err = check_superblock(fs_ctx);
	if (err) {
		log_warn("bad super-block: err=%d", err);
		return err;
	}
	return 0;
}

static int exec_require_spmaps_of(const struct silofs_fs_ctx *fs_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	enum silofs_stg_mode stg_mode = SILOFS_STG_COW;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_require_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int format_base_vspmaps_of(const struct silofs_fs_ctx *fs_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	int err;

	err = exec_require_spmaps_of(fs_ctx, vaddr);
	if (err) {
		log_err("failed to format base spmaps: "
		        "ltype=%d err=%d", vaddr->ltype, err);
		return err;
	}
	err = do_sync_fs(fs_ctx, false);
	if (err) {
		return err;
	}
	log_dbg("format base spmaps of: ltype=%d err=%d", vaddr->ltype, err);
	return 0;
}

static int format_base_vspmaps(const struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_vaddr vaddr;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		vaddr_setup(&vaddr, ltype, 0);
		err = format_base_vspmaps_of(fs_ctx, &vaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_claim_vspace(const struct silofs_fs_ctx *fs_ctx,
                             enum silofs_ltype ltype,
                             struct silofs_vaddr *out_vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_claim_vspace(&task, ltype, out_vaddr);
	return term_task(&task, err);
}

static int exec_reclaim_vspace(const struct silofs_fs_ctx *fs_ctx,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(&task, vaddr);
	return term_task(&task, err);
}

static int claim_reclaim_vspace_of(const struct silofs_fs_ctx *fs_ctx,
                                   enum silofs_ltype vspace)
{
	struct silofs_vaddr vaddr;
	const loff_t voff_exp = 0;
	int err;

	drop_caches(fs_ctx);
	err = exec_claim_vspace(fs_ctx, vspace, &vaddr);
	if (err) {
		log_err("failed to claim: vspace=%d err=%d", vspace, err);
		return err;
	}

	if (vaddr.off != voff_exp) {
		log_err("wrong first voff: vspace=%d expected-voff=%ld "
		        "got-voff=%ld", vspace, voff_exp, vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}

	drop_caches(fs_ctx);
	err = exec_reclaim_vspace(fs_ctx, &vaddr);
	if (err) {
		log_err("failed to reclaim space: vspace=%d voff=%ld err=%d",
		        vspace, vaddr.off, err);
	}
	return 0;
}

static int claim_reclaim_vspace(const struct silofs_fs_ctx *fs_ctx)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = claim_reclaim_vspace_of(fs_ctx, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fs_ctx);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_stage_spmaps_at(const struct silofs_fs_ctx *fs_ctx,
                                const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stg_mode stg_mode = SILOFS_STG_CUR;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int reload_base_vspace_of(const struct silofs_fs_ctx *fs_ctx,
                                 enum silofs_ltype vspace)
{
	struct silofs_vaddr vaddr;
	int err;

	vaddr_setup(&vaddr, vspace, 0);
	err = exec_stage_spmaps_at(fs_ctx, &vaddr);
	if (err) {
		log_err("failed to reload: vspace=%d err=%d", vspace, err);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int reload_base_vspace(const struct silofs_fs_ctx *fs_ctx)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err = 0;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = reload_base_vspace_of(fs_ctx, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fs_ctx);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_spawn_vnode(const struct silofs_fs_ctx *fs_ctx,
                            enum silofs_ltype ltype,
                            struct silofs_vnode_info **out_vi)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode(&task, NULL, ltype, out_vi);
	if (!err) {
		vi_dirtify(*out_vi, NULL);
	}
	return term_task(&task, err);
}

static int format_zero_vspace_of(const struct silofs_fs_ctx *fs_ctx,
                                 enum silofs_ltype vspace)
{
	struct silofs_vnode_info *vi = NULL;
	const struct silofs_vaddr *vaddr = NULL;
	int err;

	err = exec_spawn_vnode(fs_ctx, vspace, &vi);
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

static int format_zero_vspace(const struct silofs_fs_ctx *fs_ctx)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = format_zero_vspace_of(fs_ctx, ltype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fs_ctx);
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

static int exec_spawn_rootdir(const struct silofs_fs_ctx *fs_ctx,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = do_spawn_rootdir(&task, out_ii);
	return term_task(&task, err);
}

static int format_rootdir(const struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_inode_info *root_ii = NULL;
	int err;

	err = exec_spawn_rootdir(fs_ctx, &root_ii);
	if (err) {
		return err;
	}
	if (root_ii->i_ino != SILOFS_INO_ROOT) {
		log_err("format root-dir failed: ino=%ld", root_ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_ii_fixup_as_rootdir(root_ii);

	err = flush_and_drop_cache(fs_ctx);
	if (err) {
		return err;
	}
	return 0;
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

static int check_want_capacity(const struct silofs_fs_ctx *fs_ctx)
{
	const size_t cap_want = fs_ctx->fs_args.capacity;
	int err;

	err = check_fs_capacity(cap_want);
	if (err) {
		log_err("illegal file-system capacity: "
		        "cap=%lu err=%d", cap_want, err);
		return err;
	}
	return 0;
}

static int check_owner_ids(const struct silofs_fs_ctx *fs_ctx)
{
	const uid_t owner_uid = fs_ctx->fs_args.uid;
	const gid_t owner_gid = fs_ctx->fs_args.gid;
	uid_t suid;
	gid_t sgid;
	int err;

	err = silofs_idsmap_map_uidgid(fs_ctx->idsmap, owner_uid,
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

static int format_umeta(const struct silofs_fs_ctx *fs_ctx)
{
	const size_t cap = calc_aligned_fs_cap(fs_ctx->fs_args.capacity);
	int err;

	err = check_want_capacity(fs_ctx);
	if (err) {
		return err;
	}
	err = silofs_fsenv_format_super(fs_ctx->fsenv, cap);
	if (err) {
		return err;
	}
	err = check_superblock(fs_ctx);
	if (err) {
		return err;
	}
	err = flush_dirty(fs_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int format_vmeta(const struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = format_base_vspmaps(fs_ctx);
	if (err) {
		return err;
	}
	err = claim_reclaim_vspace(fs_ctx);
	if (err) {
		return err;
	}
	err = format_zero_vspace(fs_ctx);
	if (err) {
		return err;
	}
	err = flush_dirty(fs_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int do_format_repo(const struct silofs_fs_ctx *fs_ctx)
{
	return silofs_repo_format(fs_ctx->repo);
}

int silofs_format_repo(struct silofs_fs_ctx *fs_ctx)
{
	int ret;

	fs_ctx_lock(fs_ctx);
	ret = do_format_repo(fs_ctx);
	fs_ctx_unlock(fs_ctx);
	return ret;
}

static int do_open_repo(const struct silofs_fs_ctx *fs_ctx)
{
	return silofs_repo_open(fs_ctx->repo);
}

int silofs_open_repo(struct silofs_fs_ctx *fs_ctx)
{
	int ret;

	fs_ctx_lock(fs_ctx);
	ret = do_open_repo(fs_ctx);
	fs_ctx_unlock(fs_ctx);
	return ret;
}

static int stat_bootrec_of(const struct silofs_fs_ctx *fs_ctx,
                           const struct silofs_uaddr *uaddr)
{
	ssize_t sz = -1;
	int err;

	err = silofs_repo_stat_lobj(fs_ctx->repo, &uaddr->laddr, &sz);
	if (err) {
		log_err("failed to stat bootrec: err=%d", err);
		return err;
	}
	if (sz != SILOFS_BOOTREC_SIZE) {
		log_warn("bad bootrec: size=%zd", sz);
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

static int save_bootrec_of(const struct silofs_fs_ctx *fs_ctx,
                           const struct silofs_uaddr *uaddr,
                           const struct silofs_bootrec *brec)
{
	silofs_assert_eq(uaddr->laddr.len, sizeof(struct silofs_bootrec1k));
	return silofs_save_bootrec(fs_ctx->fsenv, &uaddr->laddr, brec);
}

static int reload_bootrec_of(struct silofs_fs_ctx *fs_ctx,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_bootrec *out_brec)
{
	int err;

	err = stat_bootrec_of(fs_ctx, uaddr);
	if (err) {
		return err;
	}
	err = silofs_load_bootrec(fs_ctx->fsenv, &uaddr->laddr, out_brec);
	if (err) {
		return err;
	}
	return 0;
}

static int unlink_bootrec_of(struct silofs_fs_ctx *fs_ctx,
                             const struct silofs_uaddr *uaddr)
{
	int err;

	err = silofs_repo_unlink_lobj(fs_ctx->repo, &uaddr->laddr);
	if (err) {
		log_err("failed to unlink bootrec: err=%d", err);
		return err;
	}
	return 0;
}

static int save_bootrec(const struct silofs_fs_ctx *fs_ctx,
                        const struct silofs_bootrec *brec)
{
	struct silofs_uaddr uaddr;

	silofs_bootrec_self_uaddr(brec, &uaddr);
	return save_bootrec_of(fs_ctx, &uaddr, brec);
}

static int update_save_bootrec(const struct silofs_fs_ctx *fs_ctx,
                               struct silofs_bootrec *brec)
{
	const struct silofs_sb_info *sbi = fs_ctx->fsenv->fse_sbi;

	silofs_bootrec_set_sb_ulink(brec, sbi_ulink(sbi));
	return save_bootrec(fs_ctx, brec);
}

static int do_format_fs(struct silofs_fs_ctx *fs_ctx,
                        struct silofs_lvid *out_lvid)
{
	struct silofs_bootrec brec;
	int err;

	silofs_bootrec_init(&brec);
	err = check_want_capacity(fs_ctx);
	if (err) {
		return err;
	}
	err = check_owner_ids(fs_ctx);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fs_ctx, &brec);
	if (err) {
		return err;
	}
	err = format_umeta(fs_ctx);
	if (err) {
		return err;
	}
	err = format_vmeta(fs_ctx);
	if (err) {
		return err;
	}
	err = format_rootdir(fs_ctx);
	if (err) {
		return err;
	}
	err = update_save_bootrec(fs_ctx, &brec);
	if (err) {
		return err;
	}
	silofs_bootrec_lvid(&brec, out_lvid);
	return 0;
}

int silofs_format_fs(struct silofs_fs_ctx *fs_ctx,
                     struct silofs_lvid *out_lvid)
{
	int ret;

	fs_ctx_lock(fs_ctx);
	ret = do_format_fs(fs_ctx, out_lvid);
	fs_ctx_unlock(fs_ctx);
	return ret;
}

static int fse_reload_root_sb_lseg(struct silofs_fs_ctx *fs_ctx,
                                   const struct silofs_bootrec *brec)
{
	silofs_fsenv_bind_child(fs_ctx->fsenv, &brec->sb_ulink);
	return silofs_fsenv_reload_sb_lseg(fs_ctx->fsenv);
}

static int do_boot_fs(struct silofs_fs_ctx *fs_ctx,
                      const struct silofs_lvid *lvid)
{
	struct silofs_bootrec brec;
	struct silofs_uaddr brec_uaddr;
	int err;

	silofs_make_bootrec_uaddr(lvid, &brec_uaddr);
	err = reload_bootrec_of(fs_ctx, &brec_uaddr, &brec);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fs_ctx, &brec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sb_lseg(fs_ctx, &brec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_boot_fs(struct silofs_fs_ctx *fs_ctx,
                   const struct silofs_lvid *lvid)
{
	int ret;

	fs_ctx_lock(fs_ctx);
	ret = do_boot_fs(fs_ctx, lvid);
	fs_ctx_unlock(fs_ctx);
	return ret;
}

static int do_open_fs(const struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = reload_super(fs_ctx);
	if (err) {
		return err;
	}
	err = reload_base_vspace(fs_ctx);
	if (err) {
		return err;
	}
	err = reload_free_vspace(fs_ctx);
	if (err) {
		return err;
	}
	err = reload_fs_meta(fs_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_open_fs(struct silofs_fs_ctx *fs_ctx)
{
	int ret;

	fs_ctx_lock(fs_ctx);
	ret = do_open_fs(fs_ctx);
	fs_ctx_unlock(fs_ctx);
	return ret;
}

static int do_close_fs(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = flush_dirty(fs_ctx);
	if (err) {
		return err;
	}
	err = fsync_lsegs(fs_ctx);
	if (err) {
		return err;
	}
	err = shutdown_fsenv(fs_ctx);
	if (err) {
		return err;
	}
	drop_caches(fs_ctx);
	return err;
}

int silofs_close_fs(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	fs_ctx_lock(fs_ctx);
	err = do_close_fs(fs_ctx);
	fs_ctx_unlock(fs_ctx);
	return err;
}

int silofs_poke_fs(struct silofs_fs_ctx *fs_ctx,
                   const struct silofs_lvid *lvid,
                   struct silofs_bootrec *out_brec)
{
	struct silofs_uaddr brec_uaddr = { .voff = -1 };

	silofs_make_bootrec_uaddr(lvid, &brec_uaddr);
	return silofs_load_bootrec(fs_ctx->fsenv, &brec_uaddr.laddr, out_brec);
}

static int exec_clone_fs(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_bootrecs *out_brecs)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_clone(&task, SILOFS_INO_ROOT, 0, out_brecs);
	if (err) {
		return err;
	}
	return term_task(&task, err);
}

int silofs_fork_fs(struct silofs_fs_ctx *fs_ctx,
                   struct silofs_lvid *out_new,
                   struct silofs_lvid *out_alt)
{
	struct silofs_bootrecs brecs;
	int err;

	err = exec_clone_fs(fs_ctx, &brecs);
	if (err) {
		return err;
	}
	silofs_bootrecs_to_lvids(&brecs, out_new, out_alt);
	return 0;
}

static int exec_unref_fs(struct silofs_fs_ctx *fse)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (!err) {
		err = silofs_fs_unrefs(&task);
		err = term_task(&task, err);
	}
	return err;
}

int silofs_unref_fs(struct silofs_fs_ctx *fs_ctx,
                    const struct silofs_lvid *lvid)
{
	struct silofs_bootrec brec;
	struct silofs_uaddr brec_uaddr;
	int err;

	silofs_make_bootrec_uaddr(lvid, &brec_uaddr);
	err = reload_bootrec_of(fs_ctx, &brec_uaddr, &brec);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fs_ctx, &brec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sb_lseg(fs_ctx, &brec);
	if (err) {
		return err;
	}
	err = reload_super(fs_ctx);
	if (err) {
		return err;
	}
	err = exec_unref_fs(fs_ctx);
	if (err) {
		return err;
	}
	err = unlink_bootrec_of(fs_ctx, &brec_uaddr);
	if (err) {
		return err;
	}
	err = do_close_fs(fs_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int exec_inspect_fs(struct silofs_fs_ctx *fs_ctx,
                           silofs_visit_laddr_fn cb, void *user_ctx)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_inspect(&task, cb, user_ctx);
	return term_task(&task, err);
}

int silofs_inspect_fs(struct silofs_fs_ctx *fs_ctx,
                      silofs_visit_laddr_fn cb, void *user_ctx)
{
	return exec_inspect_fs(fs_ctx, cb, user_ctx);
}

static int exec_pack_fs(struct silofs_fs_ctx *fs_ctx,
                        struct silofs_caddr *out_caddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fs_ctx, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_pack(&task, out_caddr);
	return term_task(&task, err);
}

int silofs_pack_fs(struct silofs_fs_ctx *fs_ctx,
                   struct silofs_caddr *out_caddr)
{
	return exec_pack_fs(fs_ctx, out_caddr);
}
