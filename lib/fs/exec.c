/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define ROUND_TO_4K(n)  SILOFS_ROUND_TO(n, (4 * SILOFS_KILO))

union silofs_fs_alloc_u {
	struct silofs_qalloc    qalloc;
	struct silofs_calloc    calloc;
};

struct silofs_fs_core {
	struct silofs_password  passwd;
	union silofs_fs_alloc_u alloc_u;
	struct silofs_cache     cache;
	struct silofs_repo      repo;
	struct silofs_submitq   submitq;
	struct silofs_idsmap    idsm;
	struct silofs_uber      uber;
};

union silofs_fs_core_u {
	struct silofs_fs_core c;
	uint8_t dat[ROUND_TO_4K(sizeof(struct silofs_fs_core))];
};

union silofs_fuseq_page {
	struct silofs_fuseq     fuseq;
	uint8_t page[4096];
};

struct silofs_fs_env_obj {
	union silofs_fs_core_u  fs_core;
	struct silofs_fs_env    fs_env;
};

/* local functions */
static void fse_fini(struct silofs_fs_env *fse);


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

static struct silofs_fs_env_obj *fse_obj_of(struct silofs_fs_env *fse)
{
	return container_of(fse, struct silofs_fs_env_obj, fs_env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fs_args_assign(struct silofs_fs_args *fs_args,
                           const struct silofs_fs_args *other)
{
	memcpy(fs_args, other, sizeof(*fs_args));
}

static void fse_init_commons(struct silofs_fs_env *fse,
                             const struct silofs_fs_args *fs_args)
{
	silofs_memzero(fse, sizeof(*fse));
	silofs_ivkey_init(&fse->fs_boot_ivkey);
	silofs_ivkey_init(&fse->fs_main_ivkey);
	fs_args_assign(&fse->fs_args, fs_args);
	fse->fs_signum = 0;
}



static int fse_init_qalloc(struct silofs_fs_env *fse)
{
	struct silofs_qalloc *qalloc;
	size_t memsize = 0;
	int mode;
	int err;

	err = calc_mem_size(fse->fs_args.memwant, &memsize);
	if (err) {
		return err;
	}
	mode = fse->fs_args.pedantic ?
	       SILOFS_QALLOC_PEDANTIC : SILOFS_QALLOC_NORMAL;
	qalloc = &fse_obj_of(fse)->fs_core.c.alloc_u.qalloc;
	err = silofs_qalloc_init(qalloc, memsize, mode);
	if (err) {
		return err;
	}
	fse->fs_qalloc = qalloc;
	fse->fs_alloc = &qalloc->alloc;
	return 0;
}

static void fse_fini_qalloc(struct silofs_fs_env *fse)
{
	if (fse->fs_qalloc != NULL) {
		silofs_qalloc_fini(fse->fs_qalloc);
		fse->fs_qalloc = NULL;
		fse->fs_alloc = NULL;
	}
}

static int fse_init_calloc(struct silofs_fs_env *fse)
{
	struct silofs_calloc *calloc;
	size_t memsize = 0;
	int err;

	err = calc_mem_size(fse->fs_args.memwant, &memsize);
	if (err) {
		return err;
	}
	calloc = &fse_obj_of(fse)->fs_core.c.alloc_u.calloc;
	err = silofs_calloc_init(calloc, memsize);
	if (err) {
		return err;
	}
	fse->fs_calloc = calloc;
	fse->fs_alloc = &calloc->alloc;
	return 0;
}

static void fse_fini_calloc(struct silofs_fs_env *fse)
{
	if (fse->fs_calloc != NULL) {
		silofs_calloc_fini(fse->fs_calloc);
		fse->fs_calloc = NULL;
		fse->fs_alloc = NULL;
	}
}

static int fse_init_alloc(struct silofs_fs_env *fse)
{
	int ret;

	if (fse->fs_args.stdalloc) {
		ret = fse_init_calloc(fse);
	} else {
		ret = fse_init_qalloc(fse);
	}
	return ret;
}

static void fse_fini_alloc(struct silofs_fs_env *fse)
{
	if (fse->fs_args.stdalloc) {
		fse_fini_calloc(fse);
	} else {
		fse_fini_qalloc(fse);
	}
}

static int fse_init_bootpath(struct silofs_fs_env *fse)
{
	return silofs_bootpath_setup(&fse->fs_bootpath,
	                             fse->fs_args.repodir,
	                             fse->fs_args.name);
}

static int fse_init_cache(struct silofs_fs_env *fse)
{
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	struct silofs_cache *cache = &fse_obj->fs_core.c.cache;
	int err;

	err = silofs_cache_init(cache, fse->fs_alloc);
	if (err) {
		return err;
	}
	fse->fs_cache = cache;
	return 0;
}

static void fse_fini_cache(struct silofs_fs_env *fse)
{
	if (fse->fs_cache != NULL) {
		silofs_cache_fini(fse->fs_cache);
		fse->fs_cache = NULL;
	}
}

static void fse_make_repo_base(const struct silofs_fs_env *fse,
                               struct silofs_repo_base *re_base)
{
	silofs_memzero(re_base, sizeof(*re_base));
	re_base->alloc = fse->fs_alloc;
	re_base->flags = fse->fs_args.rdonly ? SILOFS_REPOF_RDONLY : 0;
	silofs_substr_clone(&fse->fs_bootpath.repodir, &re_base->repodir);
}

static int fse_init_repo(struct silofs_fs_env *fse)
{
	struct silofs_repo_base re_base = { .flags = 0 };
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	struct silofs_repo *repo = &fse_obj->fs_core.c.repo;
	int err;

	fse_make_repo_base(fse, &re_base);
	err = silofs_repo_init(repo, &re_base);
	if (err) {
		return err;
	}
	fse->fs_repo = repo;
	return 0;
}

static void fse_fini_repo(struct silofs_fs_env *fse)
{
	if (fse->fs_repo != NULL) {
		silofs_repo_fini(fse->fs_repo);
		fse->fs_repo = NULL;
	}
}

static int fse_init_submitq(struct silofs_fs_env *fse)
{
	struct silofs_submitq *smq;
	int err;

	smq = &fse_obj_of(fse)->fs_core.c.submitq;
	err = silofs_submitq_init(smq, fse->fs_alloc);
	if (err) {
		return err;
	}
	fse->fs_submitq = smq;
	return 0;
}

static void fse_fini_submitq(struct silofs_fs_env *fse)
{
	if (fse->fs_submitq != NULL) {
		silofs_submitq_fini(fse->fs_submitq);
		fse->fs_submitq = NULL;
	}
}

static int fse_init_idsmap(struct silofs_fs_env *fse)
{
	const struct silofs_fs_args *fs_args = &fse->fs_args;
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	struct silofs_idsmap *idsm = &fse_obj->fs_core.c.idsm;
	int err;

	err = silofs_idsmap_init(idsm, fse->fs_alloc, fs_args->allowhostids);
	if (err) {
		return err;
	}
	err = silofs_idsmap_populate(idsm, &fs_args->iconf.ids);
	if (err) {
		silofs_idsmap_fini(idsm);
		return err;
	}
	fse->fs_idsmap = idsm;
	return 0;
}

static void fse_fini_idsmap(struct silofs_fs_env *fse)
{
	if (fse->fs_idsmap != NULL) {
		silofs_idsmap_clear(fse->fs_idsmap);
		silofs_idsmap_fini(fse->fs_idsmap);
		fse->fs_idsmap = NULL;
	}
}

static int fse_init_uber(struct silofs_fs_env *fse)
{
	const struct silofs_uber_base ub_base = {
		.fs_args = &fse->fs_args,
		.bootpath = &fse->fs_bootpath,
		.boot_ivkey = &fse->fs_boot_ivkey,
		.main_ivkey = &fse->fs_main_ivkey,
		.alloc = fse->fs_alloc,
		.cache = fse->fs_cache,
		.repo = fse->fs_repo,
		.submitq = fse->fs_submitq,
		.idsmap = fse->fs_idsmap,
	};
	struct silofs_uber *uber;
	int err;

	uber = &fse_obj_of(fse)->fs_core.c.uber;
	err = silofs_uber_init(uber, &ub_base);
	if (!err) {
		fse->fs_uber = uber;
	}
	return err;
}

static void fse_fini_uber(struct silofs_fs_env *fse)
{
	if (fse->fs_uber != NULL) {
		silofs_uber_fini(fse->fs_uber);
		fse->fs_uber = NULL;
	}
}

static union silofs_fuseq_page *fuseq_to_page(struct silofs_fuseq *fuseq)
{
	const union silofs_fuseq_page *fqp = NULL;

	STATICASSERT_EQ(sizeof(*fqp), SILOFS_PAGE_SIZE_MIN);

	fqp = container_of(fuseq, union silofs_fuseq_page, fuseq);
	return unconst(fqp);
}

static void fse_bind_fuseq(struct silofs_fs_env *fse,
                           struct silofs_fuseq *fuseq)
{
	fse->fs_fuseq = fuseq;
	if (fuseq != NULL) {
		fuseq->fq_writeback_cache = fse->fs_args.writeback_cache;
	}
}

static int fse_init_fuseq(struct silofs_fs_env *fse)
{
	union silofs_fuseq_page *fqp = NULL;
	const size_t fuseq_pg_size = sizeof(*fqp);
	void *mem = NULL;
	int err;

	if (!fse->fs_args.withfuse) {
		return 0;
	}
	mem = silofs_allocate(fse->fs_alloc, fuseq_pg_size, 0);
	if (mem == NULL) {
		log_warn("failed to allocate fuseq: size=%lu", fuseq_pg_size);
		return -SILOFS_ENOMEM;
	}
	fqp = mem;
	err = silofs_fuseq_init(&fqp->fuseq, fse->fs_alloc);
	if (err) {
		silofs_deallocate(fse->fs_alloc, mem, fuseq_pg_size, 0);
		return err;
	}
	fse_bind_fuseq(fse, &fqp->fuseq);
	return 0;
}

static void fse_fini_fuseq(struct silofs_fs_env *fse)
{
	union silofs_fuseq_page *fuseq_pg = NULL;

	if (fse->fs_fuseq != NULL) {
		fuseq_pg = fuseq_to_page(fse->fs_fuseq);

		silofs_fuseq_fini(fse->fs_fuseq);
		fse_bind_fuseq(fse, NULL);

		silofs_deallocate(fse->fs_alloc, fuseq_pg,
		                  sizeof(*fuseq_pg), 0);
	}
}

static int fse_check_args(const struct silofs_fs_args *fs_args)
{
	struct silofs_password passwd;
	int err;

	err = silofs_password_setup(&passwd, fs_args->passwd);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_init_passwd(struct silofs_fs_env *fse)
{
	struct silofs_password *passwd;
	int err;

	passwd = &fse_obj_of(fse)->fs_core.c.passwd;
	err = silofs_password_setup(passwd, fse->fs_args.passwd);
	if (err) {
		return err;
	}
	fse->fs_passwd = passwd;
	return 0;
}

static void fse_fini_passwd(struct silofs_fs_env *fse)
{
	if (fse->fs_passwd != NULL) {
		silofs_password_reset(fse->fs_passwd);
		fse->fs_passwd = NULL;
	}
}

static int fse_init_boot_ivkey(struct silofs_fs_env *fse)
{
	struct silofs_mdigest md;
	const struct silofs_password *passwd = fse->fs_passwd;
	int err;

	if (!passwd->passlen) {
		return 0;
	}
	err = silofs_mdigest_init(&md);
	if (err) {
		return err;
	}
	err = silofs_ivkey_for_bootrec(&fse->fs_boot_ivkey, passwd, &md);
	silofs_mdigest_fini(&md);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_init_passwd_boot_ivkey(struct silofs_fs_env *fse)
{
	int err;

	err = fse_init_passwd(fse);
	if (err) {
		return err;
	}
	err = fse_init_boot_ivkey(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_init_subs(struct silofs_fs_env *fse)
{
	int err;

	err = fse_init_alloc(fse);
	if (err) {
		return err;
	}
	err = fse_init_cache(fse);
	if (err) {
		return err;
	}
	err = fse_init_repo(fse);
	if (err) {
		return err;
	}
	err = fse_init_submitq(fse);
	if (err) {
		return err;
	}
	err = fse_init_idsmap(fse);
	if (err) {
		return err;
	}
	err = fse_init_uber(fse);
	if (err) {
		return err;
	}
	err = fse_init_fuseq(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_init(struct silofs_fs_env *fse,
                    const struct silofs_fs_args *args)
{
	int err;

	fse_init_commons(fse, args);
	err = fse_init_bootpath(fse);
	if (err) {
		return err;
	}
	err = fse_init_passwd_boot_ivkey(fse);
	if (err) {
		return err;
	}
	err = fse_init_subs(fse);
	if (err) {
		fse_fini(fse);
		return err;
	}
	return 0;
}

static void fse_fini_commons(struct silofs_fs_env *fse)
{
	silofs_ivkey_fini(&fse->fs_boot_ivkey);
	silofs_ivkey_fini(&fse->fs_main_ivkey);
	fse->fs_uber = NULL;
}

static void fse_fini(struct silofs_fs_env *fse)
{
	fse_fini_fuseq(fse);
	fse_fini_uber(fse);
	fse_fini_idsmap(fse);
	fse_fini_submitq(fse);
	fse_fini_repo(fse);
	fse_fini_cache(fse);
	fse_fini_alloc(fse);
	fse_fini_passwd(fse);
	fse_fini_commons(fse);
}

static void fse_lock(struct silofs_fs_env *fse)
{
	silofs_mutex_lock(&fse->fs_uber->ub_fs_lock);
}

static void fse_unlock(struct silofs_fs_env *fse)
{
	silofs_mutex_unlock(&fse->fs_uber->ub_fs_lock);
}

int silofs_fse_new(const struct silofs_fs_args *args,
                   struct silofs_fs_env **out_fse)
{
	struct silofs_fs_env *fse = NULL;
	struct silofs_fs_env_obj *fse_obj = NULL;
	size_t msz;
	void *mem = NULL;
	int err;

	STATICASSERT_LE(sizeof(*fse_obj), 128 * SILOFS_KILO);

	err = fse_check_args(args);
	if (err) {
		return err;
	}
	msz = sizeof(*fse_obj);
	err = silofs_zmalloc(msz, &mem);
	if (err) {
		return err;
	}
	fse_obj = mem;
	fse = &fse_obj->fs_env;

	err = fse_init(fse, args);
	if (err) {
		fse_fini(fse);
		free(mem);
		return err;
	}
	*out_fse = fse;
	silofs_burnstack();
	return 0;
}

void silofs_fse_del(struct silofs_fs_env *fse)
{
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);

	fse_fini(fse);
	silofs_zfree(fse_obj, sizeof(*fse_obj));
	silofs_burnstack();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_post_exec_fs(const struct silofs_fs_env *fse)
{
	const struct silofs_fuseq *fq = fse->fs_fuseq;
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

static int make_task(const struct silofs_fs_env *fse,
                     struct silofs_task *task)
{
	const struct silofs_fs_args *fs_args = &fse->fs_args;
	int err;

	err = silofs_task_init(task, fse->fs_uber);
	if (err) {
		return err;
	}
	silofs_task_set_ts(task, true);
	silofs_task_set_creds(task, fs_args->uid,
	                      fs_args->gid, fs_args->umask);
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

static void drop_caches(const struct silofs_fs_env *fse)
{
	silofs_cache_drop(fse->fs_cache);
	silofs_repo_drop_some(fse->fs_repo);
}

static int exec_stage_rootdir_inode(const struct silofs_fs_env *fse,
                                    struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_inode(&task, ino, SILOFS_STG_CUR, out_ii);
	return term_task(&task, err);
}

static int reload_rootdir_inode(const struct silofs_fs_env *fse)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = exec_stage_rootdir_inode(fse, &ii);
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

static int exec_rescan_vspace_of(const struct silofs_fs_env *fse,
                                 enum silofs_stype stype)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_rescan_vspace_of(&task, stype);
	return term_task(&task, err);
}

static int reload_free_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = exec_rescan_vspace_of(fse, stype);
		if (err && (err != -SILOFS_ENOSPC) &&
		    (err != -SILOFS_ENOENT)) {
			log_err("failed to reload free vspace: err=%d", err);
			return err;
		}
	}
	return 0;
}

static int reload_fs_meta(const struct silofs_fs_env *fse)
{
	int err;

	err = reload_rootdir_inode(fse);
	if (err) {
		log_err("failed to reload root dir: err=%d", err);
		return err;
	}
	drop_caches(fse);
	return 0;
}

static int exec_flush_dirty_now(const struct silofs_fs_env *fse)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_flush_dirty_now(&task);
	return term_task(&task, err);
}

static int flush_dirty(const struct silofs_fs_env *fse)
{
	int err;

	err = exec_flush_dirty_now(fse);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
	}
	return err;
}

static int fsync_lexts(const struct silofs_fs_env *fse)
{
	int err;

	err = silofs_repo_fsync_all(fse->fs_repo);
	if (err) {
		log_err("failed to fsync lexts: err=%d", err);
	}
	return err;
}

static int shutdown_uber(struct silofs_fs_env *fse)
{
	struct silofs_uber *uber = fse->fs_uber;
	int err;

	if (uber == NULL) {
		return 0;
	}
	err = silofs_sbi_shut(uber->ub_sbi);
	if (err) {
		return err;
	}
	silofs_uber_shut(uber);
	return 0;
}

static int do_close_repo(const struct silofs_fs_env *fse)
{
	return silofs_repo_close(fse->fs_repo);
}

int silofs_close_repo(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = do_close_repo(fse);
	fse_unlock(fse);
	return ret;
}

int silofs_exec_fs(struct silofs_fs_env *fse)
{
	struct silofs_fuseq *fq = fse->fs_fuseq;
	int err;

	if (!fse->fs_args.withfuse || (fse->fs_fuseq == NULL)) {
		return -SILOFS_EINVAL;
	}
	err = silofs_fuseq_mount(fq, fse->fs_uber, fse->fs_args.mntdir);
	if (!err) {
		err = silofs_fuseq_exec(fq);
	}
	silofs_fuseq_term(fq);
	return err;
}

void silofs_halt_fs(struct silofs_fs_env *fse, int signum)
{
	fse->fs_signum = signum;
	if (fse->fs_fuseq != NULL) {
		fse->fs_fuseq->fq_active = 0;
	}
}

static int flush_and_drop_cache(const struct silofs_fs_env *fse)
{
	int err;

	err = flush_dirty(fse);
	if (err) {
		return err;
	}
	drop_caches(fse);
	return 0;
}

static int do_sync_fs(const struct silofs_fs_env *fse, bool drop)
{
	int err;

	err = flush_dirty(fse);
	if (!err && drop) {
		drop_caches(fse);
	}
	return err;
}

int silofs_sync_fs(struct silofs_fs_env *fse, bool drop)
{
	int err = 0;

	fse_lock(fse);
	for (size_t i = 0; !err && (i < 3); ++i) {
		err = do_sync_fs(fse, drop);
	}
	fse_unlock(fse);
	return err;
}

void silofs_stat_fs(const struct silofs_fs_env *fse,
                    struct silofs_cachestats *st)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0 };
	const struct silofs_cache *cache = fse->fs_cache;

	silofs_memzero(st, sizeof(*st));
	silofs_allocstat(fse->fs_alloc, &alst);
	st->nalloc_bytes = alst.nbytes_use;
	st->ncache_ublocks += cache->c_ubki_lm.lm_htbl_sz;
	st->ncache_vblocks += cache->c_vbki_lm.lm_htbl_sz;
	st->ncache_unodes += cache->c_ui_lm.lm_htbl_sz;
	st->ncache_vnodes += cache->c_vi_lm.lm_htbl_sz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fse_derive_main_ivkey(struct silofs_fs_env *fse,
                                 const struct silofs_bootrec *brec)
{
	struct silofs_mdigest mdigest = { .md_hd = NULL };
	struct silofs_cipher_args cip_args = { .cipher_algo = 0 };
	const struct silofs_password *passwd = fse->fs_passwd;
	struct silofs_ivkey *ivkey = &fse->fs_main_ivkey;
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

static int check_superblock(const struct silofs_fs_env *fse)
{
	const struct silofs_sb_info *sbi = fse->fs_uber->ub_sbi;
	const struct silofs_super_block *sb = sbi->sb;
	int fossil;
	int err;

	err = silofs_sb_check_version(sb);
	if (err) {
		return err;
	}
	fossil = silofs_sb_test_flags(sb, SILOFS_SUPERF_FOSSIL);
	if (fossil && !fse->fs_args.rdonly) {
		return -SILOFS_EROFS;
	}
	return 0;
}

static int reload_super(const struct silofs_fs_env *fse)
{
	int err;

	err = silofs_uber_reload_super(fse->fs_uber);
	if (err) {
		log_err("failed to reload super: err=%d", err);
		return err;
	}
	err = check_superblock(fse);
	if (err) {
		log_warn("bad super-block: err=%d", err);
		return err;
	}
	return 0;
}

static int exec_require_spmaps_of(const struct silofs_fs_env *fse,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	enum silofs_stg_mode stg_mode = SILOFS_STG_COW;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_require_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int format_base_vspmaps_of(const struct silofs_fs_env *fse,
                                  const struct silofs_vaddr *vaddr)
{
	int err;

	err = exec_require_spmaps_of(fse, vaddr);
	if (err) {
		log_err("failed to format base spmaps: "
		        "stype=%d err=%d", vaddr->stype, err);
		return err;
	}
	err = do_sync_fs(fse, false);
	if (err) {
		return err;
	}
	log_dbg("format base spmaps of: stype=%d err=%d", vaddr->stype, err);
	return 0;
}

static int format_base_vspmaps(const struct silofs_fs_env *fse)
{
	struct silofs_vaddr vaddr;
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		vaddr_setup(&vaddr, stype, 0);
		err = format_base_vspmaps_of(fse, &vaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_claim_vspace(const struct silofs_fs_env *fse,
                             enum silofs_stype stype,
                             struct silofs_vaddr *out_vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_claim_vspace(&task, stype, out_vaddr);
	return term_task(&task, err);
}

static int exec_reclaim_vspace(const struct silofs_fs_env *fse,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(&task, vaddr);
	return term_task(&task, err);
}

static int claim_reclaim_vspace_of(const struct silofs_fs_env *fse,
                                   enum silofs_stype vspace)
{
	struct silofs_vaddr vaddr;
	const loff_t voff_exp = 0;
	int err;

	drop_caches(fse);
	err = exec_claim_vspace(fse, vspace, &vaddr);
	if (err) {
		log_err("failed to claim: vspace=%d err=%d", vspace, err);
		return err;
	}

	if (vaddr.off != voff_exp) {
		log_err("wrong first voff: vspace=%d expected-voff=%ld "
		        "got-voff=%ld", vspace, voff_exp, vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}

	drop_caches(fse);
	err = exec_reclaim_vspace(fse, &vaddr);
	if (err) {
		log_err("failed to reclaim space: vspace=%d voff=%ld err=%d",
		        vspace, vaddr.off, err);
	}
	return 0;
}

static int claim_reclaim_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = claim_reclaim_vspace_of(fse, stype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fse);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_stage_spmaps_at(const struct silofs_fs_env *fse,
                                const struct silofs_vaddr *vaddr)
{
	struct silofs_task task;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stg_mode stg_mode = SILOFS_STG_CUR;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_spmaps_of(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int reload_base_vspace_of(const struct silofs_fs_env *fse,
                                 enum silofs_stype vspace)
{
	struct silofs_vaddr vaddr;
	int err;

	vaddr_setup(&vaddr, vspace, 0);
	err = exec_stage_spmaps_at(fse, &vaddr);
	if (err) {
		log_err("failed to reload: vspace=%d err=%d", vspace, err);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int reload_base_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err = 0;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = reload_base_vspace_of(fse, stype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fse);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_spawn_vnode(const struct silofs_fs_env *fse,
                            enum silofs_stype stype,
                            struct silofs_vnode_info **out_vi)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_spawn_vnode_of(&task, NULL, stype, out_vi);
	if (!err) {
		vi_dirtify(*out_vi, NULL);
	}
	return term_task(&task, err);
}

static int format_zero_vspace_of(const struct silofs_fs_env *fse,
                                 enum silofs_stype vspace)
{
	struct silofs_vnode_info *vi = NULL;
	const struct silofs_vaddr *vaddr = NULL;
	int err;

	err = exec_spawn_vnode(fse, vspace, &vi);
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

static int format_zero_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = format_zero_vspace_of(fse, stype);
		if (err) {
			return err;
		}
		err = flush_and_drop_cache(fse);
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
	return silofs_spawn_inode_of(task, &inp, out_ii);
}

static int exec_spawn_rootdir(const struct silofs_fs_env *fse,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = do_spawn_rootdir(&task, out_ii);
	return term_task(&task, err);
}

static int format_rootdir(const struct silofs_fs_env *fse)
{
	struct silofs_inode_info *root_ii = NULL;
	int err;

	err = exec_spawn_rootdir(fse, &root_ii);
	if (err) {
		return err;
	}
	if (root_ii->i_ino != SILOFS_INO_ROOT) {
		log_err("format root-dir failed: ino=%ld", root_ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_ii_fixup_as_rootdir(root_ii);

	err = flush_and_drop_cache(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int check_capacity(const struct silofs_fs_env *fse)
{
	const size_t cap_want = fse->fs_args.capacity;
	size_t capacity = 0;
	int err;

	err = silofs_calc_fs_capacity(cap_want, &capacity);
	if (err) {
		log_err("illegal capacity: cap=%lu err=%d", cap_want, err);
		return err;
	}
	return 0;
}

static int check_owner_ids(const struct silofs_fs_env *fse)
{
	const uid_t owner_uid = fse->fs_args.uid;
	const gid_t owner_gid = fse->fs_args.gid;
	uid_t suid;
	gid_t sgid;
	int err;

	err = silofs_idsmap_map_uidgid(fse->fs_idsmap, owner_uid,
	                               owner_gid, &suid, &sgid);
	if (err) {
		log_err("unable to map owner credentials: uid=%ld gid=%ld",
		        (long)owner_uid, (long)owner_gid);
		return err;
	}
	return 0;
}

static int format_umeta(const struct silofs_fs_env *fse)
{
	const size_t cap_want = fse->fs_args.capacity;
	size_t capacity = 0;
	int err;

	err = silofs_calc_fs_capacity(cap_want, &capacity);
	if (err) {
		return err;
	}
	err = silofs_uber_format_super(fse->fs_uber, capacity);
	if (err) {
		return err;
	}
	err = check_superblock(fse);
	if (err) {
		log_err("internal sb format: err=%d", err);
		return err;
	}
	err = flush_dirty(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int format_vmeta(const struct silofs_fs_env *fse)
{
	int err;

	err = format_base_vspmaps(fse);
	if (err) {
		return err;
	}
	err = claim_reclaim_vspace(fse);
	if (err) {
		return err;
	}
	err = format_zero_vspace(fse);
	if (err) {
		return err;
	}
	err = flush_dirty(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int do_format_repo(const struct silofs_fs_env *fse)
{
	return silofs_repo_format(fse->fs_repo);
}

int silofs_format_repo(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = do_format_repo(fse);
	fse_unlock(fse);
	return ret;
}

static int do_open_repo(const struct silofs_fs_env *fse)
{
	return silofs_repo_open(fse->fs_repo);
}

int silofs_open_repo(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = do_open_repo(fse);
	fse_unlock(fse);
	return ret;
}

static int stat_bootrec_of(const struct silofs_fs_env *fse,
                           const struct silofs_uaddr *uaddr)
{
	struct stat st = { .st_size = -1 };
	int err;

	err = silofs_repo_stat_obj(fse->fs_repo, &uaddr->laddr, &st);
	if (err) {
		log_err("failed to stat bootrec: err=%d", err);
		return err;
	}
	if (st.st_size != SILOFS_BOOTREC_SIZE) {
		log_warn("bad bootrec: size=%ld", st.st_size);
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

static int save_bootrec_of(const struct silofs_fs_env *fse,
                           const struct silofs_uaddr *uaddr,
                           const struct silofs_bootrec *brec)
{
	struct silofs_bootrec1k brec1k = { .br_magic = 0 };
	const struct silofs_crypto *crypto = &fse->fs_uber->ub_crypto;
	const struct silofs_ivkey *ivkey = &fse->fs_boot_ivkey;
	int err;

	silofs_assert_eq(uaddr->laddr.len, sizeof(brec1k));
	err = silofs_bootrec_encode(brec, &brec1k, crypto, ivkey);
	if (err) {
		return err;
	}
	err = silofs_repo_save_obj(fse->fs_repo, &uaddr->laddr, &brec1k);
	if (err) {
		return err;
	}
	return 0;
}

static int load_bootrec_of(const struct silofs_fs_env *fse,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_bootrec *out_brec)
{
	struct silofs_bootrec1k brec1k = { .br_magic = 0 };
	const struct silofs_crypto *crypto = &fse->fs_uber->ub_crypto;
	const struct silofs_ivkey *ivkey = &fse->fs_boot_ivkey;
	int err;

	silofs_assert_eq(uaddr->laddr.len, sizeof(brec1k));
	err = silofs_repo_load_obj(fse->fs_repo, &uaddr->laddr, &brec1k);
	if (err) {
		log_err("failed to load bootrec: err=%d", err);
		return err;
	}
	err = silofs_bootrec_decode(out_brec, &brec1k, crypto, ivkey);
	if (err) {
		log_err("failed to decode bootrec: err=%d", err);
		return err;
	}
	return 0;
}

static int reload_bootrec_of(struct silofs_fs_env *fse,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_bootrec *out_brec)
{
	int err;

	err = stat_bootrec_of(fse, uaddr);
	if (err) {
		return err;
	}
	err = load_bootrec_of(fse, uaddr, out_brec);
	if (err) {
		return err;
	}
	return 0;
}

static int unlink_bootrec_of(struct silofs_fs_env *fse,
                             const struct silofs_uaddr *uaddr)
{
	int err;

	err = silofs_repo_unlink_obj(fse->fs_repo, &uaddr->laddr);
	if (err) {
		log_err("failed to unlink bootrec: err=%d", err);
		return err;
	}
	return 0;
}

static int save_bootrec(const struct silofs_fs_env *fse,
                        const struct silofs_bootrec *brec)
{
	struct silofs_uaddr uaddr;

	silofs_bootrec_self_uaddr(brec, &uaddr);
	return save_bootrec_of(fse, &uaddr, brec);
}

static int update_save_bootrec(const struct silofs_fs_env *fse,
                               struct silofs_bootrec *brec)
{
	const struct silofs_sb_info *sbi = fse->fs_uber->ub_sbi;

	silofs_bootrec_set_sb_ulink(brec, sbi_ulink(sbi));
	return save_bootrec(fse, brec);
}

static int do_format_fs(struct silofs_fs_env *fse,
                        struct silofs_treeid *out_treeid)
{
	struct silofs_bootrec brec;
	int err;

	silofs_bootrec_init(&brec);
	err = check_capacity(fse);
	if (err) {
		return err;
	}
	err = check_owner_ids(fse);
	if (err) {
		return err;
	}
	err = fse_derive_main_ivkey(fse, &brec);
	if (err) {
		return err;
	}
	err = format_umeta(fse);
	if (err) {
		return err;
	}
	err = format_vmeta(fse);
	if (err) {
		return err;
	}
	err = format_rootdir(fse);
	if (err) {
		return err;
	}
	err = update_save_bootrec(fse, &brec);
	if (err) {
		return err;
	}
	silofs_bootrec_treeid(&brec, out_treeid);
	return 0;
}

int silofs_format_fs(struct silofs_fs_env *fse,
                     struct silofs_treeid *out_treeid)
{
	int ret;

	fse_lock(fse);
	ret = do_format_fs(fse, out_treeid);
	fse_unlock(fse);
	return ret;
}

static int fse_reload_root_sb_lext(struct silofs_fs_env *fse,
                                   const struct silofs_bootrec *brec)
{
	silofs_uber_bind_child(fse->fs_uber, &brec->sb_ulink);
	return silofs_uber_reload_sb_lext(fse->fs_uber);
}

static int do_boot_fs(struct silofs_fs_env *fse,
                      const struct silofs_treeid *treeid)
{
	struct silofs_bootrec brec;
	struct silofs_uaddr uaddr;
	int err;

	silofs_make_bootrec_uaddr(treeid, &uaddr);
	err = reload_bootrec_of(fse, &uaddr, &brec);
	if (err) {
		return err;
	}
	err = fse_derive_main_ivkey(fse, &brec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sb_lext(fse, &brec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_boot_fs(struct silofs_fs_env *fse,
                   const struct silofs_treeid *treeid)
{
	int ret;

	fse_lock(fse);
	ret = do_boot_fs(fse, treeid);
	fse_unlock(fse);
	return ret;
}

static int do_open_fs(const struct silofs_fs_env *fse)
{
	int err;

	err = reload_super(fse);
	if (err) {
		return err;
	}
	err = reload_base_vspace(fse);
	if (err) {
		return err;
	}
	err = reload_free_vspace(fse);
	if (err) {
		return err;
	}
	err = reload_fs_meta(fse);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_open_fs(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = do_open_fs(fse);
	fse_unlock(fse);
	return ret;
}

static int do_close_fs(struct silofs_fs_env *fse)
{
	int err;

	err = flush_dirty(fse);
	if (err) {
		return err;
	}
	err = fsync_lexts(fse);
	if (err) {
		return err;
	}
	err = shutdown_uber(fse);
	if (err) {
		return err;
	}
	drop_caches(fse);
	return err;
}

int silofs_close_fs(struct silofs_fs_env *fse)
{
	int err;

	fse_lock(fse);
	err = do_close_fs(fse);
	fse_unlock(fse);
	return err;
}

int silofs_poke_fs(struct silofs_fs_env *fse,
                   const struct silofs_treeid *treeid,
                   struct silofs_bootrec *out_brec)
{
	struct silofs_uaddr uaddr = { .voff = -1 };

	silofs_make_bootrec_uaddr(treeid, &uaddr);
	return load_bootrec_of(fse, &uaddr, out_brec);
}

static int exec_clone_fs(const struct silofs_fs_env *fse,
                         struct silofs_bootrecs *out_brecs)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_clone(&task, SILOFS_INO_ROOT, 0, out_brecs);
	if (err) {
		return err;
	}
	return term_task(&task, err);
}

int silofs_fork_fs(struct silofs_fs_env *fse,
                   struct silofs_treeid *out_new,
                   struct silofs_treeid *out_alt)
{
	struct silofs_bootrecs brecs;
	int err;

	err = exec_clone_fs(fse, &brecs);
	if (err) {
		return err;
	}
	silofs_bootrecs_to_treeids(&brecs, out_new, out_alt);
	return 0;
}

static int exec_inspect_fs(struct silofs_fs_env *fse, silofs_visit_laddr_fn cb)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_inspect(&task, cb);
	return term_task(&task, err);
}

int silofs_inspect_fs(struct silofs_fs_env *fse, silofs_visit_laddr_fn cb)
{
	return exec_inspect_fs(fse, cb);
}

static int exec_unref_fs(struct silofs_fs_env *fse)
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

int silofs_unref_fs(struct silofs_fs_env *fse,
                    const struct silofs_treeid *treeid)
{
	struct silofs_bootrec brec;
	struct silofs_uaddr uaddr;
	int err;

	silofs_make_bootrec_uaddr(treeid, &uaddr);
	err = reload_bootrec_of(fse, &uaddr, &brec);
	if (err) {
		return err;
	}
	err = fse_derive_main_ivkey(fse, &brec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sb_lext(fse, &brec);
	if (err) {
		return err;
	}
	err = reload_super(fse);
	if (err) {
		return err;
	}
	err = exec_unref_fs(fse);
	if (err) {
		return err;
	}
	err = unlink_bootrec_of(fse, &uaddr);
	if (err) {
		return err;
	}
	err = do_close_fs(fse);
	if (err) {
		return err;
	}
	return 0;
}
