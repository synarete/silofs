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
#include <silofs/fuseq.h>
#include <silofs/fs-private.h>
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
	union silofs_fs_alloc_u alloc_u;
	struct silofs_repo      repo;
	struct silofs_submitq   submitq;
	struct silofs_uber      uber;
	struct silofs_idsmap    idsm;
	struct silofs_password  passwd;
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
		return -ENOMEM;
	}
	if (mem_rlim < mem_floor) {
		return -ENOMEM;
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
	silofs_ivkey_init(&fse->fs_ivkey);
	fs_args_assign(&fse->fs_args, fs_args);
	fse->fs_args.uid = getuid();
	fse->fs_args.gid = getgid();
	fse->fs_args.pid = getpid();
	fse->fs_args.umask = 0022;
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
	mode = fse->fs_args.pedantic ? 1 : 0;
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

static int fse_make_repocfg(struct silofs_fs_env *fse,
                            struct silofs_repocfg *rcfg)
{
	silofs_memzero(rcfg, sizeof(*rcfg));
	rcfg->rc_alloc = fse->fs_alloc;
	rcfg->rc_rdonly = fse->fs_args.rdonly;
	return silofs_bootpath_setup(&rcfg->rc_bootpath,
	                             fse->fs_args.repodir, fse->fs_args.name);
}

static int fse_init_repo(struct silofs_fs_env *fse)
{
	struct silofs_repocfg rcfg = { .rc_rdonly = false };
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	struct silofs_repo *repo;
	int err;

	silofs_memzero(&rcfg, sizeof(rcfg));
	err = fse_make_repocfg(fse, &rcfg);
	if (err) {
		return err;
	}
	repo = &fse_obj->fs_core.c.repo;
	err = silofs_repo_init(repo, &rcfg);
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
	err = silofs_idsmap_populate(idsm, &fs_args->ids);
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
		.ivkey = &fse->fs_ivkey,
		.alloc = fse->fs_alloc,
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
		fuseq->fq_writeback_cache = fse->fs_args.wbackcache;
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
	mem = silofs_allocate(fse->fs_alloc, fuseq_pg_size);
	if (mem == NULL) {
		log_warn("failed to allocate fuseq: size=%lu", fuseq_pg_size);
		return -ENOMEM;
	}
	fqp = mem;
	err = silofs_fuseq_init(&fqp->fuseq, fse->fs_alloc);
	if (err) {
		silofs_deallocate(fse->fs_alloc, mem, fuseq_pg_size);
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

		silofs_deallocate(fse->fs_alloc, fuseq_pg, sizeof(*fuseq_pg));
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

static int fse_init_subs(struct silofs_fs_env *fse)
{
	int err;

	err = fse_init_passwd(fse);
	if (err) {
		return err;
	}
	err = fse_init_alloc(fse);
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
	err = fse_init_subs(fse);
	if (err) {
		fse_fini(fse);
	}
	return err;
}

static void fse_fini_commons(struct silofs_fs_env *fse)
{
	silofs_ivkey_fini(&fse->fs_ivkey);
	fse->fs_uber = NULL;
}

static void fse_fini(struct silofs_fs_env *fse)
{
	fse_fini_fuseq(fse);
	fse_fini_uber(fse);
	fse_fini_idsmap(fse);
	fse_fini_submitq(fse);
	fse_fini_repo(fse);
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

static int remap_creds(const struct silofs_fs_env *fse,
                       struct silofs_task *task)
{
	const struct silofs_ucred *xcred = &task->t_oper.op_creds.xcred;
	struct silofs_ucred *icred = &task->t_oper.op_creds.icred;

	if (!fse->fs_idsmap->idm_size) {
		return 0; /* using local ids */
	}
	return silofs_idsmap_map_uidgid(fse->fs_idsmap,
	                                xcred->uid, xcred->gid,
	                                &icred->uid, &icred->gid);
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
	silofs_task_set_umask(task, fs_args->umask);
	silofs_task_set_creds(task, fs_args->uid, fs_args->gid, fs_args->pid);
	return remap_creds(fse, task);
}

static int term_task(struct silofs_task *task, int status)
{
	int err;

	err = silofs_task_submit(task, true);
	silofs_task_fini(task);
	silofs_burnstack();
	return status ? status : err;
}

static void drop_cache(const struct silofs_fs_env *fse)
{
	silofs_repo_drop_cache(fse->fs_repo);
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
	err = silofs_stage_inode(&task, ino, SILOFS_STAGE_CUR, out_ii);
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
		if (err && (err != -ENOSPC) && (err != -ENOENT)) {
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
	drop_cache(fse);
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

static int shutdown_uber(struct silofs_fs_env *fse)
{
	struct silofs_uber *uber = fse->fs_uber;
	int err;

	if ((uber == NULL) || (uber->ub_sbi == NULL)) {
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
		return -EINVAL;
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

	err = exec_flush_dirty_now(fse);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
		return err;
	}
	drop_cache(fse);
	return 0;
}

static int do_sync_fs(const struct silofs_fs_env *fse)
{
	int err;

	err = exec_flush_dirty_now(fse);
	if (!err) {
		drop_cache(fse);
	}
	return err;
}

int silofs_sync_fs(struct silofs_fs_env *fse)
{
	int err = 0;

	fse_lock(fse);
	for (size_t i = 0; !err && (i < 2); ++i) {
		err = do_sync_fs(fse);
	}
	fse_unlock(fse);
	return err;
}

void silofs_stat_fs(const struct silofs_fs_env *fse,
                    struct silofs_fs_stats *st)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0 };
	const struct silofs_cache *cache = &fse->fs_repo->re_cache;

	silofs_memzero(st, sizeof(*st));
	silofs_allocstat(fse->fs_alloc, &alst);
	st->nalloc_bytes = alst.nbytes_use;
	st->ncache_ublocks += cache->c_ubki_lm.lm_htbl_sz;
	st->ncache_vblocks += cache->c_vbki_lm.lm_htbl_sz;
	st->ncache_unodes += cache->c_ui_lm.lm_htbl_sz;
	st->ncache_vnodes += cache->c_vi_lm.lm_htbl_sz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int derive_main_ivkey(struct silofs_fs_env *fse,
                             const struct silofs_bootsec *bsec)
{
	struct silofs_mdigest mdigest = { .md_hd = NULL };
	struct silofs_cipher_args cip_args = { .cipher_algo = 0 };
	const struct silofs_password *pswd = fse->fs_passwd;
	int err = 0;

	if (!pswd->passlen) {
		return 0;
	}
	err = silofs_mdigest_init(&mdigest);
	if (err) {
		return err;
	}
	silofs_bootsec_cipher_args(bsec, &cip_args);
	err = silofs_derive_ivkey(&cip_args, pswd, &mdigest, &fse->fs_ivkey);
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
		return -EROFS;
	}
	return 0;
}

static int calc_key_hash(const struct silofs_fs_env *fse,
                         struct silofs_hash256 *out_hash)
{
	struct silofs_mdigest mdigest;
	const struct silofs_ivkey *ivkey = &fse->fs_ivkey;
	int err;

	err = silofs_mdigest_init(&mdigest);
	if (err) {
		return err;
	}
	silofs_calc_key_hash(&ivkey->key, &mdigest, out_hash);
	silofs_mdigest_fini(&mdigest);
	return 0;
}

static int verify_bootsec_keyhash(const struct silofs_fs_env *fse,
                                  const struct silofs_bootsec *bsec)
{
	struct silofs_hash256 hash;
	const enum silofs_bootf mask = SILOFS_BOOTF_KEY_SHA256;
	int err;

	if ((bsec->flags & mask) != mask) {
		return 0;
	}
	err = calc_key_hash(fse, &hash);
	if (err) {
		return err;
	}
	err = silofs_bootsec_check_keyhash(bsec, &hash);
	if (err) {
		log_err("failed to verify bootsec: err=%d", err);
		return err;
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
	enum silofs_stage_mode stg_mode = SILOFS_STAGE_COW;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_require_spmaps_at(&task, vaddr, stg_mode, &sni, &sli);
	return term_task(&task, err);
}

static int format_base_spmaps_of(const struct silofs_fs_env *fse,
                                 const struct silofs_vaddr *vaddr)
{
	int err;

	err = exec_require_spmaps_of(fse, vaddr);
	if (err) {
		log_err("failed to format base spmaps: "
		        "stype=%d err=%d", vaddr->stype, err);
		return err;
	}
	err = do_sync_fs(fse);
	if (err) {
		return err;
	}
	log_dbg("format base spmaps of: stype=%d err=%d", vaddr->stype, err);
	return 0;
}

static int format_base_spmaps(const struct silofs_fs_env *fse)
{
	struct silofs_vaddr vaddr;
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		vaddr_setup(&vaddr, stype, 0);
		err = format_base_spmaps_of(fse, &vaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int exec_claim_vspace(const struct silofs_fs_env *fse,
                             enum silofs_stype stype,
                             struct silofs_voaddr *out_voa)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_claim_vspace(&task, stype, SILOFS_DQID_DFL, out_voa);
	return term_task(&task, err);
}

static int exec_reclaim_vspace(const struct silofs_fs_env *fse,
                               const struct silofs_voaddr *voa)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(&task, &voa->vaddr);
	return term_task(&task, err);
}

static int format_claim_vspace_of(const struct silofs_fs_env *fse,
                                  enum silofs_stype vspace)
{
	struct silofs_voaddr voa;
	const loff_t voff_exp = 0;
	int err;

	err = exec_claim_vspace(fse, vspace, &voa);
	if (err) {
		log_err("failed to claim: vspace=%d err=%d", vspace, err);
		return err;
	}
	if (voa.vaddr.off != voff_exp) {
		log_err("wrong first voff: vspace=%d expected-voff=%ld "
		        "got-voff=%ld", vspace, voff_exp, voa.vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}
	err = exec_reclaim_vspace(fse, &voa);
	if (err) {
		log_err("failed to reclaim space: vspace=%d voff=%ld err=%d",
		        vspace, voa.vaddr.off, err);
	}
	return 0;
}

static int format_base_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = format_claim_vspace_of(fse, stype);
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
	const enum silofs_stage_mode stg_mode = SILOFS_STAGE_CUR;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_stage_spmaps_at(&task, vaddr, stg_mode, &sni, &sli);
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
	err = silofs_spawn_vnode(&task, stype, 0, out_vi);
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

static int exec_spawn_rootdir_inode(const struct silofs_fs_env *fse,
                                    struct silofs_inode_info **out_ii)
{
	struct silofs_task task;
	const mode_t mode = S_IFDIR | 0755;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_spawn_inode(&task, SILOFS_INO_NULL, 0, mode, 0, out_ii);
	return term_task(&task, err);
}

static int format_rootdir_inode(const struct silofs_fs_env *fse)
{
	struct silofs_inode_info *root_ii = NULL;
	int err;

	err = exec_spawn_rootdir_inode(fse, &root_ii);
	if (err) {
		return err;
	}
	if (root_ii->i_ino != SILOFS_INO_ROOT) {
		log_err("format root-dir failed: ino=%ld", root_ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_ii_fixup_as_rootdir(root_ii);
	return flush_and_drop_cache(fse);
}

static int format_meta(const struct silofs_fs_env *fse)
{
	int err;

	err = format_base_spmaps(fse);
	if (err) {
		return err;
	}
	err = format_base_vspace(fse);
	if (err) {
		return err;
	}
	err = format_zero_vspace(fse);
	if (err) {
		return err;
	}
	err = format_rootdir_inode(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int format_super(const struct silofs_fs_env *fse)
{
	const size_t cap_want = fse->fs_args.capacity;
	size_t capacity = 0;
	int err;

	err = silofs_calc_fs_capacity(cap_want, &capacity);
	if (err) {
		log_err("illegal capacity: cap=%lu err=%d", cap_want, err);
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

static int save_bootsec_of(const struct silofs_fs_env *fse,
                           const struct silofs_uuid *uuid,
                           const struct silofs_bootsec *bsec)
{
	return silofs_repo_save_bootsec(fse->fs_repo, uuid, bsec);
}

static int load_bootsec_of(const struct silofs_fs_env *fse,
                           const struct silofs_uuid *uuid,
                           struct silofs_bootsec *out_bsec)
{
	return silofs_repo_load_bootsec(fse->fs_repo, uuid, out_bsec);
}

static int reload_bootsec_of(struct silofs_fs_env *fse,
                             const struct silofs_uuid *uuid,
                             struct silofs_bootsec *out_bsec)
{
	int err;

	err = silofs_repo_stat_bootsec(fse->fs_repo, uuid);
	if (err) {
		log_err("failed to stat bootsec: err=%d", err);
		return err;
	}
	err = silofs_repo_load_bootsec(fse->fs_repo, uuid, out_bsec);
	if (err) {
		log_err("failed to reload bootsec: err=%d", err);
		return err;
	}
	return 0;
}

static int unlink_bootsec_of(struct silofs_fs_env *fse,
                             const struct silofs_uuid *uuid)
{
	int err;

	err = silofs_repo_unlink_bootsec(fse->fs_repo, uuid);
	if (err) {
		log_err("failed to unlink bootsec: err=%d", err);
		return err;
	}
	return 0;
}

static int save_bootsec(const struct silofs_fs_env *fse,
                        const struct silofs_bootsec *bsec)
{
	return save_bootsec_of(fse, &bsec->uuid, bsec);
}

static int update_save_bootsec(const struct silofs_fs_env *fse,
                               struct silofs_bootsec *bsec)
{
	const struct silofs_sb_info *sbi = fse->fs_uber->ub_sbi;

	silofs_bootsec_set_sb_uaddr(bsec, sbi_uaddr(sbi));
	return save_bootsec(fse, bsec);
}

static int do_format_fs(struct silofs_fs_env *fse,
                        struct silofs_uuid *out_uuid)
{
	struct silofs_bootsec bsec;
	int err;

	silofs_bootsec_init(&bsec);
	err = derive_main_ivkey(fse, &bsec);
	if (err) {
		return err;
	}
	err = format_super(fse);
	if (err) {
		return err;
	}
	err = format_meta(fse);
	if (err) {
		return err;
	}
	err = update_save_bootsec(fse, &bsec);
	if (err) {
		return err;
	}
	silofs_bootsec_uuid(&bsec, out_uuid);
	return 0;
}

int silofs_format_fs(struct silofs_fs_env *fse, struct silofs_uuid *out_uuid)
{
	int ret;

	fse_lock(fse);
	ret = do_format_fs(fse, out_uuid);
	fse_unlock(fse);
	return ret;
}

static int fse_reload_root_sblob(struct silofs_fs_env *fse,
                                 const struct silofs_bootsec *bsec)
{
	silofs_uber_set_sbaddr(fse->fs_uber, &bsec->sb_uaddr);
	return silofs_uber_reload_sblob(fse->fs_uber);
}

static int do_boot_fs(struct silofs_fs_env *fse,
                      const struct silofs_uuid *uuid)
{
	struct silofs_bootsec bsec;
	int err;

	err = reload_bootsec_of(fse, uuid, &bsec);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fse, &bsec);
	if (err) {
		return err;
	}
	err = verify_bootsec_keyhash(fse, &bsec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sblob(fse, &bsec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_boot_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid)
{
	int ret;

	fse_lock(fse);
	ret = do_boot_fs(fse, uuid);
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

	err = exec_flush_dirty_now(fse);
	if (err) {
		return err;
	}
	err = shutdown_uber(fse);
	if (err) {
		return err;
	}
	err = exec_flush_dirty_now(fse);
	if (err) {
		return err;
	}
	drop_cache(fse);
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

int silofs_poke_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid)
{
	struct silofs_bootsec bsec;

	return load_bootsec_of(fse, uuid, &bsec);
}

static int exec_clone_fs(const struct silofs_fs_env *fse,
                         struct silofs_bootsecs *out_bsecs)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_clone(&task, SILOFS_INO_ROOT, 0, out_bsecs);
	if (err) {
		return err;
	}
	return term_task(&task, err);
}

int silofs_fork_fs(struct silofs_fs_env *fse,
                   struct silofs_uuid *out_new,
                   struct silofs_uuid *out_alt)
{
	struct silofs_bootsecs bsecs;
	int err;

	err = exec_clone_fs(fse, &bsecs);
	if (err) {
		return err;
	}
	silofs_bootsec_uuid(&bsecs.bsec[0], out_new);
	silofs_bootsec_uuid(&bsecs.bsec[1], out_alt);
	return 0;
}

static int exec_inspect_fs(struct silofs_fs_env *fse)
{
	struct silofs_task task;
	int err;

	err = make_task(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_inspect(&task);
	return term_task(&task, err);
}

int silofs_inspect_fs(struct silofs_fs_env *fse)
{
	return exec_inspect_fs(fse);
}

static int exec_unref_fs(struct silofs_fs_env *fse)
{
	struct silofs_task task;
	int err = 0;

	err = make_task(fse, &task);
	if (!err) {
		err = silofs_fs_unrefs(&task);
		err = term_task(&task, err);
	}
	return err;
}

int silofs_unref_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid)
{
	struct silofs_bootsec bsec;
	int err;

	err = reload_bootsec_of(fse, uuid, &bsec);
	if (err) {
		return err;
	}
	err = derive_main_ivkey(fse, &bsec);
	if (err) {
		return err;
	}
	err = verify_bootsec_keyhash(fse, &bsec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sblob(fse, &bsec);
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
	err = unlink_bootsec_of(fse, uuid);
	if (err) {
		return err;
	}
	err = shutdown_uber(fse);
	if (err) {
		return err;
	}
	return 0;
}
