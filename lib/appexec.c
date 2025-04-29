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
#include <sys/stat.h>
#include <silofs/defs.h>
#include <silofs/ioctls.h>
#include <silofs/appexec.h>
#include "repo.h"
#include "idsmap.h"
#include "bootrec.h"
#include "lcache.h"
#include "lnodes.h"
#include "uidgid.h"
#include "task.h"
#include "inode.h"
#include "namei.h"
#include "env.h"
#include "flush.h"
#include "stage.h"
#include "opexec.h"
#include "fuseq.h"
#include "walk.h"

static int reload_super(struct silofs_task *task)
{
	int err;

	err = silofs_env_reload_sb_lseg(task->t_env);
	if (err) {
		return err;
	}
	err = silofs_env_reload_super(task->t_env);
	if (err) {
		return err;
	}
	return 0;
}

static int reload_vspace(struct silofs_task *task)
{
	return silofs_reload_vspace(task);
}

static int reload_rootd(struct silofs_task *task)
{
	struct silofs_inode_info *ii = NULL;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

	err = silofs_stage_inode(task, ino, SILOFS_STG_CUR, &ii);
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

static int reload_vmeta(struct silofs_task *task)
{
	int err;

	err = reload_super(task);
	if (err) {
		return err;
	}
	err = reload_vspace(task);
	if (err) {
		return err;
	}
	err = reload_rootd(task);
	if (err) {
		return err;
	}
	return 0;
}

static void relax_caches(struct silofs_task *task, bool now)
{
	const int flags = now ? SILOFS_CTLF_NOW : SILOFS_CTLF_IDLE;

	silofs_env_relax_caches(task->t_env, flags);
}

static int flush_dirty(struct silofs_task *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
	}
	return err;
}

static void drop_caches(struct silofs_task *task)
{
	silofs_env_drop_caches(task->t_env);
}

static void drop_relax_caches(struct silofs_task *task)
{
	drop_caches(task);
	relax_caches(task, false);
}

static size_t calc_aligned_fs_cap(const struct silofs_task *task)
{
	const size_t fs_cap_want = task->t_env->base.args->capacity;
	const size_t align_size = SILOFS_LSEG_SIZE_MAX;

	return (fs_cap_want / align_size) * align_size;
}

static int format_super(struct silofs_task *task)
{
	const size_t fs_cap = calc_aligned_fs_cap(task);

	return silofs_env_format_super(task->t_env, fs_cap);
}

static int appexec_resync_vmeta(struct silofs_task *task, bool drop)
{
	int err;

	relax_caches(task, drop);
	err = flush_dirty(task);
	if (err || !drop) {
		return err;
	}
	drop_relax_caches(task);
	return 0;
}

static int do_claim_reclaim(struct silofs_task *task, enum silofs_ltype ltype)
{
	struct silofs_vaddr vaddr;
	const loff_t voff_exp = 0;
	int err;

	err = silofs_claim_vspace(task, ltype, &vaddr);
	if (err) {
		log_err("vclaim failed: ltype=%d err=%d", ltype, err);
		return err;
	}
	if (vaddr.off != voff_exp) {
		log_err("bad claim: ltype=%d exp=%ld got=%ld", ltype, voff_exp,
		        vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}
	drop_caches(task);
	err = silofs_reclaim_vspace(task, &vaddr);
	if (err) {
		log_err("bad reclaim: ltype=%d voff=%ld err=%d", ltype,
		        vaddr.off, err);
	}
	return 0;
}

static int retry_claim(struct silofs_task *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isvnode(ltype)) {
			continue;
		}
		err = do_claim_reclaim(task, ltype);
		if (err) {
			return err;
		}
		err = flush_dirty(task);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

static int require_spmaps_of(struct silofs_task *task, enum silofs_ltype ltype)
{
	struct silofs_vaddr vaddr;
	struct silofs_spleaf_info *sli = NULL;

	silofs_vaddr_setup(&vaddr, ltype, 0);
	return silofs_require_spleaf_of(task, &vaddr, SILOFS_STG_COW, &sli);
}

static int format_spmaps_of(struct silofs_task *task, enum silofs_ltype ltype)
{
	int err;

	err = require_spmaps_of(task, ltype);
	if (err) {
		log_err("format spmaps failed: ltype=%d err=%d", ltype, err);
		return err;
	}
	err = flush_dirty(task);
	if (err) {
		return err;
	}
	log_dbg("format spmaps of: ltype=%d", ltype);
	return 0;
}

static int format_spmaps(struct silofs_task *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isvnode(ltype)) {
			continue;
		}
		err = format_spmaps_of(task, ltype);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

static loff_t vni_offset(const struct silofs_vnode_info *vni)
{
	const struct silofs_vaddr *vaddr = silofs_vni_vaddr(vni);

	return vaddr->off;
}

static int claim_offset_zero(struct silofs_task *task, enum silofs_ltype ltype)
{
	struct silofs_vnode_info *vni = NULL;
	loff_t off = -1;
	int err;

	err = silofs_spawn_vnode(task, NULL, ltype, &vni);
	if (err) {
		log_err("failed to spawn: ltype=%d err=%d", ltype, err);
		return err;
	}
	off = vni_offset(vni);
	if (off != 0) {
		log_err("format zspace failed: ltype=%d off=%ld", ltype, off);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int format_nil_space(struct silofs_task *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isvnode(ltype)) {
			continue;
		}
		err = claim_offset_zero(task, ltype);
		if (err) {
			return err;
		}
		err = flush_dirty(task);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

static int
spawn_rootdir(struct silofs_task *task, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp;

	silofs_inew_params_of(task, NULL, S_IFDIR | 0755, 0, &inp);
	return silofs_spawn_inode(task, &inp, out_ii);
}

static int format_rootdir(struct silofs_task *task)
{
	struct silofs_inode_info *root_ii = NULL;
	int err;

	err = spawn_rootdir(task, &root_ii);
	if (err) {
		return err;
	}
	if (root_ii->i_ino != SILOFS_INO_ROOT) {
		log_err("failed to format root-dir: ino=%ld", root_ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_ii_fixup_as_rootdir(root_ii);
	return 0;
}

static int setup_bootrec(struct silofs_task *task)
{
	return silofs_env_setup_bootrec(task->t_env);
}

static int commit_bootrec(struct silofs_task *task)
{
	return silofs_env_commit_bootrec(task->t_env);
}

static int appexec_format_meta(struct silofs_task *task)
{
	int err;

	err = setup_bootrec(task);
	if (err) {
		return err;
	}
	err = format_super(task);
	if (err) {
		return err;
	}
	err = flush_dirty(task);
	if (err) {
		return err;
	}
	err = format_spmaps(task);
	if (err) {
		return err;
	}
	err = retry_claim(task);
	if (err) {
		return err;
	}
	err = format_nil_space(task);
	if (err) {
		return err;
	}
	err = format_rootdir(task);
	if (err) {
		return err;
	}
	err = flush_dirty(task);
	if (err) {
		return err;
	}
	err = commit_bootrec(task);
	if (err) {
		return err;
	}
	drop_relax_caches(task);
	return 0;
}

static int reload_bootrec(const struct silofs_task *task)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_bootrec_caddr(task->t_env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_env_reload_bootrec(task->t_env);
	if (err) {
		return err;
	}
	return 0;
}

static int appexec_reload_fs(struct silofs_task *task)
{
	int err;

	err = reload_bootrec(task);
	if (err) {
		return err;
	}
	err = reload_vmeta(task);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

static int unlink_bootrec(struct silofs_task *task)
{
	int err;

	err = silofs_env_unlink_bootrec(task->t_env);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

static int appexec_fork_fs(struct silofs_task *task)
{
	struct silofs_bootrec_caddrs caddrs;
	int err;

	err = silofs_env_bootrec_caddr(task->t_env, &caddrs.curr);
	if (err) {
		return err;
	}
	err = silofs_exec_forkfs(task, SILOFS_INO_ROOT, 0, &caddrs);
	if (err) {
		return err;
	}
	err = flush_dirty(task);
	if (err) {
		return err;
	}
	drop_relax_caches(task);
	return 0;
}

static int shutdown_fs(struct silofs_task *task)
{
	struct silofs_repo *repo = silofs_task_repo(task);
	int err;

	err = silofs_repo_fsync_all(repo);
	if (err) {
		return err;
	}
	drop_relax_caches(task);

	err = silofs_env_shut(task->t_env);
	if (err) {
		return err;
	}
	drop_relax_caches(task);

	return 0;
}

static int appexec_unload_fs(struct silofs_task *task)
{
	int err;

	err = flush_dirty(task);
	if (err) {
		return err;
	}
	err = shutdown_fs(task);
	if (err) {
		return err;
	}
	return 0;
}

static int appexec_remove_fs(struct silofs_task *task)
{
	int err;

	err = silofs_exec_unrefs(task);
	if (err) {
		return err;
	}
	err = unlink_bootrec(task);
	if (err) {
		return err;
	}
	err = shutdown_fs(task);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void caddr_to_xref(const struct silofs_caddr *caddr, int status,
                          struct silofs_xref *out_xref)
{
	if (status == 0) {
		silofs_xref_from_caddr(out_xref, caddr);
	} else {
		silofs_xref_reset(out_xref);
	}
}

int silofs_check_fs_xref(const struct silofs_xref *xref)
{
	struct silofs_caddr caddr;

	return silofs_xref_to_caddr_with(xref, SILOFS_CTYPE_BOOTREC, &caddr);
}

int silofs_check_ar_xref(const struct silofs_xref *xref)
{
	struct silofs_caddr caddr;

	return silofs_xref_to_caddr_with(xref, SILOFS_CTYPE_PACKIDX, &caddr);
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

static int do_map_task_creds(struct silofs_task *task)
{
	const struct silofs_cred *xcred = &task->t_oper.op_creds.host_cred;
	struct silofs_cred *icred = &task->t_oper.op_creds.fs_cred;

	return silofs_idsmap_map_uidgid(silofs_task_idsmap(task), xcred->uid,
	                                xcred->gid, &icred->uid, &icred->gid);
}

static int map_task_creds(struct silofs_task *task)
{
	const struct silofs_idsmap *idsm = silofs_task_idsmap(task);
	int err = 0;

	if (idsm->idm_usize || idsm->idm_gsize) {
		err = do_map_task_creds(task);
	}
	task->t_runnable = (err == 0);
	return err;
}

static int make_task(struct silofs_env *env, struct silofs_task *task)
{
	const struct silofs_args *args = env->base.args;

	silofs_task_init(task, env);
	silofs_task_set_ts(task, true);
	silofs_task_set_creds(task, args->uid, args->gid, args->umask);
	task->t_bootrec_op = true;
	return map_task_creds(task);
}

static int term_task(struct silofs_task *task, int status)
{
	int err = 0;

	if (task->t_runnable) {
		err = silofs_task_submit(task, true);
	}
	silofs_task_fini(task);
	return status ? status : err;
}

static int exec_reload_fs(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_reload_fs(&task);
	}
	return term_task(&task, err);
}

static int exec_resync_vmeta(struct silofs_env *env, bool drop)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_resync_vmeta(&task, drop);
	}
	return term_task(&task, err);
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
	const struct silofs_args *args = env->base.args;
	struct silofs_fuseq *fuseq = env->base.fuseq;
	int err;

	err = silofs_fuseq_mount(fuseq, env, args->boot.mntdir);
	if (err) {
		return err;
	}
	err = silofs_fuseq_exec(fuseq);
	if (err) {
		return err;
	}
	return 0;
}

static bool run_with_fuse(const struct silofs_env *env)
{
	const struct silofs_fuseq *fuseq = env->base.fuseq;

	return (fuseq != NULL) && silofs_env_hasflag(env, SILOFS_F_WITHFUSE);
}

int silofs_run_fs(struct silofs_env *env)
{
	struct silofs_fuseq *fuseq = env->base.fuseq;
	int err;

	if (!run_with_fuse(env)) {
		return -SILOFS_EINVAL;
	}
	err = silofs_fuseq_update(fuseq);
	if (!err) {
		err = do_mount_and_exec(env);
		silofs_fuseq_term(fuseq);
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

int silofs_sync_fs(struct silofs_env *env, bool drop)
{
	int err = 0;

	silofs_env_lock(env);
	for (int i = 0; (i < 3) && !err; ++i) {
		err = exec_resync_vmeta(env, drop);
	}
	silofs_env_unlock(env);
	return err;
}

void silofs_stat_fs(const struct silofs_env *env,
                    struct silofs_cache_stats *cst)
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
	const size_t cap_want = env->base.args->capacity;
	int err;

	err = check_fs_capacity(cap_want);
	if (err) {
		log_err("illegal file-system capacity: cap=%lu err=%d",
		        cap_want, err);
		return err;
	}
	return 0;
}

static int check_owner_ids(const struct silofs_env *env)
{
	const struct silofs_args *args = env->base.args;
	const uid_t owner_uid = args->uid;
	const gid_t owner_gid = args->gid;
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

static int exec_format_meta(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_format_meta(&task);
	}
	return term_task(&task, err);
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

static int require_bootrec_caddr(const struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };

	return silofs_env_bootrec_caddr(env, &caddr);
}

static int require_no_bootrec_caddr(const struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_bootrec_caddr(env, &caddr);
	return err ? 0 : -SILOFS_EEXIST;
}

static int require_pack_caddr(const struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };

	return silofs_env_pack_caddr(env, &caddr);
}

static int check_format_fs(struct silofs_env *env)
{
	int err;

	err = check_want_capacity(env);
	if (err) {
		return err;
	}
	err = check_owner_ids(env);
	if (err) {
		return err;
	}
	err = require_no_bootrec_caddr(env);
	if (err) {
		return err;
	}
	return 0;
}

static int do_format_fs(struct silofs_env *env)
{
	int err;

	err = check_format_fs(env);
	if (err) {
		return err;
	}
	err = silofs_env_format_bstore(env);
	if (err) {
		return err;
	}
	err = exec_format_meta(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_format_fs(struct silofs_env *env)
{
	int ret;

	silofs_env_lock(env);
	ret = do_format_fs(env);
	silofs_env_unlock(env);
	return ret;
}

static int do_sense_fs(struct silofs_env *env)
{
	int err;

	err = require_bootrec_caddr(env);
	if (err) {
		return err;
	}
	err = silofs_env_sense_bootrec(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sense_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = do_sense_fs(env);
	silofs_env_unlock(env);
	return err;
}

int silofs_open_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = exec_reload_fs(env);
	silofs_env_unlock(env);
	return err;
}

static int exec_unload_fs(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_unload_fs(&task);
	}
	return term_task(&task, err);
}

int silofs_close_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = exec_unload_fs(env);
	silofs_env_unlock(env);
	return err;
}

static int do_sense_ar(struct silofs_env *env)
{
	int err;

	err = require_pack_caddr(env);
	if (err) {
		return err;
	}
	err = silofs_env_sense_pack(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sense_ar(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = do_sense_ar(env);
	silofs_env_unlock(env);

	return err;
}

static int exec_fork_fs(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_fork_fs(&task);
	}
	return term_task(&task, err);
}

int silofs_fork_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = exec_fork_fs(env);
	silofs_env_unlock(env);
	return err;
}

static int exec_reload_remove_fs(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (err) {
		goto out;
	}
	err = appexec_reload_fs(&task);
	if (err) {
		goto out;
	}
	err = appexec_remove_fs(&task);
	if (err) {
		goto out;
	}
out:
	return term_task(&task, err);
}

int silofs_remove_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = exec_reload_remove_fs(env);
	silofs_env_unlock(env);
	return err;
}

static int exec_inspect_fs(struct silofs_env *env,
                           const struct silofs_laddr_visitor *lvis)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = silofs_exec_walkfs(&task, lvis);
	}
	return term_task(&task, err);
}

static int
inspect_view(void *ctx, const struct silofs_laddr *laddr, size_t len)
{
	struct silofs_strbuf sbuf;

	silofs_laddr_to_ascii(laddr, &sbuf);
	silofs_log_info("%s:%zu", sbuf.str, len);
	silofs_unused(ctx);
	return 0;
}

int silofs_inspect_fs(struct silofs_env *env, bool view)
{
	const struct silofs_laddr_visitor lvis = {
		.hook = view ? inspect_view : NULL,
		.userp = NULL,
	};
	int err;

	silofs_env_lock(env);
	err = exec_inspect_fs(env, &lvis);
	silofs_env_unlock(env);
	return err;
}

static int exec_pack_fs(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = silofs_exec_archive(&task);
	}
	return term_task(&task, err);
}

static int do_archive_fs(struct silofs_env *env)
{
	int err;

	err = require_bootrec_caddr(env);
	if (err) {
		return err;
	}
	err = exec_pack_fs(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_archive_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = do_archive_fs(env);
	silofs_env_unlock(env);
	return err;
}

static int exec_unpack_fs(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = silofs_exec_restore(&task);
	}
	return term_task(&task, err);
}

static int do_restore_fs(struct silofs_env *env)
{
	int err;

	err = require_pack_caddr(env);
	if (err) {
		return err;
	}
	err = exec_unpack_fs(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_restore_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = do_restore_fs(env);
	silofs_env_unlock(env);
	return err;
}

void silofs_get_args(const struct silofs_env *env,
                     struct silofs_args *out_args)
{
	memcpy(out_args, env->base.args, sizeof(*out_args));
}

int silofs_get_fs_xref(struct silofs_env *env, struct silofs_xref *out_xref)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int ret;

	silofs_env_lock(env);
	ret = silofs_env_bootrec_caddr(env, &caddr);
	silofs_env_unlock(env);
	caddr_to_xref(&caddr, ret, out_xref);
	return ret;
}

int silofs_get_fs_base_xref(struct silofs_env *env,
                            struct silofs_xref *out_xref)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int ret;

	silofs_env_lock(env);
	ret = silofs_env_base_caddr(env, &caddr);
	silofs_env_unlock(env);
	caddr_to_xref(&caddr, ret, out_xref);
	return ret;
}

int silofs_get_fs_fork_xref(struct silofs_env *env,
                            struct silofs_xref *out_xref)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int ret;

	silofs_env_lock(env);
	ret = silofs_env_fork_caddr(env, &caddr);
	silofs_env_unlock(env);
	caddr_to_xref(&caddr, ret, out_xref);
	return ret;
}

int silofs_set_fs_xref(struct silofs_env *env, const struct silofs_xref *xref)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	silofs_env_lock(env);
	err = silofs_xref_to_caddr(xref, &caddr);
	if (!err) {
		err = silofs_env_set_bootrec_caddr(env, &caddr);
	}
	silofs_env_unlock(env);
	return err;
}

int silofs_get_ar_xref(struct silofs_env *env, struct silofs_xref *out_xref)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int ret;

	silofs_env_lock(env);
	ret = silofs_env_pack_caddr(env, &caddr);
	silofs_env_unlock(env);
	caddr_to_xref(&caddr, ret, out_xref);
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
	err = check_endianess64(SILOFS_BOOTREC_MAGIC, "@SILOFS@");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_AR_INDEX_MAGIC, "%silofs%");
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
	const rlim_t nofiles_min = 512;
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
	if (rlim.rlim_cur < nofiles_min) {
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

int silofs_init_once(void)
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

void silofs_getversions(struct silofs_versions *out_vers)
{
	out_vers->silofs_version = silofs_version.string;
	out_vers->gcrypt_version = silofs_gcrypt_version();
	out_vers->zstd_version = silofs_zstd_version();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_remap_status_code(int status)
{
	int ret = status;

	if (ret) {
		ret = abs(status);
		if (ret >= SILOFS_ERRBASE2) {
			ret = EUCLEAN;
		} else if (ret >= SILOFS_ERRBASE) {
			ret = (ret - SILOFS_ERRBASE);
		}
	}
	return -ret;
}
