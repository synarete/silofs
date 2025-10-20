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
#include <silofs/ondisk.h>
#include <silofs/ioctls.h>
#include <silofs/appexec.h>
#include "bs.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"
#include "opexec.h"
#include "fuseq.h"
#include "walk.h"

static void setup_mbr_addr(const union silofs_blobidu *blobid,
                           struct silofs_baddr *out_baddr)
{
	silofs_baddr_init(out_baddr, blobid, SILOFS_BMODE_CAS,
	                  SILOFS_MTYPE_MBR, 0);
}

static int import_blobid(const struct silofs_blobid *blobid,
                         union silofs_blobidu *out_blobid)
{
	return silofs_blobid_import(out_blobid, blobid);
}

static void export_blobid(const union silofs_blobidu *blobid,
                          struct silofs_blobid *out_blobid)
{
	silofs_blobid_export(blobid, out_blobid);
}

static int decode_fs_blobid(const struct silofs_blobid *blobid,
                            struct silofs_baddr *out_baddr)
{
	union silofs_blobidu blobidu;
	int err;

	err = import_blobid(blobid, &blobidu);
	if (err) {
		return err;
	}
	setup_mbr_addr(&blobidu, out_baddr);
	return 0;
}

static int decode_ar_blobid(const struct silofs_blobid *blobid,
                            struct silofs_baddr *out_baddr)
{
	union silofs_blobidu blobidu;
	int err;

	err = import_blobid(blobid, &blobidu);
	if (err) {
		return err;
	}
	setup_mbr_addr(&blobidu, out_baddr);
	return 0;
}

static void encode_fs_blobid(const struct silofs_baddr *baddr,
                             struct silofs_blobid *out_blobid)
{
	silofs_assert_eq(baddr->pos, 0);
	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_MBR);
	silofs_assert_eq(baddr->bmode, SILOFS_BMODE_CAS);

	export_blobid(&baddr->blobid, out_blobid);
}

static void encode_ar_blobid(const struct silofs_baddr *baddr,
                             struct silofs_blobid *out_blobid)
{
	silofs_assert_eq(baddr->pos, 0);
	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_MBR);
	silofs_assert_eq(baddr->bmode, SILOFS_BMODE_CAS);

	export_blobid(&baddr->blobid, out_blobid);
}

int silofs_encode_blobid(const struct silofs_blobid *blobid, char *s, size_t n)
{
	union silofs_blobidu blobidu;
	struct silofs_strspan ss;
	int err;

	err = silofs_blobid_import(&blobidu, blobid);
	if (err) {
		return err;
	}
	silofs_strspan_initk(&ss, s, 0, n);
	return silofs_blobid_to_str(&blobidu, &ss);
}

int silofs_decode_blobid(struct silofs_blobid *blobid, const char *s)
{
	union silofs_blobidu blobidu;
	struct silofs_strview sv;
	int err;

	silofs_strview_init(&sv, s);
	err = silofs_blobid_from_str(&blobidu, &sv);
	if (err) {
		return err;
	}
	silofs_blobid_export(&blobidu, blobid);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int reload_super(struct silofs_task_ctx *task)
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

static int reload_vspace(struct silofs_task_ctx *task)
{
	return silofs_reload_vspace(task);
}

static int reload_rootd(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

	err = silofs_stage_inode(task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!silofs_ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o",
		        silofs_ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int reload_vmeta(struct silofs_task_ctx *task)
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

static void relax_caches(struct silofs_task_ctx *task, bool now)
{
	const int flags = now ? SILOFS_CTLF_NOW : SILOFS_CTLF_IDLE;

	silofs_env_relax_caches(task->t_env, flags);
}

static int flush_dirty(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
	}
	return err;
}

static void drop_caches(struct silofs_task_ctx *task)
{
	silofs_env_drop_caches(task->t_env);
}

static void drop_relax_caches(struct silofs_task_ctx *task)
{
	drop_caches(task);
	relax_caches(task, false);
}

static size_t calc_aligned_fs_cap(const struct silofs_task_ctx *task)
{
	const size_t fs_cap_want = task->t_env->base.args->capacity;
	const size_t align_size = SILOFS_LSEG_SIZE_MAX;

	return (fs_cap_want / align_size) * align_size;
}

static int format_super(struct silofs_task_ctx *task)
{
	const size_t fs_cap = calc_aligned_fs_cap(task);

	return silofs_env_format_super(task->t_env, fs_cap);
}

static int appexec_resync_vmeta(struct silofs_task_ctx *task, bool drop)
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

static int
do_claim_reclaim(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_vaddr vaddr;
	const off_t voff_exp = 0;
	int err;

	err = silofs_claim_vspace(task, mtype, &vaddr);
	if (err) {
		log_err("vclaim failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	if (vaddr.off != voff_exp) {
		log_err("bad claim: mtype=%d exp=%ld got=%ld", mtype, voff_exp,
		        vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}
	drop_caches(task);
	err = silofs_reclaim_vspace(task, &vaddr);
	if (err) {
		log_err("bad reclaim: mtype=%d voff=%ld err=%d", mtype,
		        vaddr.off, err);
	}
	return 0;
}

static int retry_claim(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype) ||
		    (mtype == SILOFS_MTYPE_LSMAP)) {
			continue;
		}
		err = do_claim_reclaim(task, mtype);
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
require_spmaps_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_spleaf_info *sli = nullptr;

	silofs_vaddr_setup(&vaddr, mtype, 0);
	return silofs_require_spleaf_of(task, &vaddr, SILOFS_STG_COW, &sli);
}

static int
format_spmaps_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	int err;

	err = require_spmaps_of(task, mtype);
	if (err) {
		log_err("format spmaps failed: mtype=%d err=%d", mtype, err);
		return err;
	}
	err = flush_dirty(task);
	if (err) {
		return err;
	}
	log_dbg("format spmaps of: mtype=%d", mtype);
	return 0;
}

static int format_spmaps(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype)) {
			continue;
		}
		err = format_spmaps_of(task, mtype);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

static off_t vni_offset(const struct silofs_vnode_info *vni)
{
	const struct silofs_vaddr *vaddr = silofs_vni_vaddr(vni);

	return vaddr->off;
}

static int
claim_offset_zero(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_vnode_info *vni = nullptr;
	off_t off = -1;
	int err;

	err = silofs_spawn_vnode(task, nullptr, mtype, &vni);
	if (err) {
		log_err("failed to spawn: mtype=%d err=%d", mtype, err);
		return err;
	}
	off = vni_offset(vni);
	if (off != 0) {
		log_err("format zspace failed: mtype=%d off=%ld", mtype, off);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int format_nil_space(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype) ||
		    (mtype == SILOFS_MTYPE_LSMAP)) { /* TODO: revisit */
			continue;
		}
		err = claim_offset_zero(task, mtype);
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
spawn_rootdir(struct silofs_task_ctx *task, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp;

	silofs_inew_params_of(task, nullptr, S_IFDIR | 0755, 0, &inp);
	return silofs_spawn_inode(task, &inp, out_ii);
}

static int format_rootdir(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *root_ii = nullptr;
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

static int setup_mbr(struct silofs_task_ctx *task)
{
	return silofs_env_setup_fs_mbr(task->t_env);
}

static int
commit_mbr(struct silofs_task_ctx *task, struct silofs_baddr *out_baddr)
{
	return silofs_env_commit_fs_mbr(task->t_env, out_baddr);
}

static int appexec_format_meta(struct silofs_task_ctx *task,
                               struct silofs_baddr *out_baddr)
{
	int err;

	err = setup_mbr(task);
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
	err = commit_mbr(task, out_baddr);
	if (err) {
		return err;
	}
	drop_relax_caches(task);
	return 0;
}

static int
reload_fs(struct silofs_task_ctx *task, const struct silofs_baddr *baddr)
{
	int err;

	err = silofs_env_reload_fs_mbr(task->t_env, baddr);
	if (err) {
		return err;
	}
	err = reload_vmeta(task);
	if (err) {
		return err;
	}
	return 0;
}

static int
appexec_open_fs(struct silofs_task_ctx *task, const struct silofs_baddr *baddr)
{
	int err;

	err = reload_fs(task, baddr);
	if (!err) {
		drop_caches(task);
	}
	return err;
}

static int
appexec_fork_fs(struct silofs_task_ctx *task, struct silofs_mrefs *out_mrefs)
{
	int err;

	err = silofs_exec_forkfs(task, SILOFS_INO_ROOT, 0, out_mrefs);
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

static int shutdown_fs(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_repo_fsync_all(task->t_repo);
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

static int appexec_unload_fs(struct silofs_task_ctx *task)
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

static int
remove_mbr(struct silofs_task_ctx *task, const struct silofs_baddr *baddr)
{
	return silofs_env_unlink_mbr(task->t_env, baddr);
}

static int appexec_remove_fs(struct silofs_task_ctx *task,
                             const struct silofs_baddr *baddr)
{
	int err;

	err = reload_fs(task, baddr);
	if (err) {
		return err;
	}
	err = silofs_exec_unrefs(task);
	if (err) {
		return err;
	}
	err = remove_mbr(task, baddr);
	if (err) {
		return err;
	}
	err = shutdown_fs(task);
	if (err) {
		return err;
	}
	return 0;
}

static int appexec_sense_fs(struct silofs_task_ctx *task,
                            const struct silofs_baddr *baddr)
{
	int err;

	err = silofs_env_sense_mbr(task->t_env, baddr);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

static int appexec_archive_fs(struct silofs_task_ctx *task,
                              const struct silofs_baddr *fs_baddr,
                              struct silofs_baddr *out_ar_baddr)
{
	int err;

	err = reload_fs(task, fs_baddr);
	if (err) {
		return err;
	}
	err = silofs_exec_archive(task, out_ar_baddr);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

static int appexec_restore_fs(struct silofs_task_ctx *task,
                              const struct silofs_baddr *ar_mref,
                              struct silofs_baddr *out_fs_mref)
{
	int err;

	err = silofs_exec_restore(task, ar_mref, out_fs_mref);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_post_exec_fs(struct silofs_env *env)
{
	const struct silofs_fuseq *fuseq = env->base.fuseq;
	int ret = 0;

	if ((fuseq != nullptr) && fuseq->fq_got_init) {
		ret = fuseq->fq_got_destroy ? 0 : -SILOFS_ENOTDONE;
	}
	return ret;
}

static int do_map_task_creds(struct silofs_task_ctx *task)
{
	const struct silofs_cred *xcred = &task->t_auth.creds.host_cred;
	struct silofs_cred *icred = &task->t_auth.creds.fs_cred;

	return silofs_idsmap_map_uidgid(task->t_idsm, xcred->uid, xcred->gid,
	                                &icred->uid, &icred->gid);
}

static int map_task_creds(struct silofs_task_ctx *task)
{
	const struct silofs_idsmap *idsm = task->t_idsm;
	int err = 0;

	if (idsm->idm_usize || idsm->idm_gsize) {
		err = do_map_task_creds(task);
	}
	task->t_runnable = (err == 0);
	return err;
}

static int make_task(struct silofs_env *env, struct silofs_task_ctx *task)
{
	const struct silofs_env_args *args = env->base.args;

	silofs_task_init(task, env);
	silofs_task_set_ts(task, true);
	silofs_task_set_creds(task, args->uid, args->gid, args->umask);
	task->t_mbr_op = true;
	return map_task_creds(task);
}

static int term_task(struct silofs_task_ctx *task, int status)
{
	int err = 0;

	if (task->t_runnable) {
		err = silofs_task_submit(task, true);
	}
	silofs_task_fini(task);
	return status ? status : err;
}

static int
exec_open_fs(struct silofs_env *env, const struct silofs_baddr *baddr)
{
	struct silofs_task_ctx task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_open_fs(&task, baddr);
	}
	return term_task(&task, err);
}

static int exec_resync_vmeta(struct silofs_env *env, bool drop)
{
	struct silofs_task_ctx task;
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
	const struct silofs_env_args *args = env->base.args;
	struct silofs_fuseq *fuseq = env->base.fuseq;
	int err;

	err = silofs_fuseq_mount(fuseq, env, args->boot_args.mntdir);
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

	return (fuseq != nullptr) &&
	       silofs_env_hasflag(env, SILOFS_F_WITHFUSE);
}

int silofs_exec_fs(struct silofs_env *env)
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
	if (env->base.fuseq != nullptr) {
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
	const struct silofs_env_args *args = env->base.args;
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

static int
exec_format_meta(struct silofs_env *env, struct silofs_baddr *out_baddr)
{
	struct silofs_task_ctx task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_format_meta(&task, out_baddr);
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
	return 0;
}

static int do_format_fs(struct silofs_env *env, struct silofs_baddr *out_baddr)
{
	int err;

	err = check_format_fs(env);
	if (err) {
		return err;
	}
	err = exec_format_meta(env, out_baddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_format_fs(struct silofs_env *env,
                     struct silofs_blobid *out_fs_blobid)
{
	struct silofs_baddr baddr;
	int ret;

	silofs_env_lock(env);
	ret = do_format_fs(env, &baddr);
	silofs_env_unlock(env);
	encode_fs_blobid(&baddr, out_fs_blobid);
	return ret;
}

static int
exec_sense_fs(struct silofs_env *env, const struct silofs_baddr *baddr)
{
	struct silofs_task_ctx task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_sense_fs(&task, baddr);
	}
	return term_task(&task, err);
}

int silofs_sense_fs(struct silofs_env *env,
                    const struct silofs_blobid *fs_blobid)
{
	struct silofs_baddr baddr;
	int err;

	err = decode_fs_blobid(fs_blobid, &baddr);
	if (!err) {
		silofs_env_lock(env);
		err = exec_sense_fs(env, &baddr);
		silofs_env_unlock(env);
	}
	return err;
}

int silofs_sense_ar(struct silofs_env *env,
                    const struct silofs_blobid *ar_blobid)
{
	struct silofs_baddr baddr;
	int err;

	err = decode_ar_blobid(ar_blobid, &baddr);
	if (!err) {
		silofs_env_lock(env);
		err = exec_sense_fs(env, &baddr);
		silofs_env_unlock(env);
	}
	return err;
}

int silofs_open_fs(struct silofs_env *env, const struct silofs_blobid *blobid)
{
	struct silofs_baddr baddr;
	int err;

	err = decode_fs_blobid(blobid, &baddr);
	if (!err) {
		silofs_env_lock(env);
		err = exec_open_fs(env, &baddr);
		silofs_env_unlock(env);
	}
	return err;
}

static int exec_unload_fs(struct silofs_env *env)
{
	struct silofs_task_ctx task;
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

static int exec_fork_fs(struct silofs_env *env, struct silofs_mrefs *out_mrefs)
{
	struct silofs_task_ctx task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_fork_fs(&task, out_mrefs);
	}
	return term_task(&task, err);
}

int silofs_fork_fs(struct silofs_env *env,
                   struct silofs_blobid *out_main_blobid,
                   struct silofs_blobid *out_fork_blobid)
{
	struct silofs_mrefs mrefs;
	int err;

	silofs_env_lock(env);
	err = exec_fork_fs(env, &mrefs);
	silofs_env_unlock(env);
	encode_fs_blobid(&mrefs.main, out_main_blobid);
	encode_fs_blobid(&mrefs.fork, out_fork_blobid);
	return err;
}

static int
exec_reload_remove_fs(struct silofs_env *env, const struct silofs_baddr *baddr)
{
	struct silofs_task_ctx task;
	int err;

	err = make_task(env, &task);
	if (err) {
		goto out;
	}
	err = appexec_open_fs(&task, baddr);
	if (err) {
		goto out;
	}
	err = appexec_remove_fs(&task, baddr);
	if (err) {
		goto out;
	}
out:
	return term_task(&task, err);
}

int silofs_remove_fs(struct silofs_env *env,
                     const struct silofs_blobid *blobid)
{
	struct silofs_baddr baddr;
	int err;

	err = decode_fs_blobid(blobid, &baddr);
	if (!err) {
		silofs_env_lock(env);
		err = exec_reload_remove_fs(env, &baddr);
		silofs_env_unlock(env);
	}
	return err;
}

static int exec_inspect_fs(struct silofs_env *env,
                           const struct silofs_laddr_visitor *lvis)
{
	struct silofs_task_ctx task;
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
		.hook = view ? inspect_view : nullptr,
		.userp = nullptr,
	};
	int err;

	silofs_env_lock(env);
	err = exec_inspect_fs(env, &lvis);
	silofs_env_unlock(env);
	return err;
}

static int
exec_archive_fs(struct silofs_env *env, const struct silofs_baddr *fs_baddr,
                struct silofs_baddr *out_ar_baddr)
{
	struct silofs_task_ctx task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_archive_fs(&task, fs_baddr, out_ar_baddr);
	}
	return term_task(&task, err);
}

int silofs_archive_fs(struct silofs_env *env,
                      const struct silofs_blobid *fs_blobid,
                      struct silofs_blobid *out_ar_blobid)
{
	struct silofs_baddr fs_baddr;
	struct silofs_baddr ar_baddr;
	int err;

	err = decode_fs_blobid(fs_blobid, &fs_baddr);
	if (!err) {
		silofs_env_lock(env);
		err = exec_archive_fs(env, &fs_baddr, &ar_baddr);
		silofs_env_unlock(env);
		encode_ar_blobid(&ar_baddr, out_ar_blobid);
	}
	return err;
}

static int
exec_restore_fs(struct silofs_env *env, const struct silofs_baddr *ar_mref,
                struct silofs_baddr *out_fs_mref)
{
	struct silofs_task_ctx task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = appexec_restore_fs(&task, ar_mref, out_fs_mref);
	}
	return term_task(&task, err);
}

int silofs_restore_fs(struct silofs_env *env,
                      const struct silofs_blobid *ar_blobid,
                      struct silofs_blobid *out_fs_blobid)
{
	struct silofs_baddr ar_mref;
	struct silofs_baddr fs_mref;
	int err;

	err = decode_ar_blobid(ar_blobid, &ar_mref);
	if (!err) {
		silofs_env_lock(env);
		err = exec_restore_fs(env, &ar_mref, &fs_mref);
		silofs_env_unlock(env);
		encode_fs_blobid(&fs_mref, out_fs_blobid);
	}
	return err;
}

const struct silofs_env_args *silofs_get_env_args(const struct silofs_env *env)
{
	return env->base.args;
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
	err = check_endianess64(SILOFS_MBR_MAGIC, "@SILOFS@");
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

static int check_pre_init_lib(void)
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
	return 0;
}

static int do_init_lib(bool with_fips)
{
	int err;

	err = silofs_init_times();
	if (err) {
		return err;
	}
	err = silofs_init_gcrypt(with_fips);
	if (err) {
		return err;
	}
	return 0;
}

static bool g_initlib_once_done;

static bool init_with_fips(void)
{
	const char *name = "SILOFS_FIPS";
	const char *value = nullptr;
	size_t len = 0;
	bool ret = false;

	value = secure_getenv(name);
	len = silofs_str_length(value);
	if (len == 1) {
		ret = silofs_str_compare(value, "1", len);
	}
	return ret;
}

int silofs_init_once(void)
{
	int ret = 0;

	if (g_initlib_once_done) {
		goto out;
	}
	ret = check_pre_init_lib();
	if (ret != 0) {
		goto out;
	}
	ret = do_init_lib(init_with_fips());
	if (ret != 0) {
		goto out;
	}
	silofs_affirm_ondisk_format();
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
