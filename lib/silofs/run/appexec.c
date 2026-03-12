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
#include <sys/stat.h>

#include <silofs/ondisk.h>
#include <silofs/ioctls.h>
#include <silofs/appexec.h>
#include <silofs/infra.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/fuse.h>
#include "mbr.h"
#include "env.h"
#include "exec.h"
#include "walk.h"

static void relax_caches(struct silofs_task_ctx *task, bool now)
{
	silofs_env_relax_caches(task->env, //
	                        now ? SILOFS_CTLF_NOW : SILOFS_CTLF_IDLE);
}

static int flush_dirty(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
		return err;
	}
	err = silofs_destage_dirty(task);
	if (err) {
		log_err("failed to destage dirty: err=%d", err);
		return err;
	}
	return 0;
}

static void drop_caches(struct silofs_task_ctx *task)
{
	silofs_env_drop_caches(task->env);
}

static void drop_relax_caches(struct silofs_task_ctx *task)
{
	drop_caches(task);
	relax_caches(task, false);
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

static int appexec_reload_fs(struct silofs_task_ctx *task,
                             const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_exec_reload_repo(task);
	if (err) {
		goto out;
	}
	err = silofs_exec_reload_bs(task, mbref);
	if (err) {
		goto out;
	}
	err = silofs_exec_reload_fs(task);
	if (err) {
		goto out;
	}
	drop_caches(task);
out:
	return err;
}

static int
appexec_fork_fs(struct silofs_task_ctx *task, struct silofs_mbrefs *out_mbrefs)
{
	int err;

	err = silofs_exec_forkfs(task, SILOFS_INO_ROOT, 0, out_mbrefs);
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

	err = silofs_repo_fsync_all(task->repo);
	if (err) {
		return err;
	}
	drop_relax_caches(task);

	err = silofs_env_shut(task->env);
	if (err) {
		return err;
	}
	drop_relax_caches(task);

	return 0;
}

static int close_repo(struct silofs_task_ctx *task)
{
	return silofs_repo_close(task->repo);
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
	err = close_repo(task);
	if (err) {
		return err;
	}
	return 0;
}

static int
remove_mbr(struct silofs_task_ctx *task, const struct silofs_mbref *mbref)
{
	return silofs_env_unref_fs_mbr(task->env, mbref);
}

static int appexec_remove_fs(struct silofs_task_ctx *task,
                             const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_exec_reload_repo(task);
	if (err) {
		return err;
	}
	err = silofs_exec_reload_bs(task, mbref);
	if (err) {
		return err;
	}
	err = silofs_exec_reload_fs(task);
	if (err) {
		return err;
	}
	err = silofs_exec_unrefs(task);
	if (err) {
		return err;
	}
	err = remove_mbr(task, mbref);
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
                            const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_env_sense_mbr(task->env, mbref);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

static int appexec_preserve_fs(struct silofs_task_ctx *task,
                               const struct silofs_mbref *fs_mbref,
                               struct silofs_mbref *out_ar_mbref)
{
	int err;

	err = silofs_exec_reload_bs(task, fs_mbref);
	if (err) {
		return err;
	}
	err = silofs_exec_reload_fs(task);
	if (err) {
		return err;
	}
	err = silofs_exec_preserve(task, out_ar_mbref);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_post_exec_fs(struct silofs_env *env)
{
	const struct silofs_fuseq *fuseq = env->fuseq;
	int ret;

	ret = 0;
	if ((fuseq != nullptr) && fuseq->fq_got_init) {
		ret = fuseq->fq_got_destroy ? 0 : -SILOFS_ENOTDONE;
	}
	return ret;
}

static int do_map_task_creds(struct silofs_task_ctx *task)
{
	const struct silofs_cred *xcred = &task->auth.creds.host_cred;
	struct silofs_cred *icred       = &task->auth.creds.fs_cred;

	return silofs_idsmap_mapcreds(task->idsm, xcred->uid, xcred->gid,
	                              &icred->uid, &icred->gid);
}

static int map_task_creds(struct silofs_task_ctx *task)
{
	const struct silofs_idsmap *idsm = task->idsm;
	int err                          = 0;

	if (idsm->idm_usize || idsm->idm_gsize) {
		err = do_map_task_creds(task);
	}
	task->runnable = (err == 0);
	return err;
}

static int make_priv_task(struct silofs_env *env, struct silofs_task_ctx *task)
{
	silofs_task_init(task, env);
	silofs_task_update_times(task, true);
	silofs_task_update_creds(task, getuid(), getgid(), 0077);
	task->priv_op = true;
	return map_task_creds(task);
}

static int term_task(struct silofs_task_ctx *task, int status)
{
	int err = 0;

	if (task->runnable) {
		err = silofs_task_submit(task, true);
	}
	silofs_task_fini(task);
	return status ? status : err;
}

static int
exec_reload_fs(struct silofs_env *env, const struct silofs_mbref *mbref)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (!err) {
		err = appexec_reload_fs(&task, mbref);
	}
	return term_task(&task, err);
}

static int exec_resync_vmeta(struct silofs_env *env, bool drop)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (!err) {
		err = appexec_resync_vmeta(&task, drop);
	}
	return term_task(&task, err);
}

static int do_mount_and_exec(struct silofs_env *env, const char *mntdir)
{
	struct silofs_fuseq *fuseq = env->fuseq;
	int err;

	err = silofs_fuseq_mount(fuseq, mntdir);
	if (!err) {
		err = silofs_fuseq_exec(fuseq);
	}
	silofs_fuseq_term(fuseq);
	return err;
}

int silofs_exec_fs(struct silofs_env *env, const char *mntdir)
{
	struct silofs_fuseq *fuseq = env->fuseq;
	int err;

	if (fuseq == nullptr) {
		return -SILOFS_EINVAL;
	}
	err = silofs_fuseq_update(fuseq);
	if (err) {
		return err;
	}
	err = do_mount_and_exec(env, mntdir);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_halt_fs(struct silofs_env *env)
{
	silofs_env_lock(env);
	if (env->fuseq != nullptr) {
		env->fuseq->fq_active = 0;
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

void silofs_collect_stats(const struct silofs_env *env,
                          struct silofs_cache_stats *out_cstats)
{
	silofs_lcache_collect_stats(env->base.lcache, out_cstats);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_format_repo(struct silofs_env *env)
{
	struct stat st;
	const char *path  = env->repodir;
	const size_t len  = silofs_str_length(path);
	const int o_flags = O_DIRECTORY | O_RDONLY | O_PATH;
	int dfd           = -1;
	int err;

	if (!len || (len > SILOFS_REPOPATH_MAX)) {
		err = -SILOFS_EINVAL;
		goto out;
	}
	err = silofs_sys_open(env->repodir, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}
	err = silofs_sys_fstat(dfd, &st);
	if (err) {
		goto out;
	}
out:
	silofs_sys_closefd(&dfd);
	return err;
}

static int exec_format_repo(struct silofs_env *env)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (err) {
		goto out;
	}
	err = silofs_exec_format_repo(&task);
	if (err) {
		goto out;
	}
	log_dbg("format-repo done: %s", env->repodir);
out:
	return term_task(&task, err);
}

static int do_format_repo(struct silofs_env *env)
{
	int err;

	err = check_format_repo(env);
	if (err) {
		return err;
	}
	err = exec_format_repo(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_format_repo(struct silofs_env *env)
{
	int ret;

	silofs_env_lock(env);
	ret = do_format_repo(env);
	silofs_env_unlock(env);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_fs_capacity(size_t fscap)
{
	if ((fscap < SILOFS_CAPACITY_SIZE_MIN) ||
	    (fscap > SILOFS_CAPACITY_SIZE_MAX)) {
		log_err("illegal file-system capacity: %zu", fscap);
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int check_owner_ids(const struct silofs_env *env)
{
	const struct silofs_cred *owner_cred = &env->owner_cred;
	uid_t suid;
	gid_t sgid;
	int err;

	err = silofs_idsmap_mapcreds(env->base.idsmap, owner_cred->uid,
	                             owner_cred->gid, &suid, &sgid);
	if (err) {
		log_err("unable to map owner credentials: uid=%u gid=%u",
		        owner_cred->uid, owner_cred->gid);
		return err;
	}
	return 0;
}

static int
exec_format_fs(struct silofs_env *env, struct silofs_mbref *out_mbref)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (err) {
		goto out;
	}
	err = silofs_exec_reload_repo(&task);
	if (err) {
		goto out;
	}
	err = silofs_exec_format_ps(&task);
	if (err) {
		goto out;
	}
	err = silofs_exec_format_fs(&task, out_mbref);
	if (err) {
		goto out;
	}
	log_dbg("format-fs done: fscap=%zu", env->fscap);
out:
	return term_task(&task, err);
}

static int check_format_fs(struct silofs_env *env)
{
	int err;

	err = check_fs_capacity(env->fscap);
	if (err) {
		return err;
	}
	err = check_owner_ids(env);
	if (err) {
		return err;
	}
	return 0;
}

static void
encode_fsref(const struct silofs_mbref *mbref, struct silofs_fsref *out_fsref)
{
	silofs_fsref_export(out_fsref, mbref);
}

static void encode_fsrefs(const struct silofs_mbrefs *mbrefs,
                          struct silofs_fsrefs *out_fsrefs)
{
	silofs_fsrefs_export(out_fsrefs, mbrefs);
}

static int
decode_fsref(const struct silofs_fsref *fsref, struct silofs_mbref *out_mbref)
{
	return silofs_fsref_import(fsref, out_mbref);
}

static int do_format_fs(struct silofs_env *env, struct silofs_fsref *out_fsref)
{
	struct silofs_mbref mbref;
	int err;

	err = check_format_fs(env);
	if (err) {
		return err;
	}
	err = exec_format_fs(env, &mbref);
	if (err) {
		return err;
	}
	encode_fsref(&mbref, out_fsref);
	return 0;
}

int silofs_format_fs(struct silofs_env *env, struct silofs_fsref *out_fsref)
{
	int err;

	silofs_env_lock(env);
	err = do_format_fs(env, out_fsref);
	silofs_env_unlock(env);
	return err;
}

static int
exec_sense_fs(struct silofs_env *env, const struct silofs_mbref *mbref)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (err) {
		goto out;
	}
	err = silofs_exec_reload_repo(&task);
	if (err) {
		goto out;
	}
	err = appexec_sense_fs(&task, mbref);
out:
	return term_task(&task, err);
}

static int
do_sense_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	struct silofs_mbref mbref;
	int err;

	err = decode_fsref(fsref, &mbref);
	if (err) {
		return err;
	}
	err = exec_sense_fs(env, &mbref);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sense_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	int err;

	silofs_env_lock(env);
	err = do_sense_fs(env, fsref);
	silofs_env_unlock(env);
	return err;
}

static int
do_reload_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	struct silofs_mbref mbref;
	int err;

	err = decode_fsref(fsref, &mbref);
	if (err) {
		return err;
	}
	err = exec_reload_fs(env, &mbref);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_reload_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	int err;

	silofs_env_lock(env);
	err = do_reload_fs(env, fsref);
	silofs_env_unlock(env);
	return err;
}

static int exec_unload_fs(struct silofs_env *env)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (!err) {
		err = appexec_unload_fs(&task);
	}
	return term_task(&task, err);
}

int silofs_unload_fs(struct silofs_env *env)
{
	int err;

	silofs_env_lock(env);
	err = exec_unload_fs(env);
	silofs_env_unlock(env);
	return err;
}

static int
exec_fork_fs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (!err) {
		err = appexec_fork_fs(&task, out_mbrefs);
	}
	return term_task(&task, err);
}

static int do_fork_fs(struct silofs_env *env, struct silofs_fsrefs *out_fsrefs)
{
	struct silofs_mbrefs mbrefs;
	int err;

	err = exec_fork_fs(env, &mbrefs);
	if (err) {
		return err;
	}
	encode_fsrefs(&mbrefs, out_fsrefs);
	return 0;
}

int silofs_fork_fs(struct silofs_env *env, struct silofs_fsrefs *out_fsrefs)
{
	int err;

	silofs_env_lock(env);
	err = do_fork_fs(env, out_fsrefs);
	silofs_env_unlock(env);
	return err;
}

static int
exec_reload_remove_fs(struct silofs_env *env, const struct silofs_mbref *mbref)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (err) {
		goto out;
	}
	err = silofs_exec_reload_repo(&task);
	if (err) {
		return err;
	}
	err = appexec_reload_fs(&task, mbref);
	if (err) {
		goto out;
	}
	err = appexec_remove_fs(&task, mbref);
	if (err) {
		goto out;
	}
out:
	return term_task(&task, err);
}

static int
do_remove_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	struct silofs_mbref mbref;
	int err;

	err = decode_fsref(fsref, &mbref);
	if (err) {
		return err;
	}
	err = exec_reload_remove_fs(env, &mbref);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_remove_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	int err;

	silofs_env_lock(env);
	err = do_remove_fs(env, fsref);
	silofs_env_unlock(env);
	return err;
}

static int exec_inspect_fs(struct silofs_env *env,
                           const struct silofs_laddr_visitor *lvis)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (err) {
		goto out;
	}
	err = silofs_exec_reload_repo(&task);
	if (err) {
		goto out;
	}
	err = silofs_exec_walkfs(&task, lvis);
out:
	return term_task(&task, err);
}

static int
inspect_view(void *ctx, const struct silofs_laddr *laddr, size_t len)
{
	/* FIXME */
	silofs_unused(laddr);
	silofs_unused(len);
	silofs_unused(ctx);
	return 0;
}

int silofs_inspect_fs(struct silofs_env *env, bool view)
{
	const struct silofs_laddr_visitor lvis = {
		.hook  = view ? inspect_view : nullptr,
		.userp = nullptr,
	};
	int err;

	silofs_env_lock(env);
	err = exec_inspect_fs(env, &lvis);
	silofs_env_unlock(env);
	return err;
}

static int
exec_preserve_fs(struct silofs_env *env, const struct silofs_mbref *fs_mbref,
                 struct silofs_mbref *out_ar_mbref)
{
	struct silofs_task_ctx task;
	int err;

	err = make_priv_task(env, &task);
	if (err) {
		goto out;
	}
	err = silofs_exec_reload_repo(&task);
	if (err) {
		goto out;
	}
	err = appexec_preserve_fs(&task, fs_mbref, out_ar_mbref);
out:
	return term_task(&task, err);
}

static int
do_preserve_fs(struct silofs_env *env, const struct silofs_fsref *fsref,
               struct silofs_fsref *out_fsref)
{
	struct silofs_mbref mbref[2];
	int err;

	err = decode_fsref(fsref, &mbref[0]);
	if (err) {
		return err;
	}
	err = exec_preserve_fs(env, &mbref[0], &mbref[1]);
	if (err) {
		return err;
	}
	encode_fsref(&mbref[1], out_fsref);
	return 0;
}

int silofs_preserve_fs(struct silofs_env *env,
                       const struct silofs_fsref *fsref,
                       struct silofs_fsref *out_fsref)
{
	int err;

	silofs_env_lock(env);
	err = do_preserve_fs(env, fsref, out_fsref);
	silofs_env_unlock(env);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int errno_or_errnum(int errnum)
{
	return (errno > 0) ? -errno : -abs(errnum);
}

static int check_endianess32(uint32_t val, const char *str)
{
	char buf[16]          = "";
	const uint32_t val_le = htole32(val);

	for (size_t i = 0; i < 4; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess64(uint64_t val, const char *str)
{
	char buf[16]          = "";
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
	const long page_size_min  = SILOFS_PAGE_SIZE_MIN;
	const long page_shift_min = SILOFS_PAGE_SHIFT_MIN;
	const long page_shift_max = SILOFS_PAGE_SHIFT_MAX;
	const long cl_size_min    = SILOFS_CACHELINE_SIZE_MIN;
	const long cl_size_max    = SILOFS_CACHELINE_SIZE_MAX;
	long page_shift           = 0;
	long val;

	errno = 0;
	val   = silofs_sc_phys_pages();
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

	silofs_validate_ondisk_format();

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

static bool has_env_var(const char *name, const char *valwant)
{
	const char *val = secure_getenv(name);

	return silofs_str_isequal(val, valwant);
}

static int init_gcrypt(void)
{
	const bool with_fips = has_env_var("SILOFS_FIPS", "1");

	return silofs_init_gcrypt(with_fips);
}

static void init_panic(void)
{
	if (has_env_var("SILOFS_PANIC_MODE_WAIT", "1")) {
		silofs_panic_mode = SILOFS_PANIC_MODE_WAIT;
	}
}

static int do_init_lib(void)
{
	int err;

	err = silofs_init_times();
	if (err) {
		return err;
	}
	err = init_gcrypt();
	if (err) {
		return err;
	}
	init_panic();
	return 0;
}

static bool g_initlib_once_done;

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
	ret = do_init_lib();
	if (ret != 0) {
		goto out;
	}
	g_initlib_once_done = true;
out:
	return ret;
}

void silofs_getversions(struct silofs_versions *out_vers)
{
	out_vers->silofs_version = silofs_version.string;
	out_vers->gcrypt_version = silofs_gcrypt_version();
	out_vers->zstd_version   = silofs_zstd_version();
}

void silofs_getfsmeta(struct silofs_fsmeta *out_fsmeta)
{
	silofs_fsmeta_setup(out_fsmeta);
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

int silofs_mkpasswd(struct silofs_password *pw, const char *s)
{
	return silofs_password_setup(pw, s);
}
