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
#include "uber.h"
#include "lnodes.h"
#include "lcache.h"
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

	return silofs_xref_to_caddr_with(xref, SILOFS_CTYPE_UBER, &caddr);
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

static int map_creds_of(struct silofs_task *task)
{
	const struct silofs_idsmap *idsm = silofs_task_idsmap(task);
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
	const struct silofs_args *args = env->base.args;
	int err;

	silofs_task_init(task, env);
	silofs_task_set_ts(task, true);
	silofs_task_set_creds(task, args->uid, args->gid, args->umask);
	task->t_uber_op = true;
	err = map_creds_of(task);
	task->t_runnable = (err == 0);
	return err;
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
		err = silofs_appexec_reload_fs(&task);
	}
	return term_task(&task, err);
}

static int exec_resync_vmeta(struct silofs_env *env, bool drop)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = silofs_appexec_resync_vmeta(&task, drop);
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
	int cnt = 3;
	int err = 0;

	silofs_env_lock(env);
	while ((cnt-- > 0) && !err) {
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
	err = exec_resync_vmeta(env, false);
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

static int exec_retry_vclaim(struct silofs_env *env)
{
	struct silofs_task task;
	int err;

	err = make_task(env, &task);
	if (!err) {
		err = silofs_appexec_retry_claim(&task);
	}
	return term_task(&task, err);
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
		err = exec_resync_vmeta(env, true);
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

	silofs_inew_params_of(task, NULL, S_IFDIR | 0755, 0, &inp);
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
		err = exec_resync_vmeta(env, true);
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
	const struct silofs_args *args = env->base.args;
	const size_t cap_want = args->capacity;
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

static size_t calc_aligned_fs_cap(size_t cap_want)
{
	const size_t align_size = SILOFS_LSEG_SIZE_MAX;

	return (cap_want / align_size) * align_size;
}

static int format_umeta(struct silofs_env *env)
{
	const struct silofs_args *args = env->base.args;
	size_t fs_cap;
	int err;

	err = check_want_capacity(env);
	if (err) {
		return err;
	}
	fs_cap = calc_aligned_fs_cap(args->capacity);
	err = silofs_env_format_super(env, fs_cap);
	if (err) {
		return err;
	}
	err = exec_resync_vmeta(env, false);
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
	err = exec_retry_vclaim(env);
	if (err) {
		return err;
	}
	err = format_zero_vspace(env);
	if (err) {
		return err;
	}
	err = exec_resync_vmeta(env, true);
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

static int require_uber_caddr(const struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };

	return silofs_env_uber_caddr(env, &caddr);
}

static int require_no_uber_caddr(const struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_uber_caddr(env, &caddr);
	return err ? 0 : -SILOFS_EEXIST;
}

static int require_pack_caddr(const struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };

	return silofs_env_pack_caddr(env, &caddr);
}

static int do_format_fs(struct silofs_env *env)
{
	int err;

	err = require_no_uber_caddr(env);
	if (err) {
		return err;
	}
	err = silofs_env_format_bstore(env);
	if (err) {
		return err;
	}
	err = silofs_env_format_uber(env);
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
	err = silofs_env_commit_uber(env);
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

	err = require_uber_caddr(env);
	if (err) {
		return err;
	}
	err = silofs_env_sense_uber(env);
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
		err = silofs_appexec_unload_fs(&task);
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
		err = silofs_appexec_fork_fs(&task);
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
	err = silofs_appexec_reload_fs(&task);
	if (err) {
		goto out;
	}
	err = silofs_appexec_remove_fs(&task);
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

static int inspect_view(void *ctx, const struct silofs_laddr *laddr)
{
	struct silofs_strbuf sbuf;

	silofs_laddr_to_ascii(laddr, &sbuf);
	silofs_log_info("%s", sbuf.str);
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

	err = require_uber_caddr(env);
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
	ret = silofs_env_uber_caddr(env, &caddr);
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
		err = silofs_env_set_uber_caddr(env, &caddr);
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
	err = check_endianess64(SILOFS_UBER_MAGIC, "@SILOFS@");
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
