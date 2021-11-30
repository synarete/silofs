/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/mpool.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/spclaim.h>
#include <silofs/fs/itable.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/fuseq.h>
#include <silofs/fs/exec.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define ROUND_TO_K(n)  SILOFS_ROUND_TO(n, SILOFS_KILO)

struct silofs_fs_core {
	struct silofs_qalloc    qalloc;
	struct silofs_mpool     mpool;
	struct silofs_cache     cache;
	struct silofs_crypto    crypto;
	struct silofs_repo      repo;
	struct silofs_fs_apex hyperi;
};

union silofs_fs_core_u {
	struct silofs_fs_core c;
	uint8_t dat[ROUND_TO_K(sizeof(struct silofs_fs_core))];
};

union silofs_fuseq_page {
	struct silofs_fuseq     fuseq;
	uint8_t page[SILOFS_PAGE_SIZE];
};

struct silofs_fs_env_obj {
	union silofs_fs_core_u   fs_core;
	struct silofs_fs_env     fs_env;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fs_env_obj *fse_obj_of(struct silofs_fs_env *fse)
{
	return container_of(fse, struct silofs_fs_env_obj, fs_env);
}

static const struct silofs_mdigest *
fse_mdigest(const struct silofs_fs_env *fse)
{
	return &fse->fs_crypto->md;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fse_init_commons(struct silofs_fs_env *fse)
{
	silofs_memzero(fse, sizeof(*fse));
	silofs_kivam_init(&fse->fs_kivam);
	silofs_passphrase_reset(&fse->fs_passph);
	fse->fs_args.uid = getuid();
	fse->fs_args.gid = getgid();
	fse->fs_args.pid = getpid();
	fse->fs_args.umask = 0022;
	fse->fs_signum = 0;
}

static int fse_init_qalloc(struct silofs_fs_env *fse)
{
	int err;
	size_t memsize = 0;
	const int mode = fse->fs_args.pedantic ? 1 : 0;
	struct silofs_qalloc *qalloc = &fse_obj_of(fse)->fs_core.c.qalloc;

	err = silofs_boot_mem(fse->fs_args.memwant, &memsize);
	if (err) {
		return err;
	}
	err = silofs_qalloc_init(qalloc, memsize, mode);
	if (err) {
		return err;
	}
	fse->fs_qalloc = qalloc;
	fse->fs_alif = &qalloc->alif;
	return 0;
}

static void fse_fini_qalloc(struct silofs_fs_env *fse)
{
	if (fse->fs_qalloc != NULL) {
		silofs_qalloc_fini(fse->fs_qalloc);
		fse->fs_qalloc = NULL;
		fse->fs_alif = NULL;
	}
}

static int fse_init_mpool(struct silofs_fs_env *fse)
{
	struct silofs_mpool *mpool = &fse_obj_of(fse)->fs_core.c.mpool;

	silofs_mpool_init(mpool, fse->fs_qalloc);
	fse->fs_mpool = mpool;
	return 0;
}

static void fse_fini_mpool(struct silofs_fs_env *fse)
{
	if (fse->fs_mpool != NULL) {
		silofs_assert_eq(fse->fs_mpool->mp_nbytes_alloc, 0);
		silofs_mpool_fini(fse->fs_mpool);
		fse->fs_mpool = NULL;
	}
}

static int fse_init_cache(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_qalloc *qalloc = fse->fs_qalloc;
	struct silofs_alloc_if *alif = &fse->fs_mpool->mp_alif;
	struct silofs_cache *cache = &fse_obj_of(fse)->fs_core.c.cache;

	err = silofs_cache_init(cache, qalloc, alif);
	if (!err) {
		fse->fs_cache = cache;
	}
	return err;
}

static void fse_fini_cache(struct silofs_fs_env *fse)
{
	if (fse->fs_cache != NULL) {
		silofs_cache_fini(fse->fs_cache);
		fse->fs_cache = NULL;
	}
}

static int fse_init_crypto(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_crypto *crypto = &fse_obj_of(fse)->fs_core.c.crypto;

	err = silofs_crypto_init(crypto);
	if (!err) {
		fse->fs_crypto = crypto;
	}
	return err;
}

static void fse_fini_crypto(struct silofs_fs_env *fse)
{
	if (fse->fs_crypto != NULL) {
		silofs_crypto_fini(fse->fs_crypto);
		fse->fs_crypto = NULL;
	}
}

static int fse_init_repo(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_repo *repo = &fse_obj_of(fse)->fs_core.c.repo;
	const struct silofs_fs_args *args = &fse->fs_args;

	err = silofs_repo_init(repo, fse->fs_cache,
	                       args->repodir, !args->rdonly);
	if (!err) {
		fse->fs_repo = repo;
	}
	return err;
}

static void fse_fini_repo(struct silofs_fs_env *fse)
{
	if (fse->fs_repo != NULL) {
		silofs_repo_fini(fse->fs_repo);
		fse->fs_repo = NULL;
	}
}

static int fse_init_hyper(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_fs_apex *apex = &fse_obj_of(fse)->fs_core.c.hyperi;

	err = silofs_apex_init(apex, fse->fs_repo, fse->fs_crypto);
	if (!err) {
		apex->ap_args = &fse->fs_args;
		fse->fs_apex = apex;
	}
	return err;
}

static void fse_fini_hyper(struct silofs_fs_env *fse)
{
	if (fse->fs_apex != NULL) {
		silofs_apex_fini(fse->fs_apex);
		fse->fs_apex = NULL;
	}
}

static union silofs_fuseq_page *fuseq_to_page(struct silofs_fuseq *fuseq)
{
	return container_of(fuseq, union silofs_fuseq_page, fuseq);
}

static int fse_init_fuseq(struct silofs_fs_env *fse)
{
	int err;
	void *mem;
	union silofs_fuseq_page *fuseq_pg = NULL;
	const size_t fuseq_pg_size = sizeof(*fuseq_pg);
	struct silofs_alloc_if *alif = &fse->fs_qalloc->alif;

	STATICASSERT_EQ(sizeof(*fuseq_pg), SILOFS_PAGE_SIZE);

	if (!fse->fs_args.with_fuseq) {
		return 0;
	}
	mem = silofs_allocate(alif, fuseq_pg_size);
	if (mem == NULL) {
		log_warn("failed to allocate fuseq: size=%lu", fuseq_pg_size);
		return -ENOMEM;
	}
	fuseq_pg = mem;
	err = silofs_fuseq_init(&fuseq_pg->fuseq, alif);
	if (err) {
		silofs_deallocate(alif, mem, fuseq_pg_size);
		return err;
	}
	fse->fs_fuseq = &fuseq_pg->fuseq;
	return 0;
}

static void fse_fini_fuseq(struct silofs_fs_env *fse)
{
	union silofs_fuseq_page *fuseq_pg = NULL;
	struct silofs_alloc_if *alif = &fse->fs_qalloc->alif;

	if (fse->fs_fuseq != NULL) {
		fuseq_pg = fuseq_to_page(fse->fs_fuseq);

		silofs_fuseq_fini(fse->fs_fuseq);
		fse->fs_fuseq = NULL;

		silofs_deallocate(alif, fuseq_pg, sizeof(*fuseq_pg));
	}
}

static int fse_check_args(const struct silofs_fs_args *args)
{
	int err;
	struct silofs_passphrase passph;

	err = silofs_passphrase_setup(&passph, args->passwd);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_apply_args(struct silofs_fs_env *fse,
                          const struct silofs_fs_args *args)
{
	int err;

	/* TODO: check more */
	err = silofs_passphrase_setup(&fse->fs_passph, args->passwd);
	if (err) {
		return err;
	}
	/* TODO: maybe strdup? */
	memcpy(&fse->fs_args, args, sizeof(fse->fs_args));
	return 0;
}

static int fse_init(struct silofs_fs_env *fse,
                    const struct silofs_fs_args *args)
{
	int err;

	fse_init_commons(fse);
	err = fse_apply_args(fse, args);
	if (err) {
		return err;
	}
	err = fse_init_qalloc(fse);
	if (err) {
		return err;
	}
	err = fse_init_mpool(fse);
	if (err) {
		return err;
	}
	err = fse_init_cache(fse);
	if (err) {
		return err;
	}
	err = fse_init_crypto(fse);
	if (err) {
		return err;
	}
	err = fse_init_repo(fse);
	if (err) {
		return err;
	}
	err = fse_init_hyper(fse);
	if (err) {
		return err;
	}
	err = fse_init_fuseq(fse);
	if (err) {
		return err;
	}
	return 0;
}

static void fse_fini_commons(struct silofs_fs_env *fse)
{
	silofs_kivam_fini(&fse->fs_kivam);
	silofs_passphrase_reset(&fse->fs_passph);
	fse->fs_apex = NULL;
}

static void fse_fini(struct silofs_fs_env *fse)
{
	fse_fini_fuseq(fse);
	fse_fini_hyper(fse);
	fse_fini_cache(fse);
	fse_fini_crypto(fse);
	fse_fini_repo(fse);
	fse_fini_mpool(fse);
	fse_fini_qalloc(fse);
	fse_fini_commons(fse);
}

int silofs_fse_new(const struct silofs_fs_args *args,
                   struct silofs_fs_env **out_fse)
{
	int err;
	void *mem = NULL;
	struct silofs_fs_env *fse = NULL;
	struct silofs_fs_env_obj *fse_obj = NULL;

	err = fse_check_args(args);
	if (err) {
		return err;
	}
	err = silofs_zmalloc(sizeof(*fse_obj), &mem);
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

static void fse_relax_cache(struct silofs_fs_env *fse, bool drop_cache)
{
	silofs_cache_relax(fse->fs_cache, SILOFS_F_BRINGUP);
	if (drop_cache) {
		silofs_cache_drop(fse->fs_cache);
	}
}

static struct silofs_sb_info *fse_sbi(const struct silofs_fs_env *fse)
{
	silofs_assert_not_null(fse->fs_apex);
	silofs_assert_not_null(fse->fs_apex->ap_sbi);

	return fse->fs_apex->ap_sbi;
}

static int fse_reload_rootdir(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_inode_info *ii = NULL;
	const ino_t ino = SILOFS_INO_ROOT;

	err = silofs_stage_inode(fse_sbi(fse), ino, SILOFS_STAGE_RDONLY, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o", ii_mode(ii));
		return -EFSCORRUPTED;
	}
	return 0;
}

static void fse_relax_drop_caches(struct silofs_fs_env *fse)
{
	fse_relax_cache(fse, true);
	silofs_drop_itable_cache(fse_sbi(fse));
}

static int fse_reload_meta(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_sb_info *sbi = fse_sbi(fse);

	err = silofs_sbi_reload_spmaps(sbi);
	if (err) {
		return err;
	}
	err = silofs_sbi_reload_itable(sbi);
	if (err) {
		return err;
	}
	err = fse_reload_rootdir(fse);
	if (err) {
		return err;
	}
	fse_relax_drop_caches(fse);
	err = fse_reload_rootdir(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_flush_dirty(const struct silofs_fs_env *fse)
{
	return silofs_repo_collect_flush(fse->fs_repo, SILOFS_F_NOW);
}

static void fse_drop_caches(const struct silofs_fs_env *fse)
{
	if (fse->fs_apex && fse->fs_apex->ap_sbi) {
		silofs_drop_itable_cache(fse->fs_apex->ap_sbi);
	}
	silofs_cache_drop(fse->fs_cache);
	silofs_burnstack();
}

static int fse_shut_super(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_fs_apex *apex = fse->fs_apex;

	if ((apex == NULL) || (apex->ap_sbi == NULL)) {
		return 0;
	}
	err = silofs_sbi_shut(apex->ap_sbi);
	if (err) {
		return err;
	}
	silofs_apex_bind_to_sbi(apex, NULL);
	return 0;
}

int silofs_fse_shut(struct silofs_fs_env *fse)
{
	int err;

	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	err = fse_shut_super(fse);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	fse_drop_caches(fse);
	return err;
}

static int fse_close_repo(struct silofs_fs_env *fse)
{
	return silofs_repo_close(fse->fs_repo);
}

int silofs_fse_term(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		return err;
	}
	err = fse_close_repo(fse);
	if (err) {
		return err;
	}
	silofs_burnstack();
	return 0;
}

static int silofs_fse_exec(struct silofs_fs_env *fse)
{
	int err;
	struct silofs_fuseq *fq = fse->fs_fuseq;
	const char *mount_point = fse->fs_args.mntdir;

	err = silofs_fuseq_mount(fq, fse->fs_apex, mount_point);
	if (!err) {
		err = silofs_fuseq_exec(fq);
	}
	silofs_fuseq_term(fq);
	return err;
}

void silofs_fse_halt(struct silofs_fs_env *fse, int signum)
{
	fse->fs_signum = signum;
	if (fse->fs_fuseq != NULL) {
		fse->fs_fuseq->fq_active = 0;
	}
}

int silofs_fse_sync_drop(struct silofs_fs_env *fse)
{
	int err;

	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	fse_drop_caches(fse);
	return 0;
}

void silofs_fse_stats(const struct silofs_fs_env *fse,
                      struct silofs_fs_stats *st)
{
	struct silofs_alloc_stat alst = { .nbytes_used = 0 };
	const struct silofs_cache *cache = fse->fs_cache;

	silofs_allocstat(fse->fs_alif, &alst);
	st->nalloc_bytes = alst.nbytes_used;
	st->ncache_ublocks = cache->c_ubi_lm.lm_htbl_sz;
	st->ncache_vblocks = cache->c_vbi_lm.lm_htbl_sz;
	st->ncache_unodes = cache->c_ui_lm.lm_htbl_sz;
	st->ncache_vnodes = cache->c_vi_lm.lm_htbl_sz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fse_derive_main_key(struct silofs_fs_env *fse)
{
	int err;
	const char *repodir = fse->fs_args.repodir;
	const struct silofs_mdigest *md = fse_mdigest(fse);
	const struct silofs_passphrase *pp = &fse->fs_passph;
	struct silofs_cipher_args cip_args = { .cipher_algo = 0 };

	if (!fse->fs_passph.passlen) {
		return 0; /* operation without passphrase */
	}
	/* XXX */
	silofs_default_cip_args(&cip_args);
	/*
	err = silofs_mbr_cipher_args(fse->fs_apex->ap_mbr, &cip_args);
	if (err) {
	        log_err("bad mbr: %s err=%d", repodir, err);
	}
	*/
	err = silofs_derive_kivam(&cip_args, pp, md, &fse->fs_kivam);
	if (err) {
		log_err("derive iv-key failed: %s err=%d", repodir, err);
		return err;
	}
	return 0;
}

static int fse_check_sb(const struct silofs_fs_env *fse,
                        const struct silofs_super_block *sb)
{
	int err;

	err = silofs_sb_check_root(sb);
	if (err) {
		return err;
	}
	err = silofs_sb_check_rand(sb, fse_mdigest(fse));
	if (err) {
		return err;
	}
	return 0;
}

static int fse_reload_super(struct silofs_fs_env *fse)
{
	struct silofs_sb_info *sbi = NULL;
	const struct silofs_uaddr *sb_uaddr = &fse->fs_apex->ap_sb_uaddr;
	int err;

	silofs_assert(!uaddr_isnull(sb_uaddr));

	err = silofs_apex_stage_super(fse->fs_apex, sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	err = fse_check_sb(fse, sbi->sb);
	if (err) {
		log_warn("bad super-block: err=%d", err);
		return err;
	}
	silofs_apex_bind_to_sbi(fse->fs_apex, sbi);
	return 0;
}

static int fse_lock_repo(const struct silofs_fs_env *fse)
{
	const struct silofs_fs_args *fs_args = &fse->fs_args;
	int err;

	if (fs_args->wlock) {
		err = silofs_repo_wlock(fse->fs_repo);
		if (err) {
			return err;
		}
	}
	if (fs_args->xlock) {
		err = silofs_repo_xlock(fse->fs_repo);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_fse_reopen_repo(struct silofs_fs_env *fse)
{
	struct silofs_mboot_info mbi;
	struct silofs_fs_apex *apex = fse->fs_apex;
	int err;

	err = silofs_repo_open(fse->fs_repo);
	if (err) {
		return err;
	}
	err = fse_lock_repo(fse);
	if (err) {
		return err;
	}
	err = silofs_mbi_init_by(&mbi, apex);
	if (err) {
		return err;
	}
	err = silofs_repo_load_mboot(apex->ap_repo, &mbi);
	if (err) {
		goto out;
	}
out:
	silofs_mbi_fini(&mbi);
	return err;
}

static int fse_load_mbr(const struct silofs_fs_env *fse)
{
	return silofs_apex_load_root_mbr(fse->fs_apex);
}

int silofs_fse_reopen_fs(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_reopen_repo(fse);
	if (err) {
		return err;
	}
	err = fse_load_mbr(fse);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_reload(struct silofs_fs_env *fse)
{
	int err;

	err = fse_derive_main_key(fse);
	if (err) {
		return err;
	}
	err = fse_reload_super(fse);
	if (err) {
		return err;
	}
	err = fse_reload_meta(fse);
	if (err) {
		return err;
	}
	silofs_burnstack();
	return 0;
}

int silofs_fse_verify(struct silofs_fs_env *fse)
{
	int err;
	int err2;

	err = silofs_fse_reopen_fs(fse);
	if (err) {
		return err;
	}
	err = fse_derive_main_key(fse);
	if (err) {
		goto out;
	}
	err = fse_reload_super(fse);
	if (err) {
		goto out;
	}
	err = fse_shut_super(fse);
	if (err) {
		goto out;
	}
	fse_relax_cache(fse, true);
out:
	err2 = fse_close_repo(fse);
	return err || err2;
}

static int fse_format_block_zero(const struct silofs_fs_env *fse)
{
	int err;
	loff_t off_bkz;
	struct silofs_vnode_info *vi = NULL;

	err = silofs_spawn_vnode(fse_sbi(fse), SILOFS_STYPE_DATABK, &vi);
	if (err) {
		log_err("failed to spawn block-zero: err=%d", err);
		return err;
	}
	off_bkz = vaddr_off(vi_vaddr(vi));
	if (off_bkz != 0) {
		log_err("bad offset for block-zero: off=%ld", off_bkz);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int fse_format_rootdir(const struct silofs_fs_env *fse,
                              const struct silofs_oper *op)
{
	int err;
	const mode_t mode = S_IFDIR | 0755;
	struct silofs_inode_info *root_ii = NULL;
	struct silofs_sb_info *sbi = fse_sbi(fse);
	const ino_t parent_ino = SILOFS_INO_NULL;

	err = silofs_spawn_inode(sbi, op, parent_ino, 0, mode, 0, &root_ii);
	if (err) {
		return err;
	}
	silofs_fixup_rootdir(root_ii);
	err = silofs_bind_rootdir(sbi, root_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_format_fs_meta(const struct silofs_fs_env *fse,
                              const struct silofs_oper *op)
{
	int err;
	struct silofs_sb_info *sbi = fse_sbi(fse);

	err = silofs_sbi_format_spmaps(sbi);
	if (err) {
		return err;
	}
	err = fse_format_block_zero(fse);
	if (err) {
		return err;
	}
	err = silofs_sbi_format_itable(sbi);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	err = fse_format_rootdir(fse, op);
	if (err) {
		return err;
	}
	silofs_burnstack();
	return 0;
}

static int fse_make_oper_self(struct silofs_fs_env *fse,
                              struct silofs_oper *op)
{
	silofs_memzero(op, sizeof(*op));

	op->op_ucred.uid = fse->fs_args.uid;
	op->op_ucred.gid = fse->fs_args.gid;
	op->op_ucred.pid = fse->fs_args.pid;
	op->op_ucred.umask = fse->fs_args.umask;
	op->op_unique = 0; /* TODO: make me a negative running sequence no */

	return silofs_ts_gettime(&op->op_xtime, true);
}

static int fse_format_super(struct silofs_fs_env *fse,
                            const struct silofs_oper *op)
{
	struct silofs_sb_info *sbi = NULL;
	const size_t capacity = fse->fs_apex->ap_args->capacity;
	int err;

	err = silofs_apex_spawn_super(fse->fs_apex, capacity, &sbi);
	if (err) {
		return err;
	}
	err = fse_check_sb(fse, sbi->sb);
	if (err) {
		log_err("internal sb format: err=%d", err);
		return err;
	}
	silofs_sbi_update_birth_time(sbi, op->op_xtime.tv_sec);
	silofs_apex_bind_to_sbi(fse->fs_apex, sbi);
	return 0;
}

static int fse_save_mbr(struct silofs_fs_env *fse)
{
	return silofs_apex_save_root_mbr(fse->fs_apex);
}

static int fse_format_repo(struct silofs_fs_env *fse)
{
	return silofs_repo_format(fse->fs_repo);
}

int silofs_fse_format_repo(struct silofs_fs_env *fse)
{
	struct silofs_oper op;
	int err;

	err = fse_make_oper_self(fse, &op);
	if (err) {
		return err;
	}
	err = fse_format_repo(fse);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_format_fs(struct silofs_fs_env *fse)
{
	struct silofs_oper op;
	int err;

	err = fse_make_oper_self(fse, &op);
	if (err) {
		return err;
	}
	err = silofs_fse_reopen_repo(fse);
	if (err) {
		return err;
	}
	err = fse_derive_main_key(fse);
	if (err) {
		return err;
	}
	err = fse_format_super(fse, &op);
	if (err) {
		return err;
	}
	err = fse_format_fs_meta(fse, &op);
	if (err) {
		return err;
	}
	err = silofs_fse_sync_drop(fse);
	if (err) {
		return err;
	}
	err = fse_save_mbr(fse);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_serve(struct silofs_fs_env *fse)
{
	const char *repodir = fse->fs_args.repodir;
	const char *mntdir = fse->fs_args.mntdir;
	int err = 0;
	int err2 = 0;

	if (!fse->fs_args.with_fuseq || (fse->fs_fuseq == NULL)) {
		return -EINVAL;
	}
	err = silofs_fse_reopen_fs(fse);
	if (err) {
		log_err("failed to reopen repo: %s %d", repodir, err);
		return err;
	}
	err = silofs_fse_reload(fse);
	if (err) {
		log_err("failed to reload: %s %d", repodir, err);
		goto out;
	}
	err = silofs_fse_exec(fse);
	if (err) {
		log_err("exec-fs error: %s %d", mntdir, err);
		/* no return -- do post-exec cleanups */
	}
	err = silofs_fse_shut(fse);
	if (err) {
		log_err("shut-fs error: %s %d", repodir, err);
		goto out;
	}
out:
	err2 = silofs_fse_term(fse);
	if (err2) {
		log_err("term-fs error: %s %d", fse->fs_args.mntdir, err2);
		goto out;
	}
	return err ? err : err2;
}
