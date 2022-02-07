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
#include <silofs/fs/opers.h>
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
	struct silofs_crypto    crypto;
	struct silofs_repo      main_repo;
	struct silofs_repo      cold_repo;
	struct silofs_fs_apex   apex;
};

union silofs_fs_core_u {
	struct silofs_fs_core c;
	uint8_t dat[ROUND_TO_K(sizeof(struct silofs_fs_core))];
};

union silofs_fuseq_page {
	struct silofs_fuseq     fuseq;
	uint8_t page[4096];
};

struct silofs_fs_env_obj {
	union silofs_fs_core_u  fs_core;
	struct silofs_fs_env    fs_env;
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
	struct silofs_qalloc *qalloc = &fse_obj_of(fse)->fs_core.c.qalloc;
	size_t memsize = 0;
	int mode;
	int err;

	err = silofs_boot_mem(fse->fs_args.memwant, &memsize);
	if (err) {
		return err;
	}
	mode = fse->fs_args.pedantic ? 1 : 0;
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

static int fse_init_crypto(struct silofs_fs_env *fse)
{
	struct silofs_crypto *crypto = &fse_obj_of(fse)->fs_core.c.crypto;
	int err;

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

static size_t fse_repo_memsz_hint(const struct silofs_fs_env *fse)
{
	return fse->fs_qalloc->alst.memsz_data;
}

static int fse_init_main_repo(struct silofs_fs_env *fse)
{
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	const struct silofs_fs_args *args = &fse->fs_args;
	struct silofs_repo *repo = NULL;
	size_t msz_hint;
	int err;

	if (!args->main_repodir) {
		goto out;
	}
	repo = &fse_obj->fs_core.c.main_repo;
	msz_hint = fse_repo_memsz_hint(fse);
	err = silofs_repo_init(repo, fse->fs_alif, fse->fs_crypto,
	                       args->main_repodir, msz_hint, !args->rdonly);
	if (err) {
		return err;
	}
out:
	fse->fs_main_repo = repo;
	return 0;
}

static void fse_fini_main_repo(struct silofs_fs_env *fse)
{
	if (fse->fs_main_repo != NULL) {
		silofs_repo_fini(fse->fs_main_repo);
		fse->fs_main_repo = NULL;
	}
}

static int fse_init_cold_repo(struct silofs_fs_env *fse)
{
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	const struct silofs_fs_args *args = &fse->fs_args;
	struct silofs_repo *repo = NULL;
	int err;

	if (!args->cold_repodir) {
		goto out;
	}
	repo = &fse_obj->fs_core.c.cold_repo;
	err = silofs_repo_init(repo, fse->fs_alif, fse->fs_crypto,
	                       args->cold_repodir, fse_repo_memsz_hint(fse),
	                       !args->rdonly);
	if (err) {
		return err;
	}
out:
	fse->fs_cold_repo = repo;
	return 0;
}

static void fse_fini_cold_repo(struct silofs_fs_env *fse)
{
	if (fse->fs_cold_repo != NULL) {
		silofs_repo_fini(fse->fs_cold_repo);
		fse->fs_cold_repo = NULL;
	}
}

static int fse_init_repos(struct silofs_fs_env *fse)
{
	int err;

	err = fse_init_main_repo(fse);
	if (err) {
		return err;
	}
	err = fse_init_cold_repo(fse);
	if (err) {
		return err;
	}
	return 0;
}

static void fse_fini_repos(struct silofs_fs_env *fse)
{
	fse_fini_main_repo(fse);
	fse_fini_cold_repo(fse);
}

static int fse_init_apex(struct silofs_fs_env *fse)
{
	struct silofs_fs_apex *apex = &fse_obj_of(fse)->fs_core.c.apex;
	int err;

	err = silofs_apex_init(apex, fse->fs_alif, fse->fs_crypto,
	                       fse->fs_main_repo, fse->fs_cold_repo);
	if (!err) {
		apex->ap_args = &fse->fs_args;
		fse->fs_apex = apex;
	}
	return err;
}

static void fse_fini_apex(struct silofs_fs_env *fse)
{
	if (fse->fs_apex != NULL) {
		silofs_apex_fini(fse->fs_apex);
		fse->fs_apex = NULL;
	}
}

static union silofs_fuseq_page *fuseq_to_page(struct silofs_fuseq *fuseq)
{
	const union silofs_fuseq_page *fqp = NULL;

	STATICASSERT_EQ(sizeof(*fqp), SILOFS_PAGE_SIZE_MIN);

	fqp = container_of(fuseq, union silofs_fuseq_page, fuseq);
	return unconst(fqp);
}

static int fse_init_fuseq(struct silofs_fs_env *fse)
{
	union silofs_fuseq_page *fqp = NULL;
	const size_t fuseq_pg_size = sizeof(*fqp);
	struct silofs_alloc_if *alif = &fse->fs_qalloc->alif;
	void *mem = NULL;
	int err;

	if (!fse->fs_args.withfuse) {
		return 0;
	}
	mem = silofs_allocate(alif, fuseq_pg_size);
	if (mem == NULL) {
		log_warn("failed to allocate fuseq: size=%lu", fuseq_pg_size);
		return -ENOMEM;
	}
	fqp = mem;
	err = silofs_fuseq_init(&fqp->fuseq, alif);
	if (err) {
		silofs_deallocate(alif, mem, fuseq_pg_size);
		return err;
	}
	fse->fs_fuseq = &fqp->fuseq;
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
	struct silofs_passphrase passph;
	int err;

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
	err = fse_init_crypto(fse);
	if (err) {
		return err;
	}
	err = fse_init_repos(fse);
	if (err) {
		return err;
	}
	err = fse_init_apex(fse);
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
	fse_fini_apex(fse);
	fse_fini_crypto(fse);
	fse_fini_repos(fse);
	fse_fini_qalloc(fse);
	fse_fini_commons(fse);
}

int silofs_fse_new(const struct silofs_fs_args *args,
                   struct silofs_fs_env **out_fse)
{
	struct silofs_fs_env *fse = NULL;
	struct silofs_fs_env_obj *fse_obj = NULL;
	void *mem = NULL;
	int err;

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

static void fse_drop_caches(const struct silofs_fs_env *fse)
{
	if (fse->fs_apex && fse->fs_apex->ap_sbi) {
		silofs_drop_itable_cache(fse->fs_apex->ap_sbi);
	}
	if (fse->fs_main_repo) {
		silofs_repo_drop_cache(fse->fs_main_repo);
	}
	if (fse->fs_cold_repo) {
		silofs_repo_drop_cache(fse->fs_cold_repo);
	}
	silofs_burnstack();
}

static void fse_relax_cache(struct silofs_fs_env *fse, bool drop_cache)
{
	const int flags = SILOFS_F_BRINGUP;

	if (fse->fs_main_repo) {
		silofs_repo_relax_cache(fse->fs_main_repo, flags);
	}
	if (fse->fs_cold_repo) {
		silofs_repo_relax_cache(fse->fs_cold_repo, flags);
	}
	if (drop_cache) {
		fse_drop_caches(fse);
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
	struct silofs_inode_info *ii = NULL;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

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
	struct silofs_sb_info *sbi = fse_sbi(fse);
	int err;

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
	return silofs_repo_collect_flush(fse->fs_main_repo, SILOFS_F_NOW);
}

static int fse_shut_apex(struct silofs_fs_env *fse)
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
	silofs_apex_shut(apex);
	return 0;
}

int silofs_fse_shut(struct silofs_fs_env *fse)
{
	int err;

	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	err = fse_shut_apex(fse);
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

int silofs_fse_close_repos(struct silofs_fs_env *fse)
{
	int err;

	if (fse->fs_cold_repo != NULL) {
		err = silofs_repo_close(fse->fs_cold_repo);
		if (err) {
			return err;
		}
	}
	if (fse->fs_main_repo != NULL) {
		err = silofs_repo_close(fse->fs_main_repo);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_fse_term(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		return err;
	}
	err = silofs_fse_close_repos(fse);
	if (err) {
		return err;
	}
	silofs_burnstack();
	return 0;
}

static int silofs_fse_exec(struct silofs_fs_env *fse)
{
	struct silofs_fuseq *fq = fse->fs_fuseq;
	const char *mount_point = fse->fs_args.mntdir;
	int err;

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
	const struct silofs_cache *cache = NULL;

	silofs_memzero(st, sizeof(*st));
	silofs_allocstat(fse->fs_alif, &alst);
	st->nalloc_bytes = alst.nbytes_used;
	if (fse->fs_main_repo != NULL) {
		cache = &fse->fs_main_repo->re_cache;
		st->ncache_ublocks += cache->c_ubi_lm.lm_htbl_sz;
		st->ncache_vblocks += cache->c_vbi_lm.lm_htbl_sz;
		st->ncache_unodes += cache->c_ui_lm.lm_htbl_sz;
		st->ncache_vnodes += cache->c_vi_lm.lm_htbl_sz;
	}
	if (fse->fs_cold_repo != NULL) {
		cache = &fse->fs_cold_repo->re_cache;
		st->ncache_ublocks += cache->c_ubi_lm.lm_htbl_sz;
		st->ncache_vblocks += cache->c_vbi_lm.lm_htbl_sz;
		st->ncache_unodes += cache->c_ui_lm.lm_htbl_sz;
		st->ncache_vnodes += cache->c_vi_lm.lm_htbl_sz;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fse_derive_main_key(struct silofs_fs_env *fse)
{
	struct silofs_cipher_args cip_args = { .cipher_algo = 0 };
	const struct silofs_mdigest *md = fse_mdigest(fse);
	const struct silofs_passphrase *pp = &fse->fs_passph;
	int err;

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
		log_err("derive iv-key failed: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_check_sb(const struct silofs_fs_env *fse,
                        const struct silofs_super_block *sb)
{
	bool fossil;
	int err;

	err = silofs_sb_check_root(sb);
	if (err) {
		return err;
	}
	fossil = silofs_sb_test_flags(sb, SILOFS_SUPERF_FOSSIL);
	if (fossil && !fse->fs_args.rdonly) {
		return -EROFS;
	}
	return 0;
}

static int fse_reload_bootsec(const struct silofs_fs_env *fse,
                              struct silofs_bootsec *out_bsec)
{
	struct silofs_namestr name;
	struct silofs_fs_apex *apex = fse->fs_apex;
	int err;

	err = silofs_apex_lock_boot(apex);
	if (err) {
		return err;
	}
	err = silofs_apex_boot_name(apex, &name);
	if (err) {
		goto out_err;
	}
	err = silofs_apex_load_boot(apex, &name, out_bsec);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_apex_unlock_boot(apex);
	return err;
}

static int fse_reload_super(struct silofs_fs_env *fse)
{
	struct silofs_bootsec bsec;
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = fse_reload_bootsec(fse, &bsec);
	if (err) {
		return err;
	}
	err = silofs_apex_stage_super(fse->fs_apex, &bsec.sb_uaddr, &sbi);
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

int silofs_fse_open_repos(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_repo_open(fse->fs_main_repo);
	if (err) {
		return err;
	}
	if (fse->fs_cold_repo == NULL) {
		return 0;
	}
	err = silofs_repo_open(fse->fs_cold_repo);
	if (err) {
		return err;
	}
	return err;
}

int silofs_fse_reopen(struct silofs_fs_env *fse)
{
	struct silofs_bootsec bsec;
	int err;

	err = silofs_fse_open_repos(fse);
	if (err) {
		return err;
	}
	err = fse_reload_bootsec(fse, &bsec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_reload(struct silofs_fs_env *fse)
{
	int err;

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

	err = silofs_fse_reopen(fse);
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
	err = fse_shut_apex(fse);
	if (err) {
		goto out;
	}
	fse_relax_cache(fse, true);
out:
	err2 = silofs_fse_close_repos(fse);
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
                              const struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_inode_info *root_ii = NULL;
	struct silofs_sb_info *sbi = fse_sbi(fse);
	const ino_t parent_ino = SILOFS_INO_NULL;
	const struct silofs_creds *creds = &fs_ctx->fsc_oper.op_creds;
	const mode_t mode = S_IFDIR | 0755;
	int err;

	err = silofs_spawn_inode(sbi, creds, parent_ino, 0, mode, 0, &root_ii);
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
                              const struct silofs_fs_ctx *fsc)
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
	err = fse_format_rootdir(fse, fsc);
	if (err) {
		return err;
	}
	silofs_burnstack();
	return 0;
}

static int fse_make_self_ctx(struct silofs_fs_env *fse,
                             struct silofs_fs_ctx *fs_ctx)
{
	silofs_memzero(fs_ctx, sizeof(*fs_ctx));

	fs_ctx->fsc_apex = fse->fs_apex;
	fs_ctx->fsc_oper.op_creds.ucred.uid = fse->fs_args.uid;
	fs_ctx->fsc_oper.op_creds.ucred.gid = fse->fs_args.gid;
	fs_ctx->fsc_oper.op_creds.ucred.pid = fse->fs_args.pid;
	fs_ctx->fsc_oper.op_creds.ucred.umask = fse->fs_args.umask;
	fs_ctx->fsc_oper.op_unique = 0; /* TODO: negative running sequence */

	return silofs_ts_gettime(&fs_ctx->fsc_oper.op_creds.xtime, true);
}

static int fse_format_super(struct silofs_fs_env *fse,
                            const struct silofs_fs_ctx *fs_ctx)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_fs_apex *apex = fse->fs_apex;
	const size_t cap_want = apex->ap_args->capacity;
	const time_t btime = fs_ctx->fsc_oper.op_creds.xtime.tv_sec;
	size_t capacity = 0;
	int err;

	err = silofs_calc_fs_capacity(cap_want, &capacity);
	if (err) {
		log_err("illegal capacity: cap=%lu err=%d", cap_want, err);
		return err;
	}
	err = silofs_apex_spawn_super(fse->fs_apex, capacity, &sbi);
	if (err) {
		return err;
	}
	err = fse_check_sb(fse, sbi->sb);
	if (err) {
		log_err("internal sb format: err=%d", err);
		return err;
	}
	silofs_sbi_update_birth_time(sbi, btime);
	silofs_apex_bind_to_sbi(apex, sbi);
	return 0;
}

static int fse_save_main_bootsec(struct silofs_fs_env *fse)
{
	struct silofs_bootsec bsec;
	struct silofs_namestr name;
	const struct silofs_fs_apex *apex = fse->fs_apex;
	const struct silofs_sb_info *sbi = apex->ap_sbi;

	silofs_apex_main_fsname(apex, &name);
	silofs_bootsec_setup(&bsec, sbi_uaddr(sbi));
	return silofs_apex_save_boot(apex, &bsec, &name);
}

static int fse_format_main_repo(struct silofs_fs_env *fse)
{
	struct silofs_repo *repo = fse->fs_main_repo;

	return repo ? silofs_repo_format(repo) : 0;
}

static int fse_format_cold_repo(struct silofs_fs_env *fse)
{
	struct silofs_repo *repo = fse->fs_cold_repo;

	return repo ? silofs_repo_format(repo) : 0;
}

int silofs_fse_format_repos(struct silofs_fs_env *fse)
{
	int err;

	err = fse_format_main_repo(fse);
	if (err) {
		return err;
	}
	err = fse_format_cold_repo(fse);
	if (err) {
		return err;
	}
	err = silofs_fse_close_repos(fse);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_format_fs(struct silofs_fs_env *fse)
{
	struct silofs_fs_ctx fs_ctx;
	int err;

	err = fse_make_self_ctx(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = silofs_fse_open_repos(fse);
	if (err) {
		return err;
	}
	err = fse_format_super(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = fse_format_fs_meta(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	err = fse_save_main_bootsec(fse);
	if (err) {
		return err;
	}
	fse_drop_caches(fse);
	return 0;
}

int silofs_fse_serve(struct silofs_fs_env *fse)
{
	int err = 0;
	int err2 = 0;

	if (!fse->fs_args.withfuse || (fse->fs_fuseq == NULL)) {
		return -EINVAL;
	}
	err = silofs_fse_reopen(fse);
	if (err) {
		log_err("failed to reopen repo: %s err=%d",
		        fse->fs_args.main_repodir, err);
		return err;
	}
	err = silofs_fse_reload(fse);
	if (err) {
		log_err("failed to reload: %s err=%d",
		        fse->fs_args.main_repodir, err);
		goto out;
	}
	err = silofs_fse_exec(fse);
	if (err) {
		log_err("exec-fs error: %s err=%d",
		        fse->fs_args.mntdir, err);
		/* no return -- do post-exec cleanups */
	}
	err = silofs_fse_shut(fse);
	if (err) {
		log_err("shut-fs error: %s err=%d",
		        fse->fs_args.main_repodir, err);
		goto out;
	}
out:
	err2 = silofs_fse_term(fse);
	if (err2) {
		log_err("term-fs error: %s err=%d",
		        fse->fs_args.mntdir, err2);
		goto out;
	}
	return err ? err : err2;
}

static int fse_archive_fs(struct silofs_fs_env *fse)
{
	struct silofs_fs_ctx fs_ctx;
	const char *src_name = fse->fs_args.main_name;
	const char *dst_name = fse->fs_args.cold_name;
	int err;

	err = fse_make_self_ctx(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = silofs_fs_pack(&fs_ctx, src_name, dst_name);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_archive(struct silofs_fs_env *fse)
{
	int err = 0;
	int err2 = 0;

	if (fse->fs_args.withfuse) {
		return -EINVAL;
	}
	err = silofs_fse_reopen(fse);
	if (err) {
		log_err("failed to reopen repos: err=%d", err);
		return err;
	}
	err = silofs_fse_reload(fse);
	if (err) {
		log_err("failed to reload: %s err=%d",
		        fse->fs_args.main_repodir, err);
		goto out;
	}
	err = fse_archive_fs(fse);
	if (err) {
		log_err("archive-fs error: err=%d", err);
		/* no return -- do post-archive cleanups */
	}
	err = silofs_fse_shut(fse);
	if (err) {
		log_err("shut-fs error: err=%d", err);
		goto out;
	}
out:
	err2 = silofs_fse_term(fse);
	if (err2) {
		log_err("term-fs error: err=%d", err2);
	}
	return err ? err : err2;
}

static int fse_restore_fs(struct silofs_fs_env *fse)
{
	struct silofs_fs_ctx fs_ctx;
	const char *src_name = fse->fs_args.cold_name;
	const char *dst_name = fse->fs_args.main_name;
	int err;

	err = fse_make_self_ctx(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = silofs_fs_unpack(&fs_ctx, src_name, dst_name);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_restore(struct silofs_fs_env *fse)
{
	int err = 0;
	int err2 = 0;

	if (fse->fs_args.withfuse) {
		return -EINVAL;
	}
	err = silofs_fse_reopen(fse);
	if (err) {
		log_err("failed to reopen repos: err=%d", err);
		return err;
	}
	err = fse_restore_fs(fse);
	if (err) {
		log_err("restore-fs error: err=%d", err);
		/* no return -- do post-restore cleanups */
	}
	err = silofs_fse_shut(fse);
	if (err) {
		log_err("shut-fs error: err=%d", err);
		goto out;
	}
out:
	err2 = silofs_fse_term(fse);
	if (err2) {
		log_err("term-fs error: err=%d", err2);
	}
	return err ? err : err2;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_repo *repo_of(const struct silofs_fs_env *fse)
{
	return fse->fs_args.restore ? fse->fs_cold_repo : fse->fs_main_repo;
}

int silofs_fse_lock_boot(const struct silofs_fs_env *fse,
                         const struct silofs_namestr *name, int *pfd)
{
	return silofs_repo_lock_bsec(repo_of(fse), name, pfd);
}

int silofs_fse_unlock_boot(const struct silofs_fs_env *fse,
                           const struct silofs_namestr *name, int *pfd)
{
	return silofs_repo_unlock_bsec(repo_of(fse), name, pfd);
}

int silofs_fse_load_boot(const struct silofs_fs_env *fse,
                         const struct silofs_namestr *name,
                         struct silofs_bootsec *out_bsec)
{
	return silofs_repo_load_bsec(repo_of(fse), name, out_bsec);
}
