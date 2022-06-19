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
#include <silofs/fs.h>
#include <silofs/fs/fuseq.h>
#include <silofs/fs/private.h>
#include <sys/resource.h>
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
	struct silofs_repos     repos;
	struct silofs_fs_uber   uber;
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

static size_t align_down(size_t sz, size_t align)
{
	return (sz / align) * align;
}

static int getmemlimit(size_t *out_lim)
{
	int err;
	struct rlimit rlim = {
		.rlim_cur = 0
	};

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	if (!err) {
		*out_lim = rlim.rlim_cur;
	}
	return err;
}

static int calc_mem_size(size_t mem_want, size_t *out_mem_size)
{
	size_t mem_floor;
	size_t mem_ceil;
	size_t mem_rlim;
	size_t mem_glim;
	size_t page_size;
	size_t phys_pages;
	size_t mem_total;
	size_t mem_uget;
	int err;

	/* zero implies default value */
	if (mem_want == 0) {
		mem_want = 2 * SILOFS_GIGA;
	}

	page_size = (size_t)silofs_sc_page_size();
	phys_pages = (size_t)silofs_sc_phys_pages();
	mem_total = (page_size * phys_pages);
	mem_floor = SILOFS_UGIGA / 8;
	if (mem_total < mem_floor) {
		return -ENOMEM;
	}
	err = getmemlimit(&mem_rlim);
	if (err) {
		return err;
	}
	if (mem_rlim < mem_floor) {
		return -ENOMEM;
	}
	mem_glim = 64 * SILOFS_UGIGA;
	mem_ceil = silofs_min3(mem_glim, mem_rlim, mem_total / 4);
	mem_uget = silofs_clamp(mem_want, mem_floor, mem_ceil);
	*out_mem_size = align_down(mem_uget, SILOFS_UMEGA);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

	err = calc_mem_size(fse->fs_args.memwant, &memsize);
	if (err) {
		return err;
	}
	mode = fse->fs_args.pedantic ? 1 : 0;
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
	size_t memsz_hint = fse->fs_qalloc->alst.memsz_data;

	if (fse->fs_args.warm_repodir && fse->fs_args.cold_repodir) {
		memsz_hint /= 2;
	}
	return memsz_hint;
}

static int fse_main_bootpath(struct silofs_fs_env *fse,
                             struct silofs_bootpath *bp)
{
	const struct silofs_fs_args *args = &fse->fs_args;

	return silofs_bootpath_setup(bp, args->warm_repodir, args->warm_name);
}

static int fse_cold_bootpath(struct silofs_fs_env *fse,
                             struct silofs_bootpath *bp)
{
	const struct silofs_fs_args *args = &fse->fs_args;

	return silofs_bootpath_setup(bp, args->cold_repodir, args->cold_name);
}

static int fse_init_warm_repo(struct silofs_fs_env *fse)
{
	struct silofs_bootpath bpath = { .repodir = NULL };
	struct silofs_repo *repo = &fse->fs_repos->repo_warm;
	int err;

	if (fse->fs_args.warm_repodir == NULL) {
		return 0;
	}
	err = fse_main_bootpath(fse, &bpath);
	if (err) {
		return err;
	}
	err = silofs_repo_init(repo, fse->fs_alloc, &bpath,
	                       fse_repo_memsz_hint(fse), !fse->fs_args.rdonly);
	if (err) {
		return err;
	}
	return 0;
}

static void fse_fini_warm_repo(struct silofs_fs_env *fse)
{
	struct silofs_repo *repo = &fse->fs_repos->repo_warm;

	if (repo->re_inited) {
		silofs_repo_fini(repo);
	}
}

static int fse_init_cold_repo(struct silofs_fs_env *fse)
{
	struct silofs_bootpath bpath = { .repodir = NULL };
	struct silofs_repo *repo = &fse->fs_repos->repo_cold;
	int err;

	if (fse->fs_args.cold_repodir == NULL) {
		return 0;
	}
	err = fse_cold_bootpath(fse, &bpath);
	if (err) {
		return err;
	}
	err = silofs_repo_init(repo, fse->fs_alloc, &bpath,
	                       fse_repo_memsz_hint(fse), !fse->fs_args.rdonly);
	if (err) {
		return err;
	}
	return 0;
}

static void fse_fini_cold_repo(struct silofs_fs_env *fse)
{
	struct silofs_repo *repo = &fse->fs_repos->repo_cold;

	if (repo->re_inited) {
		silofs_repo_fini(repo);
	}
}

static int fse_init_repos(struct silofs_fs_env *fse)
{
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	int err;

	fse->fs_repos = &fse_obj->fs_core.c.repos;
	err = fse_init_warm_repo(fse);
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
	fse_fini_warm_repo(fse);
	fse_fini_cold_repo(fse);
}

static int fse_init_uber(struct silofs_fs_env *fse)
{
	struct silofs_fs_uber *uber = &fse_obj_of(fse)->fs_core.c.uber;
	int err;

	err = silofs_uber_init(uber, fse->fs_repos);
	if (!err) {
		uber->ub_args = &fse->fs_args;
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
	struct silofs_alloc *alloc = &fse->fs_qalloc->alloc;
	void *mem = NULL;
	int err;

	if (!fse->fs_args.withfuse) {
		return 0;
	}
	mem = silofs_allocate(alloc, fuseq_pg_size);
	if (mem == NULL) {
		log_warn("failed to allocate fuseq: size=%lu", fuseq_pg_size);
		return -ENOMEM;
	}
	fqp = mem;
	err = silofs_fuseq_init(&fqp->fuseq, alloc);
	if (err) {
		silofs_deallocate(alloc, mem, fuseq_pg_size);
		return err;
	}
	fse_bind_fuseq(fse, &fqp->fuseq);
	return 0;
}

static void fse_fini_fuseq(struct silofs_fs_env *fse)
{
	union silofs_fuseq_page *fuseq_pg = NULL;
	struct silofs_alloc *alloc = &fse->fs_qalloc->alloc;

	if (fse->fs_fuseq != NULL) {
		fuseq_pg = fuseq_to_page(fse->fs_fuseq);

		silofs_fuseq_fini(fse->fs_fuseq);
		fse_bind_fuseq(fse, NULL);

		silofs_deallocate(alloc, fuseq_pg, sizeof(*fuseq_pg));
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

static void fse_fini_commons(struct silofs_fs_env *fse)
{
	silofs_kivam_fini(&fse->fs_kivam);
	silofs_passphrase_reset(&fse->fs_passph);
	fse->fs_uber = NULL;
}

static void fse_fini(struct silofs_fs_env *fse)
{
	fse_fini_fuseq(fse);
	fse_fini_uber(fse);
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
	if (fse->fs_uber && fse->fs_uber->ub_sbi) {
		silofs_drop_itable_cache(fse->fs_uber->ub_sbi);
	}
	if (fse->fs_repos->repo_warm.re_inited) {
		silofs_repo_drop_cache(&fse->fs_repos->repo_warm);
	}
	if (fse->fs_repos->repo_cold.re_inited) {
		silofs_repo_drop_cache(&fse->fs_repos->repo_cold);
	}
	silofs_burnstack();
}

static void fse_relax_cache(struct silofs_fs_env *fse, bool drop_cache)
{
	const int flags = SILOFS_F_BRINGUP;

	if (fse->fs_repos->repo_warm.re_inited) {
		silofs_repo_relax_cache(&fse->fs_repos->repo_warm, flags);
	}
	if (fse->fs_repos->repo_cold.re_inited) {
		silofs_repo_relax_cache(&fse->fs_repos->repo_cold, flags);
	}
	if (drop_cache) {
		fse_drop_caches(fse);
	}
}

static struct silofs_sb_info *fse_sbi(const struct silofs_fs_env *fse)
{
	silofs_assert_not_null(fse->fs_uber);
	silofs_assert_not_null(fse->fs_uber->ub_sbi);

	return fse->fs_uber->ub_sbi;
}

static int fse_reload_rootdir(struct silofs_fs_env *fse)
{
	struct silofs_sb_info *sbi = fse_sbi(fse);
	struct silofs_inode_info *ii = NULL;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

	err = silofs_sbi_stage_inode(sbi, ino, SILOFS_STAGE_RO, &ii);
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

static int fse_reload_free_vspace(struct silofs_fs_env *fse)
{
	struct silofs_sb_info *sbi = fse_sbi(fse);
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = silofs_sbi_rescan_free_vspace(sbi, stype);
		if (err && (err != -ENOSPC) && (err != -ENOENT)) {
			return err;
		}
	}
	return 0;
}

static int fse_reload_inodes_table(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_sbi_reload_itable(fse_sbi(fse));
	if (err) {
		log_err("failed to load inodes-table: err=%d", err);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int fse_reload_meta(struct silofs_fs_env *fse)
{
	int err;

	err = fse_reload_inodes_table(fse);
	if (err) {
		return err;
	}
	err = fse_reload_rootdir(fse);
	if (err) {
		return err;
	}
	fse_relax_cache(fse, true);
	return 0;
}

static int fse_flush_dirty(const struct silofs_fs_env *fse)
{
	int err;

	silofs_assert_not_null(fse->fs_uber);

	err = silofs_uber_flush_dirty(fse->fs_uber, SILOFS_F_NOW);
	if (err) {
		log_err("failed to flush-dirty: err=%d", err);
	}
	return err;
}

static int fse_shut_uber(struct silofs_fs_env *fse)
{
	struct silofs_fs_uber *uber = fse->fs_uber;
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

int silofs_fse_close_repos(struct silofs_fs_env *fse)
{
	int err;

	if (fse->fs_repos->repo_cold.re_inited) {
		err = silofs_repo_close(&fse->fs_repos->repo_cold);
		if (err) {
			return err;
		}
	}
	if (fse->fs_repos->repo_warm.re_inited) {
		err = silofs_repo_close(&fse->fs_repos->repo_warm);
		if (err) {
			return err;
		}
	}
	return 0;
}

static void fse_update_bootsec(const struct silofs_fs_env *fse,
                               struct silofs_bootsec *bsec)
{
	const struct silofs_sb_info *sbi = fse_sbi(fse);

	silofs_assert_eq(sbi->sb->sb_flags, 0);

	silofs_bootsec_set_sb_uaddr(bsec, sbi_uaddr(sbi));
}

int silofs_fse_resolve(const struct silofs_fs_env *fse,
                       struct silofs_bootsec *bsec)
{
	const struct silofs_fs_uber *uber = fse->fs_uber;
	int ret = -ENOENT;

	if (uber && uber->ub_sbi) {
		silofs_bootsec_init(bsec);
		fse_update_bootsec(fse, bsec);
		ret = 0;
	}
	return ret;
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

	err = silofs_fuseq_mount(fq, fse->fs_uber, mount_point);
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

static int fse_flush_and_drop_caches(const struct silofs_fs_env *fse)
{
	int err;

	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	fse_drop_caches(fse);
	return 0;
}

int silofs_fse_sync_drop(struct silofs_fs_env *fse)
{
	return fse_flush_and_drop_caches(fse);
}

void silofs_fse_stats(const struct silofs_fs_env *fse,
                      struct silofs_fs_stats *st)
{
	struct silofs_alloc_stat alst = { .nbytes_used = 0 };
	const struct silofs_cache *cache = NULL;

	silofs_memzero(st, sizeof(*st));
	silofs_allocstat(fse->fs_alloc, &alst);
	st->nalloc_bytes = alst.nbytes_used;
	if (fse->fs_repos->repo_warm.re_inited) {
		cache = &fse->fs_repos->repo_warm.re_cache;
		st->ncache_ublocks += cache->c_ubki_lm.lm_htbl_sz;
		st->ncache_vblocks += cache->c_vbki_lm.lm_htbl_sz;
		st->ncache_unodes += cache->c_ui_lm.lm_htbl_sz;
		st->ncache_vnodes += cache->c_vi_lm.lm_htbl_sz;
	}
	if (fse->fs_repos->repo_cold.re_inited) {
		cache = &fse->fs_repos->repo_cold.re_cache;
		st->ncache_ublocks += cache->c_ubki_lm.lm_htbl_sz;
		st->ncache_vblocks += cache->c_vbki_lm.lm_htbl_sz;
		st->ncache_unodes += cache->c_ui_lm.lm_htbl_sz;
		st->ncache_vnodes += cache->c_vi_lm.lm_htbl_sz;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fse_derive_main_key(struct silofs_fs_env *fse,
                               const struct silofs_bootsec *bsec)
{
	struct silofs_cipher_args cip_args = { .cipher_algo = 0 };
	const struct silofs_mdigest *md = fse_mdigest(fse);
	const struct silofs_passphrase *pp = &fse->fs_passph;
	int err;

	if (!pp->passlen) {
		return 0; /* operation without passphrase */
	}
	silofs_bootsec_cipher_args(bsec, &cip_args);
	err = silofs_derive_kivam(&cip_args, pp, md, &fse->fs_kivam);
	if (err) {
		log_err("failed to derive iv-key: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_check_super_block(const struct silofs_fs_env *fse,
                                 const struct silofs_sb_info *sbi)
{
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

static void fse_key_hash(const struct silofs_fs_env *fse,
                         struct silofs_hash256 *out_hash)
{
	const struct silofs_kivam *kivam = &fse->fs_kivam;

	silofs_calc_key_hash(&kivam->key, fse_mdigest(fse), out_hash);
}

static int fse_verify_bootsec(const struct silofs_fs_env *fse,
                              const struct silofs_bootsec *bsec)
{
	struct silofs_hash256 hash;
	const enum silofs_bootf mask = SILOFS_BOOTF_KEY_SHA256;

	if ((bsec->flags & mask) != mask) {
		return 0;
	}
	fse_key_hash(fse, &hash);
	if (!silofs_bootsec_has_keyhash(bsec, &hash)) {
		return -EKEYEXPIRED;
	}
	return 0;
}

static int fse_reload_supers(struct silofs_fs_env *fse,
                             const struct silofs_uaddr *sb_uaddr)
{
	struct silofs_fs_uber *uber = fse->fs_uber;
	int err;

	err = silofs_uber_reload_supers(uber, sb_uaddr);
	if (err) {
		return err;
	}
	err = fse_check_super_block(fse, uber->ub_sbi);
	if (err) {
		log_warn("bad super-block: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_format_base_spmaps_of(const struct silofs_fs_env *fse,
                                     const struct silofs_vaddr *vaddr)
{
	struct silofs_sb_info *sbi = fse_sbi(fse);
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stage_mode stg_mode = SILOFS_STAGE_RW;
	int err;

	err = silofs_sbi_require_spmaps_at(sbi, vaddr, stg_mode, &sni, &sli);
	if (err) {
		log_err("failed to format base spmaps: stype=%d err=%d",
		        vaddr->stype, err);
		return err;
	}
	err = fse_flush_and_drop_caches(fse);
	if (err) {
		return err;
	}
	log_dbg("format base spmaps of: stype=%d err=%d", vaddr->stype, err);
	return 0;
}

static int fse_format_base_spmaps(const struct silofs_fs_env *fse)
{
	struct silofs_vaddr vaddr;
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		vaddr_setup(&vaddr, stype, 0);
		err = fse_format_base_spmaps_of(fse, &vaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int fse_format_claim_vspace_of(const struct silofs_fs_env *fse,
                                      enum silofs_stype vspace)
{
	struct silofs_voaddr voa;
	struct silofs_sb_info *sbi = fse_sbi(fse);
	const loff_t voff_exp = 0;
	int err;

	err = silofs_sbi_claim_vspace(sbi, vspace, &voa);
	if (err) {
		log_err("failed to claim: vspace=%d err=%d", vspace, err);
		return err;
	}
	if (voa.vaddr.voff != voff_exp) {
		log_err("wrong first voff: vspace=%d expected-voff=%ld "
		        "got-voff=%ld", vspace, voff_exp, voa.vaddr.voff);
		return -EFSCORRUPTED; /* TODO: should be internal */
	}
	err = silofs_sbi_reclaim_vspace(sbi, &voa.vaddr);
	if (err) {
		log_err("failed to reclaim space: err=%d", err);
	}
	return 0;
}

static int fse_format_base_vspace(const struct silofs_fs_env *fse)
{
	struct silofs_spacestats spst = { .capacity = 0 };
	struct silofs_sb_info *sbi = fse_sbi(fse);
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = fse_format_claim_vspace_of(fse, stype);
		if (err) {
			return err;
		}
		err = fse_flush_and_drop_caches(fse);
		if (err) {
			return err;
		}
		silofs_sti_collect_stats(&sbi->sb_sti, &spst);
	}
	return 0;
}

static int fse_reload_base_vspace_of(const struct silofs_fs_env *fse,
                                     enum silofs_stype vspace)
{
	struct silofs_vaddr vaddr;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	struct silofs_sb_info *sbi = fse_sbi(fse);
	const enum silofs_stage_mode stg_mode = SILOFS_STAGE_RO;
	int err;

	vaddr_setup(&vaddr, vspace, 0);
	err = silofs_sbi_stage_spmaps_at(sbi, &vaddr, stg_mode, &sni, &sli);
	if (err) {
		log_err("failed to reload: vspace=%d err=%d", vspace, err);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int fse_reload_base_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = fse_reload_base_vspace_of(fse, stype);
		if (err) {
			return err;
		}
		err = fse_flush_and_drop_caches(fse);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int fse_format_zero_vspace_of(const struct silofs_fs_env *fse,
                                     enum silofs_stype vspace)
{
	struct silofs_vnode_info *vi = NULL;
	loff_t voff;
	int err;

	err = silofs_sbi_spawn_vnode(fse_sbi(fse), vspace, &vi);
	if (err) {
		log_err("failed to spawn: vspace=%d err=%d", vspace, err);
		return err;
	}
	voff = vaddr_off(vi_vaddr(vi));
	if (voff != 0) {
		log_err("bad offset: vspace=%d voff=%ld", vspace, voff);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int fse_format_zero_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = fse_format_zero_vspace_of(fse, stype);
		if (err) {
			return err;
		}
		err = fse_flush_and_drop_caches(fse);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int fse_format_inodes_table(const struct silofs_fs_env *fse)
{
	struct silofs_sb_info *sbi = fse_sbi(fse);
	int err;

	err = silofs_sbi_format_itable(sbi);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_format_rootdir(const struct silofs_fs_env *fse,
                              const struct silofs_creds *creds)
{
	struct silofs_sb_info *sbi = fse_sbi(fse);
	struct silofs_inode_info *root_ii = NULL;
	int err;

	err = silofs_sbi_spawn_inode(sbi, creds, SILOFS_INO_NULL,
	                             0, S_IFDIR | 0755, 0, &root_ii);
	if (err) {
		return err;
	}
	silofs_ii_fixup_as_rootdir(root_ii);
	err = silofs_bind_rootdir(sbi, root_ii);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_format_fs_meta(const struct silofs_fs_env *fse,
                              const struct silofs_creds *creds)
{
	int err;

	err = fse_format_base_spmaps(fse);
	if (err) {
		return err;
	}
	err = fse_format_base_vspace(fse);
	if (err) {
		return err;
	}
	err = fse_format_zero_vspace(fse);
	if (err) {
		return err;
	}
	err = fse_format_inodes_table(fse);
	if (err) {
		return err;
	}
	err = fse_format_rootdir(fse, creds);
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

	fs_ctx->fsc_uber = fse->fs_uber;
	fs_ctx->fsc_oper.op_creds.ucred.uid = fse->fs_args.uid;
	fs_ctx->fsc_oper.op_creds.ucred.gid = fse->fs_args.gid;
	fs_ctx->fsc_oper.op_creds.ucred.pid = fse->fs_args.pid;
	fs_ctx->fsc_oper.op_creds.ucred.umask = fse->fs_args.umask;
	fs_ctx->fsc_oper.op_unique = 0; /* TODO: negative running sequence */

	return silofs_ts_gettime(&fs_ctx->fsc_oper.op_creds.xtime, true);
}

static int fse_format_supers(struct silofs_fs_env *fse)
{
	struct silofs_fs_uber *uber = fse->fs_uber;
	const size_t cap_want = uber->ub_args->capacity;
	size_t capacity = 0;
	int err;

	err = silofs_calc_fs_capacity(cap_want, &capacity);
	if (err) {
		log_err("illegal capacity: cap=%lu err=%d", cap_want, err);
		return err;
	}
	err = silofs_uber_format_supers(uber, capacity);
	if (err) {
		return err;
	}
	err = fse_check_super_block(fse, uber->ub_sbi);
	if (err) {
		log_err("internal sb format: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_format_main_warm(struct silofs_fs_env *fse)
{
	struct silofs_repo *repo = &fse->fs_repos->repo_warm;

	return repo->re_inited ? silofs_repo_format(repo) : 0;
}

static int fse_format_cold_repo(struct silofs_fs_env *fse)
{
	struct silofs_repo *repo = &fse->fs_repos->repo_cold;

	return repo->re_inited ? silofs_repo_format(repo) : 0;
}

int silofs_fse_format_repos(struct silofs_fs_env *fse)
{
	int err;

	err = fse_format_main_warm(fse);
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

int silofs_fse_open_repos(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_repo_open(&fse->fs_repos->repo_warm);
	if (err) {
		return err;
	}
	if (!fse->fs_repos->repo_cold.re_inited) {
		return 0;
	}
	err = silofs_repo_open(&fse->fs_repos->repo_cold);
	if (err) {
		return err;
	}
	return err;
}

int silofs_fse_reopen(struct silofs_fs_env *fse,
                      const struct silofs_bootsec *bsec)
{
	int err;

	err = fse_derive_main_key(fse, bsec);
	if (err) {
		return err;
	}
	err = fse_verify_bootsec(fse, bsec);
	if (err) {
		return err;
	}
	err = silofs_fse_open_repos(fse);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_reload(struct silofs_fs_env *fse,
                      const struct silofs_bootsec *bsec)
{
	int err;

	err = fse_reload_supers(fse, &bsec->sb_uaddr);
	if (err) {
		return err;
	}
	err = fse_reload_base_vspace(fse);
	if (err) {
		return err;
	}
	err = fse_reload_free_vspace(fse);
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

int silofs_fse_verify(struct silofs_fs_env *fse,
                      const struct silofs_bootsec *bsec)
{
	int err2;
	int err;

	err = silofs_fse_reopen(fse, bsec);
	if (err) {
		return err;
	}
	err = silofs_fse_reload(fse, bsec);
	if (err) {
		goto out;
	}
	err = silofs_fse_shut(fse);
	if (err) {
		goto out;
	}
out:
	err2 = silofs_fse_term(fse);
	return err ? err : err2;
}

static const struct silofs_creds *creds_of(const struct silofs_fs_ctx *fs_ctx)
{
	return &fs_ctx->fsc_oper.op_creds;
}

int silofs_fse_format_fs(struct silofs_fs_env *fse,
                         struct silofs_bootsec *out_bsec)
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
	err = fse_format_supers(fse);
	if (err) {
		return err;
	}
	err = fse_format_fs_meta(fse, creds_of(&fs_ctx));
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	err = silofs_fse_resolve(fse, out_bsec);
	if (err) {
		return err;
	}
	fse_drop_caches(fse);
	return 0;
}

int silofs_fse_serve(struct silofs_fs_env *fse,
                     const struct silofs_bootsec *bsec)
{
	int err = 0;
	int err2 = 0;

	if (!fse->fs_args.withfuse || (fse->fs_fuseq == NULL)) {
		return -EINVAL;
	}
	err = silofs_fse_reopen(fse, bsec);
	if (err) {
		log_err("failed to reopen repo: %s err=%d",
		        fse->fs_args.warm_repodir, err);
		return err;
	}
	err = silofs_fse_reload(fse, bsec);
	if (err) {
		log_err("failed to reload: %s err=%d",
		        fse->fs_args.warm_repodir, err);
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
		        fse->fs_args.warm_repodir, err);
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

bool silofs_fse_served_clean(const struct silofs_fs_env *fse)
{
	const struct silofs_fuseq *fq = fse->fs_fuseq;

	return fq && fq->fq_got_init && fq->fq_got_destroy;
}

int silofs_fse_shut(struct silofs_fs_env *fse)
{
	int err;

	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	err = fse_shut_uber(fse);
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

static int fse_archive_fs(struct silofs_fs_env *fse,
                          const struct silofs_bootsec *src_bsec,
                          struct silofs_bootsec *dst_bsec)
{
	struct silofs_fs_ctx fs_ctx;
	int err;

	err = fse_make_self_ctx(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = silofs_fs_pack(&fs_ctx, &fse->fs_kivam, src_bsec, dst_bsec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_archive(struct silofs_fs_env *fse,
                       const struct silofs_bootsec *src_bsec,
                       struct silofs_bootsec *dst_bsec)
{
	int err2 = 0;
	int err = 0;

	if (fse->fs_args.withfuse) {
		return -EINVAL;
	}
	err = silofs_fse_reopen(fse, src_bsec);
	if (err) {
		log_err("failed to reopen repos: err=%d", err);
		return err;
	}
	err = silofs_fse_reload(fse, src_bsec);
	if (err) {
		log_err("failed to reload: %s err=%d",
		        fse->fs_args.warm_repodir, err);
		goto out;
	}
	err = fse_archive_fs(fse, src_bsec, dst_bsec);
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

static int fse_restore_fs(struct silofs_fs_env *fse,
                          const struct silofs_bootsec *src_bsec,
                          struct silofs_bootsec *dst_bsec)
{
	struct silofs_fs_ctx fs_ctx;
	int err;

	err = fse_make_self_ctx(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = silofs_fs_unpack(&fs_ctx, &fse->fs_kivam, src_bsec, dst_bsec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_restore(struct silofs_fs_env *fse,
                       const struct silofs_bootsec *src_bsec,
                       struct silofs_bootsec *dst_bsec)
{
	int err = 0;
	int err2 = 0;

	if (fse->fs_args.withfuse) {
		return -EINVAL;
	}
	err = silofs_fse_reopen(fse, src_bsec);
	if (err) {
		log_err("failed to reopen repos: err=%d", err);
		return err;
	}
	err = fse_restore_fs(fse, src_bsec, dst_bsec);
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

static int fse_snap_fs(struct silofs_fs_env *fse, int flags,
                       struct silofs_bootsecs *out_bsecs)

{
	struct silofs_fs_ctx fs_ctx;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

	err = fse_make_self_ctx(fse, &fs_ctx);
	if (err) {
		return err;
	}
	err = silofs_fs_clone(&fs_ctx, ino, flags, out_bsecs);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_snap(struct silofs_fs_env *fse,
                    const struct silofs_bootsec *src_bsec,
                    struct silofs_bootsecs *out_bsecs)
{
	int err = 0;
	int err2 = 0;

	if (fse->fs_args.withfuse) {
		return -EINVAL;
	}
	err = silofs_fse_reopen(fse, src_bsec); /* XXX */
	if (err) {
		log_err("failed to reopen repos: err=%d", err);
		return err;
	}
	err = silofs_fse_reload(fse, src_bsec); /* XXX */
	if (err) {
		log_err("failed to reload: %s err=%d",
		        fse->fs_args.warm_repodir, err);
		goto out;
	}
	err = fse_snap_fs(fse, 0, out_bsecs);
	if (err) {
		log_err("snap-fs error: err=%d", err);
		/* no return -- do post-snap cleanups */
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
