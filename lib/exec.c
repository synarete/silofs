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

struct silofs_fs_core {
	struct silofs_qalloc    qalloc;
	struct silofs_crypto    crypto;
	struct silofs_repos     repos;
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
	qalloc = &fse_obj_of(fse)->fs_core.c.qalloc;
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
	struct silofs_crypto *crypto;
	int err;

	crypto = &fse_obj_of(fse)->fs_core.c.crypto;
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
	const struct silofs_fs_args *args = &fse->fs_args;
	const size_t mem_div = (args->repodir && args->atticdir) ? 2 : 1;

	return fse->fs_qalloc->alst.memsz_data / mem_div;
}

static int fse_make_blobs_repocfg(struct silofs_fs_env *fse,
                                  struct silofs_repocfg *rcfg)
{
	const struct silofs_fs_args *args = &fse->fs_args;

	silofs_memzero(rcfg, sizeof(*rcfg));
	rcfg->rc_alloc = fse->fs_alloc;
	rcfg->rc_memhint = fse_repo_memsz_hint(fse);
	rcfg->rc_repo_mode = SILOFS_REPO_LOCAL;
	rcfg->rc_rdonly = args->rdonly;
	return silofs_bootpath_setup(&rcfg->rc_bootpath,
	                             args->repodir, args->name);
}

static int fse_make_attic_repocfg(struct silofs_fs_env *fse,
                                  struct silofs_repocfg *rcfg)
{
	const struct silofs_fs_args *args = &fse->fs_args;

	silofs_memzero(rcfg, sizeof(*rcfg));
	rcfg->rc_alloc = fse->fs_alloc;
	rcfg->rc_memhint = fse_repo_memsz_hint(fse);
	rcfg->rc_repo_mode = SILOFS_REPO_ATTIC;
	rcfg->rc_rdonly = args->rdonly;
	return silofs_bootpath_setup(&rcfg->rc_bootpath,
	                             args->atticdir, args->arname);
}

static int fse_make_repocfg(struct silofs_fs_env *fse,
                            struct silofs_repocfg rcfg[2])
{
	const struct silofs_fs_args *args = &fse->fs_args;
	int err;

	if (args->repodir && args->name) {
		err = fse_make_blobs_repocfg(fse, &rcfg[0]);
		if (err) {
			return err;
		}
	}
	if (args->atticdir && args->arname) {
		err = fse_make_attic_repocfg(fse, &rcfg[1]);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int fse_init_repos(struct silofs_fs_env *fse)
{
	struct silofs_repocfg rcfg[2];
	struct silofs_fs_env_obj *fse_obj = fse_obj_of(fse);
	struct silofs_repos *repos;
	int err;

	silofs_memzero(rcfg, sizeof(rcfg));
	err = fse_make_repocfg(fse, rcfg);
	if (err) {
		return err;
	}
	repos = &fse_obj->fs_core.c.repos;
	err = silofs_repos_init(repos, rcfg);
	if (err) {
		return err;
	}
	fse->fs_repos = repos;
	return 0;
}

static void fse_fini_repos(struct silofs_fs_env *fse)
{
	if (fse->fs_repos != NULL) {
		silofs_repos_fini(fse->fs_repos);
		fse->fs_repos = NULL;
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
	err = silofs_idsmap_populate(idsm, &fs_args->ca.ids);
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
	const struct silofs_uber_args args = {
		.alloc = fse->fs_alloc,
		.repos = fse->fs_repos,
		.idsm = fse->fs_idsmap,
		.ivkey = &fse->fs_ivkey,
	};
	struct silofs_uber *uber;
	int err;

	uber = &fse_obj_of(fse)->fs_core.c.uber;
	err = silofs_uber_init(uber, &args);
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
	struct silofs_password passwd;
	int err;

	err = silofs_password_setup(&passwd, args->passwd);
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

static int fse_init(struct silofs_fs_env *fse,
                    const struct silofs_fs_args *args)
{
	int err;

	fse_init_commons(fse, args);
	err = fse_init_passwd(fse);
	if (err) {
		goto out_err;
	}
	err = fse_init_qalloc(fse);
	if (err) {
		goto out_err;
	}
	err = fse_init_crypto(fse);
	if (err) {
		goto out_err;
	}
	err = fse_init_repos(fse);
	if (err) {
		goto out_err;
	}
	err = fse_init_idsmap(fse);
	if (err) {
		goto out_err;
	}
	err = fse_init_uber(fse);
	if (err) {
		goto out_err;
	}
	err = fse_init_fuseq(fse);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	fse_fini(fse);
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
	fse_fini_repos(fse);
	fse_fini_crypto(fse);
	fse_fini_qalloc(fse);
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

static void fse_drop_caches(const struct silofs_fs_env *fse)
{
	if (fse->fs_uber && fse->fs_uber->ub_sbi) {
		silofs_drop_itable_cache(fse->fs_uber->ub_sbi);
	}
	silofs_repos_drop_cache(fse->fs_repos);
	silofs_burnstack();
}

static void fse_relax_cache(struct silofs_fs_env *fse, bool drop_cache)
{
	const int flags = SILOFS_F_BRINGUP;

	silofs_repos_relax_cache(fse->fs_repos, flags);
	if (drop_cache) {
		fse_drop_caches(fse);
	}
}

static struct silofs_sb_info *fse_sbi(const struct silofs_fs_env *fse)
{
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
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int fse_reload_free_vspace(struct silofs_fs_env *fse)
{
	struct silofs_sb_info *sbi = fse_sbi(fse);
	enum silofs_stype stype;
	int err = 0;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = silofs_sbi_rescan_free_vspace(sbi, stype);
		if (err && (err != -ENOSPC) && (err != -ENOENT)) {
			break;
		}
		err = 0;
	}
	if (err) {
		log_err("failed to reload free vspace: err=%d", err);
	}
	return err;
}

static int fse_reload_inodes_table(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_sbi_reload_itable(fse_sbi(fse));
	if (err) {
		log_err("failed to load inodes-table: err=%d", err);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int fse_reload_fs_meta(struct silofs_fs_env *fse)
{
	int err;

	err = fse_reload_inodes_table(fse);
	if (err) {
		log_err("failed to reload inodes table: err=%d", err);
		return err;
	}
	err = fse_reload_rootdir(fse);
	if (err) {
		log_err("failed to reload root dir: err=%d", err);
		return err;
	}
	fse_relax_cache(fse, true);
	return 0;
}

static int fse_flush_dirty(const struct silofs_fs_env *fse)
{
	struct silofs_uber *uber = fse->fs_uber;
	int err;

	err = silofs_uber_flush_dirty(uber, SILOFS_DQID_ALL, SILOFS_F_NOW);
	if (err) {
		log_err("failed to flush-dirty: err=%d", err);
	}
	silofs_burnstack();
	return err;
}

static int fse_shut_uber(struct silofs_fs_env *fse)
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

int silofs_fse_close_repo(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = silofs_repos_close(fse->fs_repos);
	fse_unlock(fse);
	return ret;
}

int silofs_fse_exec_fs(struct silofs_fs_env *fse)
{
	struct silofs_fuseq *fq = fse->fs_fuseq;
	const char *mount_point = fse->fs_args.mntdir;
	int err;

	if (!fse->fs_args.withfuse || (fse->fs_fuseq == NULL)) {
		return -EINVAL;
	}
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
	const struct silofs_repos *repos = fse->fs_repos;
	const struct silofs_cache *cache = NULL;

	silofs_memzero(st, sizeof(*st));
	silofs_allocstat(fse->fs_alloc, &alst);
	st->nalloc_bytes = alst.nbytes_used;

	for (size_t i = 0; i < ARRAY_SIZE(repos->repo); ++i) {
		cache = &repos->repo[i].re_cache;
		if (cache->c_inited) {
			st->ncache_ublocks += cache->c_ubki_lm.lm_htbl_sz;
			st->ncache_vblocks += cache->c_vbki_lm.lm_htbl_sz;
			st->ncache_unodes += cache->c_ui_lm.lm_htbl_sz;
			st->ncache_vnodes += cache->c_vi_lm.lm_htbl_sz;
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fse_derive_main_key(struct silofs_fs_env *fse,
                               const struct silofs_bootsec *bsec)
{
	struct silofs_cipher_args cip_args = { .cipher_algo = 0 };
	const struct silofs_mdigest *md = fse_mdigest(fse);
	const struct silofs_password *pswd = fse->fs_passwd;
	int err = 0;

	if (!pswd->passlen) {
		return 0;
	}
	silofs_bootsec_cipher_args(bsec, &cip_args);
	err = silofs_derive_ivkey(&cip_args, pswd, md, &fse->fs_ivkey);
	if (err) {
		log_err("failed to derive main-key: err=%d", err);
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
	const struct silofs_ivkey *ivkey = &fse->fs_ivkey;

	silofs_calc_key_hash(&ivkey->key, fse_mdigest(fse), out_hash);
}

static int fse_verify_bootsec(const struct silofs_fs_env *fse,
                              const struct silofs_bootsec *bsec)
{
	struct silofs_hash256 hash;
	const enum silofs_bootf mask = SILOFS_BOOTF_KEY_SHA256;
	int err;

	if ((bsec->flags & mask) != mask) {
		return 0;
	}
	fse_key_hash(fse, &hash);
	err = silofs_bootsec_check_keyhash(bsec, &hash);
	if (err) {
		log_err("failed to verify bootsec: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_reload_supers(struct silofs_fs_env *fse)
{
	struct silofs_uber *uber = fse->fs_uber;
	int err;

	err = silofs_uber_reload_supers(uber);
	if (err) {
		log_err("failed to reload supers: err=%d", err);
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

	err = silofs_sbi_claim_vspace(sbi, vspace, SILOFS_DQID_DFL, &voa);
	if (err) {
		log_err("failed to claim: vspace=%d err=%d", vspace, err);
		return err;
	}
	if (voa.vaddr.voff != voff_exp) {
		log_err("wrong first voff: vspace=%d expected-voff=%ld "
		        "got-voff=%ld", vspace, voff_exp, voa.vaddr.voff);
		return -SILOFS_EFSCORRUPTED; /* TODO: should be internal */
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
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int fse_reload_base_vspace(const struct silofs_fs_env *fse)
{
	enum silofs_stype stype;
	int err = 0;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = fse_reload_base_vspace_of(fse, stype);
		if (err) {
			break;
		}
		err = fse_flush_and_drop_caches(fse);
		if (err) {
			break;
		}
	}
	if (err) {
		log_err("failed to reload base vspace: err=%d", err);
	}
	return err;
}

static int fse_format_zero_vspace_of(const struct silofs_fs_env *fse,
                                     enum silofs_stype vspace)
{
	struct silofs_vnode_info *vi = NULL;
	loff_t voff;
	int err;

	err = silofs_sbi_spawn_vnode(fse_sbi(fse), vspace, 0, &vi);
	if (err) {
		log_err("failed to spawn: vspace=%d err=%d", vspace, err);
		return err;
	}
	voff = vaddr_off(vi_vaddr(vi));
	if (voff != 0) {
		log_err("bad offset: vspace=%d voff=%ld", vspace, voff);
		return -SILOFS_EFSCORRUPTED;
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

static int fse_format_meta(const struct silofs_fs_env *fse,
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
	err = fse_flush_dirty(fse);
	if (err) {
		return err;
	}
	return 0;
}

static void fse_make_self_xcred(struct silofs_fs_env *fse,
                                struct silofs_task *task)
{
	const struct silofs_fs_args *args = &fse->fs_args;
	struct silofs_creds *creds = &task->t_oper.op_creds;

	creds->xcred.uid = args->uid;
	creds->xcred.gid = args->gid;
	creds->xcred.pid = args->pid;
	creds->xcred.umask = args->umask;
}

static int fse_make_self_icred(struct silofs_fs_env *fse,
                               struct silofs_task *task)
{
	const struct silofs_idsmap *idsm = fse->fs_idsmap;
	const struct silofs_ucred *xcred = &task->t_oper.op_creds.xcred;
	struct silofs_ucred *icred = &task->t_oper.op_creds.icred;
	int err = 0;

	icred->uid = xcred->uid;
	icred->gid = xcred->gid;
	icred->pid = xcred->pid;
	icred->umask = xcred->umask;
	if (idsm->idm_size > 0) {
		err = silofs_idsmap_map_uidgid(idsm, xcred->uid, xcred->gid,
		                               &icred->uid, &icred->gid);
	}
	return err;
}

static int fse_make_self_ctx(struct silofs_fs_env *fse,
                             struct silofs_task *task)
{
	struct silofs_creds *creds = &task->t_oper.op_creds;
	int err;

	silofs_memzero(task, sizeof(*task));
	task->t_uber = fse->fs_uber;
	task->t_oper.op_unique = 0;
	fse_make_self_xcred(fse, task);
	err = fse_make_self_icred(fse, task);
	if (err) {
		return err;
	}
	err = silofs_ts_gettime(&creds->ts, true);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_format_supers(struct silofs_fs_env *fse)
{
	struct silofs_uber *uber = fse->fs_uber;
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

int silofs_fse_format_repos(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = silofs_repos_format(fse->fs_repos);
	fse_unlock(fse);
	return ret;
}

int silofs_fse_open_repos(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = silofs_repos_open(fse->fs_repos);
	fse_unlock(fse);
	return ret;
}

static enum silofs_repo_mode repo_mode_of(bool warm_repo)
{
	return warm_repo ? SILOFS_REPO_LOCAL : SILOFS_REPO_ATTIC;
}

static int fse_save_bootsec_of(const struct silofs_fs_env *fse, bool warm,
                               const struct silofs_uuid *uuid,
                               const struct silofs_bootsec *bsec)
{
	const enum silofs_repo_mode rt = repo_mode_of(warm);

	return silofs_repos_save_bootsec(fse->fs_repos, rt, uuid, bsec);
}

static int fse_load_bootsec_of(const struct silofs_fs_env *fse, bool warm,
                               const struct silofs_uuid *uuid,
                               struct silofs_bootsec *out_bsec)
{
	const enum silofs_repo_mode rt = repo_mode_of(warm);

	return silofs_repos_load_bootsec(fse->fs_repos, rt, uuid, out_bsec);
}

static int fse_reload_bootsec(struct silofs_fs_env *fse, bool warm,
                              const struct silofs_uuid *uuid,
                              struct silofs_bootsec *out_bsec)
{
	const enum silofs_repo_mode rt = repo_mode_of(warm);
	int err;

	err = silofs_repos_stat_bootsec(fse->fs_repos, rt, uuid);
	if (err) {
		log_err("failed to stat bootsec: err=%d", err);
		return err;
	}
	err = silofs_repos_load_bootsec(fse->fs_repos, rt, uuid, out_bsec);
	if (err) {
		log_err("failed to reload bootsec: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_unlink_bootsec(struct silofs_fs_env *fse, bool warm,
                              const struct silofs_uuid *uuid)
{
	const enum silofs_repo_mode rt = repo_mode_of(warm);
	int err;

	err = silofs_repos_unlink_bootsec(fse->fs_repos, rt, uuid);
	if (err) {
		log_err("failed to unlink bootsec: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_save_bootsec(const struct silofs_fs_env *fse, bool warm,
                            const struct silofs_bootsec *bsec)
{
	return fse_save_bootsec_of(fse, warm, &bsec->uuid, bsec);
}

static int fse_fill_save_bootsec(const struct silofs_fs_env *fse,
                                 struct silofs_bootsec *out_bsec)
{
	const struct silofs_sb_info *sbi = fse->fs_uber->ub_sbi;

	silofs_bootsec_init(out_bsec);
	silofs_bootsec_set_sb_uaddr(out_bsec, sbi_uaddr(sbi));
	return fse_save_bootsec(fse, true, out_bsec);
}

static const struct silofs_creds *creds_of(const struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}

static int fse_format_fs(struct silofs_fs_env *fse,
                         struct silofs_uuid *out_uuid)
{
	struct silofs_bootsec bsec;
	struct silofs_task task;
	int err;

	err = fse_make_self_ctx(fse, &task);
	if (err) {
		return err;
	}
	err = fse_format_supers(fse);
	if (err) {
		return err;
	}
	err = fse_format_meta(fse, creds_of(&task));
	if (err) {
		return err;
	}
	err = fse_fill_save_bootsec(fse, &bsec);
	if (err) {
		return err;
	}
	silofs_bootsec_uuid(&bsec, out_uuid);
	return 0;
}

int silofs_fse_format_fs(struct silofs_fs_env *fse,
                         struct silofs_uuid *out_uuid)
{
	int ret;

	fse_lock(fse);
	ret = fse_format_fs(fse, out_uuid);
	fse_unlock(fse);
	return ret;
}

static int fse_reload_root_sblob(struct silofs_fs_env *fse,
                                 const struct silofs_bootsec *bsec)
{
	silofs_uber_set_sbaddr(fse->fs_uber, &bsec->sb_uaddr);
	return silofs_uber_reload_sblob(fse->fs_uber);
}

static int fse_boot_fs(struct silofs_fs_env *fse,
                       const struct silofs_uuid *uuid)
{
	struct silofs_bootsec bsec;
	int err;

	err = fse_reload_bootsec(fse, true, uuid, &bsec);
	if (err) {
		return err;
	}
	err = fse_derive_main_key(fse, &bsec);
	if (err) {
		return err;
	}
	err = fse_verify_bootsec(fse, &bsec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sblob(fse, &bsec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_boot_fs(struct silofs_fs_env *fse,
                       const struct silofs_uuid *uuid)
{
	int ret;

	fse_lock(fse);
	ret = fse_boot_fs(fse, uuid);
	fse_unlock(fse);
	return ret;
}

static int fse_open_fs(struct silofs_fs_env *fse)
{
	int err;

	err = fse_reload_supers(fse);
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
	err = fse_reload_fs_meta(fse);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_open_fs(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = fse_open_fs(fse);
	fse_unlock(fse);
	return ret;
}

bool silofs_fse_served_clean(const struct silofs_fs_env *fse)
{
	const struct silofs_fuseq *fq = fse->fs_fuseq;

	return fq && fq->fq_got_init && fq->fq_got_destroy;
}

static int fse_close_fs(struct silofs_fs_env *fse)
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

int silofs_fse_close_fs(struct silofs_fs_env *fse)
{
	int ret;

	fse_lock(fse);
	ret = fse_close_fs(fse);
	fse_unlock(fse);
	return ret;
}

int silofs_fse_poke_fs(struct silofs_fs_env *fse, bool warm,
                       const struct silofs_uuid *uuid)
{
	struct silofs_bootsec bsec;

	return fse_load_bootsec_of(fse, warm, uuid, &bsec);
}

int silofs_fse_pack_fs(struct silofs_fs_env *fse,
                       const struct silofs_uuid *uuid,
                       struct silofs_uuid *out_uuid)
{
	struct silofs_task task;
	struct silofs_bootsec bsec_src;
	struct silofs_bootsec bsec_dst;
	int err;

	if (fse->fs_args.withfuse) {
		return -EINVAL;
	}
	err = fse_reload_bootsec(fse, true, uuid, &bsec_src);
	if (err) {
		return err;
	}
	err = fse_derive_main_key(fse, &bsec_src);
	if (err) {
		return err;
	}
	err = fse_verify_bootsec(fse, &bsec_src);
	if (err) {
		return err;
	}
	err = fse_make_self_ctx(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_pack(&task, &fse->fs_ivkey, &bsec_src, &bsec_dst);
	if (err) {
		return err;
	}
	err = fse_save_bootsec(fse, false, &bsec_dst);
	if (err) {
		return err;
	}
	silofs_bootsec_uuid(&bsec_dst, out_uuid);
	return 0;
}

int silofs_fse_unpack_fs(struct silofs_fs_env *fse,
                         const struct silofs_uuid *uuid,
                         struct silofs_uuid *out_uuid)
{
	struct silofs_task task;
	struct silofs_bootsec bsec_src;
	struct silofs_bootsec bsec_dst;
	int err;

	if (fse->fs_args.withfuse) {
		return -EINVAL;
	}
	err = fse_reload_bootsec(fse, false, uuid, &bsec_src);
	if (err) {
		return err;
	}
	err = fse_derive_main_key(fse, &bsec_src);
	if (err) {
		return err;
	}
	err = fse_verify_bootsec(fse, &bsec_src);
	if (err) {
		return err;
	}
	err = fse_make_self_ctx(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_unpack(&task, &fse->fs_ivkey, &bsec_src, &bsec_dst);
	if (err) {
		return err;
	}
	err = fse_save_bootsec(fse, true, &bsec_dst);
	if (err) {
		return err;
	}
	silofs_bootsec_uuid(&bsec_dst, out_uuid);
	return 0;
}

int silofs_fse_fork_fs(struct silofs_fs_env *fse,
                       struct silofs_uuid *out_new,
                       struct silofs_uuid *out_alt)
{
	struct silofs_task task;
	struct silofs_bootsecs bsecs;
	int err;

	err = fse_make_self_ctx(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_clone(&task, SILOFS_INO_ROOT, 0, &bsecs);
	if (err) {
		return err;
	}
	silofs_bootsec_uuid(&bsecs.bsec[0], out_new);
	silofs_bootsec_uuid(&bsecs.bsec[1], out_alt);
	return 0;
}

int silofs_fse_inspect_fs(struct silofs_fs_env *fse)
{
	struct silofs_task task;
	int err;

	err = fse_make_self_ctx(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_inspect(&task);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fse_unref_fs(struct silofs_fs_env *fse,
                        const struct silofs_uuid *uuid)
{
	struct silofs_task task;
	struct silofs_bootsec bsec;
	int err;

	err = fse_reload_bootsec(fse, true, uuid, &bsec);
	if (err) {
		return err;
	}
	err = fse_verify_bootsec(fse, &bsec);
	if (err) {
		return err;
	}
	err = fse_reload_root_sblob(fse, &bsec);
	if (err) {
		return err;
	}
	err = fse_reload_supers(fse);
	if (err) {
		return err;
	}
	err = fse_make_self_ctx(fse, &task);
	if (err) {
		return err;
	}
	err = silofs_fs_unrefs(&task);
	if (err) {
		return err;
	}
	err = fse_unlink_bootsec(fse, true, uuid);
	if (err) {
		return err;
	}
	err = fse_shut_uber(fse);
	if (err) {
		return err;
	}
	return 0;
}
