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
#ifndef SILOFS_REPO_H_
#define SILOFS_REPO_H_


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* blob-reference using file-descriptor and fixed-size */
struct silofs_blob_fdsz {
	int fd;
	int sz;
};

/* blob-reference cache-entry */
struct silofs_blobref_info {
	struct silofs_cache_elem        br_ce;
	struct silofs_blobid            br_blobid;
	struct silofs_iovref            br_ior;
	struct silofs_blob_fdsz         br_fdsz;
	bool                            br_locked;
	bool                            br_rdonly;
};

/* repository init config */
struct silofs_repocfg {
	struct silofs_bootpath          rc_bootpath;
	struct silofs_alloc            *rc_alloc;
	size_t                          rc_memhint;
	enum silofs_repo_mode           rc_repo_mode;
	bool                            rc_rdonly;
};

/* blobs repository */
struct silofs_repo {
	struct silofs_repocfg           re_cfg;
	struct silofs_cache             re_cache;
	struct silofs_mdigest           re_mdigest;
	const char                     *re_root_dir;
	int                             re_root_dfd;
	int                             re_dots_dfd;
	int                             re_blobs_dfd;
	bool                            re_rw;
};

/* repository pair */
struct silofs_repos {
	struct silofs_repo              repo[2];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_blobref_info *
silofs_bri_new(struct silofs_alloc *alloc,
               const struct silofs_blobid *blobid);

void silofs_bri_del(struct silofs_blobref_info *bri,
                    struct silofs_alloc *alloc);

int silofs_bri_storev(const struct silofs_blobref_info *bri,
                      const struct silofs_oaddr *oaddr,
                      const struct iovec *iov, size_t cnt);

int silofs_bri_storev2(const struct silofs_blobref_info *bri, loff_t off,
                       const struct iovec *iov, size_t cnt);

int silofs_bri_pwriten(const struct silofs_blobref_info *bri, loff_t off,
                       const void *buf, size_t len);

int silofs_bri_preadn(const struct silofs_blobref_info *bri,
                      loff_t off, void *buf, size_t len);

int silofs_bri_load_bk(const struct silofs_blobref_info *bri,
                       const struct silofs_bkaddr *bkaddr,
                       struct silofs_block *bk);

int silofs_bri_store_bk(const struct silofs_blobref_info *bri,
                        const struct silofs_bkaddr *bkaddr,
                        const struct silofs_block *bk);

int silofs_bri_store_obj(const struct silofs_blobref_info *bri,
                         const struct silofs_oaddr *oaddr, const void *dat);

int silofs_bri_trim_nbks(const struct silofs_blobref_info *bri,
                         const struct silofs_bkaddr *bkaddr, size_t cnt);

int silofs_bri_resolve(struct silofs_blobref_info *bri,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_iovec *iov);

int silofs_bri_flock(struct silofs_blobref_info *bri);

int silofs_bri_funlock(struct silofs_blobref_info *bri);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_repo *
silofs_repos_get(const struct silofs_repos *repos, enum silofs_repo_mode rt);

int silofs_repos_init(struct silofs_repos *repos,
                      const struct silofs_repocfg rcfg[2]);

void silofs_repos_fini(struct silofs_repos *repos);

int silofs_repos_format(struct silofs_repos *repos);

int silofs_repos_open(struct silofs_repos *repos);

int silofs_repos_close(struct silofs_repos *repos);

void silofs_repos_drop_cache(struct silofs_repos *repos);

void silofs_repos_relax_cache(struct silofs_repos *repos, int flags);

void silofs_repos_pre_forkfs(struct silofs_repos *repos);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repos_save_bootsec(const struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid,
                              const struct silofs_bootsec *bsec);

int silofs_repos_load_bootsec(const struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid,
                              struct silofs_bootsec *out_bsec);

int silofs_repos_stat_bootsec(const struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid);

int silofs_repos_unlink_bootsec(const struct silofs_repos *repos,
                                enum silofs_repo_mode repo_mode,
                                const struct silofs_uuid *uuid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repos_lookup_blob(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_blobid *blobid);

int silofs_repos_spawn_blob(struct silofs_repos *repos,
                            enum silofs_repo_mode repo_mode,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobref_info **out_bri);

int silofs_repos_stage_blob(struct silofs_repos *repos, bool rw,
                            enum silofs_repo_mode repo_mode,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobref_info **out_bri);

int silofs_repos_remove_blob(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_blobid *blobid);

int silofs_repos_require_blob(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_blobid *blobid,
                              struct silofs_blobref_info **out_bri);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repos_stage_ubk(struct silofs_repos *repos, bool rw,
                           enum silofs_repo_mode repo_mode,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki);

int silofs_repos_spawn_ubk(struct silofs_repos *repos, bool rw,
                           enum silofs_repo_mode repo_mode,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki);

int silofs_repos_require_ubk(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_bkaddr *bkaddr,
                             struct silofs_ubk_info **out_ubki);

#endif /* SILOFS_REPO_H_ */
