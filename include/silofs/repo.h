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

/* blob control file */
struct silofs_blobf {
	struct silofs_namebuf           b_name;
	struct silofs_cache_elem        b_ce;
	struct silofs_mutex             b_mutex;
	struct silofs_blobid            b_blobid;
	struct silofs_iovref            b_iovref;
	ssize_t                         b_size;
	int                             b_fd;
	bool                            b_flocked;
	bool                            b_rdonly;
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

struct silofs_blobf *
silofs_blobf_new(struct silofs_alloc *alloc,
                 const struct silofs_blobid *blobid);

void silofs_blobf_del(struct silofs_blobf *blobf,
                      struct silofs_alloc *alloc);

int silofs_blobf_pwriten(struct silofs_blobf *blobf, loff_t off,
                         const void *buf, size_t len, bool sync);

int silofs_blobf_load_ubk(struct silofs_blobf *blobf,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info *ubki);

int silofs_blobf_load_vbk(struct silofs_blobf *blobf,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_vbk_info *vbki);

int silofs_blobf_trim_nbks(struct silofs_blobf *blobf,
                           const struct silofs_bkaddr *bkaddr, size_t cnt);

int silofs_blobf_resolve(struct silofs_blobf *blobf,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_iovec *iov);

int silofs_blobf_flock(struct silofs_blobf *blobf);

int silofs_blobf_funlock(struct silofs_blobf *blobf);


int silofs_blobf_read_blob(struct silofs_blobf *blobf, void *buf, size_t len);

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

int silofs_repos_save_bootsec(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid,
                              const struct silofs_bootsec *bsec);

int silofs_repos_load_bootsec(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid,
                              struct silofs_bootsec *out_bsec);

int silofs_repos_stat_bootsec(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_uuid *uuid);

int silofs_repos_unlink_bootsec(struct silofs_repos *repos,
                                enum silofs_repo_mode repo_mode,
                                const struct silofs_uuid *uuid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repos_lookup_blob(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_blobid *blobid);

int silofs_repos_spawn_blob(struct silofs_repos *repos,
                            enum silofs_repo_mode repo_mode,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobf **out_blobf);

int silofs_repos_stage_blob(struct silofs_repos *repos, bool rw,
                            enum silofs_repo_mode repo_mode,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobf **out_blobf);

int silofs_repos_remove_blob(struct silofs_repos *repos,
                             enum silofs_repo_mode repo_mode,
                             const struct silofs_blobid *blobid);

int silofs_repos_require_blob(struct silofs_repos *repos,
                              enum silofs_repo_mode repo_mode,
                              const struct silofs_blobid *blobid,
                              struct silofs_blobf **out_blobf);

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
