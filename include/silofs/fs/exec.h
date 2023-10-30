/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_EXEC_H_
#define SILOFS_EXEC_H_

/* initialization configurations */
struct silofs_iconf {
	struct silofs_namebuf   name;
	struct silofs_uuid      uuid;
	struct silofs_ids       ids;
};

/* file-system input arguments */
struct silofs_fs_args {
	struct silofs_iconf     iconf;
	const char             *repodir;
	const char             *name;
	const char             *mntdir;
	const char             *passwd;
	uid_t                   uid;
	gid_t                   gid;
	pid_t                   pid;
	mode_t                  umask;
	size_t                  capacity;
	size_t                  memwant;
	bool                    withfuse;
	bool                    pedantic;
	bool                    allowother;
	bool                    allowhostids;
	bool                    allowadmin;
	bool                    writeback_cache;
	bool                    lazytime;
	bool                    noexec;
	bool                    nosuid;
	bool                    nodev;
	bool                    rdonly;
	bool                    asyncwr;
	bool                    stdalloc;
};

/* file-system environment context */
struct silofs_fs_env {
	struct silofs_fs_args   fs_args;
	struct silofs_bootpath  fs_bootpath;
	struct silofs_ivkey     fs_boot_ivkey;
	struct silofs_ivkey     fs_main_ivkey;
	struct silofs_qalloc   *fs_qalloc;
	struct silofs_calloc   *fs_calloc;
	struct silofs_alloc    *fs_alloc;
	struct silofs_cache    *fs_cache;
	struct silofs_repo     *fs_repo;
	struct silofs_submitq  *fs_submitq;
	struct silofs_idsmap   *fs_idsmap;
	struct silofs_uber     *fs_uber;
	struct silofs_fuseq    *fs_fuseq;
	struct silofs_password *fs_passwd;
	struct silofs_uaddr     fs_sb_addr;
	int                     fs_signum;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fse_new(const struct silofs_fs_args *args,
                   struct silofs_fs_env **out_fse);

void silofs_fse_del(struct silofs_fs_env *fse);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_repo(struct silofs_fs_env *fse);

int silofs_open_repo(struct silofs_fs_env *fse);

int silofs_close_repo(struct silofs_fs_env *fse);

int silofs_format_fs(struct silofs_fs_env *fse,
                     struct silofs_treeid *out_treeid);

int silofs_boot_fs(struct silofs_fs_env *fse,
                   const struct silofs_treeid *treeid);

int silofs_open_fs(struct silofs_fs_env *fse);

int silofs_poke_fs(struct silofs_fs_env *fse,
                   const struct silofs_treeid *out_treeid,
                   struct silofs_bootrec *out_brec);

int silofs_close_fs(struct silofs_fs_env *fse);

int silofs_exec_fs(struct silofs_fs_env *fse);

int silofs_post_exec_fs(const struct silofs_fs_env *fse);

int silofs_fork_fs(struct silofs_fs_env *fse,
                   struct silofs_treeid *out_new,
                   struct silofs_treeid *out_alt);

int silofs_inspect_fs(struct silofs_fs_env *fse, silofs_visit_laddr_fn cb);

int silofs_unref_fs(struct silofs_fs_env *fse,
                    const struct silofs_treeid *treeid);

void silofs_halt_fs(struct silofs_fs_env *fse, int signum);

int silofs_sync_fs(struct silofs_fs_env *fse, bool drop);

void silofs_stat_fs(const struct silofs_fs_env *fse,
                    struct silofs_cachestats *st);

#endif /* SILOFS_EXEC_H_ */
