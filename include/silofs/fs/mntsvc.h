/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_MNTSVC_H_
#define SILOFS_MNTSVC_H_

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <silofs/defs.h>

struct silofs_ms_env;

struct silofs_fsinfo {
	long vfstype;
	const char *name;
	bool allowed;
	bool isfuse;
};

struct silofs_mntrule {
	char *path;
	uid_t uid;
	bool  recursive;
};

struct silofs_mntrules {
	size_t nrules;
	struct silofs_mntrule rules[SILOFS_MNTRULE_MAX];
};

struct silofs_ms_args {
	const char *runstatedir;
	bool use_abstract;
};


int silofs_mse_new(const struct silofs_ms_args *ms_args,
                   struct silofs_ms_env **out_mse);

void silofs_mse_del(struct silofs_ms_env *mse);

int silofs_mse_serve(struct silofs_ms_env *mse,
                     const struct silofs_mntrules *mrules);

void silofs_mse_halt(struct silofs_ms_env *mse, int signum);


int silofs_mntrpc_handshake(uid_t uid, gid_t gid);

int silofs_mntrpc_mount(const char *mountpoint, uid_t uid, gid_t gid,
                        size_t max_read, unsigned long ms_flags,
                        bool allow_other, bool check_only, int *out_fd);

int silofs_mntrpc_umount(const char *mountpoint,  uid_t uid, gid_t gid,
                         unsigned int mnt_flags);

bool silofs_is_fuse_fstype(long fstype);

const struct silofs_fsinfo *silofs_fsinfo_by_vfstype(long vfstype);

int silofs_check_mntdir_fstype(long vfstype);

#endif /* SILOFS_MNTSVC_H_ */
