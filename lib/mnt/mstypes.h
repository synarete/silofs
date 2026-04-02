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
#ifndef SILOFS_MSTYPES_H_
#define SILOFS_MSTYPES_H_

#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>

#include <silofs/ondisk.h>
#include <silofs/mntsvc.h>
#include <silofs/base.h>
#include <silofs/str.h>

enum silofs_mntcmd {
	SILOFS_MNTCMD_NONE      = 0,
	SILOFS_MNTCMD_HANDSHAKE = 1,
	SILOFS_MNTCMD_MOUNT     = 2,
	SILOFS_MNTCMD_UMOUNT    = 3,
};

struct silofs_mntmsg {
	uint32_t mn_magic;
	uint16_t mn_version_major;
	uint16_t mn_version_minor;
	uint32_t mn_cmd;
	uint32_t mn_status;
	uint64_t mn_flags;
	uint32_t mn_user_id;
	uint32_t mn_group_id;
	uint32_t mn_root_mode;
	uint32_t mn_max_read;
	uint8_t  mn_allowother;
	uint8_t  mn_checkonly;
	uint8_t  mn_reserved2[86];
	uint8_t  mn_path[SILOFS_MNTPATH_MAX];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_mntparams {
	const char *path;
	uint64_t    flags;
	uid_t       user_id;
	gid_t       group_id;
	mode_t      root_mode;
	size_t      max_read;
	bool        allowother;
	bool        checkonly;
};

struct silofs_mntclnt {
	struct silofs_socket   mc_sock;
	struct silofs_sockaddr mc_srvaddr;
};

struct silofs_mntsvc {
	char                   ms_peer_ids[64];
	struct silofs_sockaddr ms_peer;
	struct ucred           ms_peer_ucred;
	struct silofs_mntsrv  *ms_srv;
	struct silofs_socket   ms_asock;
	uint32_t               ms_page_size;
	int                    ms_fuse_fd;
	int                    ms_mntd_fd;

	struct silofs_mntmsg ms_mmsg;
} silofs_attr_aligned64;

struct silofs_mntsrv {
	struct silofs_ms_args         ms_args;
	const struct silofs_mntrules *ms_rules;
	struct silofs_socket          ms_lsock;
	struct silofs_mntsvc          ms_svc;
};

struct silofs_ms_env {
	struct silofs_mntsrv *ms_srv;
	int                   ms_active;
	int                   ms_signum;
};

#endif /* SILOFS_MSTYPES_H_ */
