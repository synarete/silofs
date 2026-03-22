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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/fs.h>
#include <silofs/fuse/fuse_abi.h>
#include <silofs/fuse/fqtypes.h>

#define FUSEQ_HDR_IN_SIZE (40)

#define REQUIRE_SIZEOF(type, size) \
	SILOFS_STATICASSERT(((sizeof(type) == (size)) && ((size) % 8) == 0))

#define REQUIRE_OFFSET(type, member, offset) \
	SILOFS_STATICASSERT_EQ(offsetof(type, member), offset)

#define REQUIRE_BASEOF(type, member) \
	REQUIRE_OFFSET(type, member, FUSEQ_HDR_IN_SIZE)

void silofs_guarantee_fuse_proto(void)
{
	REQUIRE_SIZEOF(struct fuse_in_header, 40);
	REQUIRE_SIZEOF(struct fuse_rename_in, 8);
	REQUIRE_SIZEOF(struct fuse_rename2_in, 16);
	REQUIRE_SIZEOF(struct fuse_setxattr1_in, FUSE_COMPAT_SETXATTR_IN_SIZE);
	REQUIRE_SIZEOF(struct silofs_fuseq_hdr_in, FUSEQ_HDR_IN_SIZE);
	REQUIRE_OFFSET(struct silofs_fuseq_hdr_in, hdr, 0);
	REQUIRE_SIZEOF(struct silofs_fuseq_init_in, 104);
	REQUIRE_BASEOF(struct silofs_fuseq_init_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_setattr_in, 128);
	REQUIRE_BASEOF(struct silofs_fuseq_setattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_lookup_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_lookup_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_forget_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_forget_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_getattr_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_getattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_symlink_in, 4648);
	REQUIRE_BASEOF(struct silofs_fuseq_symlink_in, name_target);
	REQUIRE_SIZEOF(struct silofs_fuseq_mknod_in, 568);
	REQUIRE_BASEOF(struct silofs_fuseq_mknod_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_mkdir_in, 560);
	REQUIRE_BASEOF(struct silofs_fuseq_mkdir_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_mkdir_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_unlink_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_unlink_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_rmdir_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_rmdir_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_rename_in, 1072);
	REQUIRE_BASEOF(struct silofs_fuseq_rename_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_rename_in, name_newname, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_link_in, 560);
	REQUIRE_BASEOF(struct silofs_fuseq_link_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_link_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_open_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_open_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_release_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_release_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_fsync_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_fsync_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_fsync_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_fsync_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_setxattr1_in, 2608);
	REQUIRE_BASEOF(struct silofs_fuseq_setxattr1_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_setxattr1_in, name_value, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_setxattr_in, 2616);
	REQUIRE_BASEOF(struct silofs_fuseq_setxattr_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_setxattr_in, name_value, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_getxattr_in, 560);
	REQUIRE_BASEOF(struct silofs_fuseq_getxattr_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_getxattr_in, name, 48);
	REQUIRE_SIZEOF(struct silofs_fuseq_listxattr_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_listxattr_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_removexattr_in, 552);
	REQUIRE_BASEOF(struct silofs_fuseq_removexattr_in, name);
	REQUIRE_SIZEOF(struct silofs_fuseq_flush_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_flush_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_opendir_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_opendir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_readdir_in, 80);
	REQUIRE_BASEOF(struct silofs_fuseq_readdir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_releasedir_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_releasedir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_fsyncdir_in, 56);
	REQUIRE_BASEOF(struct silofs_fuseq_fsyncdir_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_access_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_access_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_create_in, 568);
	REQUIRE_BASEOF(struct silofs_fuseq_create_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_create_in, name, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_interrupt_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_interrupt_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_interrupt_in, 48);
	REQUIRE_BASEOF(struct silofs_fuseq_interrupt_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_ioctl_in, 4168);
	REQUIRE_BASEOF(struct silofs_fuseq_ioctl_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_ioctl_in, buf, 72);
	REQUIRE_SIZEOF(struct silofs_fuseq_rename2_in, 1080);
	REQUIRE_BASEOF(struct silofs_fuseq_rename2_in, arg);
	REQUIRE_OFFSET(struct silofs_fuseq_rename2_in, name_newname, 56);
	REQUIRE_SIZEOF(struct silofs_fuseq_lseek_in, 64);
	REQUIRE_BASEOF(struct silofs_fuseq_lseek_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_read_in, 80);
	REQUIRE_BASEOF(struct silofs_fuseq_read_in, arg);
	REQUIRE_SIZEOF(struct silofs_fuseq_copy_file_range_in, 96);
	REQUIRE_BASEOF(struct silofs_fuseq_copy_file_range_in, arg);
}
