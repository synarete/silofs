/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_KNOWNFS_H_
#define SILOFS_KNOWNFS_H_

/* suber-block magin-numbers of own file-systems */
#define FUSE_SUPER_MAGIC      0x65735546 /*  from kernel 'fs/fuse/inode.c' */
#define TMPFS_MAGIC           0x01021994
#define XFS_SB_MAGIC          0x58465342
#define EXT234_SUPER_MAGIC    0x0000EF53
#define ZFS_SUPER_MAGIC       0x2FC12FC1
#define BTRFS_SUPER_MAGIC     0x9123683E
#define CEPH_SUPER_MAGIC      0x00C36400
#define CIFS_MAGIC_NUMBER     0xFF534D42
#define ECRYPTFS_SUPER_MAGIC  0x0000F15F
#define F2FS_SUPER_MAGIC      0xF2F52010
#define NFS_SUPER_MAGIC       0x00006969
#define NTFS_SB_MAGIC         0x5346544E
#define OVERLAYFS_SUPER_MAGIC 0x794C7630

#endif /* SILOFS_KNOWNFS_H_ */
