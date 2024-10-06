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
#ifndef SILOFS_FS_H_
#define SILOFS_FS_H_

#include <silofs/consts.h>
#include <silofs/errors.h>
#include <silofs/defs.h>
#include <silofs/ioctls.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <silofs/ps.h>

#include <silofs/fs/types.h>
#include <silofs/fs/uidgid.h>
#include <silofs/fs/idmap.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/lcache.h>
#include <silofs/fs/lnodes.h>
#include <silofs/fs/encdec.h>
#include <silofs/fs/task.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stats.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>
#include <silofs/fs/walk.h>
#include <silofs/fs/opers.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/vstage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/claim.h>
#include <silofs/fs/fsenv.h>
#include <silofs/fs/ustage.h>
#include <silofs/fs/flush.h>
#include <silofs/fs/mntsvc.h>
#include <silofs/fs/pack.h>

#ifdef SILOFS_HAVE_PRIVATE
#include <silofs/fs-private.h>
#endif

#endif /* SILOFS_FS_H_ */
