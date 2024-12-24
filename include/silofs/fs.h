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

#include <silofs/repo.h>
#include <silofs/pnodes.h>
#include <silofs/pcache.h>
#include <silofs/bstore.h>

#include <silofs/types.h>
#include <silofs/uidgid.h>
#include <silofs/idsmap.h>
#include <silofs/boot.h>
#include <silofs/spxmap.h>
#include <silofs/lnodes.h>
#include <silofs/lcache.h>
#include <silofs/encdec.h>
#include <silofs/task.h>
#include <silofs/super.h>
#include <silofs/stats.h>
#include <silofs/inode.h>
#include <silofs/dir.h>
#include <silofs/file.h>
#include <silofs/symlink.h>
#include <silofs/xattr.h>
#include <silofs/walk.h>
#include <silofs/opers.h>
#include <silofs/namei.h>
#include <silofs/vstage.h>
#include <silofs/spmaps.h>
#include <silofs/claim.h>
#include <silofs/fsenv.h>
#include <silofs/ustage.h>
#include <silofs/flush.h>
#include <silofs/mntsvc.h>
#include <silofs/pack.h>

#ifdef SILOFS_USE_PRIVATE
#include <silofs/fs-private.h>
#endif

#endif /* SILOFS_FS_H_ */
