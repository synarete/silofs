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
#ifndef SILOFS_FS_H_
#define SILOFS_FS_H_

#include <silofs/infra.h>
#include <silofs/fsdef.h>
#include <silofs/errors.h>
#include <silofs/types.h>
#include <silofs/ioctls.h>
#include <silofs/address.h>
#include <silofs/boot.h>
#include <silofs/nodes.h>
#include <silofs/zcmpr.h>
#include <silofs/crypto.h>
#include <silofs/spxmap.h>
#include <silofs/cache.h>
#include <silofs/repo.h>
#include <silofs/super.h>
#include <silofs/stats.h>
#include <silofs/idmap.h>
#include <silofs/itable.h>
#include <silofs/inode.h>
#include <silofs/dir.h>
#include <silofs/file.h>
#include <silofs/symlink.h>
#include <silofs/xattr.h>
#include <silofs/task.h>
#include <silofs/opers.h>
#include <silofs/namei.h>
#include <silofs/stage.h>
#include <silofs/spmaps.h>
#include <silofs/spclaim.h>
#include <silofs/uber.h>
#include <silofs/kcopy.h>
#include <silofs/exec.h>
#include <silofs/walk.h>
#include <silofs/pack.h>
#include <silofs/mntsvc.h>

#endif /* SILOFS_FS_H_ */
