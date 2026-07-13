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
#ifndef SILOFS_FS_H_
#define SILOFS_FS_H_

#include <silofs/macros.h>
#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pstor.h>
#include <silofs/vfs.h>

#include <silofs/fs/pglue.h>
#include <silofs/fs/lspace.h>
#include <silofs/fs/super.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/inops.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/file.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>
#include <silofs/fs/task.h>
#include <silofs/fs/format.h>

#endif /* SILOFS_FS_H_ */
