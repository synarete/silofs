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
#ifndef SILOFS_ARCHIVE_H_
#define SILOFS_ARCHIVE_H_

#include <silofs/ondisk.h>
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/fs.h>
#include "index.h"

int silofs_do_preserve_fs(struct silofs_task_ctx *task,
                          struct silofs_mbref    *out_ar_mbref);

#endif /* SILOFS_ARCHIVE_H_ */
