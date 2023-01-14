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
#ifndef SILOFS_TASK_H_
#define SILOFS_TASK_H_

void silofs_task_init(struct silofs_task *task, struct silofs_uber *uber);

void silofs_task_fini(struct silofs_task *task);

void silofs_task_set_creds(struct silofs_task *task,
                           uid_t uid, gid_t gid, pid_t pid);

void silofs_task_set_umask(struct silofs_task *task, mode_t umask);

void silofs_task_set_ts(struct silofs_task *task, bool rt);

struct silofs_alloc *silofs_task_alloc(const struct silofs_task *task);

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task);

const struct silofs_creds *silofs_task_creds(const struct silofs_task *task);

#endif /* SILOFS_TASK_H_ */




