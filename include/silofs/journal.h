/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_JOURNAL_H_
#define SILOFS_JOURNAL_H_

void silofs_seal_jrec(struct silofs_journal_rec *jrec);

int silofs_verify_jrec(const struct silofs_journal_rec *jrec);

void silofs_jrec_by_sqe(struct silofs_journal_rec *jrec,
                        const struct silofs_submitq_ent *sqe);

#endif /* SILOFS_JOURNAL_H_ */
