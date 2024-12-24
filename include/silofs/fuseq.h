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
#ifndef SILOFS_FUSEQ_H_
#define SILOFS_FUSEQ_H_

#include <silofs/infra.h>

/* fuse-queue machinery */
struct silofs_fuseq_conn_info {
	size_t   buffsize;
	uint32_t kern_proto_major;
	uint32_t kern_proto_minor;
	uint32_t kern_cap;
	uint32_t proto_major;
	uint32_t proto_minor;
	uint32_t want_cap;
	uint32_t max_write;
	uint32_t max_read;
	uint32_t max_readahead;
	uint32_t max_background;
	uint32_t congestion_threshold;
	uint32_t time_gran;
	uint32_t max_pages;
} silofs_attr_aligned64;

struct silofs_fuseq_thread {
	struct silofs_thread th;
	struct silofs_fuseq *fq;
	uint32_t             idx;
	bool                 execed;
	bool                 joined;
	uint8_t              pad[2];
};

struct silofs_fuseq_worker {
	struct silofs_fuseq_thread fqw_th;
	uint32_t                   fqw_pad[3];
} silofs_attr_aligned64;

struct silofs_fuseq_dispatcher {
	struct silofs_oper_args      fqd_args;
	struct silofs_fuseq_thread   fqd_th;
	struct silofs_list_head      fqd_lh;
	struct silofs_fuseq_inb     *fqd_inb;
	struct silofs_fuseq_outb    *fqd_outb;
	struct silofs_fuseq_rw_iter *fqd_rwi;
	struct silofs_piper          fqd_piper;
	time_t                       fqd_time_stamp;
	volatile uint64_t            fqd_req_count;
	bool                         fqd_init_ok;
} silofs_attr_aligned64;

struct silofs_fuseq_subx {
	struct silofs_fuseq_worker     *fq_workers;
	struct silofs_fuseq_dispatcher *fq_disptchs;
	uint32_t                        fq_nworkers_lim;
	uint32_t                        fq_nworkers_run;
	uint32_t                        fq_ndisptch_lim;
	uint32_t                        fq_ndisptch_run;
};

struct silofs_fuseq {
	struct silofs_fuseq_subx      fq_subx;
	struct silofs_fuseq_conn_info fq_coni;
	struct silofs_mutex           fq_ch_lock;
	struct silofs_mutex           fq_op_lock;
	struct silofs_mutex           fq_ctl_lock;
	struct silofs_sem             fq_sem;
	struct silofs_fsenv          *fq_fsenv;
	struct silofs_alloc          *fq_alloc;
	struct silofs_listq           fq_curr_opers;
	size_t                        fq_selfsize;
	size_t                        fq_pagesize;
	int64_t                       fq_nexecs;
	int64_t                       fq_nopers;
	uid_t                         fq_fs_owner;
	volatile int                  fq_active;
	volatile int                  fq_fuse_fd;
	bool                          fq_init_locks;
	bool                          fq_got_init;
	bool                          fq_reply_init_ok;
	bool                          fq_got_destroy;
	bool                          fq_deny_others;
	bool                          fq_mount;
	bool                          fq_umount;
	bool                          fq_writeback_cache;
	bool                          fq_may_splice;
} silofs_attr_aligned64;

int silofs_fuseq_new(struct silofs_alloc *alloc, struct silofs_fuseq **out_fq);

void silofs_fuseq_del(struct silofs_fuseq *fq, struct silofs_alloc *alloc);

int silofs_fuseq_update(struct silofs_fuseq *fq);

int silofs_fuseq_mount(struct silofs_fuseq *fq, struct silofs_fsenv *fsenv,
                       const char *path);

int silofs_fuseq_exec(struct silofs_fuseq *fq);

void silofs_fuseq_term(struct silofs_fuseq *fq);

void silofs_guarantee_fuse_proto(void);

#endif /* SILOFS_FUSEQ_H_ */
