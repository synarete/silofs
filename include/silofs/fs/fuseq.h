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
#ifndef SILOFS_FUSEQ_H_
#define SILOFS_FUSEQ_H_


/* fuse-q machinery */
struct silofs_fuseq_conn_info {
	uint32_t        kern_proto_major;
	uint32_t        kern_proto_minor;
	uint32_t        kern_cap;
	uint32_t        proto_major;
	uint32_t        proto_minor;
	uint32_t        want_cap;
	size_t          pagesize;
	size_t          buffsize;
	uint32_t        max_write;
	uint32_t        max_read;
	uint32_t        max_readahead;
	uint32_t        max_background;
	uint32_t        congestion_threshold;
	uint32_t        time_gran;
	uint32_t        max_pages;
} silofs_aligned64;

struct silofs_fuseq_worker {
	struct silofs_thread            fw_th;
	struct silofs_list_head         fw_lh;
	struct silofs_fuseq            *fw_fq;
	struct silofs_fuseq_inb        *fw_inb;
	struct silofs_fuseq_outb       *fw_outb;
	struct silofs_fuseq_rw_iter    *fw_rwi;
	struct silofs_oper_args        *fw_args;
	struct silofs_piper             fw_piper;
	time_t                          fw_time_stamp;
	volatile uint64_t               fw_req_count;
	uint32_t                        fw_index;
	bool                            fw_leader;
	bool                            fw_init_ok;
} silofs_aligned64;

struct silofs_fuseq {
	struct silofs_fuseq_worker      fq_workers[4];
	struct silofs_fuseq_conn_info   fq_coni;
	struct silofs_mutex             fq_ch_lock;
	struct silofs_mutex             fq_op_lock;
	struct silofs_mutex             fq_ctl_lock;
	struct silofs_fsenv            *fq_fsenv;
	struct silofs_alloc            *fq_alloc;
	struct silofs_listq             fq_curr_opers;
	size_t                          fq_nopers;
	size_t                          fq_nopers_done;
	size_t                          fq_ntimedout;
	uid_t                           fq_fs_owner;
	int32_t                         fq_nexecs;
	uint32_t                        fq_nworkers_lim;
	uint32_t                        fq_nworkers_run;
	volatile int                    fq_active;
	volatile int                    fq_fuse_fd;
	bool                            fq_init_locks;
	bool                            fq_got_init;
	bool                            fq_reply_init_ok;
	bool                            fq_got_destroy;
	bool                            fq_deny_others;
	bool                            fq_mount;
	bool                            fq_umount;
	bool                            fq_writeback_cache;
	bool                            fq_may_splice;
} silofs_aligned64;


int silofs_fuseq_init(struct silofs_fuseq *fq, struct silofs_alloc *alloc);

void silofs_fuseq_fini(struct silofs_fuseq *fq);

int silofs_fuseq_update(struct silofs_fuseq *fq);

int silofs_fuseq_mount(struct silofs_fuseq *fq,
                       struct silofs_fsenv *fsenv, const char *path);

int silofs_fuseq_exec(struct silofs_fuseq *fq);

void silofs_fuseq_term(struct silofs_fuseq *fq);

void silofs_guarantee_fuse_proto(void);

#endif /* SILOFS_FUSEQ_H_ */
