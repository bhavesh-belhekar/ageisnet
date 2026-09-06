// SPDX-License-Identifier: GPL-2.0
/* Shared definitions for capture.bpf.c / smoke.c (L3 parity smoke). */
#ifndef __CAPTURE_COMMON_H
#define __CAPTURE_COMMON_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

struct capture_evt {
	__u32 netns;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 protocol;
	__u8 type; /* 1 = open, 2 = close */
	__u8 reserve;
	__u64 sent;
	__u64 recv;
	__u32 pid;
};

#endif /* __CAPTURE_COMMON_H */