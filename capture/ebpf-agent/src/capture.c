// SPDX-License-Identifier: GPL-2.0
/*
 * Production CO-RE capture binary (evolved from the L3 parity smoke).
 *
 * Loads the CO-RE tracepoint (sock/inet_sock_set_state) + 2 legacy kprobes
 * (tcp_sendmsg, tcp_cleanup_rbuf) via libbpf, polls the ring buffer and
 * prints each event on one line in the loader's pipe contract:
 *
 *   EVTO|netns|saddr|daddr|sport|dport|sent|recv|pid    (open)
 *   EVTC|netns|saddr|daddr|sport|dport|sent|recv|pid    (close)
 *
 * netns is the socket-owner network namespace inode (CO-RE read of
 * sk->__sk_common.skc_net), so attribution is independent of the task
 * context running the state transition. stdout is reserved for pipe lines;
 * diagnostics go to stderr. Exits non-zero if it cannot load/attach, per
 * RULES.md Section 4.2 (never run half-working).
 *
 * Optional positional arg in milliseconds bounds the run (parity harness).
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <arpa/inet.h>

#include "capture_common.h"
#include "capture.skel.h"

#define VMLINUX_HINT "/sys/kernel/btf/vmlinux"

static volatile sig_atomic_t stop;

static void sig_handler(int sig)
{
	(void)sig;
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	struct capture_evt *e = data;
	char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
	const char *prefix;

	(void)ctx;
	if (sz != sizeof(*e))
		return 0;
	inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));
	prefix = e->type == 1 ? "EVTO" : "EVTC";
	printf("%s|%u|%s|%s|%u|%u|%llu|%llu|%u\n",
	       prefix, e->netns, saddr, daddr, e->sport, e->dport,
	       (unsigned long long)e->sent, (unsigned long long)e->recv, e->pid);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	struct capture_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	int ms = 0, iterations = -1;

	if (argc > 1)
		ms = atoi(argv[1]);
	if (ms > 0)
		iterations = ms / 200;
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = capture_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr,
			"eBPF capture failed to load (errno=%d %s)\n"
			"  hook: tracepoint/sock/inet_sock_set_state "
			"(needs CONFIG_DEBUG_INFO_BTF + BTF vmlinux at %s)\n"
			"  hook: kprobe tcp_sendmsg, kprobe tcp_cleanup_rbuf "
			"(needs kernel symbols present)\n"
			"  requirement: CAP_BPF/CAP_NET_ADMIN/CAP_SYS_ADMIN  "
			"(or root/privileged host)\n"
			"  check: /sys/kernel/btf/vmlinux exists in the "
			"container and bpftool/clang versions from the image\n",
			errno, strerror(errno), VMLINUX_HINT);
		return 1;
	}

	err = capture_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "eBPF capture attach failed: %d %s\n",
			err, strerror(-err));
		return 1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ringbuf new failed\n");
		return 1;
	}

	fprintf(stderr, "capture attached; poll loop running\n");
	while (!stop && iterations != 0) {
		ring_buffer__poll(rb, 200);
		if (iterations > 0)
			iterations--;
	}
	ring_buffer__free(rb);
	capture_bpf__destroy(skel);
	return 0;
}