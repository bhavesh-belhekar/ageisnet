#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "capture_common.h"

/* TCP state values from include/net/tcp_states.h */
#define TCP_ESTABLISHED 1
#define CLOSE_MASK (4 | 6 | 7 | 9) /* FIN_WAIT1 | TIME_WAIT | CLOSE | LAST_ACK */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} sent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} recv SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u8);
} opened SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u8);
} done SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/*
 * netns ownership lives on the socket itself (sk->__sk_common.skc_net),
 * resolvable via CO-RE (this kernel moved it off the old sk_sk_net path,
 * which is why bpftrace type-resolution failed on it).
 */
static __always_inline __u32 sock_netns(struct sock *sk)
{
	struct net *net;
	__u32 inum;

	net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
	if (!net)
		return 0;
	inum = BPF_CORE_READ(net, ns.inum);
	return inum;
}

static __always_inline void submit_evt(
	__u64 key, __u8 type, __u32 pid, __u16 protocol,
	__u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
	const struct sock *skaddr)
{
	struct capture_evt *evt;

	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;
	evt->netns = sock_netns((struct sock *)skaddr);
	evt->saddr = saddr;
	evt->daddr = daddr;
	evt->sport = sport;
	evt->dport = dport;
	evt->protocol = protocol;
	evt->type = type;
	evt->pid = pid;
	evt->reserve = 0;
	{
		__u64 *s = bpf_map_lookup_elem(&sent, &key);
		__u64 *r = bpf_map_lookup_elem(&recv, &key);
		evt->sent = s ? *s : 0;
		evt->recv = r ? *r : 0;
	}
	bpf_ringbuf_submit(evt, 0);
}

SEC("tracepoint/sock/inet_sock_set_state")
int tp_sock_state(struct trace_event_raw_inet_sock_set_state *t)
{
	__u64 key;
	__u32 pid;
	__u8 one = 1;
	__u32 saddr, daddr;

	if (t->family != 2 || t->protocol != 6)
		return 0;
	key = (__u64)t->skaddr;
	pid = bpf_get_current_pid_tgid() >> 32;

	/* saddr/daddr are 4-byte aligned __u8 arrays in network order */
	saddr = *(__u32 *)&t->saddr[0];
	daddr = *(__u32 *)&t->daddr[0];

	if (t->newstate == TCP_ESTABLISHED) {
		if (bpf_map_lookup_elem(&opened, &key))
			return 0;
		bpf_map_update_elem(&opened, &key, &one, BPF_ANY);
		/* clear stale state from a previous life of this sk address */
		bpf_map_delete_elem(&done, &key);
		bpf_map_delete_elem(&sent, &key);
		bpf_map_delete_elem(&recv, &key);
		submit_evt(key, 1, pid, t->protocol, saddr, daddr, t->sport,
			   t->dport, t->skaddr);
	} else if ((t->newstate == 4 || t->newstate == 6 ||
		    t->newstate == 7 || t->newstate == 9)) {
		if (bpf_map_lookup_elem(&done, &key))
			return 0;
		bpf_map_update_elem(&done, &key, &one, BPF_ANY);
		submit_evt(key, 2, pid, t->protocol, saddr, daddr, t->sport,
			   t->dport, t->skaddr);
		bpf_map_delete_elem(&sent, &key);
		bpf_map_delete_elem(&recv, &key);
		bpf_map_delete_elem(&opened, &key);
	}
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	__u64 key = (__u64)sk;
	__u64 *v = bpf_map_lookup_elem(&sent, &key);
	__u64 n = (__u64)len;

	if (v)
		__sync_fetch_and_add(v, n);
	else
		bpf_map_update_elem(&sent, &key, &n, BPF_ANY);
	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kp_cleanup_rbuf, struct sock *sk, int copied)
{
	__u64 key = (__u64)sk;
	__u64 *v;
	__u64 n;

	if (copied <= 0)
		return 0;
	v = bpf_map_lookup_elem(&recv, &key);
	n = (__u64)copied;
	if (v)
		__sync_fetch_and_add(v, n);
	else
		bpf_map_update_elem(&recv, &key, &n, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";