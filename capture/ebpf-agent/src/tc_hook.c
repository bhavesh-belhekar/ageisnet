#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

SEC("classifier")
int tc_ingress_egress(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";