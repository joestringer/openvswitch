#include <linux/skbuff.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("bpf_simple")
int bpf_simple(struct sk_buff *skb)
{
	char fmt[] = "skb %x \n";

	bpf_printk(fmt, sizeof(fmt), skb);

	return 0;
}

char _license[] SEC("license") = "GPL";
