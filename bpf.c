#include <stddef.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)
	
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
        (void *) BPF_FUNC_skb_store_bytes;


static long (*bpf_skb_load_bytes)(const void *skb, int offset, void *to, int len) = (void*) BPF_FUNC_skb_load_bytes;
		
		
int modudp(struct __sk_buff *skb);

SEC("modudp")
int main_modup(struct __sk_buff *skb)
{
	/* We will access all data through pointers to structs */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
		return TC_ACT_UNSPEC;

	/* for easy access we re-use the Kernel's struct definitions */
	struct ethhdr  *eth  = data;
	struct iphdr   *ip   = (data + sizeof(struct ethhdr));
	struct udphdr  *udp  = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	
	char udppayload[100];
	

	/* Only actual IP packets are allowed */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	/* We handle only UDP traffic */
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_UNSPEC;
	

	__be16 size = __constant_htons(1);
	if (udp->len < size)
		return TC_ACT_UNSPEC;
//	__u32 udp_len = __constant_htons(udp->len);
	__u32 udp_len = bpf_ntohs(udp->len);
	if(udp_len<=1){
		return TC_ACT_UNSPEC;
	}
    long err=0;
	if (udp_len == 40){
		
    	err = bpf_skb_load_bytes(skb,sizeof(struct ethhdr) + sizeof(struct iphdr) ,udppayload,40);
	}
	else if(udp_len == 64){
    	err = bpf_skb_load_bytes(skb,sizeof(struct ethhdr) + sizeof(struct iphdr) ,udppayload,64);
	}
    else return TC_ACT_UNSPEC;		
    if(err){
		trace_printk("error N %d", err);
		return TC_ACT_UNSPEC;
	}
	
	/* Let's grab the IP addresses.
	 * They are 32-bit, so it is easy to access */
	__u32 src_ip = ip->saddr;
	__u32 dst_ip = ip->daddr;

//	trace_printk("[action] IP Packet, proto= %d, src= %lu, dst= %lu\n", ip->protocol, src_ip, dst_ip);
//	for(int i=0; i<2; i++){
//		trace_printk("%d",udppayload[i]);
//	}
	if((udppayload[8]==1)&(udppayload[9]==1))trace_printk("udplen= %d\n", udp_len);
	__u32 msg_cook = *(__u32*)(udppayload+12);
    __u32 msg_cookie = ((__u32)udppayload[12] << 24) + (((__u32)udppayload[13]+1) << 16) + ((__u32)udppayload[14] << 8) + (__u32)udppayload[15];
	trace_printk("message cookie %d", msg_cookie);
	trace_printk("cookie2 %d", udppayload[13] << 16);
	__u32 c = bpf_htonl(((201<<24)+(202<<16)+(203<<8)+204) ^ bpf_htonl(msg_cook));
	int off = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if(udp_len == 40){
		err = bpf_skb_store_bytes(skb, off+36, &c, sizeof(c), BPF_F_RECOMPUTE_CSUM);
//		err = bpf_skb_store_bytes(skb, off+38, &c, sizeof(c), BPF_F_RECOMPUTE_CSUM);
	}
    if(err) trace_printk("error store %d", err);
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
