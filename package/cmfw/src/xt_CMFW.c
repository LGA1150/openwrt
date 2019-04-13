/*
   Netfilter target which handle string replacing
*/
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/netfilter/x_tables.h>
#include <linux/textsearch.h>


MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_CMFW");

#define HTTP_REQ_STR "GET /"
#define HTTP_HOST_MAGIC "\nHost:"
#define TCP_MSS (ETH_DATA_LEN - sizeof(struct iphdr) - sizeof(struct tcphdr))
static DEFINE_PER_CPU(bool, cmfw_active);
static struct ts_config *ts_conf;

static unsigned int
cmfw_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct sk_buff *nskb;
	/*TCP Header*/
	struct tcphdr *tcph, *ntcph;
	/*IP Header*/
	struct iphdr *iph, *niph;
	/*Parameters from user-space*/	
	unsigned int pos;
	/*Packet Payload*/
	char *payload;
	/*Payload size*/
	int payload_size;
	int header_size;

	tcph = (struct tcphdr *)skb_transport_header(skb);
	iph = ip_hdr(skb);
	payload = (unsigned char *)tcph + tcph->doff * 4;
	payload_size = skb_tail_pointer(skb) - (unsigned char *)payload;
	header_size = (iph->ihl + tcph->doff) * 4;

	if (unlikely(__this_cpu_read(cmfw_active)))
		return XT_CONTINUE;

	/* Too small to be an HTTP request */
	if (payload_size < strlen(HTTP_REQ_STR)) {
		pr_debug("Too small to be an HTTP request");
		return XT_CONTINUE;
	}

	/* Probably not an HTTP GET request */
	if (strncmp(payload, HTTP_REQ_STR, strlen(HTTP_REQ_STR))) {
		pr_debug("Probably not an HTTP GET request");
		return XT_CONTINUE;
	}
	
	pos = skb_find_text(skb, header_size, skb->len, ts_conf);

	/* Not found */
	if (pos == UINT_MAX) {
		pr_debug("Not found");
		return XT_CONTINUE;
	}

	pr_debug("%u", pos);
	/* skb not linearizable */
	if (skb_linearize(skb) < 0) {
		pr_debug("skb not linearizable");
		return NF_DROP;
	}

	pos++;

	nskb = pskb_copy(skb, GFP_ATOMIC);
	ntcph = (struct tcphdr *)skb_transport_header(skb);
	niph = ip_hdr(skb);
	skb_trim(nskb, nskb->len - payload_size + pos);
	niph->tot_len = htons(ntohs(niph->tot_len) - payload_size + pos);
	ntcph->check = 0;
	ntcph->check = ~tcp_v4_check(nskb->len - 4*niph->ihl, niph->saddr, niph->daddr, 0);		
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)ntcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);
	// tcp_v4_send_check(nskb->sk, nskb);  // this line will cause kernel panic, don't know why
	__this_cpu_write(cmfw_active, true);
	ip_local_out(xt_net(par), nskb->sk, nskb);
	__this_cpu_write(cmfw_active, false);

	memmove(payload, payload + pos, payload_size - pos);
	skb_trim(skb, skb->len - pos);
	iph->tot_len = htons(ntohs(iph->tot_len) - pos);
	tcph->seq = htonl(ntohl(tcph->seq) + pos);
	tcph->psh = 0;
	tcph->check = 0;
	tcph->check = tcp_v4_check(skb->len - 4*iph->ihl, iph->saddr, iph->daddr, csum_partial((char *)tcph, skb->len-4*iph->ihl, 0));
	// tcp_v4_send_check(skb->sk, skb); // this line will cause kernel panic, don't know why
	ip_send_check(iph);
	return XT_CONTINUE;
}

static struct xt_target cmfw_tg_reg __read_mostly = {
	.name     = "CMFW",
	.revision = 0,
	.family   = NFPROTO_IPV4,
	.target   = cmfw_tg,
	.proto    = IPPROTO_TCP,
	.me       = THIS_MODULE,
};

static int __init cmfw_tg_init(void)
{
	ts_conf = textsearch_prepare("bm", HTTP_HOST_MAGIC, strlen(HTTP_HOST_MAGIC), GFP_ATOMIC, TS_AUTOLOAD);
	return xt_register_target(&cmfw_tg_reg);
}

static void __exit cmfw_tg_exit(void)
{
	textsearch_destroy(ts_conf);
	xt_unregister_target(&cmfw_tg_reg);
}

module_init(cmfw_tg_init);
module_exit(cmfw_tg_exit);
