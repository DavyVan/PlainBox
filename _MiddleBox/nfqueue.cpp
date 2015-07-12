#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <cerrno>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pcap.h>
#include "nfqueue.h"

static struct nfq_handle *h;
static struct nfq_q_handle *qh;

extern int got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet);
extern int drop;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	uint32_t id = 0;
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("------------------------------------------------id=%d\n", id);
		//hw_protocol = ntohs(ph->hw_protocol);
	}

    unsigned char *ibuf;
    int len = nfq_get_payload(nfa, &ibuf);
//    pkt->setIbuf(ibuf, len);

    //do something
    //for (int i = 0; i < 20; ++i) printf("%02x ", ibuf[i]);printf("\n");
    got_packet(NULL, NULL, ibuf-14);

	
	if (drop) {//DROP packet
	    printf("#####################nfqueue drop! id=%d\n", id);
	    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	} else {
    	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

static void iptables_start()
{puts("iptables_start()");
    int ret;
//    ret = system("ip6tables -t raw -A PREROUTING -j NFQUEUE --queue-num 0");
    ret = system("iptables  -A FORWARD -j NFQUEUE --queue-num 0");
    
    ret = system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    ret = system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    
    ret = system("sysctl net.ipv4.ip_forward=1");
}

static void iptables_stop()
{puts("iptables_stop()");
    int ret;
//    ret = system("ip6tables -t raw -D PREROUTING -j NFQUEUE --queue-num 0");
    ret = system("iptables  -D FORWARD -j NFQUEUE --queue-num 0");
//    ret = system("iptables -t raw -D POSTROUTING -j NFQUEUE --queue-num 0");

    ret = system("iptables -D INPUT -j NFQUEUE --queue-num 0");
    ret = system("iptables -D OUTPUT -j NFQUEUE --queue-num 0");

}

int nfqueue_init()
{
    iptables_start();
	struct nfnl_handle *nh;
	int fd;

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);
	return fd;
}

void nfqueue_handle(char *buf, int len)
{
    nfq_handle_packet(h, buf, len);
}

void nfqueue_close()
{
    iptables_stop();
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);printf("unbind ok\n");

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);
}


