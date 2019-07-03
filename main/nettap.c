
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "asterisk/logger.h"
#include "asterisk/network.h"
#include "asterisk/utils.h"



void log_addr (char* label, bpf_u_int32 address) {
  struct in_addr addr;
  addr.s_addr = address;
  ast_log(LOG_NOTICE, "%s: %s\n",label, ast_inet_ntoa(addr));
}

int perform_filter(pcap_t* descr, struct bpf_program* fp, bpf_u_int32 net_ip, bpf_u_int32 mask_ip) {
  char buf[256];
  struct in_addr addr;
  addr.s_addr = net_ip;

  sprintf(buf, "ip proto udp dst net %s", ast_inet_ntoa(addr));
  /* filter for UDP (RTP) traffic only */
  if(pcap_compile(descr, fp, buf, 0, mask_ip) == -1) { ast_log(LOG_ERROR, "Error calling pcap_compile\n"); return 1; }
  if(pcap_setfilter(descr, fp) == -1) { ast_log(LOG_ERROR,"Error setting filter\n"); return 1; }

  return 0;
}

void __process_packet(u_char* user_data, const struct pcap_pkthdr* hdr, const u_char* packet) {
  struct ip* ip_hdr;
  struct udphdr* udp_hdr;
  
  ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
  udp_hdr = (struct udphdr*)(ip_hdr + 1);
  ast_log(LOG_NOTICE, "packet len: %d ip ver: %d from: %s:%d to: %s:%d\n",hdr->len, ip_hdr->ip_v,
    ast_inet_ntoa(ip_hdr->ip_src), udp_hdr->uh_sport, ast_inet_ntoa(ip_hdr->ip_dst), udp_hdr->uh_dport);
}

static void __nettap_thread(void *data) {
  int ret;
  char* dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
  bpf_u_int32 net_ip;
  bpf_u_int32 mask_ip;
  struct bpf_program fp;

  /*u_char *ptr;  printing out hardware header info */

  ast_log(LOG_DEBUG, "Started Net Capture Thread\n");

  dev = pcap_lookupdev(errbuf);

  if (dev == NULL) { ast_log(LOG_ERROR, "Couldn't get pcap device!!!!"); return; }

  ret = pcap_lookupnet(dev, &net_ip, &mask_ip, errbuf);
  if(ret == -1) { ast_log(LOG_ERROR, "%s\n", errbuf); return dev; }

  log_addr("NET:", net_ip);
  log_addr("MASK:", mask_ip);

  descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);

  if (descr == NULL) { ast_log(LOG_ERROR, "pcap_open_live(): %s\n", errbuf); return;}

  if (perform_filter(descr, &fp, net_ip, mask_ip)) { return; }

  pcap_loop(descr, -1, __process_packet, NULL);
}

static void __ast_nettap_start()
{
  pthread_t t;

  /* Start the thread running. */
  if (ast_pthread_create_detached(&t, NULL, __nettap_thread, NULL)) {
    ast_log(LOG_WARNING, "Failed to create nettap thread\n");
  }
}

void redroute_init_pcap() {
  __ast_nettap_start();
}
