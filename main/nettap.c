
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "asterisk/logger.h"

char *__get_pcap_device() {
  char *dev; /* name of the device to use */ 
  char *net; /* dot notation of the network address */
  char *mask;/* dot notation of the network mask    */
  int ret;   /* return code */
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp; /* ip          */
  bpf_u_int32 maskp;/* subnet mask */
  struct in_addr addr;

  /* ask pcap to find a valid device for use to sniff on */
  dev = pcap_lookupdev(errbuf);

  /* error checking */
  if(dev == NULL) {
    ast_log(LOG_ERROR, "%s\n", errbuf);
    return NULL;
  }

  /* print out device name */
  ast_log(LOG_NOTICE, "DEV: %s\n", dev);

  /* ask pcap for the network address and mask of the device */
  ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

  if(ret == -1) {
    ast_log(LOG_ERROR, "%s\n", errbuf);
    return dev;
  }

  /* get the network address in a human readable form */
  addr.s_addr = netp;
  net = inet_ntoa(addr);

  if(net == NULL) {
    ast_log(LOG_ERROR, "inet_ntoa");
    return dev;
  }

  ast_log(LOG_NOTICE, "NET: %s\n", net);

  /* do the same as above for the device's mask */
  addr.s_addr = maskp;
  mask = inet_ntoa(addr);
  
  if(mask == NULL) {
    ast_log(LOG_ERROR, "inet_ntoa");
    return dev;
  }
  
  ast_log(LOG_NOTICE, "MASK: %s\n", mask);
  return dev;
}

void process_packet(u_char* user_data, const struct pcap_pkthdr* hdr, const u_char* packet) {
  ast_log(LOG_NOTICE, "Grabbed packet of length %d\n",hdr->len);
}

static void *nettap_thread(void *data) {
  ast_log(LOG_DEBUG, "Started Net Capture Thread\n");
  
  int i;
  char* dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
  const u_char *packet;
  struct pcap_pkthdr hdr;     /* pcap.h */
  struct ether_header *eptr;  /* net/ethernet.h */

  u_char *ptr; /* printing out hardware header info */

  dev = __get_pcap_device();

  if (dev == NULL) {
    ast_log(LOG_ERROR, "Couldn't get pcap device!!!!");
    return;
  }

  descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);

  if (descr == NULL) {
    ast_log(LOG_ERROR, "pcap_open_live(): %s\n", errbuf);
    return;
  }

  pcap_loop(descr, -1, process_packet, NULL);
}

static void ast_nettap_start()
{
  pthread_t t;

  /* Start the thread running. */
  if (ast_pthread_create_detached(&t, NULL, nettap_thread, NULL)) {
    ast_log(LOG_WARNING, "Failed to create nettap thread\n");
  }
}

int redroute_init_pcap() {
  ast_nettap_start();
}
