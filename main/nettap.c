
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "asterisk/logger.h"

int redroute_init_pcap() {
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
    return 1;
  }

  /* print out device name */
  ast_log(LOG_NOTICE, "DEV: %s\n", dev);

  /* ask pcap for the network address and mask of the device */
  ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

  if(ret == -1) {
    ast_log(LOG_ERROR, "%s\n", errbuf);
    return 1;
  }

  /* get the network address in a human readable form */
  addr.s_addr = netp;
  net = inet_ntoa(addr);

  if(net == NULL)/* thanks Scott :-P */
  {
    ast_log(LOG_ERROR, "inet_ntoa");
    return 1;
  }

  ast_log(LOG_NOTICE, "NET: %s\n", net);

  /* do the same as above for the device's mask */
  addr.s_addr = maskp;
  mask = inet_ntoa(addr);
  
  if(mask == NULL)
  {
    ast_log(LOG_ERROR, "inet_ntoa");
    return 1;
  }
  
  ast_log(LOG_NOTICE, "MASK: %s\n", mask);

  return 0;
}
