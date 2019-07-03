#ifndef _ASTERISK_NETCAP_H
#define _ASTERISK_NETCAP_H

#include "asterisk/linkedlists.h"

struct redroute_packet_entry {
    void* packet;
    AST_LIST_ENTRY(redroute_packet_entry) next;
};

//static AST_LIST_HEAD(redroute_packet_queue, redroute_packet_entry);

int redroute_init_pcap();

#endif