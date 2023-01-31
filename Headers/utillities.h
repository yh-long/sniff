#ifndef UTILLITIES_H
#define UTILLITIES_H
#define HAVE_REMOTE
#include "pcap.h"
#include"protocol.h"
#include<iostream>
using namespace std;
class Utillities
{
public:
    Utillities();
    int analyze_frame(const u_char *pkt,datapkt *data,pktCount *npacket);
    int analyze_arp(const u_char *pkt,datapkt *data,pktCount *npacket);
    int analyze_ip(const u_char *pkt,datapkt *data,pktCount *npacket);
    int analyze_icmp(const u_char *pkt,datapkt *data,pktCount *npacket);
    int analyze_tcp(const u_char *pkt,datapkt *data,pktCount *npacket) ;
    int analyze_udp(const u_char *pkt,datapkt *data,pktCount *npacket);
    int analyze_tls(const u_char *pkt,datapkt *data,pktCount *npacket);
private:
    const u_char *pktInitialAddress;//捕获的数据包的起始地址
};

#endif // UTILLITIES_H
