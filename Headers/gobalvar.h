#ifndef GOBALVAR_H
#define GOBALVAR_H
#include "config.h"
//全局变量
extern pcap_if_t* alldevs;//所有网卡
extern pcap_if_t* d;
extern int i ;
extern pcap_t* adhandle;//当前网卡
extern int res;
extern char errbuf[PCAP_ERRBUF_SIZE];//错误数组
extern struct tm* ltime;//时间
extern char timestr[16];
extern struct pcap_pkthdr* header;//数据包信息
extern const u_char* pkt_data;//数据包数据
extern time_t local_tv_sec;
extern u_int netmask;
extern char *packet_filter ; //过滤器
extern struct bpf_program fcode;
extern int net_index;
extern int net_capture;
extern pcap_dumper_t * dumpfile;
extern char filepath[100];//保存文件路径
extern int count;
#endif // GOBALVAR_H
