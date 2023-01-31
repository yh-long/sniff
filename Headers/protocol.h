#ifndef PROTOCOL_H
#define PROTOCOL_H
#define HAVE_REMOTE
#define _XKEYCHECK_H//解决关键词宏重定义
#include "pcap.h"
#include "vector"
using namespace std;
//保存的数据结构
typedef struct _datapkt
{
    char pktType[8];
    int time[6];
    int len;
    struct _ethhdr *ethh;
    struct _arphdr *arph;
    struct _iphdr *iph;
    struct _icmphdr *icmph;
    struct _udphdr *udph;
    struct _tcphdr *tcph;
    struct _tlshdr *tlsph;
    u_char *apph;//应用层包头
    bool isHttp=false;
    bool isTLS=false;
    int httpsize;//应用层数据大小
}datapkt;
//该容器用于存储数据包分析之得到的结构体；
typedef std::vector<datapkt *> datapktVec;
//该容器用于存储捕获的单个数据包的全部数据，从而能够在对应控件中显示数据包的十六进制形式内容
typedef std::vector<u_char *> dataVec;
typedef std::vector<struct pcap_pkthdr*> dataheaderVec;

typedef struct _pktCount{
int n_sum;
int n_arp;
int n_ip;
int n_tcp;
int n_udp;
int n_icmp;
int n_other;
int n_http;
}pktCount;



#define PROTO_IP 0x0800
#define PROTO_ARP 0x0806
#define ETHERNET_SIZE 14
typedef struct _ethhdr{
u_char dest[6];//目标MAC地址
u_char src[6];//源MAC地址
u_short type;//类型
}ethhdr;

//arp
typedef struct _arphdr{
    u_short htype;//硬件类型
    u_short ptype;//协议地址
    u_char hsize;//硬件地址
    u_char prsize;//协议地址
    u_short opcode;//操作码
    u_char senderMac[6];//源MAC地址
    u_char senderIP[4];//源IP地址
    u_char destMc[6];//目的MAC地址
    u_char destIP[4];//目的IP地址
}arphdr;
//ip
typedef struct _iphdr{
    u_char ip_vhl;//版本4位
    //u_char ip_headlen;//头部长度4位
    u_char tos;//服务类型8位
    u_short ip_len;//数据包长度16位
    u_short identification;//标识16位
    u_short flags_fo;//标志位3位
    #define IP_RF 0x800
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char ttl;//存活时间8位
    u_char proto;//协议8位
    u_short hchecksum;//校验码16位
    u_char saddr[4];//源地址32位
    u_char daddr[4];//目的地址32位
}iphdr;
#define IP_HL(ip) ((ip)->ip_vhl&0x0f)
#define IP_V(ip) ((ip)->ip_vhl>>4)
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
//icmp
typedef struct _icmphdr{
u_char type;//类型字段，占8位
u_char code;//代码字段，占8位
u_short chk_sum;//校验和字段，占16位
u_short identification;//标识符字段，占16位
u_short seq;//序列号字段，占16位
}icmphdr;
//udp
typedef struct _udphdr{
    u_short sport;//源端口
    u_short dport;//目的端口
    u_short len;//UDP数据包长度
    u_short crc;//校验码
}updhdr;
//tcp
typedef struct _tcphdr{
    u_short srcPort;//源端口
    u_short destPort;//目的端口
    u_int seq;//序列号
    u_int ack_sql;//确认号
    u_char th_offx2; //data offset,rsvd
    #define TH_OFF(th)(((th)->th_offx2 & 0xf0) >>4)//得到前4位，即包首部长度
    u_char th_flags;//
    #define TH_FIN 0X01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0X80
    #define TH_FLAGS (TH_FIN|TH_SYN| TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short wnd_size;//窗口大小，16位
    u_short checksum;//校验和, 16位
    u_short urg_ptr;//紧急指针
}tcphdr;
//tls
#define Application_Date 17
#define Handshark 22
#define Alert 21
#define Clent_Hello 1
#define Server_Hello 2
#define Certificate 11
#define Client_Key_Exchange 16
#define Change_cipher_Spec 20
typedef struct _tlshdr{
    u_char content_type;
    u_char version;
    u_short length;
    u_char handshake_type;
    u_short hand_length;
    u_short hand_version;
    u_char random[32];
}tlshdr;
#endif // PROTOCOL_H
