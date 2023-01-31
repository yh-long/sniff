#include "utillities.h"
#include "gobalvar.h"
#include<QDebug>
Utillities::Utillities()
{

}

int Utillities::analyze_frame(const u_char *pkt,datapkt *data,pktCount *npacket){
    //数据包总数
    npacket->n_sum++;

    struct _ethhdr *ethh = (struct _ethhdr*)pkt;
    data->ethh=ethh;
    for(int i=0;i<6;i++){
        data->ethh->dest[i]=ethh->dest[i];
        data->ethh->src[i]=ethh->src[i];
        //qDebug()<<data->ethh->dest[i]<<ethh->src[i];
    }
    data->ethh->type=ethh->type;
    switch (ntohs(data->ethh->type)) {
        case PROTO_IP:
            analyze_ip((u_char*)pkt+14,data,npacket);
            break;
        case 0x86dd:
            //analyze_ipv6((u_char*)pkt+14,data,npacket);
            strcpy(data->pktType,"IPV6");
            break;
        case PROTO_ARP:
            analyze_arp((u_char*)pkt+14,data,npacket);
            break;
        default:
            npacket->n_other++;
            //ret=-1;
            break;
    }
    //qDebug()<<"网络层协议："<<ntohs(data->ethh->type);
    return 0;
}
int Utillities::analyze_arp(const u_char *pkt,datapkt *data,pktCount *npacket){
    //qDebug("网络层协议：arp");
    struct _arphdr *arphdr=(_arphdr*)pkt;
    data->arph=(_arphdr*)malloc(sizeof(_arphdr));
    data->arph->htype=arphdr->htype;
    data->arph->ptype=arphdr->ptype;
    data->arph->hsize=arphdr->hsize;
    data->arph->prsize=arphdr->prsize;
    data->arph->opcode=arphdr->opcode;

    for(int i=0;i<6;i++){
        data->arph->senderMac[i]=arphdr->senderMac[i];
        data->arph->destMc[i]=arphdr->destMc[i];

    }
    for(int i=0;i<4;i++){
        data->arph->senderIP[i]=arphdr->senderIP[i];
        data->arph->destIP[i]=arphdr->destIP[i];
    }

    npacket->n_arp++;
    strcpy(data->pktType,"ARP");
    return 0;
}
int Utillities::analyze_ip(const u_char *pkt,datapkt *data,pktCount *npacket){
    //qDebug("网络层协议：ip");
    strcpy(data->pktType,"IPV4");
    struct _iphdr *iphdr=(struct _iphdr*)pkt;
    data->iph=(_iphdr*)malloc(sizeof(_iphdr));
    //地址
    for(int i=0;i<4;i++){
    data->iph->saddr[i]=iphdr->saddr[i];
    //qDebug()<<data->iph->saddr[i];
    data->iph->daddr[i]=iphdr->daddr[i];
    }
    //版本
    data->iph->ip_vhl=iphdr->ip_vhl;
    data->iph->tos=iphdr->tos;
    data->iph->ip_len=iphdr->ip_len;
    data->iph->identification=iphdr->identification;
    data->iph->flags_fo=iphdr->flags_fo;

    data->iph->ttl=iphdr->ttl;
    data->iph->proto=iphdr->proto;
    data->iph->hchecksum=iphdr->hchecksum;
    npacket->n_ip++;
    //qDebug()<<"proto"<<iphdr->proto;
    switch (iphdr->proto) {
    case PROTO_ICMP:
        analyze_icmp((u_char*)pkt+20,data,npacket);
        break;
    case 2:
        strcpy(data->pktType,"IGMP");
        break;
    case PROTO_TCP:
         analyze_tcp((u_char*)pkt+20,data,npacket);
        break;
    case PROTO_UDP:
        analyze_udp((u_char*)pkt+20,data,npacket);
        break;
    case 88:
        strcpy(data->pktType,"ICRP");
        break;
    case 89:
        strcpy(data->pktType,"OSPF");
        break;
    }
    return 0;
}
int Utillities::analyze_icmp(const u_char *pkt,datapkt *data,pktCount *npacket){
    //qDebug("传输层协议：icmp");
    struct _icmphdr* icmphdr=(_icmphdr*)pkt;
    data->icmph=(_icmphdr*)malloc(sizeof(_icmphdr));
    data->icmph->type=icmphdr->type;
    data->icmph->code=icmphdr->code;
    data->icmph->chk_sum=icmphdr->chk_sum;
    data->icmph->identification=icmphdr->identification;
    data->icmph->seq=icmphdr->seq;
    npacket->n_icmp++;
    strcpy(data->pktType,"ICMP");
    return 0;
}
int Utillities::analyze_tcp(const u_char *pkt,datapkt *data,pktCount *npacket) {
    //qDebug()<<"传输层协议：tcp"<<data->ethh->type;
    npacket->n_tcp++;
    struct _tcphdr* tcphdr=(_tcphdr*)pkt;
    data->tcph=(_tcphdr*)malloc(sizeof(_tcphdr));
    data->tcph->srcPort=tcphdr->srcPort;
    data->tcph->destPort=tcphdr->destPort;
    data->tcph->seq=ntohs(tcphdr->seq);
    data->tcph->ack_sql=ntohs(tcphdr->ack_sql);
    data->tcph->th_offx2=tcphdr->th_offx2;
    data->tcph->th_flags=tcphdr->th_flags;
    data->tcph->wnd_size=tcphdr->wnd_size;
    data->tcph->checksum=tcphdr->checksum;
    data->tcph->urg_ptr=tcphdr->urg_ptr;

    //过滤HTTP协议
    u_char *httpdata = (u_char *)tcphdr + TH_OFF(tcphdr) * 4;
    const char  *token[]={"GET","POST","HTTP/1.1","HTTP/1.0"};
    u_char *httpHeader;
    for(int i=0;i<4;i++){
        httpHeader=(u_char*)strstr((char*)httpdata,token[i]);
        if(httpHeader){
            //qDebug()<<(char*)httpdata;
            npacket->n_http++;
            strcpy(data->pktType,"HTTP");
            data->isHttp = true;
            qDebug()<<"debug info:find a http packet!";
            int size=data->len-((u_char*)httpdata-pkt);
            qDebug()<<"size:"<<size;
            data->httpsize=size;
            data->apph=((u_char*)malloc(size*sizeof(u_char)));
            for(int j=0;j<size;j++){
                data->apph[j]=httpdata[j];
            }
        }
        if(data->isHttp){
            return 1;
        }
    }

    //根据端口是否为443端口初步过滤出HTTPS协议
    if(ntohs(tcphdr->srcPort) == 443 || ntohs(tcphdr->destPort) == 443){
        int istls=analyze_tls((u_char*)pkt+20,data,npacket);
        if(istls==0){
            return 0;
        }
    }

   strcpy(data->pktType,"TCP");
   return 0;
}

int Utillities::analyze_udp(const u_char *pkt,datapkt *data,pktCount *npacket){
    struct _udphdr *udphdr=(_udphdr*)pkt;
    data->udph=(_udphdr*)malloc(sizeof(_udphdr));
    data->udph->sport=udphdr->sport;
    data->udph->dport=ntohs(udphdr->dport);
    data->udph->crc=udphdr->crc;
    data->udph->len=udphdr->len;
    npacket->n_udp++;
    strcpy(data->pktType,"UDP");
    //qDebug("传输层协议：udp");

    return 0;
}

int Utillities::analyze_tls(const u_char *pkt,datapkt *data,pktCount *npacket){
    struct  _tlshdr *tlshdr=(_tlshdr*)pkt;

    data->tlsph=(_tlshdr*)malloc(sizeof(_tlshdr));
    data->tlsph->content_type=tlshdr->content_type;
    if(tlshdr->content_type==Handshark){
        for(int i=0;i<data->len-52;i++){
            qDebug()<<pkt[i];
        }
        strcpy(data->pktType,"TLS");
        data->isTLS=true;

        qDebug()<<QString("%1").arg(ntohs(tlshdr->content_type),8,16,QLatin1Char('0'));
        return 0;
    }else{

    }
    return -1;
}
