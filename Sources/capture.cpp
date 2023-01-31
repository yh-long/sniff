#include "capture.h"
#include<QDebug>
#include<QMutex>
#include<QTextCodec>
Capture::Capture()
{
    npacket->n_sum=0;
    npacket->n_arp=0;
    npacket->n_ip=0;
    npacket->n_tcp=0;
    npacket->n_udp=0;
    npacket->n_icmp=0;
    npacket->n_http=0;
    npacket->n_other=0;
    isStop=false;
}
void Capture::run(){
    // 将时间戳转换成可识别的格式
    time(&local_tv_sec);
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%Y%m%d %H%M%S", ltime);
    //qDebug("%s\n", timestr);
    qDebug()<<"抓包线程ID："<<currentThreadId();
    while(isStop!=true&&(res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
       //qDebug()<<"是否停止:"<<isStop;
       //qDebug()<<"线程ID："<<currentThreadId();



       if(res==0){//读取数据包超时
           continue;
       }

       //显示数据
       QTextCodec::codecForName("gbk");

       //存储捕获到的数据包
       struct _datapkt *data = (struct _datapkt*)malloc(sizeof(struct _datapkt));
       data->isHttp=false;
       //复制数据包到data
       memset(data,0,sizeof(struct _datapkt));
        //数据包长度
       data->len=header->len;

    //分析数据包的范围
       Utillities * fc=new Utillities;
       if(fc->analyze_frame(pkt_data,data,npacket)<0){
           continue;
       }


       //解析后的数据
       u_char *ppkt_data=(u_char *)malloc(header->len *sizeof(u_char));
       memcpy(ppkt_data,pkt_data,header->len);

       /*数据包加入容器*/
       datapktLink.push_back(data);
       datacharLink.push_back(ppkt_data);
       dataheaderLink.push_back(header);
       //qDebug()<<dataheaderLink.size();

       //获取数据包长度
       QString pkt_len = QString::number(data->len);
       //显示源MAC地址
       QString srcMac;
       char *buf = (char * ) malloc(80 * sizeof(char) ) ;
       sprintf(buf,"%02x-%02X-%02x-%02x-%02x-%02x",data->ethh->src[0],data->ethh->src[1],
               data->ethh->src[2], data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
       srcMac = QString(QLatin1String(buf) );
       //显示目的MAC地址
       QString dstMac;
       sprintf(buf,"%02x-%02X-%02x-%02x-%02x-%02x" ,data->ethh->dest[0],data->ethh->dest[1],
               data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4], data->ethh->dest[5]);
       dstMac = QString(QLatin1String( buf) );
       //获得当前协议
       QString protoType = QString(data->pktType) ;
       //获得源IP地址,首先对网络层协议进行判断，IP协议或者ARP协议Qstring srcIP;
       QString srcIP;
       if(data->ethh->type == 0x0806||data->ethh->type == 1544){//ARP
           sprintf(buf,"%d .%d .%d .%d", data->arph->senderIP[0],data->arph->senderIP[1],
                   data->arph->senderIP[2],data->arph->senderIP[3]);
                   srcIP = QString(QLatin1String(buf) );
       }
       else if(data->ethh->type == 0x0800||data->ethh->type == 8)//IP
       {
           sprintf(buf,"%d .%d .%d .%d" ,data->iph->saddr[0], data->iph->saddr[1],
                  data->iph->saddr[2],data->iph->saddr[3]);
                  srcIP = QString(QLatin1String(buf));
       }
       //获得源IP地址,首先对网络层协议进行判断，IP协议或者ARP协议Qstring dstIP;
       QString dstIP;
       if(data->ethh->type == 0x0806||data->ethh->type == 1544){//ARPi
           sprintf(buf,"%d .%d .%d .%d", data->arph->destIP[0],data->arph->destIP[1],
                   data->arph->destIP[2],data->arph->destIP[3]);
                   dstIP = QString(QLatin1String(buf) );
       }
       else if(data->ethh->type == 0x0800||data->ethh->type == 8)//IP
       {
           sprintf(buf,"%d .%d .%d .%d" ,data->iph->daddr[0],data->iph->daddr[1],
                   data->iph->daddr[2],data->iph->daddr[3]);
                   dstIP = QString(QLatin1String(buf));
       }
       //qDebug()<<"信号:"<<timestr<<srcMac<<dstMac<<pkt_len<<protoType<<srcIP<<dstIP;
       emit addOneCaptureLine(timestr, srcMac, dstMac, pkt_len, protoType, srcIP, dstIP);
       emit updatePktCount();

       emit num(i);

       //sleep(1);/*抓包速度*/
  }

   if (res == -1) {
      qDebug()<<"数据包读取失败: "<<pcap_geterr(adhandle);
   }

}
void Capture::setflag(bool flag)
{
    isStop = flag;
     qDebug()<<isStop;
}
