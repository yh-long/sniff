#include "arp_spoof.h"
#include "qpushbutton.h"
#include <QRegularExpressionValidator>
#include "qtablewidget.h"
#include<QMessageBox>
ARP_spoof::ARP_spoof(QWidget *parent):QDialog(parent)
{
    this->setFixedSize(450,300);
    this->setWindowTitle("ARP欺骗");
    /*初始化*/
    dstIP=new QLabel("目标IP",this);
    dstMAC=new QLabel("目标MAC",this);
    gatewayIP=new QLabel("网关IP",this);
    gatewayMAC=new QLabel("网关MAC",this);
    dstipline=new QLineEdit("",this);
    dstmacline=new QLineEdit("",this);
    gateipline=new QLineEdit("",this);
    gatemacline=new QLineEdit("",this);
    arptable=new QTableWidget(this);
    /*标签*/
    dstIP->move(120,20);
    dstMAC->move(120,50);
    gatewayIP->move(120,80);
    gatewayMAC->move(120,110);
    /*输入框*/
    dstipline->move(180,20);
    dstmacline->move(180,50);
    gateipline->move(180,80);
    gatemacline->move(180,110);
    dstipline->setPlaceholderText("255.255.255.255");
    dstmacline->setPlaceholderText("FF-FF-FF-FF-FF-FF");
    gateipline->setPlaceholderText("255.255.255.255");
    gatemacline->setPlaceholderText("FF-FF-FF-FF-FF-FF");

    /*输入限制*/
    QRegularExpression regExpip("([0-9]{1,3}[.]{1}){1,4}");
    QRegularExpression regExp("([A-Fa-f0-9]{2}[-]{1}){1,6}");
    QValidator *validatorip = new QRegularExpressionValidator(regExpip, this );
    QValidator *validator = new QRegularExpressionValidator(regExp, this );
    dstipline->setValidator(validatorip);
    dstmacline->setValidator( validator );
    gateipline->setValidator(validatorip);
    gatemacline->setValidator( validator );
    /*输出框*/
    arptable->setColumnCount(1);
    arptable->setHorizontalHeaderLabels(QStringList() << tr("信息"));
    arptable->scrollToBottom();//自动
    arptable->setColumnWidth(0, 300);
    arptable->move(60,140);
    arptable->resize(300,100);
    /*按钮*/
    QPushButton *arpstart=new QPushButton("开始",this);
    arpstart->move(80,250);
    QPushButton *arppause=new QPushButton("暂停",this);
    arppause->move(180,250);
    QPushButton *arpstop=new QPushButton("结束",this);
    arpstop->move(280,250);
    /*信号绑定*/
    connect(arpstart,SIGNAL(clicked()), this, SLOT(on_arpstart_clicked()));
    connect(arpstop,SIGNAL(clicked()), this, SLOT(on_arpstop_clicked()));
    connect(arppause,SIGNAL(clicked()), this, SLOT(on_arppause_clicked()));
    //线程控制
    connect(this,&ARP_spoof::isstop, arpth, &ArpThread::setflag);
    connect(this,&ARP_spoof::isstop, sendpktthread, &SendPktThread::setflag);
    //执行信息
    connect(arpth, &ArpThread::info,this,&ARP_spoof::infoview);
    connect(sendpktthread, &SendPktThread::info,this,&ARP_spoof::infoview);
    //传递参数
    connect(this,&ARP_spoof::sendMacIp,arpth,&ArpThread::MacIp);
    connect(this,&ARP_spoof::send,sendpktthread,&SendPktThread::MacIp);
}
//创建进程
void ARP_spoof::on_arpstart_clicked(){
    emit isstop(false);
    QString dstip=dstipline->text();
    QString dstmac=dstmacline->text();
    QString gateip=gateipline->text();
    QString gatemac=gatemacline->text();
    if(dstip==""||dstmac==""||gateip==""||gatemac==""){
        QMessageBox::warning(this, tr("提示"),tr("请输入要欺骗的地址"),QMessageBox::Warning,QMessageBox::Ok);
    }else{
        emit sendMacIp(dstmac,dstip,gatemac,gateip);

        arpth->start();
    }

    if(d->addresses!=NULL){
        // 获取接口第一个地址的掩码
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }else{
        netmask=0xffffff;
    }

    QString filterContent="not arp";
    QByteArray ba=filterContent.toLatin1();
    packet_filter=NULL;
    packet_filter=ba.data();

    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask)<0){
        QMessageBox::warning(this, "Cheat Error!",tr("过滤规则设置失败"),QMessageBox::Ok);   
        return;
    }
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        // 释放设备列表
        QMessageBox::warning(this, "Cheat Error!",tr("过滤规则设置失败"),QMessageBox::Ok);
        return;
    }
    emit send(arpth->mac,arpth->send_targetmac,arpth->send_gatemac,arpth->send_targetip,arpth->send_gateip);

    sendpktthread->start();

}
//暂停进程
void ARP_spoof::on_arppause_clicked()
{
    emit isstop(true);
    arpth->wait();
    sendpktthread->wait();
}
//结束进程
void ARP_spoof::on_arpstop_clicked(){
    emit isstop(true);
    arpth->wait();
    arpth->exit(1);
    sendpktthread->wait();
    sendpktthread->exit();
    for(int row = arptable->rowCount() - 1;row >= 0; row--)
    {
        arptable->removeRow(row);
    }

}
//显示信息
void ARP_spoof::infoview(QString info){
    int RowCont=arptable->rowCount();
    arptable->insertRow(RowCont);//增加一行
    arptable->setItem(RowCont,0,new QTableWidgetItem(info));
    arptable->scrollToBottom();
}
