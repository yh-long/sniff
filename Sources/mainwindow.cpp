#include "mainwindow.h"
#include "ui_mainwindow.h"
#include<thread>//线程
#include <QDateTime>//系统时间的头文件
#include<QDir>
#include <typeinfo>
#include<QMessageBox>
#include<iostream>
#include<string>
#include<QFileDialog>

//全局变量
pcap_if_t* alldevs;
pcap_if_t* d;
int i = 0;
pcap_t* adhandle;//网卡
int res;
char errbuf[PCAP_ERRBUF_SIZE];//错误号
struct pcap_pkthdr* header;//
const u_char* pkt_data;//数据包结构
char timestr[16];//时间
struct tm* ltime;
time_t local_tv_sec;
u_int netmask;
char *packet_filter; //过滤器
struct bpf_program fcode;
int net_index;//网卡序号
int net_capture;
int count;//数据包总数
char filepath[100];//保存文件



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    initScene();

    connect(this,&MainWindow::isdone,cap,&Capture::setflag);
    connect(cap, &Capture::addOneCaptureLine, this,&MainWindow::updateTableWidget);
    connect(ui->showWidget, SIGNAL(cellClicked(int,int)), this, SLOT(showProtoTree(int,int)));
    connect(cap, &Capture::updatePktCount, this,&MainWindow::updateCapCalculate);

    ui->showWidget->setColumnCount(8);
    ui->showWidget->setHorizontalHeaderLabels(QStringList() << tr("序号") << tr("时间")
                                                  << tr("目的MAC地址") << tr("源MAC地址")
                                                  << tr("长度") << tr("协议类型")
                                                  << tr("源IP地址") << tr("目的IP地址"));
    //设置为单行选中
    ui->showWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置选择模式，即选择单行
    ui->showWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    //设置为禁止修改
    ui->showWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->showWidget->verticalHeader()->setVisible(false);    //隐藏列表头
    ui->showWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::initScene(){
    setFixedSize(UI_WIDTH,UI_HEIGHT);
    setWindowTitle(UI_TITLE);
    setWindowIcon(QIcon( UI_ICO));
    const QSize MAIN_SIZE_MAX = QSize(16777215, 16777215);
    this->setMaximumSize(MAIN_SIZE_MAX);
    this->setWindowFlag(Qt::WindowMaximizeButtonHint, true);
    this->setStyleSheet("QMenu::item:selected{background-color:rgb(0,100,200);}\
                             QMenuBar{background-color:rgb(200,200,200);}");
    ui->comboBox->addItem(tr("选择网卡"));
    ui->btn_over->setEnabled(false);
    ui->btn_pause->setEnabled(false);
    if(net_card_find()==-1){
        QMessageBox::critical(this, tr("提示"),  tr("适配器打开失败"),QMessageBox::Ok);
    }
}

int MainWindow::net_card_find(){
    /* 获取本机设备列表 */
    if(pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            qDebug() << errbuf;
            return -1;
        }
    /* 打印列表 */
    for (d = alldevs; d; d = d->next)
    {
        //qDebug() <<i++<< d->name;
        i++;
        if (d->description){
            //qDebug() << d->description;
            //显示在下拉框
            ui->comboBox->addItem(QString("%1").arg(d->description));
        }
        for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
            if(a->addr->sa_family == AF_INET){
                qDebug("IPv4 地址 . . . . . . . . . . . . :%s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
            }
        }
    }
    if(i == 0)
    {
        qDebug("Wnpcap没有发现任何网卡");
        return -1;
    }
    return 0;
}



int MainWindow::net_card_open(){
    //跳转到已选中的适配器
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            qDebug() << errbuf;
        }
     d = alldevs;
     for(i=0; i<net_index; i++){
         if(d!=NULL&&d->next!=NULL)
           d = d->next;
     }

     //打开设备
     if ((adhandle = pcap_open(d->name,          // 设备名
             65536,            // 要捕捉的数据包的部分
                               // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
             PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
             1000,             // 读取超时时间
             NULL,             // 远程机器验证
             errbuf            // 错误缓冲池
     )) == NULL||net_index==0)
     {
       qDebug("Unable to open the adapter. %s is not supported by WinPcap\n", d->name);

       //释放设列表
       pcap_freealldevs(alldevs);
       return -1;
     }
     return 0;
}

int MainWindow::net_card_filter(){

    //监听网卡
    for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
        if(a->addr->sa_family == AF_INET)
        qDebug("IPv4 地址 . . . . . . . . . . . . :%s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
        qDebug("正在监听 %s...", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
    }
    // 设置过滤器
   if (d->addresses != NULL){
       // 获取接口第一个地址的掩码
       netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else{
       // 如果这个接口没有地址，那么我们假设这个接口在C类网络中
       netmask = 0xffffff;
    }
   //获取过滤规则
   QString filterContent=ui->filter->text();
   QByteArray ba=filterContent.toLatin1();
   packet_filter=NULL;
   packet_filter=ba.data();
   qDebug("过滤规则:%s",packet_filter);
   //qDebug()<<typeid(packet_filter).name();
   //设置过滤规则
   if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) >= 0)
   {
       //设置过滤器
       if (pcap_setfilter(adhandle, &fcode) < 0)
       {
           // 释放设备列表
           //pcap_freealldevs(alldevs);
           return -1;
       }
       QMessageBox::about(this, tr("提示"),tr("过滤规则设置成功"));
   }
   else
   {
       // 释放设备列表
       //pcap_freealldevs(alldevs);
       return -1;
   }
   return 0;
}

//数据显示
void MainWindow::showProtoTree(int row,int col){
    qDebug() << "所点击的单元格的row=" << row << ",col=" << col;
    // 获取所点击的单元格
    //QTableWidgetItem* item = ui->showWidget->item(row ,col);
    //qDebug() << item->text();

    /*bitflow*/
    ui->tableWidget->clear();
    //清除上次数据
    for(int row = ui->tableWidget->rowCount() - 1;row >= 0; row--)
    {
        ui->tableWidget->removeRow(row);
    }
    ui->tableWidget->setColumnCount(17);//设置列数
    ui->tableWidget->setShowGrid(false);  /* 去除QTableWidget组件中的线 */
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    /*for(int i=0;i<16;i++){
        ui->tableWidget->setColumnWidth(i,31);
    }*/
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(16,QHeaderView::Interactive);

    ui->tableWidget->setColumnWidth(16,130);

    int iRow = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(iRow);//总行数增加1
    /*输出数据流*/
    int len = cap->datapktLink[row]->len;
    QString c="";
    for (i = 0; i < len; i++)
    {
        QString a=QString("%1").arg(cap->datacharLink[row][i]);
        int tmp = a.toInt();
        QChar b;
        if(tmp>128){
            b='.';
        }else{
            b=QChar(tmp);
        }
        c=c.append(b);
        //qDebug()<<a<<i;
        a=QString("%1").arg(tmp,2,16,QLatin1Char('0'));
        if(i%16==15){
            int Row1 = ui->tableWidget->rowCount();
            ui->tableWidget->setItem(Row1-1, 16, new QTableWidgetItem(c)); //添加到界面
            c="";
        }
        if ((i % 16) == 0 && i > 0){
            int Row2 = ui->tableWidget->rowCount();
            ui->tableWidget->insertRow(Row2);//总行数增加1
        }
        int Row3 = ui->tableWidget->rowCount();
        ui->tableWidget->setItem(Row3-1, i%16, new QTableWidgetItem(a)); //添加到界面
        /*qDebug()<<b<<Row3;*/
    }
    int Row1 = ui->tableWidget->rowCount();
    ui->tableWidget->setItem(Row1-1, 16, new QTableWidgetItem(c)); //添加到界面

    /*PROTOWidget*/
    ui->protoWidget->setColumnCount(1);
    //设置协议解析窗口表头
    ui->protoWidget->setHeaderLabel(QString::number(row+1).append("号数据包分析"));
    ui->protoWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->protoWidget->header()->setStretchLastSection(false);
    /*数据分析*/
    ui->protoWidget->clear();//清除上次分析

    QStringList ethDataList;
    ui->protoWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    QTreeWidgetItem *ethD = new QTreeWidgetItem(ui->protoWidget, ethDataList << "Ethernet II" << "0");

    QTableWidgetItem* item2 = ui->showWidget->item(row ,2);
    QString dst=item2->text();//获取目的MAC
    new QTreeWidgetItem(ethD, QStringList() <<QString("目的MAC：").append(dst)<< "1");

    QTableWidgetItem* item1 = ui->showWidget->item(row ,3);
    QString src=item1->text();//获取源MAC
    new QTreeWidgetItem(ethD,QStringList() << QString("源MAC：").append(src)<< "2");

    QString test=QString("%1").arg(ntohs(cap->datapktLink[row]->ethh->type));
    int tmp = test.toInt();
    test=QString("%1").arg(tmp,4,16,QLatin1Char('0'));//获取网络层类型

    new QTreeWidgetItem(ethD,QStringList() << QString("类型：0x").append(test)<< "3");

    //内存拷贝
    struct _ethhdr *ethh = (struct _ethhdr*)cap->datacharLink[row];
    cap->datapktLink[row]->ethh=ethh;
    //qDebug()<<ntohs(cap->datapktLink[row]->ethh->type)<<PROTO_IP;

    //网络层
    QStringList netDataList;

    if(ntohs(cap->datapktLink[row]->ethh->type)==PROTO_ARP){
        QTreeWidgetItem *arpD = new QTreeWidgetItem(ui->protoWidget, netDataList << "Internet Protocol" << "0");
        QString htyp=QString("%1").arg(cap->datapktLink[row]->arph->htype);
        new QTreeWidgetItem(arpD, QStringList() << QString("硬件类型：").append(htyp)<< "1");

        QString ptyp=QString("%1").arg(cap->datapktLink[row]->arph->ptype);
        new QTreeWidgetItem(arpD,QStringList() << QString("协议类型：").append(ptyp) << "2");

        QString hs=QString("%1").arg(cap->datapktLink[row]->arph->hsize);
        new QTreeWidgetItem(arpD,QStringList() << QString("硬件大小：").append(hs) << "3");

        QString ps=QString("%1").arg(cap->datapktLink[row]->arph->prsize);
        new QTreeWidgetItem(arpD, QStringList() << QString("协议大小：").append(ps) << "4");

        QString op=QString("%1").arg(cap->datapktLink[row]->arph->opcode);
        new QTreeWidgetItem(arpD,QStringList() << QString("操作码：").append(op) << "5");

        QString renderMAC,renderIp,dstMAC,dstIp,temp="";
        int tmp;
        for(int i=0;i<6;i++){
            temp=QString("%1").arg(cap->datapktLink[row]->arph->senderMac[i]);
            tmp= temp.toInt();
            temp=QString("%1").arg(tmp,2,16,QLatin1Char('0'));
            if(i>0){
               renderMAC.append('.'+temp);
            }else{
                renderMAC.append(temp);
            }
            temp=QString("%1").arg(cap->datapktLink[row]->arph->destMc[i]);
            tmp = temp.toInt();
            temp=QString("%1").arg(tmp,2,16,QLatin1Char('0'));
            if(i>0){
               dstMAC.append('.'+temp);
            }else{
               dstMAC.append(temp);
            }
        }
        for(int i=0;i<4;i++){
            temp=QString("%1").arg(cap->datapktLink[row]->arph->senderIP[i]);
            if(i>0){
               renderIp.append('.'+temp);
            }else{
               renderIp.append(temp);
            }
            temp=QString("%1").arg(cap->datapktLink[row]->arph->destIP[i]);
            if(i>0){
               dstIp.append('.'+temp);
            }else{
               dstIp.append(temp);
            }
        }
        new QTreeWidgetItem(arpD,QStringList() << QString("发送MAC：").append(renderMAC) << "6");
        new QTreeWidgetItem(arpD, QStringList() << QString("发送IP：").append(renderIp) << "7");
        new QTreeWidgetItem(arpD,QStringList() << QString("接收MAC：").append(dstMAC) << "8");
        new QTreeWidgetItem(arpD,QStringList() << QString("接收IP：").append(dstIp) << "9");

    }else if(ntohs(cap->datapktLink[row]->ethh->type)==PROTO_IP){
        QTreeWidgetItem *ipD = new QTreeWidgetItem(ui->protoWidget, netDataList << "Internet Protocol" << "0");
        QString version=QString("%1").arg(cap->datapktLink[row]->iph->ip_vhl/16);//版本
        new QTreeWidgetItem(ipD, QStringList() << QString("版本：").append(version)<< "1");

        QString tos=QString("%1").arg(cap->datapktLink[row]->iph->tos);
        new QTreeWidgetItem(ipD,QStringList() << QString("服务：").append(tos) << "2");

        QString len=QString("%1").arg(ntohs(cap->datapktLink[row]->iph->ip_len));
        new QTreeWidgetItem(ipD,QStringList() << QString("总长度：").append(len) << "3");

        QString iden=QString("%1").arg(ntohs(cap->datapktLink[row]->iph->identification));
        new QTreeWidgetItem(ipD, QStringList() << QString("标识：").append(iden) << "4");

        QString flag=QString("%1").arg(cap->datapktLink[row]->iph->flags_fo);
        int tmp_flag = flag.toInt();
        flag=QString("%1").arg(tmp_flag,2,16,QLatin1Char('0'));
        QStringList flagDataList;
        QTreeWidgetItem *flagD = new QTreeWidgetItem(ipD, flagDataList <<QString("标志位：0x").append(flag) << "5");
        new QTreeWidgetItem(flagD,QStringList() << QString("80 = Reserved bit: set"));
        new QTreeWidgetItem(flagD,QStringList() << QString("40 = Don't fargment: set"));
        new QTreeWidgetItem(flagD,QStringList() << QString("20 = More fargment: set"));

        QString ttl=QString("%1").arg(cap->datapktLink[row]->iph->ttl);
        new QTreeWidgetItem(ipD,QStringList() << QString("存活时间：").append(ttl) << "6");

        QString pro=QString("%1").arg(cap->datapktLink[row]->iph->proto);
         int tmp = pro.toInt();
         switch (tmp) {
         case 1:
             pro="ICMP";
             break;
         case 6:
             pro="TCP";
             break;
         case 17:
             pro="UDP";
             break;
         default:
             break;
         }
        new QTreeWidgetItem(ipD, QStringList() << QString("协议：").append(pro) << "7");

        QString crc=QString("%1").arg(ntohs(cap->datapktLink[row]->iph->hchecksum));
        int tmp_crc = crc.toInt();
        crc=QString("%1").arg(tmp_crc,2,16,QLatin1Char('0'));
        new QTreeWidgetItem(ipD,QStringList() << QString("校验码：0x").append(crc) << "8");

        QTableWidgetItem* item6 = ui->showWidget->item(row ,6);
        QString ipsrc=item6->text();//获取源地址
        new QTreeWidgetItem(ipD,QStringList() << QString("源地址：").append(ipsrc) << "9");

        QTableWidgetItem* item7 = ui->showWidget->item(row ,7);
        QString ipdst=item7->text();//获取源地址
        new QTreeWidgetItem(ipD,QStringList() << QString("目的地址：").append(ipdst) << "10");

        //qDebug()<<"传输层协议1"<<cap->datapktLink[row]->iph->proto;
        QStringList tcpDataList;
        if(cap->datapktLink[row]->iph->proto==PROTO_UDP){
            //qDebug()<<"传输层协议"<<cap->datapktLink[row]->iph->proto;
            QTreeWidgetItem *udpD = new QTreeWidgetItem(ui->protoWidget, tcpDataList << "Transmission Control Protocol" << "0");

            QString sport=QString("%1").arg(ntohs(cap->datapktLink[row]->udph->sport));
            new QTreeWidgetItem(udpD, QStringList() << QString("源端口：").append(sport) << "1");

            QString dport=QString("%1").arg(ntohs(cap->datapktLink[row]->udph->dport));
            new QTreeWidgetItem(udpD,QStringList() << QString("目的端口：").append(dport) << "2");

            QString len=QString("%1").arg(ntohs(cap->datapktLink[row]->udph->len));
            new QTreeWidgetItem(udpD,QStringList() << QString("长度：").append(len) << "3");

            QString crc=QString("%1").arg(ntohs(cap->datapktLink[row]->udph->crc));
            int udp_crc = crc.toInt();
            crc=QString("%1").arg(udp_crc,2,16,QLatin1Char('0'));
            new QTreeWidgetItem(udpD,QStringList() << QString("校验和：0x").append(crc) << "4");
        }else if(cap->datapktLink[row]->iph->proto==PROTO_TCP){
            //qDebug()<<"传输层协议"<<cap->datapktLink[row]->iph->proto;
            QTreeWidgetItem *tcpD = new QTreeWidgetItem(ui->protoWidget, tcpDataList << "Transmission Control Protocol" << "0");
            QString srcport=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->srcPort));
            new QTreeWidgetItem(tcpD, QStringList() << QString("源端口：").append(srcport) << "1");

            QString dstport=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->destPort));
            new QTreeWidgetItem(tcpD,QStringList() << QString("目的端口：").append(dstport) << "2");

            QString seq=QString("%1").arg(cap->datapktLink[row]->tcph->seq);
            new QTreeWidgetItem(tcpD,QStringList() << QString("序列号：").append(seq) << "3");

            QString ack=QString("%1").arg(cap->datapktLink[row]->tcph->ack_sql);
            new QTreeWidgetItem(tcpD,QStringList() << QString("确认号：").append(ack) << "4");

            QString offset=QString("%1").arg((cap->datapktLink[row]->tcph->th_offx2)/4);
            new QTreeWidgetItem(tcpD,QStringList() << QString("首部长度：").append(offset) << "5");

            QString flag=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->th_flags)/256);
            //qDebug()<<TH_FLAGS<<flag<<TH_ACK;
            int tcp_flag = flag.toInt();
            flag=QString("%1").arg(tcp_flag,2,16,QLatin1Char('0'));
            QStringList flagDataList;

            QTreeWidgetItem *flagD = new QTreeWidgetItem(tcpD, flagDataList <<QString("标志：0x").append(flag)<< "7");
            new QTreeWidgetItem(flagD,QStringList() << QString("000 = Reserved"));
            new QTreeWidgetItem(flagD,QStringList() << QString("101 = Nonce: set"));
            new QTreeWidgetItem(flagD,QStringList() << QString("080 = Congestion window Reduced (CWR)"));
            new QTreeWidgetItem(flagD,QStringList() << QString("040 = ECN-Echo"));
            new QTreeWidgetItem(flagD,QStringList() << QString("020 = Urgent"));
            new QTreeWidgetItem(flagD,QStringList() << QString("010 = Acknowledgment"));
            new QTreeWidgetItem(flagD,QStringList() << QString("008 = push"));
            new QTreeWidgetItem(flagD,QStringList() << QString("004 = Reset"));
            new QTreeWidgetItem(flagD,QStringList() << QString("002 = syn"));
            new QTreeWidgetItem(flagD,QStringList() << QString("001 = Fin"));


            QString wn=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->wnd_size));
            new QTreeWidgetItem(tcpD,QStringList() << QString("窗口：").append(wn) << "8");

            QString crc=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->checksum));
            int tcp_crc = crc.toInt();
            crc=QString("%1").arg(tcp_crc,2,16,QLatin1Char('0'));
            new QTreeWidgetItem(tcpD,QStringList() << QString("校验和：0x").append(crc) << "9");

            QString ptr=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->urg_ptr));
            new QTreeWidgetItem(tcpD,QStringList() << QString("紧急指针：").append(ptr) << "10");
            if(cap->datapktLink[row]->isHttp){
                QStringList httpDataList;
                QTreeWidgetItem *httpD = new QTreeWidgetItem(ui->protoWidget, httpDataList << "Hypertext Transfer Protocol" << "0");
                QString content="";
                for (i = 0; i < cap->datapktLink[row]->httpsize; i++)
                {
                    QString a=QString("%1").arg(cap->datapktLink[row]->apph[i]);
                    int tmp = a.toInt();
                    QChar b;
                    if(tmp>128){
                        b='.';
                    }else{
                        b=QChar(tmp);
                    }
                    content=content.append(b);
                }
                new QTreeWidgetItem(httpD,QStringList() << QString(content) << "1");
            }
            if(cap->datapktLink[row]->isTLS){
                QStringList TLSList;
                QTreeWidgetItem *TLSV = new QTreeWidgetItem(ui->protoWidget, TLSList << "TLSv Record Layer: Handshark Protocol" << "0");

                QStringList TLSDataList;
                QTreeWidgetItem *TLSD = new QTreeWidgetItem(TLSV, TLSDataList << "Transport Layer Security" << "0");
                QString cont=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->srcPort));
                new QTreeWidgetItem(TLSD, QStringList() << QString("Content Type: ").append(cont) << "1");

                QString ver=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->destPort));
                new QTreeWidgetItem(TLSD,QStringList() << QString("Version: ").append(ver) << "2");

                QString leng=QString("%1").arg(cap->datapktLink[row]->tcph->seq);
                new QTreeWidgetItem(TLSD,QStringList() << QString("Length：").append(leng) << "3");

                QStringList handpDataList;
                QTreeWidgetItem *HandP = new QTreeWidgetItem(TLSD, handpDataList <<QString("Handshark Protocol").append(flag)<< "4");
                QString hty=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->srcPort));
                new QTreeWidgetItem(HandP, QStringList() << QString("Content Type: ").append(hty) << "1");

                QString hlen=QString("%1").arg(ntohs(cap->datapktLink[row]->tcph->destPort));
                new QTreeWidgetItem(HandP,QStringList() << QString("Version: ").append(hlen) << "2");

                QString hv=QString("%1").arg(cap->datapktLink[row]->tcph->seq);
                new QTreeWidgetItem(HandP,QStringList() << QString("Length：").append(hv) << "3");

                QString rand=QString("%1").arg(cap->datapktLink[row]->tcph->seq);
                new QTreeWidgetItem(HandP,QStringList() << QString("Random：").append(rand) << "4");
            }


        }else if(cap->datapktLink[row]->iph->proto==PROTO_ICMP){
            //qDebug()<<"传输层协议2"<<cap->datapktLink[row]->iph->proto;
            QTreeWidgetItem *icmpD = new QTreeWidgetItem(ui->protoWidget, tcpDataList << "Transmission Control Protocol" << "0");
            QString typ=QString("%1").arg(cap->datapktLink[row]->icmph->type);
            new QTreeWidgetItem(icmpD, QStringList() << QString("类型：").append(typ) << "1");

            QString code=QString("%1").arg(ntohs(cap->datapktLink[row]->icmph->code));
            new QTreeWidgetItem(icmpD,QStringList() << QString("代码：").append(code) << "2");

            QString crc=QString("%1").arg(ntohs(cap->datapktLink[row]->icmph->chk_sum));
            int icmp_crc = crc.toInt();
            crc=QString("%1").arg(icmp_crc,2,16,QLatin1Char('0'));
            new QTreeWidgetItem(icmpD,QStringList() << QString("校验和：0x").append(crc) << "3");

            QString idn=QString("%1").arg(ntohs(cap->datapktLink[row]->icmph->identification));
            new QTreeWidgetItem(icmpD,QStringList() << QString("标识：").append(idn) << "4");

            QString seq=QString("%1").arg(ntohs(cap->datapktLink[row]->icmph->seq));
            new QTreeWidgetItem(icmpD,QStringList() << QString("序列号：").append(seq) << "5");
        }
    }

}
/*数据包信息*/
void MainWindow::updateTableWidget(QString timestr,QString srcMac,QString dstMac,QString pkt_len,QString protoType,QString srcIP,QString dstIP){

    int RowCont;
    RowCont=ui->showWidget->rowCount();  

    ui->showWidget->insertRow(RowCont);//增加一行 
    ui->showWidget->setShowGrid(false);  /* 去除QTableWidget组件中的线 */
    //设置选中行颜色
    //ui->showWidget->setStyleSheet("selection-background-color: blue");
    int num=RowCont+1;
    QString s=QString::number(num);

    //插入元素
    ui->showWidget->setItem(RowCont,0,new QTableWidgetItem(s));
    ui->showWidget->setItem(RowCont,1,new QTableWidgetItem(timestr));
    ui->showWidget->setItem(RowCont,2,new QTableWidgetItem(dstMac));
    ui->showWidget->setItem(RowCont,3,new QTableWidgetItem(srcMac));
    ui->showWidget->setItem(RowCont,4,new QTableWidgetItem(pkt_len));
    ui->showWidget->setItem(RowCont,5,new QTableWidgetItem(protoType));
    ui->showWidget->setItem(RowCont,6,new QTableWidgetItem(srcIP));
    ui->showWidget->setItem(RowCont,7,new QTableWidgetItem(dstIP));
    if(protoType=="ARP"){
        for(int col=0;col<8;col++){
            ui->showWidget->item(RowCont, col)->setBackground(QColor(159,252,253));
        }
    }if(protoType=="IPV6"||protoType=="IPV4"){
        for(int col=0;col<8;col++){
            ui->showWidget->item(RowCont, col)->setBackground(QColor(240,135,132));
        }
    }else if(protoType=="ICMP"){
        for(int col=0;col<8;col++){
            ui->showWidget->item(RowCont, col)->setBackground(QColor(238,138,248));
        }
    }else if(protoType=="TCP"){
        for(int col=0;col<8;col++){
            ui->showWidget->item(RowCont, col)->setBackground(QColor(255,255,210));
        }
    }else if(protoType=="UDP"){
        for(int col=0;col<8;col++){
            ui->showWidget->item(RowCont, col)->setBackground(QColor(255,253,225));
        }
    }else if(protoType=="HTTP"){
        for(int col=0;col<8;col++){
            ui->showWidget->item(RowCont, col)->setBackground(QColor(226,251,219));
        }
    }

    ui->showWidget->scrollToBottom();
}
/*数据包汇总*/
void MainWindow::updateCapCalculate(){
    ui->count->setEnabled(false);
    ui->count->setText(QString::number(cap->npacket->n_sum,10));
    ui->tcp->setText(QString::number(cap->npacket->n_tcp,10));
    ui->udp->setText(QString::number(cap->npacket->n_udp,10));
    ui->icmp->setText(QString::number(cap->npacket->n_icmp,10));
    ui->ARP->setText(QString::number(cap->npacket->n_arp,10));
    ui->http->setText(QString::number(cap->npacket->n_http,10));
}


void MainWindow::on_comboBox_currentIndexChanged()
{

}

void MainWindow::on_btn_start_clicked()
{
    net_card_open();
    net_index=ui->comboBox->currentIndex();
    //qDebug("net_index:%d",net_index);

    if(net_index==0){
        QMessageBox::warning(this, tr("提示"),tr("请选择一个网卡！"),QMessageBox::Warning,QMessageBox::Ok);
    }else{
        emit isdone(false);
        if(net_card_filter()!=-1){
            cap->start();
            ui->btn_start->setEnabled(false);
            ui->btn_pause->setEnabled(true);
            ui->btn_over->setEnabled(true);
            qDebug("开始捕获");
        }else{
            QMessageBox::critical(this, tr("提示"),  tr("过滤规则设置失败"),QMessageBox::Ok);
        }
    }

}

void MainWindow::on_btn_pause_clicked()
{
    emit isdone(true);
    ui->btn_start->setEnabled(true);
    ui->btn_pause->setEnabled(false);
    cap->wait();
}

void MainWindow::on_btn_over_clicked()
{
    emit isdone(true);
    for(int row = ui->showWidget->rowCount() - 1;row >= 0; row--)
    {
        ui->showWidget->removeRow(row);
    }
    ui->btn_start->setEnabled(true);
    ui->btn_over->setEnabled(false);
    ui->btn_pause->setEnabled(false);
    ui->count->setText(0);
    ui->tcp->setText(0);
    ui->udp->setText(0);
    ui->icmp->setText(0);
    ui->ARP->setText(0);
    ui->http->setText(0);
    for(int row = ui->tableWidget->rowCount() - 1;row >= 0; row--)
    {
        ui->tableWidget->removeRow(row);
    }
    cap->datapktLink.clear();
    cap->datacharLink.clear();
    cap->npacket->n_arp=0;
    cap->npacket->n_ip=0;
    cap->npacket->n_tcp=0;
    cap->npacket->n_udp=0;
    cap->npacket->n_icmp=0;
    cap->npacket->n_http=0;
    cap->npacket->n_sum=0;
    cap->npacket->n_other=0;

    if(cap->datacharLink.empty()&&cap->datapktLink.empty()){
        ui->protoWidget->clear();
        cap->wait();
        cap->exit();
        //pcap_freealldevs(alldevs);
    }
    //qDebug("结束捕获");
}

void MainWindow::stopThread()//退出应用执行关闭线程
{
    delete cap;
    qDebug("释放线程");
    on_btn_over_clicked();
}

//ARP欺骗
void MainWindow::on_ARP_2_triggered()
{
    net_index=ui->comboBox->currentIndex();
    if(net_index==0){
        QMessageBox::warning(this, tr("提示"),tr("请选择一个网卡！"),QMessageBox::Warning,QMessageBox::Ok);
    }else{
        ARP_spoof *arp_dlog=new ARP_spoof(this);
        arp_dlog->show();
        arp_dlog->setAttribute(Qt::WA_DeleteOnClose);//关闭窗口时释放内存防止内存泄漏
    }
}

//保存离线文件
void MainWindow::on_file_save_triggered()
{

    //获取当前路径
    QString path = QDir::currentPath();
    qDebug() << path;
    //判断当前路径下文件是否存在
    QString direcPath = path + "//SavedData";
    QDir dir(direcPath);
    if(!dir.exists())
    {
        if(!dir.mkdir(direcPath))
        {
            QMessageBox::warning(this, "warning", tr("保存路径创建失败!"), QMessageBox::Ok);
        }
    }

    std::string str = direcPath.toStdString();
      /*保存文件*/
    strcpy(filepath,str.c_str());
    strcat(filepath,"//");
    strcat(filepath,timestr);
    strcat(filepath,".pcap");

    //qDebug()<<"data save path is :"+QString(filepath);
    if(!cap->datacharLink.empty()){
        pcap_dumper_t * dumpfile=pcap_dump_open(adhandle,filepath);
        if(dumpfile!=NULL){
            QMessageBox::question(this,UI_TITLE,"是否保存");
            size_t len=cap->datacharLink.size();
            for(int n=0;n<len;n++){
                 pcap_dump((u_char *)dumpfile,cap->dataheaderLink[n],cap->datacharLink[n]);
            }
        }
    }
}

//打开离线文件
void MainWindow::on_file_open_triggered()
{
    if(cap->isRunning()){
        QMessageBox::warning(this, "warning", tr("请先暂停或关闭捕获!"), QMessageBox::Ok);
    }else{
        ui->btn_over->setEnabled(true);
        for(int row = ui->tableWidget->rowCount() - 1;row >= 0; row--)
        {
            ui->tableWidget->removeRow(row);
        }
        QString openfilename=QFileDialog::getOpenFileName(this,tr("打开文件"),".","*.pcap");
        string filestr=openfilename.toStdString();
        const char *openstr=filestr.c_str();
        qDebug()<<openstr;
        char source[PCAP_BUF_SIZE];
        if(pcap_createsrcstr(source,PCAP_SRC_FILE,NULL,NULL,openstr,errbuf)!=0)
        {
             QMessageBox::warning(this, "warning", tr("创建源字符串失败!"), QMessageBox::Ok);
        }
        if((adhandle=pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000, NULL, errbuf))==NULL)
        {
             QMessageBox::warning(this, "warning", tr("无法打开本地文件!"), QMessageBox::Ok);
        }else{
            cap->start();
        }
    }
}


void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    net_index=ui->comboBox->currentIndex();
    if(net_index!=0){
        /*打开适配器*/
        if(net_card_open()==-1){
            QMessageBox::critical(this, tr("提示"),  tr("适配器打开失败"),QMessageBox::Ok);
        }
    }
}

