/*arp界面*/
#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H
#include <QThread>
#include<QObject>
#include<QDialog>
#include<string.h>
#include<gobalvar.h>
#include"arpthread.h"
#include "qlabel.h"
#include "qlineedit.h"
#include "qtablewidget.h"
#include "sendpktthread.h"

class ARP_spoof:public QDialog
{
    Q_OBJECT
public:
    ARP_spoof(QWidget *parent=nullptr);
    ArpThread *arpth=new ArpThread();
    SendPktThread *sendpktthread=new SendPktThread;
    QLabel *dstIP;
    QLabel *dstMAC;
    QLabel *gatewayIP;
    QLabel *gatewayMAC;
    QLineEdit *dstipline;
    QLineEdit *dstmacline;
    QLineEdit *gateipline;
    QLineEdit *gatemacline;
    QTableWidget *arptable;


signals:
    void isstop(bool flag);
    void sendMacIp(QString gateMac,QString gateIP,QString targetMac,QString targetIP);
    void send(u_char *curMac,u_char *targetMac,u_char *gateMac,u_char *targetip,u_char *gateip);
private slots:
    void on_arpstart_clicked();
    void on_arpstop_clicked();
    void on_arppause_clicked();
    void infoview(QString info);
};

#endif // ARP_SPOOF_H
