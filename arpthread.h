#ifndef ARPTHREAD_H
#define ARPTHREAD_H
#include <QThread>
#include<QObject>
#include <QMutex>
#include"gobalvar.h"
#include<QDebug>
#include<QString>

class ArpThread:public QThread
{
     Q_OBJECT
public:
    ArpThread();
    unsigned char* GetSelfMac(char* pDevName);
    const u_char *BuildArpPacket(unsigned char *current_mac,QString render_IP,QString target_Mac,QString target_IP);
    u_char *mac;//本机mac
    QString gateMac;
    QString gateIP;
    QString targetMac;
    QString targetIP;
    u_char packet[42];
    u_char send_targetmac[6];
    u_char send_gatemac[6];
    u_char send_targetip[4];
    u_char send_gateip[4];
public slots:
    void setflag(bool flag);
    void MacIp(QString gate_Mac,QString gate_IP,QString target_Mac,QString target_IP);
private:
    bool isStop;
signals:
    QString info(QString strinfo);

private:
    void run();
};

/*arp包*/
typedef struct _arppkt
{
    struct _ethhdr *ethh;
    struct _arphdr *arph;
}arppkt;
#endif // ARPTHREAD_H
