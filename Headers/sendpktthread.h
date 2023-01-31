#ifndef SENDPKTTHREAD_H
#define SENDPKTTHREAD_H
#include <QThread>
#include<QObject>
#include <QMutex>

#include<QDebug>
#include<QString>
#include"gobalvar.h"
#include "protocol.h"

class SendPktThread:public QThread
{
    Q_OBJECT
public:
    SendPktThread();
    u_char *modifyMac;
    u_char *targetMac;
    u_char *gateMac;
    u_char *targetIp;
    u_char *gateIp;
    u_char *currentMac;

private:
    bool isStop;
signals:
    QString info(QString strinfo);
public slots:
    void setflag(bool flag);
    void MacIp(u_char *curmac,u_char *targetmac,u_char *gatemac,u_char *targetip,u_char *gateip);

private:
    void run();
};

#endif // SENDPKTTHREAD_H
