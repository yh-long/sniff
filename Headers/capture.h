#ifndef CAPTURE_H
#define CAPTURE_H
#include <QThread>
#include<QObject>
#include <QMutex>
#include"gobalvar.h"
#include"utillities.h"
#include"protocol.h"
#include<QDebug>
#include<QString>
class Capture:public QThread
{
    Q_OBJECT
public:
    Capture();
    dataVec datacharLink;
    datapktVec datapktLink;
    dataheaderVec dataheaderLink;
    pktCount *npacket=(pktCount*)malloc(sizeof(pktCount));
    Utillities m_analyze;
    void save();
private:
    bool isStop;
public slots:
    void setflag(bool flag);
signals:
    void num(int i);
    void addOneCaptureLine(QString timestr,QString srcMac,QString dstMac,QString pkt_len,QString protoType,QString srcIP,QString dstIP);
    void updatePktCount();

private:
    void run();
};


#endif // CAPTURE_H
