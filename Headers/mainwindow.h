#ifndef MAINWINDOW_H
#define MAINWINDOW_H
/*库*/
#include<QMutex>
#include<QMessageBox>
#include<QObject>
#include<QThread>
#include <QPainter>
#include <QMouseEvent>
#include<QLabel>
#include <QTimer>
#include <QMainWindow>
/*c++库*/
#include<iostream>
/*外库*/
#define HAVE_REMOTE
#include "pcap.h"
#include<StdAfx.h>
/*用户自定义*/
#include"capture.h"
#include"config.h"
#include"arp_spoof.h"
/*--------*/

using namespace std;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow :public QMainWindow
{
    Q_OBJECT

public:
    explicit  MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void initScene();
    int net_card_find();//发现网卡
    int net_card_open();//打开网卡
    int net_card_filter();//设置过滤

signals:
    void isdone(bool flag);

private slots:
    void on_comboBox_currentIndexChanged();//选择网卡
    void on_btn_start_clicked();//捕获数据
    void on_btn_over_clicked();//结束捕获
    void showProtoTree(int,int);

    void updateTableWidget(QString timestr,QString srcMac,QString dstMac,QString pkt_len,QString protoType,QString srcIP,QString dstIP);//更新抓包窗口

    void updateCapCalculate();

    void on_btn_pause_clicked();

    void on_ARP_2_triggered();

    void on_file_save_triggered();

    void on_file_open_triggered();

    void on_comboBox_currentIndexChanged(int index);

public:
    void dealTimeout();//定时器槽函数
    void dealDone();
    void stopThread();//停止线程槽函数
    void slotGrabFullScreen();

private:
    Capture *cap=new Capture();

private:
    Ui::MainWindow *ui;
    QTimer *myTimer;
};
#endif // MAINWINDOW_H
