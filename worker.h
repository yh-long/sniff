#ifndef WORKER_H
#define WORKER_H


#include <QObject>
#include <QDebug>
#include <QThread>

class Worker : public QObject
{
Q_OBJECT

public:
    explicit Worker(QObject *parent = nullptr);

public slots:
    void doWork(int parameter);  // doWork 定义了线程要执行的操作

signals:
    void resultReady(const int result);  // 线程完成工作时发送的信号
};

#endif // WORKER_H
