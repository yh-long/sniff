#include "worker.h"

Worker::Worker(QObject *parent)
{

}

void Worker::doWork(int parameter)
{
    qDebug() << "receive the execute signal" ;
    qDebug() << "\tCurrent thread ID: " << QThread::currentThreadId();

    // 循环一百万次
    for (int i = 0; i != 1000000; ++i)
    {
        ++parameter ;
    }

    // 发送结束信号
    qDebug() << "\tFinish the work and sent the result Ready signal\n" ;

    emit resultReady(parameter);
}
