#include "controller.h"

Controller::Controller(QObject *parent) : QObject(parent)
{
    auto *worker = new Worker ;

    // 调用 moveToThread 将该任务交给 workThread
    worker->moveToThread(&workerThread);

    // operate 信号发射后启动线程工作
    connect(this, SIGNAL(operate(const int)), worker, SLOT(doWork(int)));

    // 该线程结束时销毁
    connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);

    // 线程结束后发送信号，对结果进行处理
    connect(worker, SIGNAL(resultReady(int)), this, SLOT(handleResults(int)));

    // 启动线程
    workerThread.start();

    // 发射信号，开始执行
    qDebug() << "emit the signal to execute!" ;
    qDebug() << "\tCurrent thread ID:" << QThread::currentThreadId() << '\n' ;

    emit operate(0);
}

// 析构函数中调用 quit() 函数结束线程
Controller::~Controller()
{
    workerThread.quit();
    workerThread.wait();
}

void Controller::handleResults(const int result)
{
    qDebug() << "receive the resultReady signal" ;
    qDebug() << "\tCurrent thread ID: " << QThread::currentThreadId() << '\n' ;
    qDebug() << "\tThe last result is: " << result ;
}
