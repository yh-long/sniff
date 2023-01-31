QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    arp_spoof.cpp \
    arpthread.cpp \
    capture.cpp \
    main.cpp \
    mainwindow.cpp \
    sendpktthread.cpp \
    utillities.cpp

HEADERS += \
    arp_spoof.h \
    arpthread.h \
    capture.h \
    config.h \
    gobalvar.h \
    mainwindow.h \
    protocol.h \
    sendpktthread.h \
    utillities.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
INCLUDEPATH += "D:/Qt/WpdPack/Include"
LIBS += "-LD:/Qt/WpdPack//Lib/x64" -lwpcap -lPacket
win32:DEFINES+=_CRT_SECURE_NO_WARNINGS，
win32:DEFINES+=_WINSOCK_DEPRECATED_NO_WARNINGS
CXXFLAGS="-std=c++0x"
./configure
QT += concurrent
RESOURCES += \
    resoure.qrc
CONFIG += resources_big
QT += network
QT += core5compat
