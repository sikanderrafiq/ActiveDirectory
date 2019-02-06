#-------------------------------------------------
#
# Project created by QtCreator 2018-07-27T14:21:26
#
#-------------------------------------------------

QT       += core sql network xml

DEFINES -= UNICODE
DEFINES += NO_GUI QLIQ_SERVICE HAS_SIP
DEFINES += QLIQ_DIRECT_SERVICE
DEFINES += QLIQ_CORE_QT


greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ActiveDirectory
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        MainWindow.cpp \
    DomainControllerManager.cpp

HEADERS += \
        MainWindow.h \
    DomainControllerManager.h

FORMS += \
        MainWindow.ui


# Active Directory
LIBS += -L$$PWD/lib -lactiveds -loleaut32 -lole32 -lnetapi32
