#include <QsLog.h>
#include "qliqdirect/service/QliqDirectServer.h"
#include "qliqdirect/service/QliqDirectService.h"
#include "qliqdirect/QliqDirectConfig.h"

QliqDirectService::QliqDirectService(int argc, char **argv) :
    QtService<QCoreApplication>(argc, argv, QLIQ_DIRECT_SERVICE_NAME),
    m_noAutoLogin(false),
    m_server(NULL)
{
    setServiceDescription("The service provides integration with Enterprise IT for Qliq applications");

    const QString NO_AUTO_LOGIN = "--no-auto-login";
    for (int i = 0; i < argc; ++i) {
        if (NO_AUTO_LOGIN == argv[i]) {
            m_noAutoLogin = true;
        }
    }
}

QliqDirectService::~QliqDirectService()
{
    if (m_server) {
        QLOG_SUPPORT() << "Destroying qliqDirect service 2";
        delete m_server;
    }
    QLOG_SUPPORT() << "Goodbye.";
    QsLogging::Logger::destroyInstance();
}

void QliqDirectService::start()
{
    QLOG_SUPPORT() << "Starting";

    if (!m_server)
        m_server = new QliqDirectServer();

    if (!m_server->start(!m_noAutoLogin)) {
        stop();
        QLOG_SUPPORT() << "Exiting due to an error in the start() method";
        qApp->exit(-1);
    }
}

void QliqDirectService::stop()
{
    QLOG_SUPPORT() << "Stopping";

    if (m_server) {
        m_server->stop();
        delete m_server;
        m_server = NULL;
    }
    QLOG_SUPPORT() << "Stopped";
}

void QliqDirectService::processCommand(int code)
{
}
