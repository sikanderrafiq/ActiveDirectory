#ifndef QLIQDIRECTSERVICE_H
#define QLIQDIRECTSERVICE_H
#include <QCoreApplication>
#include <qtservice.h>

class QliqDirectServer;

class QliqDirectService : public QtService<QCoreApplication>
{
public:
    QliqDirectService(int argc, char **argv);
    ~QliqDirectService();

protected:
    void start();
    void stop();
    void processCommand(int code);

private:
    bool m_noAutoLogin;
    QliqDirectServer *m_server;
};

#endif // QLIQDIRECTSERVICE_H
