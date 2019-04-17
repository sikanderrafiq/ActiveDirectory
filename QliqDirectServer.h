#ifndef QLIQDIRECTSERVER_H
#define QLIQDIRECTSERVER_H
#include <QObject>
#include <QVariantMap>
#include "qliqdirect/QliqDirectImapAccountStatusStruct.h"

class QTimer;
class QxtRPCPeer;
class WebClient;
class QliqSip;
class SipAccountSettings;
class QliqDirect;
class Database;
class ChangeNotificationReceiver;

namespace core {
class Crypto;
}

class QliqDirectServer : public QObject
{
    Q_OBJECT
public:
    explicit QliqDirectServer(QObject *parent = 0);
    ~QliqDirectServer();

    static int readHttpPortFromSettings();

public slots:
    bool start(bool autoLogin = true);
    void stop();

private slots:
    void onTimeRequested(quint64 clientId);
    void doLogin(quint64 clientId);
    void onLoginFailed(const QString& error, int networkErrorCode, int httpErrorCode, const QVariantMap& errorMap);
    void onLoginSucceeded();
    void onKeyPairReceived(const QString &qliqId, const QString &publicKey, const QString &privateKey);
    void doQuit(quint64 clientId);
    void setAdminCredentials(quint64 clientId, const QString& username, const QString& password);
    void onQliqDirectConfigReceived(const QString& userName, const QString& password, const QString& apiKey);
    void onQliqDirectConfigFailedToReceive(const QString& error);
    void onClientConnected(quint64 id);
    void onClientDisconnected(quint64 id);
    void onSipRegistrationStatusChanged(bool isRegistered, int statusCode, bool isReRegistration);
    void onImapAccountStatusUpdated(QliqDirectImapAccountStatusStruct status);
    void setHttpPort(quint64 id, int port);
    void getRegistrationStatus(quint64 clientId);
    void doSipReRegister(quint64 clientId);
    void doSipRestart(quint64 clientId);
    void onRetryLoginTimerTimedout();
    void onRpcReloadWctpConfig(quint64 clientId);
    // SMTP
    void onRpcReloadSmtpConfig(quint64 clientId);
    void sendTestEmail(quint64 clientId, const QString& from, const QString& to, const QVariantMap& config);
    // Active Directory
    void onRpcReloadAdConfig(quint64 clientId);
    void testAdAdminCredentials(quint64 clientId, const QVariantMap& config);
    void testAdSearchFilter(quint64 clientId, const QVariantMap& config, int pageSize);
    void testAdMainGroup(quint64 clientId, const QVariantMap& config, int pageSize);
    void onAdResetLocalDatabase(quint64 clientId);
    void onAdForceSync(quint64 clientId, bool isResume, bool full);
    void onAdClearAnomalyFlag(quint64 clientId);
    void loadEventLog(quint64 clientId, int offset, int count);
    void deleteEventLog(quint64 clientId);
    void getAdSyncStatus(quint64 clientId);
    void onRpcHeartbeatTimedOut();
    void onGetSqlDatabaseConfigRequest(quint64 clientId);
    // Logging
    void setLogLevel(quint64 clientId, int level);
    void getLogLevel(quint64 clientId);
    void onNotifyLogConfigChanged(quint64 clientId);
    void onDoVacuumLogDatabase(quint64 clientId);


private:
    void configureLogging(int level);
    void setupDbKey(const QString& userId, const QString& keyDirPath);

    QxtRPCPeer *rpc;
    WebClient *webClient;
    QliqSip *sip;
    QliqDirect *qliqDirect;
    core::Crypto *crypto;
    Database *db;
    ChangeNotificationReceiver *changeNotificationReceiver;
    QTimer *m_rpcHeartbeatTimer;
    QString m_setupTimeAdminEmail;
};

#endif // QLIQDIRECTSERVER_H
