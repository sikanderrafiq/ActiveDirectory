#include "QliqDirectServer.h"
#ifdef Q_OS_WIN
#include <windows.h>
#endif
#include <QDebug>
#include <QDateTime>
#include <QSettings>
#include <QDir>
#include <QCoreApplication>
#include <QxtRPCPeer>
#include <QLibrary>
#include <QTimer>
#include "sip/QliqSip.hpp"
#include "qliqdirect/service/QliqDirect.hpp"
#include "QsLog.h"
#include "QsLogDest.h"
#include "core/Crypto.hpp"
#include "core/CryptoKeyStore.hpp"
#include "AppVersionQliqDirect.h"
#include "qliqdirect/RpcConstants.h"
#include "qliqdirect/QliqDirectUtil.h"
#include "qliqdirect/service/ad/AdConfig.h"
#include "qliqdirect/service/ad/qliqDirectAD.h"
#include "qliqdirect/service/ad/AdMonitor.h"
#include "db/DatabaseKeyStore.h"
#include "db/Database.h"
#include "db/LogDatabase.h"
#include "WebClient.h"
#include "qliqdirect/QliqDirectConfig.h"
#include "qliqdirect/QliqDirectImapAccountStatusStruct.h"
#include "qliqdirect/shared/config/QliqDirectConfigFile.h"
#include "qliqdirect/shared/config/WctpConfig.h"
#include "qliqdirect/service/EmailSender.h"
#include "models/ChangeNotificationReceiver.h"
#include "service/QliqServiceUtil.h"
#include "util/OsVersion.h"
#include "util/MachineId.h"
#include "dao/QliqUserDao.h"

// This method displays a message box on user's desktop even from a GUI-less service.
// It used to display critical messages (service failure).
void showMessageBoxOnUserDesktop(const QString& title, const QString& message);

#define SETTINGS_GROUP "Server"
#define SETTINGS_USER_ID "userId"
#define SETTINGS_PASSWORD "password"
#define SETTINGS_EMAIL "email"
#define SETTINGS_SERVER_ADDRESS "serverAddress"
#define SETTINGS_REQUIRE_WCTP_SECURITY_CODE "requireWctpSecurityCode"
#define SETTINGS_WCTP_SECURITY_CODE "wctpSecurityCode"
#define SETTINGS_LOG_LEVEL "logLevel"
#define SETTINGS_PORT "port"
#define SETTINGS_GROUP_SMTP "smtp"
#define SETTINGS_ENANBLED "enabled"
#define SETTINGS_ENCRYPTION_METHOD "encryptionMethod"
#define SETTINGS_SET_FROM_EMAIL "setFromEmail"
#define SETTINGS_USE_DEFAULT_FORWARD_EMAIL "useDefaultForwardEmail"
#define SETTINGS_DEFAULT_FORWARD_EMAIL "defaultForwardEmail"
#define SETTINGS_API_KEY "apiKey"

#define LOG_RPC_REQUEST(clientId) QLOG_SUPPORT() << __FUNCTION__ << "RPC request from client" << clientId

namespace {
    SmtpConfig readSmtpConfig()
    {
        SmtpConfig config;

        QSettings settings;
        settings.beginGroup(SETTINGS_GROUP);
        settings.beginGroup(SETTINGS_GROUP_SMTP);
        config.enabled = settings.value(SETTINGS_ENANBLED).toBool();
        config.serverName = settings.value(SETTINGS_SERVER_ADDRESS).toString();
        config.port = settings.value(SETTINGS_PORT).toInt();
        if (config.port < 1) {
            config.port = 25;
        }
        config.username = settings.value(SETTINGS_USER_ID).toString();
        config.password = settings.value(SETTINGS_PASSWORD).toString();
        config.email = settings.value(SETTINGS_EMAIL).toString();
        config.encryptionMethod = settings.value(SETTINGS_ENCRYPTION_METHOD).toString();
        config.setFromEmail = settings.value(SETTINGS_SET_FROM_EMAIL).toBool();
        config.useDefaultForwardEmail = settings.value(SETTINGS_USE_DEFAULT_FORWARD_EMAIL).toBool();
        config.defaultForwardEmail = settings.value(SETTINGS_DEFAULT_FORWARD_EMAIL).toString();
        return config;
    }

    void writeSmtpConfig(const SmtpConfig& config)
    {
        QSettings settings;
        settings.beginGroup(SETTINGS_GROUP);
        settings.beginGroup(SETTINGS_GROUP_SMTP);
        settings.setValue(SETTINGS_ENANBLED, config.enabled);
        settings.setValue(SETTINGS_SERVER_ADDRESS, config.serverName);
        settings.setValue(SETTINGS_PORT, config.port);
        settings.setValue(SETTINGS_USER_ID, config.username);
        settings.setValue(SETTINGS_PASSWORD, config.password);
        settings.setValue(SETTINGS_EMAIL, config.email);
        settings.setValue(SETTINGS_ENCRYPTION_METHOD, config.encryptionMethod);
        settings.setValue(SETTINGS_SET_FROM_EMAIL, config.setFromEmail);
        settings.setValue(SETTINGS_USE_DEFAULT_FORWARD_EMAIL, config.useDefaultForwardEmail);
        settings.setValue(SETTINGS_DEFAULT_FORWARD_EMAIL, config.defaultForwardEmail);
    }

QString fixStagingWebServerForStaging(const QString& webServer)
{
    if (webServer.startsWith("http://")) {
        return QString(webServer).replace("http://", "https://");
    } else {
        return webServer;
    }
}

void dumpRegistrySettingsToConfigFile()
{
    QliqDirectConfigFile configFile;

    QSettings settings;
    settings.beginGroup(SETTINGS_GROUP);
    configFile.setLogLevel(settings.value(SETTINGS_LOG_LEVEL, QsLogging::SupportLevel).toInt());

    QString userId = settings.value(SETTINGS_USER_ID).toString();
    QString password = settings.value(SETTINGS_PASSWORD).toString();
    configFile.setValue(SETTINGS_USER_ID, userId);
    configFile.setEncryptedValue(SETTINGS_PASSWORD, password);

    QString serverAddress = settings.value(SETTINGS_SERVER_ADDRESS).toString();
    configFile.setValue(SETTINGS_SERVER_ADDRESS, serverAddress);

    QString apiKey = settings.value(SETTINGS_API_KEY).toString();
    configFile.setEncryptedValue(SETTINGS_API_KEY, apiKey);

    configFile.setHttpPort(settings.value(SETTINGS_PORT, QLIQ_DIRECT_DEFAULT_HTTP_PORT).toInt());

    AdConfig adConfig = AdConfig::load(SETTINGS_GROUP);
    configFile.setGroupValues("ActiveDirectory", adConfig.toMap());

    SmtpConfig smtpConfig = readSmtpConfig();
    configFile.setGroupValues("SMTP", smtpConfig.toMap());
}

}

QliqDirectServer::QliqDirectServer(QObject *parent) :
    QObject(parent),
    rpc(nullptr), webClient(nullptr), sip(nullptr), qliqDirect(nullptr),
    crypto(nullptr), db(nullptr), changeNotificationReceiver(nullptr),
    m_rpcHeartbeatTimer(nullptr)
{
    bool didDumpRegistryToFile = false;
    QliqDirectConfigFile configFile;
    if (!configFile.exists()) {
        dumpRegistrySettingsToConfigFile();
        configFile.sync();
        didDumpRegistryToFile = true;
    }
#ifdef QT_NO_DEBUG
    QsLogging::Level level = (QsLogging::Level) QliqDirectConfigFile().logLevel(QsLogging::SupportLevel);
#else
    QsLogging::Level level = QsLogging::DebugLevel;
#endif
    configureLogging(level);
    if (didDumpRegistryToFile) {
        QLOG_SUPPORT() << "Dumped registry settings to new config file";
    }

    // Database
    db = new Database();

    rpc = new QxtRPCPeer(this);
    rpc->attachSlot(RPC_TIME_REQUEST, this, SLOT(onTimeRequested(quint64)));
    rpc->attachSlot(RPC_DO_LOGIN, this, SLOT(doLogin(quint64)));
    rpc->attachSlot(RPC_DO_QUIT, this, SLOT(doQuit(quint64)));
    rpc->attachSlot(RPC_SET_ADMIN_CREDENTIALS, this, SLOT(setAdminCredentials(quint64,QString,QString)));
    rpc->attachSlot(RPC_SET_HTTP_PORT, this, SLOT(setHttpPort(quint64,int)));
    rpc->attachSlot(RPC_SET_LOG_LEVEL, this, SLOT(setLogLevel(quint64,int)));
    rpc->attachSlot(RPC_GET_LOG_LEVEL, this, SLOT(getLogLevel(quint64)));
    rpc->attachSlot(RPC_GET_REGISTRATION_STATUS, this, SLOT(getRegistrationStatus(quint64)));
    rpc->attachSlot(RPC_DO_SIP_REREGISTER, this, SLOT(doSipReRegister(quint64)));
    rpc->attachSlot(RPC_DO_SIP_RESTART, this, SLOT(doSipRestart(quint64)));
    rpc->attachSlot(RPC_NOTIFY_WCTP_CONFIG_CHANGED, this, SLOT(onRpcReloadWctpConfig(quint64)));
    rpc->attachSlot(RPC_RELOAD_SMTP_CONFIG, this, SLOT(onRpcReloadSmtpConfig(quint64)));
    rpc->attachSlot(RPC_SEND_TEST_EMAIL, this, SLOT(sendTestEmail(quint64,QString,QString,QVariantMap)));
    // Active Directory
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_RELOAD_CONFIG, this, SLOT(onRpcReloadAdConfig(quint64)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_TEST_ADMIN_CREDENTIALS, this, SLOT(testAdAdminCredentials(quint64,QVariantMap)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_RESET_LOCAL_DATABASE, this, SLOT(onAdResetLocalDatabase(quint64)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_TEST_SEARCH_FILTER, this, SLOT(testAdSearchFilter(quint64,QVariantMap,int)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_TEST_MAIN_GROUP, this, SLOT(testAdMainGroup(quint64,QVariantMap,int)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_LOAD_EVENT_LOG, this, SLOT(loadEventLog(quint64,int,int)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_GET_SYNC_STATUS, this, SLOT(getAdSyncStatus(quint64)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_DELETE_EVENT_LOG, this, SLOT(deleteEventLog(quint64)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_FORCE_SYNC, this, SLOT(onAdForceSync(quint64,bool,bool)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_DO_CLEAR_ANOMALY_FLAG, this, SLOT(onAdClearAnomalyFlag(quint64)));
    // Database
    rpc->attachSlot(RPC_GET_SQL_DATABASE_CONFIG, this, SLOT(onGetSqlDatabaseConfigRequest(quint64)));
    rpc->attachSlot(RPC_NOTIFY_LOG_CONFIG_CHANGED, this, SLOT(onNotifyLogConfigChanged(quint64)));
    rpc->attachSlot(RPC_NOTIFY_LOG_DB_DO_VACUUM, this, SLOT(onDoVacuumLogDatabase(quint64)));

    connect(rpc, SIGNAL(clientConnected(quint64)), SLOT(onClientConnected(quint64)));
    connect(rpc, SIGNAL(clientDisconnected(quint64)), SLOT(onClientDisconnected(quint64)));

    webClient = new WebClient(this);
    connect(webClient, SIGNAL(loginFailed2(QString,int,int,QVariantMap)), this, SLOT(onLoginFailed(QString,int,int,QVariantMap)));
    connect(webClient, SIGNAL(loginSucceeded()), this, SLOT(onLoginSucceeded()));
    connect(webClient, SIGNAL(keyPairReceived(QString,QString,QString)), SLOT(onKeyPairReceived(QString,QString,QString)));
    connect(webClient, SIGNAL(qliqDirectConfigReceived(QString,QString,QString)), SLOT(onQliqDirectConfigReceived(QString,QString,QString)));
    connect(webClient, SIGNAL(qliqDirectConfigFailedToReceive(QString)), SLOT(onQliqDirectConfigFailedToReceive(QString)));

//    m_rpcHeartbeatTimer = new QTimer(this);
//    m_rpcHeartbeatTimer->setSingleShot(false);
//    m_rpcHeartbeatTimer->setInterval(1000);
//    connect(m_rpcHeartbeatTimer, SIGNAL(timeout()), this, SLOT(onRpcHeartbeatTimedOut()));
//    m_rpcHeartbeatTimer->start();
}

QliqDirectServer::~QliqDirectServer()
{
    QLOG_SUPPORT() << "Deleting QliqDirectServer owned objects";
    delete rpc;
    delete changeNotificationReceiver;
    delete qliqDirect;

    delete sip;
    delete webClient;
    delete crypto;
    delete db;
    QLOG_SUPPORT() << "Objects deleted";
}

bool QliqDirectServer::start(bool autoLogin)
{
    // Windows service's current path is c:\windows\system32
    // Change it to app's directory
    QDir::setCurrent(QCoreApplication::applicationDirPath());

    int port = QLIQ_DIRECT_PORT;
    if (rpc->listen(QHostAddress::LocalHost, port)) {
        if (autoLogin) {
            doLogin(0);
        } else {
            QLOG_SUPPORT() << "Not doing autologin";
        }
        return true;
    } else {
        QLOG_ERROR() << "Error while trying to listen on port:" << port;
        showMessageBoxOnUserDesktop("qliqDirect Service", QString("qliqDirect Service error: Cannot listen on port %1").arg(port));
        return false;
    }
}

void QliqDirectServer::stop()
{
    QLOG_SUPPORT() << "Disconnecting RPC";
    rpc->detachSlots(this);
    rpc->stopListening();
    // The below line causes crash later in destructor
    // since last refactoring
//    rpc->disconnectAll();
    QLOG_SUPPORT() << "RPC disconnected";

    if (sip) {
        QLOG_SUPPORT() << "Stopping SIP";
        sip->stop();
        QLOG_SUPPORT() << "SIP stopped";
    }

    if (qliqDirect) {
        qliqDirect->stop();
    }
}

void QliqDirectServer::onTimeRequested(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);
    rpc->call("time-response", QDateTime::currentDateTime().toString());
}

void QliqDirectServer::doLogin(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);
    QString userId, password, serverAddress;
    {
        QliqDirectConfigFile configFile;
        userId = configFile.userId();
        password = configFile.password();
        serverAddress = configFile.webServerAddress();
    }

    if (userId.trimmed().isEmpty()) {
        QString errorMsg = "Cannot login, userId is empty";
        QLOG_ERROR() << errorMsg;
        rpc->call(RPC_NOTIFY_LOGIN, true, errorMsg, "");
        return;
    }
    if (password.trimmed().isEmpty()) {
        QString errorMsg = "Cannot login, password is empty";
        QLOG_ERROR() << errorMsg;
        rpc->call(RPC_NOTIFY_LOGIN, true, errorMsg, "");
        return;
    }
    if (serverAddress.trimmed().isEmpty()) {
        QString errorMsg = "Cannot login, server address is empty";
        QLOG_ERROR() << errorMsg;
        rpc->call(RPC_NOTIFY_LOGIN, true, errorMsg, "");
        return;
    }

    QLOG_SUPPORT() << "RPC Trying to login at webserver:" << serverAddress;

    QSettings settings;
    settings.beginGroup(SETTINGS_GROUP);
    settings.setValue(SETTINGS_USER_ID, userId);
    settings.setValue(SETTINGS_PASSWORD, password);
    settings.endGroup();

    webClient->setWebServerAddress(serverAddress);
    webClient->login(userId, password, APP_VERSION_NUMBER);
}

void QliqDirectServer::onLoginFailed(const QString &error, int networkErrorCode, int httpErrorCode, const QVariantMap& errorMap)
{
    Q_UNUSED(errorMap);

    QLOG_ERROR() << "Login failed:" << error;
    rpc->call(RPC_NOTIFY_LOGIN, true, error, webClient->webServerAddress());

    if (networkErrorCode != 0 || std::abs(httpErrorCode) / 100 == 5) {
        QLOG_SUPPORT() << "Webserver or network error, will retry login in 1 min";
        QTimer *timer = new QTimer(this);
        timer->setSingleShot(true);
        timer->setInterval(60 * 1000);
        connect(timer, SIGNAL(timeout()), SLOT(onRetryLoginTimerTimedout()));
        timer->start();
    }
}

void QliqDirectServer::onRetryLoginTimerTimedout()
{
    QTimer *timer = qobject_cast<QTimer *>(sender());
    if (timer) {
        timer->deleteLater();
    }

    if (!sip) {
        QLOG_SUPPORT() << "Retrying login";
        doLogin(0);
    }
}

void QliqDirectServer::onRpcReloadWctpConfig(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    QliqDirectConfigFile configFile;
    QliqDirectConfigFileObserver::notifyGroupChanged(configFile, WctpConfig::groupName());
    //rpc->call(clientId, RPC_NOTIFY_WCTP_CONFIG_CHANGED_RESPONSE, false, "");
}

void QliqDirectServer::onRpcReloadSmtpConfig(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    if (qliqDirect) {
        qliqDirect->reloadSmtpConfig();
    }
    rpc->call(clientId, RPC_RELOAD_SMTP_CONFIG_RESPONSE, false, "");
}

void QliqDirectServer::sendTestEmail(quint64 clientId, const QString &from, const QString &to, const QVariantMap& config)
{
    LOG_RPC_REQUEST(clientId);

    QString outErrorString;
    QliqDirectImapAccount account = EmailSender::smtpConfigToAccount(SmtpConfig::fromMap(config));
    bool ret = EmailSender::sendEmail(to, "", "qliqDirect Test E-mail", "If you can see this message it means qliqDirect's SMTP settings are valid.", account, from, &outErrorString);
    rpc->call(clientId, RPC_SEND_TEST_EMAIL_RESPONSE, ret, outErrorString);
}

void QliqDirectServer::onRpcReloadAdConfig(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    AdConfig adConfig;
    QString userId, password;
    {
        QliqDirectConfigFile configFile;
        adConfig.fromMap(configFile.groupValues("ActiveDirectory"));
        userId = configFile.userId();
        password = configFile.password();
    }

    if (qliqDirect) {
        qliqDirect->reloadAdConfig();
    }

    webClient->setQliqDirectConfig(userId, password, adConfig.isEnabled, adConfig.enableAuth, adConfig.changePasswordUrl, adConfig.autoAcceptNewUsers, adConfig.invitationMessageSubject);
    rpc->call(clientId, RPC_ACTIVE_DIRECTORY_RELOAD_CONFIG_RESPONSE, false, "");
}

void QliqDirectServer::testAdAdminCredentials(quint64 clientId, const QVariantMap &configMap)
{
    LOG_RPC_REQUEST(clientId);

    QString errorMsg;
    ActiveDirectory::Forest forest = forest.fromMap(configMap);

#ifndef QT_NO_DEBUG
    QString passwordDebugStr = forest.password;
#else
    QString passwordDebugStr = "[masked]";
#endif
    QString hostName = forest.primaryDomainController().host;
    QLOG_SUPPORT() << "Testing AD credentials, username:" << forest.userName << "password:" << passwordDebugStr << "host:" << hostName;

    ActiveDirectory::Credentials credentials;
    credentials.userName = forest.userName;
    credentials.password = forest.password;
    credentials.domain = hostName;

    ActiveDirectoryApi ad;
    long ret = ad.authenticateUser(credentials, "", &errorMsg, QSqlDatabase::database());
    if (ret == ActiveDirectoryApi::OkAuthStatus) {
        errorMsg = "";
    } else if (ret == ActiveDirectoryApi::InvalidCredentialsAuthStatus) {
        errorMsg = "Invalid credentials";
    } else if (ret == ActiveDirectoryApi::ServerUnreachableAuthStatus) {
        errorMsg = "Host is unreachable";
    }

    rpc->call(clientId, RPC_ACTIVE_DIRECTORY_TEST_ADMIN_CREDENTIALS_RESPONSE, ret >= 0, errorMsg);

    if (errorMsg.isEmpty()) {
        errorMsg = "success";
    }
    QLOG_SUPPORT() << "Testing AD credentials result:" << errorMsg;
}

void QliqDirectServer::testAdSearchFilter(quint64 clientId, const QVariantMap &configMap, int pageSize)
{
    LOG_RPC_REQUEST(clientId);

//    QString errorMsg;
//    AdConfig adConfig = AdConfig::fromMap(configMap);
////    QLOG_SUPPORT() << "username" << adConfig.userName << "password:" << adConfig.password << "domain" << adConfig.domain;
//    QVariantList results;
//    long ret = AdMonitor::testSearchFilter(adConfig, pageSize, &results, &errorMsg);
//    rpc->call(clientId, RPC_ACTIVE_DIRECTORY_TEST_SEARCH_FILTER_RESPONSE, (int)ret, errorMsg, results);
}

void QliqDirectServer::testAdMainGroup(quint64 clientId, const QVariantMap &configMap, int pageSize)
{
    LOG_RPC_REQUEST(clientId);

    QString errorMsg;
    ActiveDirectory::Forest forest = ActiveDirectory::Forest::fromMap(configMap);
    QVariantList results;
    long ret = AdMonitor::testGroupName(forest, pageSize, &results, &errorMsg, [this,clientId](const QVariantMap& entry) {
        rpc->call(clientId, RPC_ACTIVE_DIRECTORY_TEST_MAIN_GROUP_PARTIAL_RESULT_RESPONSE, entry);
        qApp->processEvents();
    });
    rpc->call(clientId, RPC_ACTIVE_DIRECTORY_TEST_MAIN_GROUP_RESPONSE, (int)ret, errorMsg, results);
}

void QliqDirectServer::onAdResetLocalDatabase(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    AdMonitor::resetSyncDatabase();
    rpc->call(clientId, RPC_ACTIVE_DIRECTORY_RESET_LOCAL_DATABASE_RESPONSE, true, "");
}

void QliqDirectServer::onAdForceSync(quint64 clientId, bool isResume, bool full)
{
    LOG_RPC_REQUEST(clientId);

    if (qliqDirect) {
        qliqDirect->forceAdSync(isResume, full);
    }
}

void QliqDirectServer::onAdClearAnomalyFlag(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    if (qliqDirect) {
        qliqDirect->clearAnomalyFlag();
    }
}

void QliqDirectServer::loadEventLog(quint64 clientId, int offset, int count)
{
    LOG_RPC_REQUEST(clientId);

    QString json = AdMonitor::loadEventLogAsJson(offset, count);
    rpc->call(clientId, RPC_ACTIVE_DIRECTORY_LOAD_EVENT_LOG_RESPONSE, json);
}

void QliqDirectServer::deleteEventLog(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    AdMonitor::deleteEventLog();
}

void QliqDirectServer::getAdSyncStatus(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    if (qliqDirect) {
        rpc->call(clientId, RPC_ACTIVE_DIRECTORY_GET_SYNC_STATUS_RESPONSE, qliqDirect->getAdSyncStatus());
    }
}

void QliqDirectServer::onRpcHeartbeatTimedOut()
{
    qDebug() << "RPC sending: " << RPC_NOTIFY_HEARTBEAT;
    rpc->call(RPC_NOTIFY_HEARTBEAT);
}

void QliqDirectServer::onGetSqlDatabaseConfigRequest(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);
    QString path = db->databasePath();
    QString key = db->encryptionKeyString();
    rpc->call(clientId, RPC_GET_SQL_DATABASE_CONFIG_RESPONSE, path, key);
}

void QliqDirectServer::onLoginSucceeded()
{
    QLOG_SUPPORT() << "Login succeeded";

    //delete sip;
    if (!sip) {
        sip = new QliqSip(webClient);
    } else {
        sip->stop();
    }
    connect(sip, SIGNAL(publicKeyNeeded(QString)),
            webClient, SLOT(getPublicKey(QString)));
    connect(webClient, SIGNAL(publicKeyReceived(QString,QString)),
            sip, SLOT(onPublicKeyReceived(QString,QString)));
    connect(webClient, SIGNAL(publicKeyFailedToReceive(QString,int)), sip, SLOT(onPublicKeyFailedToRetrieve(QString,int)));
    connect(sip, SIGNAL(registrationStatusChanged(bool,int,bool)), SLOT(onSipRegistrationStatusChanged(bool,int,bool)));

    SipAccountSettings sipAccount = webClient->userInfo().sipAccount;
    qDebug() << "\n\n\n\n=========================";
    qDebug() << "SIP password:" << sipAccount.password;
    qDebug() << "SIP server:" << sipAccount.serverInfo.url << ":" << sipAccount.serverInfo.port;
    qDebug() << "=========================\n\n\n\n";

    QLOG_SUPPORT() << "SIP URL:" << sipAccount.serverInfo.url << ":" << sipAccount.serverInfo.port;

//    if (disableSipTls) {
//        sipAccount.serverInfo.port = 5060;
//        sipAccount.serverInfo.transport = "TCP";
//    }
    sip->setAccountSettings(sipAccount);

    // To be compatible with iPhone we use a password hash as a private key password
    QString userId = webClient->userInfo().credentials.qliqId;

    const auto& myUser = webClient->userInfo().user;
    QliqUserDao::insertOrUpdate(myUser);

    //sip->setLogLevel(QsLogging::TraceLevel);
    sip->setCrypto(crypto);

    // TODO: refactor settings to config file
    QSettings settings;
    settings.beginGroup(SETTINGS_GROUP);
    int logLevel = settings.value(SETTINGS_LOG_LEVEL, -1).toInt();
    sip->setLogLevel(logLevel);

    if (!qliqDirect) {
        qliqDirect = new QliqDirect(sip, webClient, rpc, readHttpPortFromSettings());
        connect(qliqDirect, SIGNAL(imapAccountStatusUpdated(QliqDirectImapAccountStatusStruct)), this,
                 SLOT(onImapAccountStatusUpdated(QliqDirectImapAccountStatusStruct)));
        rpc->attachSlot(RPC_GET_IMAP_ACCOUNTS, qliqDirect, SIGNAL(getImapAccounts(quint64)));
        rpc->attachSlot(RPC_REFRESH_IMAP_ACCOUNT, qliqDirect, SIGNAL(checkForNewEmail(quint64,QString)));
        rpc->attachSignal(qliqDirect, SIGNAL(clearImapAccountStatusTable()), RPC_CLEAR_IMAP_STATUS_TABLE);

//        QliqDirectConfigFile configFile;
//        qliqDirect->onReadConfigFile(configFile);

        qliqDirect->reloadSmtpConfig();

        qliqDirect->reloadAdConfig();
        const AdConfig& adConfig = qliqDirect->adConfig();
        // TODO: refactor settings to config file
        QString userId = settings.value(SETTINGS_USER_ID).toString();
        QString password = settings.value(SETTINGS_PASSWORD).toString();
        webClient->setQliqDirectConfig(userId, password, adConfig.isEnabled, adConfig.enableAuth, adConfig.changePasswordUrl, adConfig.autoAcceptNewUsers, adConfig.invitationMessageSubject);

        changeNotificationReceiver = new ChangeNotificationReceiver(webClient, sip, NULL, qliqDirect->qliqConnect());
        connect(sip, SIGNAL(messageReceived(QString,QString,QVariantMap,QVariantMap)), changeNotificationReceiver, SLOT(onJsonMessageReceived(QString,QString,QVariantMap,QVariantMap)));
    }
    rpc->call(RPC_NOTIFY_LOGIN, false, "", webClient->webServerAddress());

    // Start SIP only after it was passed to other objects so the signals are connected
    sip->start();

    //changeNotificationReceiver->processPullLogsRequest(QVariantMap());
}

void QliqDirectServer::onKeyPairReceived(const QString &qliqId, const QString &publicKey, const QString &privateKey)
{
    if (qliqId != webClient->userInfo().user.qliqId)
        return;

    bool hadNoCrypto = (crypto == NULL);
    if (crypto == NULL) {
        QString keysDirPath = QliqDirectUtil::dataPathForQliqId(qliqId) + QDir::separator() + QString("keys");
        if (!QDir().mkpath(keysDirPath)) {
            QLOG_ERROR() << "Cannot create directory: " << keysDirPath;
        }

    #ifdef Q_OS_WIN
        keysDirPath = keysDirPath.replace("/", "\\");
    #endif
        core::FileCryptoKeyStore *keyStore = new core::FileCryptoKeyStore(keysDirPath.toStdString());
        crypto = new core::Crypto(keyStore);
    }

    std::string privateKeyPass = webClient->userInfo().credentials.password.toStdString();

    if (!crypto->saveKeysForUser(qliqId.toStdString(), privateKeyPass, privateKey.toStdString(), publicKey.toStdString())) {
        QLOG_ERROR() << "Cannot save keys for user" << webClient->userInfo().user.qliqId;
    } else if (hadNoCrypto) {
        core::FileCryptoKeyStore *keyStore = (core::FileCryptoKeyStore *) crypto->keyStore();
        QString dbKeyDirPath = QString::fromStdString(keyStore->pathForUser(qliqId.toStdString()));
        setupDbKey(qliqId, dbKeyDirPath);
    }
}

void QliqDirectServer::configureLogging(int level)
{
    QsLogging::Logger& logger = QsLogging::Logger::instance();
    logger.setLoggingLevel((QsLogging::Level) level);

//    QString logPath = QDesktopServices::storageLocation(QDesktopServices::DataLocation)
//            + QDir::separator() + "logs";

    QString logPath = QCoreApplication::applicationDirPath() + QDir::separator() + "logs";
    QDir dir(logPath);
    if (!dir.mkpath(logPath)) {
        qWarning() << "Cannot create directory: " << logPath;
    }
    logPath += QDir::separator() + QString(QLIQ_DIRECT_LOG_FILE_NAME);

    QsLogging::MaxSizeBytes sizeInBytesToRotateAfter(15 * 1024 * 1024); // 15 MB because it will be zipped so zip file will be like 5 MB max
    QsLogging::MaxOldLogCount oldLogsToKeep(3);
    QsLogging::DestinationPtr *fileDestination = new QsLogging::DestinationPtr(QsLogging::DestinationFactory::MakeFileDestination(logPath, QsLogging::EnableLogRotation, sizeInBytesToRotateAfter, oldLogsToKeep));
    QsLogging::DestinationPtr *debugDestination = new QsLogging::DestinationPtr(QsLogging::DestinationFactory::MakeDebugOutputDestination());
    logger.addDestination(*debugDestination);
    logger.addDestination(*fileDestination);

    QLOG_SUPPORT() << "=============================================================================================";
    QLOG_SUPPORT() << "Application started, qliqDirect version:" << APP_VERSION_NAME << "(" << APP_VERSION_NUMBER << ") build:" << APP_BUILD_NUMBER;
    QLOG_SUPPORT() << "OS version:" << OsVersion::version().toLatin1().constData();
    QLOG_SUPPORT() << "Device UUID:" << MachineId::id();
//#ifdef QLIQ_GIT_VERSION
//    QLOG_SUPPORT() << "Git hash:" << "9123598"; //QLIQ_GIT_VERSION;
//#endif
//    QLOG_SUPPORT() << "Git hash:" << GIT_HASH;
//    QLOG_SUPPORT() << "Git branch:" << GIT_BRANCH;
#ifdef Q_OS_WIN
    QLOG_SUPPORT() << "Main thread id: " << GetCurrentThreadId();
#endif
}

void QliqDirectServer::setupDbKey(const QString &userId, const QString &keyDirPath)
{
#ifdef QT_NO_DEBUG
    const unsigned int keyLen = 32;
    const QByteArray& dbKey = DatabaseKeyStore::readOrGenerateAndSaveKey(userId, keyDirPath, keyLen);
    if (!dbKey.isEmpty())
        db->setEncryptionKey(dbKey);
#endif

    QString dbPath = QliqDirectUtil::dataPathForQliqId(userId);

    bool isRetry = false;
    QString errorMsg;
    dbPath = dbPath + QDir::separator() + "qliq.db";
    db->setMyQliqId(userId);
    db->setDatabasePath(dbPath);
retry_opening_db:
    if (db->open(&errorMsg)) {
        if (db->isEmpty()) {
            errorMsg = "The database is empty";
            QFileInfo fi(dbPath);
            if (!fi.isWritable()) {
                errorMsg = "Cannot open the database file for writing";
            }
        }
    }

    if (!errorMsg.isEmpty()) {
        QLOG_ERROR() << "Cannot open the database:" << errorMsg;
        if (!isRetry) {
            QLOG_SUPPORT() << "Trying to delete and recreate the database";
            isRetry = true;
            db->close();
            QFile dbFile(dbPath);
            if (dbFile.remove()) {
                // Remove additional files present when using PRAGMA journal_mode = WAL
                QFile(dbPath + "-shm").remove();
                QFile(dbPath + "-wal").remove();
                QLOG_SUPPORT() << "Database file deleted";
                goto retry_opening_db;
            } else {
                QLOG_ERROR() << "Cannot delete the database file";
            }
        }
    }

    QLOG_SUPPORT() << "Loaded SQL* DLLs after opening db:";
    OsVersion::logLoadedDlls("sql");
}

void QliqDirectServer::doQuit(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    stop();
    qApp->quit();
}

void QliqDirectServer::setAdminCredentials(quint64 clientId, const QString &username, const QString &password)
{
    LOG_RPC_REQUEST(clientId);

    m_setupTimeAdminEmail = username;
    // Clear any saved webserver address and choose based on admin's email
    webClient->setWebServerAddress("");
    webClient->getQliqDirectConfig(username, password);
}

void QliqDirectServer::onQliqDirectConfigReceived(const QString &userName, const QString &password, const QString& apiKey)
{
    QLOG_SUPPORT() << "Received qliqDirect config from webserver";

    {
        QliqDirectConfigFile configFile;
        configFile.setValue(SETTINGS_USER_ID, userName);
        configFile.setQliqId(webClient->userInfo().user.qliqId);
        configFile.setEncryptedValue(SETTINGS_PASSWORD, password);
        configFile.setValue(SETTINGS_SERVER_ADDRESS, webClient->webServerAddress());
        configFile.setEncryptedValue(SETTINGS_API_KEY, apiKey);
        configFile.setAdminEmail(m_setupTimeAdminEmail);
    }

    doLogin(0);

    rpc->call(RPC_SET_ADMIN_CREDENTIALS_RESPONSE, "");
}

void QliqDirectServer::onQliqDirectConfigFailedToReceive(const QString &error)
{
    rpc->call(RPC_SET_ADMIN_CREDENTIALS_RESPONSE, error);
}

void QliqDirectServer::onClientConnected(quint64 id)
{
    QLOG_SUPPORT() << "onClientConnected" << id;
}

void QliqDirectServer::onClientDisconnected(quint64 id)
{
    QLOG_SUPPORT() << "onClientDisconnected" << id;
}

void QliqDirectServer::onSipRegistrationStatusChanged(bool isRegistered, int statusCode, bool isReRegistration)
{
    QLOG_SUPPORT() << "SIP registration changed to:" << isRegistered << "status:" << statusCode;
    const SipServerInfo& sipServer = webClient->userInfo().sipAccount.serverInfo;
    QString sipServerAddress = QString("%1:%2").arg(sipServer.url).arg(sipServer.port);
    rpc->call(RPC_NOTIFY_REGISTRATION, isRegistered, statusCode, sipServerAddress);
}

void QliqDirectServer::onImapAccountStatusUpdated(QliqDirectImapAccountStatusStruct status)
{
    rpc->call(RPC_IMAP_ACCOUNTS_STATUS, status.toString());
}

void QliqDirectServer::setHttpPort(quint64 clientId, int port)
{
    LOG_RPC_REQUEST(clientId);

    bool ok = false;
    if (port > 0 && port < 65535) {
        {
            QliqDirectConfigFile configFile;
            configFile.setHttpPort(port);
        }

        if (qliqDirect) {
            ok = qliqDirect->setHttpPort(port);
        } else {
            ok = true;
        }
    }
    rpc->call(clientId, RPC_SET_HTTP_PORT_RESPONSE, ok);
}

void QliqDirectServer::setLogLevel(quint64 clientId, int level)
{
    LOG_RPC_REQUEST(clientId);

    QSettings settings;
    settings.beginGroup(SETTINGS_GROUP);
    settings.setValue(SETTINGS_LOG_LEVEL, level);
    QLOG_SUPPORT() << "Saving log level:" << level;

    if (sip) {
        sip->setLogLevel(level);
    }

    if (level > QsLogging::SupportLevel) {
        // Don't go less verbose then support
        level = QsLogging::SupportLevel;
    }
    QsLogging::Logger& logger = QsLogging::Logger::instance();
    logger.setLoggingLevel((QsLogging::Level) level);
}

void QliqDirectServer::getLogLevel(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);
    QSettings settings;
    settings.beginGroup(SETTINGS_GROUP);
    int level = settings.value(SETTINGS_LOG_LEVEL, -1).toInt();
    rpc->call(clientId, RPC_GET_LOG_LEVEL_RESPONSE, level);
}

void QliqDirectServer::onNotifyLogConfigChanged(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);
    QliqServiceUtil::reloadLogConfig();
    rpc->call(clientId, RPC_NOTIFY_LOG_CONFIG_CHANGED_RESPONSE, true);
}

void QliqDirectServer::onDoVacuumLogDatabase(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);
    bool ret = false;
    if (LogDatabase::instance()) {
        ret = LogDatabase::vacuum();
    }
    rpc->call(clientId, RPC_NOTIFY_LOG_DB_DO_VACUUM_RESPONSE, ret);
}

void QliqDirectServer::getRegistrationStatus(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    bool isRegistered = false;
    int status = 0;

    if (sip) {
        isRegistered = sip->isRegistered();
        status = sip->lastRegistrationStatus();
    }

    rpc->call(clientId, RPC_GET_REGISTRATION_STATUS_RESPONSE, isRegistered, status);
}


void QliqDirectServer::doSipReRegister(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    if (sip) {
        sip->setRegistered(true);
    }
}

void QliqDirectServer::doSipRestart(quint64 clientId)
{
    LOG_RPC_REQUEST(clientId);

    if (sip) {
        sip->stop();
        sip->start();
    }
}

int QliqDirectServer::readHttpPortFromSettings()
{
    QliqDirectConfigFile configFile;
    return configFile.httpPort(QLIQ_DIRECT_DEFAULT_HTTP_PORT);
}

void showMessageBoxOnUserDesktop(const QString& title, const QString& message)
{
    QLOG_ERROR() << "Displaying error on user's desktop:" << title << message;
#ifdef Q_OS_WIN
    #define WTS_CURRENT_SERVER         ((HANDLE)NULL)
    #define WTS_CURRENT_SESSION ((DWORD)-1)

    typedef BOOL (*WTSSendMessageWPtr)(HANDLE hServer, DWORD SessionId, LPWSTR pTitle, DWORD TitleLength, LPWSTR pMessage, DWORD MessageLength, DWORD Style, DWORD Timeout,DWORD *pResponse, BOOL bWait);
    typedef DWORD (*WTSGetActiveConsoleSessionIdPtr)(void);

    QLibrary wtsapi32("wtsapi32");
    QLibrary kernel32("kernel32");
    if (wtsapi32.load() && kernel32.load()) {
        WTSGetActiveConsoleSessionIdPtr pWTSGetActiveConsoleSessionId = (WTSGetActiveConsoleSessionIdPtr) kernel32.resolve("WTSGetActiveConsoleSessionId");
        WTSSendMessageWPtr pWTSSendMessageW = (WTSSendMessageWPtr) wtsapi32.resolve("WTSSendMessageW");
        if (pWTSSendMessageW) {
            QScopedArrayPointer<WCHAR> titleArray(new WCHAR[title.size()]);
            QScopedArrayPointer<WCHAR> messageArray(new WCHAR[message.size()]);
            title.toWCharArray(titleArray.data());
            message.toWCharArray(messageArray.data());

            DWORD response;
            DWORD sessionId = pWTSGetActiveConsoleSessionId();
            pWTSSendMessageW(WTS_CURRENT_SERVER, sessionId, titleArray.data(), title.size() * sizeof(WCHAR),
                             messageArray.data(), message.size() * sizeof(WCHAR), 0, 0, &response, FALSE);
        }
    }
#endif
}
