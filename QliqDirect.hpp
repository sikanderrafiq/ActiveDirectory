#ifndef QLIQ_DIRECT_HPP
#define QLIQ_DIRECT_HPP
#include <QObject>
#include <QDateTime>
#include <QVariantMap>

#include "core/connect/ChatMessage.hpp"
#include "qliqdirect/QliqDirectImapAccountStatusStruct.h"

class QxtRPCPeer;

class QliqSip;
class QliqUser;
class WebClient;
class AdMonitor;
struct QliqDirectContact;
struct MessageItem;
struct SmtpConfig;
struct AdConfig;

namespace core {
namespace connect {
class QliqConnect;
}
}

class QliqDirect : public QObject
{
    Q_OBJECT
public:
    explicit QliqDirect(QliqSip *sip, WebClient *webClient, QxtRPCPeer *rpc, int httpPort, QObject *parent = nullptr);
    ~QliqDirect();

    bool setHttpPort(int number);
    int httpPort() const;
    void reloadSmtpConfig();
    void reloadAdConfig();
    AdConfig adConfig() const;
    QString getAdSyncStatus() const;
    void forceAdSync(bool isResume, bool full);
    void clearAnomalyFlag();
    void stop();
    AdMonitor* adMonitor();

    core::connect::QliqConnect *qliqConnect() const;

signals:
    void getQliqDirectImapSettings(const QString &adminEmail, const QString &adminPassword);

    void imapAccountStatusUpdated(QliqDirectImapAccountStatusStruct status);
    void clearImapAccountStatusTable();
    void getImapAccounts(quint64 clientId);
    void checkForNewEmail(quint64 clientId, const QString& emailAccount);

public slots:
//    void updateCensus(const QVariantMap& census);
    void onMessageReceived(const QString& to, const QString& from, const QVariantMap& message, const QVariantMap& extraHeaders);
    void onQliqDirectImapSettingsReceived(const QVariantMap& imapSettings);
    void onInvitationCreated(int id, const QliqUser& qliqUser, const QString& connectionStatus, const QString& url);
    void onInvitationCreationFailed(int id, const QString &email, const QString& errorMsg);
    void onGotAllContacts(const QString& qliqId, bool error);
    void onValidateApiKey(const QString& apiKey);
    void onQliqDirectApiKeyValidationReceived(const QString& apiKey, bool isValid);
    void onGotContactInfo(const QString& qliqId, const QString& email, const QString& mobile, const QliqUser& user, int errorCode);

private slots:
    void onChatMessagesReceived(const core::connect::ChatMessage& msg);
    void onChatMessageStatusChanged(const QString& toUserId, const QString& uuid, int status);
    void onSendMessage(const MessageItem& message);
    void onCreateMultipartyChatFinished(int id, const QString& multipartyQliqId, const QString& errorMsg);
    void onChatMessageAttachmentStatusChanged(core::connect::ChatMessageAttachmentSharedPtr attachment);

private:
    struct Private;
    Private *d;
};

#endif // QLIQ_DIRECT_HPP
