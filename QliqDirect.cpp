#include "QliqDirect.hpp"
#include <cassert>
#include <QVariantMap>
#include <QDateTime>
#include <QByteArray>
#include <QCryptographicHash>
#include <QRegExp>
#include <QProcess>
#include <QDir>
#include <QCoreApplication>
#include <QTimer>
#ifdef Q_OS_WIN
#include <windows.h>
#endif
#include <time.h>
#include <QDebug>
#include "json/JsonUtil.hpp"
#include "json/JsonSchemaValidator.hpp"
#include "json/schema/Message.h"
#include "json/schema/services/GetQliqdirectImapSettingsResponseSchema.h"
#include "json/schema/ChangeNotificationSchema.h"
#include "core/json/schema/ExtendedChatMessageSchema.h"
#include "core/connect/ChatMessageAttachment.h"
#include "core/connect/ChatMessage.hpp"
#include "core/QliqStorClient.hpp"
#include "core/connect/QliqConnect.hpp"
#include "core/connect/DBHelperConversation.hpp"
#include "sip/QliqSip.hpp"
#include "charge/DataTypes.hpp"
#include "dao/QliqUserDao.h"
#include "dao/ConversationDao.h"
#include "dao/MessageQliqDirectOriginDao.h"
#include "dao/EmailsQliqDirectProcessedDao.h"
#include "models/QliqDirectImapAccount.h"
#include "QsLog.h"
#include "WebClient.h"
#include "qliqdirect/shared/config/QliqDirectConfigFile.h"
#include "qliqdirect/service/QliqDirectImapInterface.h"
#include "qliqdirect/service/EmailSender.h"
#include "qliqdirect/service/QliqDirectRestApiInterface.h"
#include "qliqdirect/service/QliqDirectMessageHelper.h"
#include "qliqdirect/RpcConstants.h"
#include "qliqdirect/service/EmailSender.h"
#include "qliqdirect/service/ad/AdConfig.h"
#include "qliqdirect/service/ad/AdMonitor.h"
#include "qliqdirect/service/ad/AdSip.h"
#include "service/QliqServiceUtil.h"
#include "json/schema/services/ValidateQliqdirectApikeyResponseSchema.h"
#include "connect/AttachmentManager.h"
#include "util/QObjectLocator.h"

#define KEY_ERROR "error"
#define KEY_CODE "code"
#define KEY_MESSAGE "message"
#define KEY_REQUEST_ID "requestId"

using namespace core::connect;

static core::connect::QliqConnect *s_qliqConnect;

core::connect::QliqConnect *getQliqConnectFromQliqDirect()
{
    return s_qliqConnect;
}

struct MultipartyChatItem : public MessageItem {
    int id;

    MultipartyChatItem(int id = 0) :
        id(id)
    {}

    bool isEmpty() const
    {
        return id < 1;
    }
};

struct QliqDirect::Private
{
public:

    QliqSip *sip;
    WebClient *webClient;
    core::QliqStorClient *qliqStorClient;
    core::connect::QliqConnect *conn;
    QString adminEmail;
    QString adminPassword;
    QliqDirectImapInterface imapInterface;
    QliqDirectRestApiInterface *restApiInterface;
    QThread *restApiInterfaceThread;
    QList<MultipartyChatItem> MultipartyChatItems;
    QList<MessageItem> uploadMessageQueue;
    QMultiMap<QString, MessageItem> pendingInvitationMessageMap;
    bool isUploadInProgress;
    QliqDirect *owner;
    SmtpConfig smtpConfig;
    EmailSender *emailSender;
    AdMonitor *adMonitor;
    QThread *adMonitorThread;
    AdSip *adSip;
    QString recentValidApiKey;
    QDateTime recentApiKeyDateTime;

    int createMultipartyChat(const QSet<QString>& selectedIds, const QString& subject);
    void addMessageToUploadQueue(const MessageItem& message);
    void sendNextInQueue();
    void sendMessage(const MessageItem& message);

    void clearAttachmentFiles(core::connect::ChatMessageAttachmentSharedPtr attachment);

    int sendInvitation(const QliqDirectContact& emailAddress);
    void resendMessagesToEmail(const QString& email);

    Private(QliqSip *sip, WebClient *webClient, QxtRPCPeer *rpc, int httpPort,  QliqDirect *p) :
        sip(sip),
        webClient(webClient),
        imapInterface(sip),
        isUploadInProgress(false),
        owner(p)
    {
        QliqServiceUtil::reloadLogConfig();

        auto objectLocator = new QObjectLocator(p);
        Q_UNUSED(objectLocator); // will be used by static instance() method

        qliqStorClient = new core::QliqStorClient(sip);
        s_qliqConnect = conn = new core::connect::QliqConnect(qliqStorClient, sip, webClient);
        {
            const QliqUser& me = webClient->userInfo().sipAccount.user;
            conn->setUser(me);
            core::connect::ChatMessage::setUserId(me.qliqId);
            //core::Metadata::setDefaultAuthor(me.qliqId.toStdString());
            //const int secondsPerDay = 60 * 60 * 24;
            //conn->setMessageRetentionPeriod(webClient->userInfo().securitySettings.keepMessagesFor * secondsPerDay);
            conn->deleteOldMessages();
            conn->setQliqStorEnabled(false);
        }
        qRegisterMetaType<MessageItem>("MessageItem");
        restApiInterface = new QliqDirectRestApiInterface(sip, rpc);
        restApiInterface->setPortNumber(httpPort);
        restApiInterfaceThread = new QThread();
        restApiInterface->moveToThread(restApiInterfaceThread);
        connect(restApiInterfaceThread, SIGNAL(started()), restApiInterface, SLOT(startRestApiServer()));
        connect(restApiInterface, SIGNAL(finished()), restApiInterfaceThread, SLOT(quit()));
        connect(restApiInterface, SIGNAL(finished()), restApiInterface, SLOT(deleteLater()));
        connect(restApiInterface, SIGNAL(needGetContactInfo(QString,QString)), webClient, SLOT(getContactInfo(QString,QString)));
        //connect(restApiInterfaceThread, SIGNAL(finished()), restApiInterfaceThread, SLOT(deleteLater()));
        connect(conn, SIGNAL(chatMessageStatusChanged(QString,QString,int)), restApiInterface, SLOT(onChatMessageStatusChanged(QString,QString,int)));
        restApiInterfaceThread->start();

        emailSender = new EmailSender();

        adMonitorThread = new QThread();
        adMonitor = new AdMonitor(webClient);
        adMonitor->moveToThread(adMonitorThread);
        adMonitorThread->start();

        adSip = new AdSip();
        adSip->setSip(sip);
    }

    ~Private()
    {
        QLOG_SUPPORT() << "Destructing QliqDirect::Private";

        if (adMonitor->isRunning()) {
            connect(adMonitor, SIGNAL(stopped()), adMonitorThread, SLOT(quit()));
//            connect(adMonitorThread, SIGNAL(finished()), adMonitorThread, SLOT(deleteLater()));
//            connect(adMonitorThread, SIGNAL(finished()), adMonitor, SLOT(deleteLater()));
        } else {
            adMonitorThread->quit();
        }
        adMonitor->requestStop();
        emailSender->quit();

        restApiInterface->stopServer();
        restApiInterfaceThread->quit();
        restApiInterfaceThread->wait();
        delete restApiInterface;
        delete restApiInterfaceThread;

        QLOG_SUPPORT() << "Stopping EmailSender";

        //emailSender->waitForFinished();
        delete emailSender;
        QLOG_SUPPORT() << "EmailSender stopped";

        QLOG_SUPPORT() << "Stopping AdMonitor";
//        if (adMonitor->isRunning()) {

//        } else {

            adMonitorThread->wait();
//        }
        delete adMonitor;
        delete adMonitorThread;
        QLOG_SUPPORT() << "AdMonitor stopped";

        delete adSip;
        delete conn;
        s_qliqConnect = nullptr;
        delete qliqStorClient;

        QLOG_SUPPORT() << "Destructing QliqDirect::Private DONE";
    }

    void forwardToEmail(const ChatMessage& msg);
    void forwardNextMessageToEmail();
};

QliqDirect::QliqDirect(QliqSip *sip,  WebClient *webClient, QxtRPCPeer *rpc, int httpPort,  QObject *parent) :
    QObject(parent),
    d(new Private(sip, webClient, rpc, httpPort, this))
{
    connect(sip, SIGNAL(messageReceived(QString,QString,QVariantMap,QVariantMap)),
            this, SLOT(onMessageReceived(QString,QString,QVariantMap,QVariantMap)));
    connect(&d->imapInterface, SIGNAL(sendMessage(MessageItem)),
            this, SLOT(onSendMessage(MessageItem)));
    connect(&d->imapInterface, SIGNAL(imapAccountStatusUpdated(QliqDirectImapAccountStatusStruct)), this, SIGNAL(imapAccountStatusUpdated(QliqDirectImapAccountStatusStruct)));
    connect(this, SIGNAL(checkForNewEmail(quint64,QString)), &d->imapInterface, SLOT(onCheckForNewEmail(quint64,QString)));
    connect(this, SIGNAL(getImapAccounts(quint64)), &d->imapInterface, SLOT(onGetImapAccounts(quint64)));

    connect(webClient, SIGNAL(qliqDirectImapSettingsReceived(QVariantMap)), this, SLOT(onQliqDirectImapSettingsReceived(QVariantMap)));
    connect(webClient, SIGNAL(invitationCreated(int,QliqUser,QString,QString)), this, SLOT(onInvitationCreated(int,QliqUser,QString,QString)));
    connect(webClient, SIGNAL(invitationCreationFailed(int,QString,QString)), this, SLOT(onInvitationCreationFailed(int,QString,QString)));
    connect(webClient, SIGNAL(gotAllContacts(QString,bool)), this, SLOT(onGotAllContacts(QString,bool)));
    connect(webClient, SIGNAL(gotContactInfo(QString,QString,QString,QliqUser,int)), this, SLOT(onGotContactInfo(QString,QString,QString,QliqUser,int)));
    connect(this, SIGNAL(getQliqDirectImapSettings(QString,QString)), webClient, SLOT(getQliqDirectImapSettings(QString,QString)));
    connect(d->conn, SIGNAL(createMultiPartyChatFinished(int,QString,QString)), this, SLOT(onCreateMultipartyChatFinished(int,QString,QString)));
    connect(d->conn, SIGNAL(chatMessageAttachmentStatusChanged(core::connect::ChatMessageAttachmentSharedPtr)),
            this, SLOT(onChatMessageAttachmentStatusChanged(core::connect::ChatMessageAttachmentSharedPtr)));
    connect(d->conn, SIGNAL(chatMessageStatusChanged(QString,QString,int)), this, SLOT(onChatMessageStatusChanged(QString,QString,int)));
    connect(d->conn, SIGNAL(chatMessagesReceived(core::connect::ChatMessage)), this, SLOT(onChatMessagesReceived(core::connect::ChatMessage)));
    connect(d->restApiInterface, SIGNAL(sendMessage(MessageItem)), this, SLOT(onSendMessage(MessageItem)));
    connect(d->restApiInterface, SIGNAL(validateApiKey(QString)), this, SLOT(onValidateApiKey(QString)));
    connect(d->restApiInterface, SIGNAL(needGetContactInfo(QString,QString)), webClient, SLOT(getContactInfo(QString,QString)));
    connect(webClient, SIGNAL(qliqDirectApiKeyValidationReceived(QString,bool)), this, SLOT(onQliqDirectApiKeyValidationReceived(QString,bool)));
    connect(webClient, SIGNAL(gotContactInfo(QString,QString,QString,QliqUser,int)), d->restApiInterface, SLOT(onGotContactInfo(QString,QString,QString,QliqUser,int)));

    emit getQliqDirectImapSettings(webClient->userInfo().credentials.email, webClient->userInfo().credentials.password);
}

QliqDirect::~QliqDirect()
{
    disconnect();
    delete d;
}

AdMonitor* QliqDirect::adMonitor()
{
    return d->adMonitor;
}

bool QliqDirect::setHttpPort(int number)
{
    return d->restApiInterface->setPortNumber(number);
}

int QliqDirect::httpPort() const
{
    return d->restApiInterface->portNumber();
}

void QliqDirect::reloadSmtpConfig()
{
    d->smtpConfig = SmtpConfig::loadFromConfigFile();
    const SmtpConfig& config = d->smtpConfig;
    d->emailSender->setSmtpConfig(config);
    if (d->smtpConfig.enabled) {
        QLOG_SUPPORT() << "Redirecting to email is enabled (" << config.serverName << "port:" << config.port
                       << "encryption:" << config.encryptionMethod << "is relay:" << config.setFromEmail
                       << "user:" << config.username << "pwd len:" << config.password.size() << "email:" << config.email
                       << "use default forward:" << config.useDefaultForwardEmail << "default email:" << config.defaultForwardEmail << ")";
    } else {
        QLOG_SUPPORT() << "Redirecting to email is disabled";
    }
}

void QliqDirect::reloadAdConfig()
{
    AdConfig config = AdConfig::loadFromConfigFile();
    config.rewriteOldSingleServerAsForestToConfigFile();

    QLOG_SUPPORT() << "Loaded AdConfig:" << config.toString();

    //config.webServerAddress = d->webClient->webServerAddress();
    d->adMonitor->setConfig(config);
    d->adSip->setConfig(config);
    if (config.isEnabled) {
        QString domain, groupName;
        if (!config.forests.isEmpty()) {
            domain = config.forests[0].primaryDomainController().host;
            groupName = config.forests[0].syncGroup;
        }
        QLOG_SUPPORT() << "Active Directory support is enabled, forest count:" << config.forests.size() << "1st forest domain:" << domain << "sync interval:" << config.syncIntervalMins << "1st forest sync group:" << groupName << "enable avatars:" << config.enableAvatars << "enable dn auth:" << config.enableDistinguishedNameBaseAuth;
        d->adMonitor->requestStart();
        //Set SIP only after we have the config
        d->adSip->setEnabled(true);
    } else {
        QLOG_SUPPORT() << "Active Directory support is disabled";
        if (d->adMonitor->isRunning()) {
            d->adMonitor->requestStop();
            d->adMonitor->waitForStopped();
        }
        d->adSip->setEnabled(false);
    }
}

AdConfig QliqDirect::adConfig() const
{
    return d->adMonitor->config();
}

QString QliqDirect::getAdSyncStatus() const
{
    if (d->adMonitor) {
        return d->adMonitor->getAdSyncStatus();
    } else {
        return "";
    }
}

void QliqDirect::forceAdSync(bool isResume, bool full)
{
    d->adMonitor->requestSync(isResume, full);
}

void QliqDirect::clearAnomalyFlag()
{
    d->adMonitor->manualyClearAnomalyFlag();
}

void QliqDirect::stop()
{
    if (d->adMonitor && d->adMonitor->isRunning()) {
        QLOG_SUPPORT() << "Stopping Active Directory thread because service is being stopped";
        d->adMonitor->requestStop();
        d->adMonitor->waitForStopped();
        QLOG_SUPPORT() << "Active Directory stopped";
    }
}

QliqConnect *QliqDirect::qliqConnect() const
{
    return s_qliqConnect;
}

void QliqDirect::onMessageReceived(const QString &to, const QString &from, const QVariantMap &message, const QVariantMap& extraHeaders)
{
    QString type = message.value(MESSAGE_MESSAGE_TYPE).toString();
    QString command = message.value(MESSAGE_MESSAGE_COMMAND).toString();
    QString subject = message.value(MESSAGE_MESSAGE_SUBJECT).toString();

    if (type == CHANGE_NOTIFICATION_MESSAGE_TYPE_PATTERN) {
        if (command == CHANGE_NOTIFICATION_MESSAGE_COMMAND_PATTERN) {
            if (subject == GET_QLIQDIRECT_IMAP_SETTINGS_RESPONSE_DATA_IMAP_SETTINGS) {
                emit getQliqDirectImapSettings(d->webClient->userInfo().credentials.email, d->webClient->userInfo().credentials.password);
                QLOG_SUPPORT() << "IMAP setting change notification received, starting to retrive email account list";
            } else {
                QLOG_SUPPORT() << "Notification received - " << subject;
            }
        }
    }
}

void QliqDirect::onQliqDirectImapSettingsReceived(const QVariantMap &imapSettings)
{
    QList<QliqDirectImapAccount> emailAccounts;
    const QVariantList& accounts = imapSettings.value(GET_QLIQDIRECT_IMAP_SETTINGS_RESPONSE_DATA_IMAP_SETTINGS).toList();
    emit clearImapAccountStatusTable();
    foreach (const QVariant& varient, accounts){
        const QVariantMap& account = varient.toMap();
        const QliqDirectImapAccount& a = QliqDirectImapAccount::fromMap(account);
        emailAccounts.append(a);
        emit imapAccountStatusUpdated(QliqDirectImapAccountStatusStruct(a.account, "Pending", EmailsQliqDirectProcessedDao::getEmailCountForImapAccount(a.account)));
        QLOG_SUPPORT() << "IMAP Settings received for account " << a.account;
    }
    d->imapInterface.setEmailAccounts(emailAccounts);
}

void QliqDirect::onInvitationCreated(int id, const QliqUser &qliqUser, const QString &connectionStatus, const QString &url)
{
    Q_UNUSED(id)
    Q_UNUSED(connectionStatus)
    Q_UNUSED(url)

    QLOG_SUPPORT() << "Invitation created for user " << qliqUser.email << qliqUser.qliqId;

    if (QliqUserDao::selectOneBy(QliqUserDao::IdColumn, qliqUser.qliqId).qliqId.isEmpty()) {
        d->webClient->continueGetPagedContacts(true);
    } else {
        d->resendMessagesToEmail(qliqUser.email);
    }
}

void QliqDirect::onInvitationCreationFailed(int id, const QString &email, const QString &errorMsg)
{
    QLOG_ERROR() << "Invitation Request failed " << id << "failed Error : " << errorMsg;
    d->resendMessagesToEmail(email);
}

void QliqDirect::onGotAllContacts(const QString &qliqId, bool error)
{
    Q_UNUSED(qliqId)
    Q_UNUSED(error)

    if (!d->pendingInvitationMessageMap.isEmpty()) {
        QList<QString> removeInvitationUsers;
        foreach (const QString& email, d->pendingInvitationMessageMap.keys().toSet()) {
            const QliqUser& user = QliqUserDao::selectOneByEmailNotDeleted(email);
            if (!user.isEmpty()) {
                removeInvitationUsers.append(email);
                QList<MessageItem> pendingMsgForUser = d->pendingInvitationMessageMap.values(email.toLower());
                foreach (MessageItem m, pendingMsgForUser) {
                    m.toQliqUser = user.qliqId;
                    d->sendMessage(m);
                }
            }
        }
        if (!removeInvitationUsers.isEmpty()) {
            for (int i = 0; i < removeInvitationUsers.size(); i++) {
                d->pendingInvitationMessageMap.remove(removeInvitationUsers.at(i).toLower());
            }
        }
    }
}

void QliqDirect::onValidateApiKey(const QString &apiKey)
{
    if (!apiKey.isEmpty() && d->recentValidApiKey == apiKey) {
        const int msecsPerHours = 1000 * 60 * 60;
        if (d->recentApiKeyDateTime.msecsTo(QDateTime::currentDateTime()) / msecsPerHours < 1) {
            d->restApiInterface->onQliqDirectApiKeyValidationReceived(apiKey, true);
            return;
        }
    }
    d->webClient->validateApiKey(apiKey);
}

void QliqDirect::onGotContactInfo(const QString &qliqId, const QString &email, const QString& mobile, const QliqUser &user, int errorCode)
{
    if (errorCode == 0) {
        d->resendMessagesToEmail(user.email);
    } else {
        QList<MessageItem> messages = d->pendingInvitationMessageMap.values();
        if (!messages.isEmpty()) {
            const MessageItem& message = messages[0];
            QliqDirectContact c = QliqDirectMessageHelper::parseContactFromText(message.toEmail);
            d->sendInvitation(c);
        }
    }
}

void QliqDirect::onChatMessagesReceived(const core::connect::ChatMessage &msg)
{
    if (d->smtpConfig.enabled) {
        Conversation c = ConversationDao::selectOneBy(ConversationDao::IdColumn, msg.conversationId);
        QliqUser fromUser = QliqUserDao::selectOneBy(QliqUserDao::IdColumn, msg.fromUserId);
        QliqUser toUser = QliqUserDao::selectOneBy(QliqUserDao::IdColumn, c.redirectQliqId);

        bool shouldForward = true;
        if (c.redirectQliqId.isEmpty()) {
            // This is response to a message sent without the 'From' field
            // redirect only if default email address is enabled
            if (d->smtpConfig.useDefaultForwardEmail && !d->smtpConfig.defaultForwardEmail.isEmpty()) {
                toUser.qliqId = d->smtpConfig.defaultForwardEmail; // just prevent toUser.isEmpty() check below
            } else {
                QLOG_ERROR() << "Received a response message but this conversation doesn't have 'From' field and no 'Default e-mail' is configured";
                shouldForward = false;
            }
        }

        if (shouldForward) {
            if (fromUser.isEmpty()) {
                QLOG_ERROR() << "Cannot find user for qliq id:" << msg.fromUserId;
                return;
            }
            if (toUser.isEmpty()) {
                QLOG_ERROR() << "Cannot find user for qliq id:" << c.redirectQliqId;
                return;
            }

            DBHelperConversation::saveMessageSelfDeliveryStatus(msg.messageId, ChatMessage::NeedToBeForwardedToEmailStatus);
            QLOG_SUPPORT() << "Received chat message from:" << fromUser.qliqId << "call-id:" << msg.metadata.uuid << "conversation-uuid:" << c.uuid << "triggering bg thread forwarding to:" << toUser.qliqId;
            d->emailSender->triggerForwarding(msg.metadata.uuid);
        }
    } else {
        QLOG_SUPPORT() << "Ignoring received chat message because SMTP is disabled";
    }
}

int QliqDirect::Private::sendInvitation(const QliqDirectContact &contact)
{
    QliqUser user;
    user.email = contact.emailAddress;
    user.firstName = contact.firstName;
    user.lastName = contact.lastName;
    int ret = webClient->createInvitation(user);
    QLOG_SUPPORT() << "Invitation sent to " << contact.emailAddress;
    return ret;
}

void QliqDirect::Private::resendMessagesToEmail(const QString &email)
{
    QString emailKey = email.toLower();
    QList<MessageItem> pendingMsgForUser = pendingInvitationMessageMap.values(emailKey);
    pendingInvitationMessageMap.remove(emailKey);

    if (!pendingMsgForUser.isEmpty()) {
        const QliqUser& user = QliqUserDao::selectOneByEmailNotDeleted(email);
        if (!user.isEmpty()) {
            QLOG_SUPPORT() << "Resending pending invitation messages (" << pendingMsgForUser.size() << ") for email:" << email;
            foreach (MessageItem m, pendingMsgForUser) {
                m.toQliqUser = user.qliqId;
                sendMessage(m);
            }
        } else {
            const int status = -10;
            QLOG_SUPPORT() << "Could not invite user with email:" << email << "sending error status (" << status << ") for messages";
            foreach (MessageItem m, pendingMsgForUser) {
                m.toQliqUser = user.qliqId;
                restApiInterface->onChatMessageStatusChanged(m.toQliqUser, m.restApiMessageUuid, status);
            }
        }
    }
}

void QliqDirect::onQliqDirectApiKeyValidationReceived(const QString& apiKey, bool isValid)
{
    if (isValid) {
        d->recentValidApiKey = apiKey;
        d->recentApiKeyDateTime = QDateTime::currentDateTime();
    }
    d->restApiInterface->onQliqDirectApiKeyValidationReceived(apiKey, isValid);
}

void QliqDirect::onChatMessageStatusChanged(const QString &toUserId, const QString &uuid, int status)
{
    Q_UNUSED(toUserId)

    core::connect::ChatMessage *msg = core::connect::DBHelperConversation::getMessageWithUuid(uuid);
    if (!msg) {
        QLOG_ERROR() << "Cannot find message with uuid:" << uuid;
        return;
    }

    QString additionalMessage;
    if (msg->attachments().size() > 0) {
        foreach (core::connect::ChatMessageAttachmentSharedPtr attachment, msg->attachments()) {
            additionalMessage += attachment->fileName;
            if (msg->attachments().back() != attachment) {
                additionalMessage += ", ";
            }
        }
        additionalMessage += " is securely";
    } else {
        additionalMessage += "Message is securely";
    }
    switch (status) {
    case 202:
        if (MessageQliqDirectOriginDao::hasRowsForMessageUuid(uuid)) {

            MessageQliqDirectOriginDao::updateSentTimeForMessageUuid(uuid, QDateTime::currentDateTime());
            messageOriginDetails det = MessageQliqDirectOriginDao::originDetailsForMessageUuid(uuid);
            if (det.interfaceType == MessageItem::ImapiInterface)
                d->imapInterface.sendStatusUpdateEmail(QliqDirectMessageHelper::parseContactFromText(det.fromEmail), det.imapAccount,
                                                       QliqUserDao::selectOneBy(QliqUserDao::IdColumn, msg->toUserId).email, msg->subject, "sent", det.sentTimeStamp, additionalMessage);
        } else {
            QLOG_SUPPORT() << uuid << " does not exist";
        }
        break;

    case 200:
        if (MessageQliqDirectOriginDao::hasRowsForMessageUuid(uuid)) {
            MessageQliqDirectOriginDao::updateDeliveredTimeForMessageUuid(uuid, QDateTime::currentDateTime());
            messageOriginDetails det = MessageQliqDirectOriginDao::originDetailsForMessageUuid(uuid);
            if (det.interfaceType == MessageItem::ImapiInterface)
                d->imapInterface.sendStatusUpdateEmail(QliqDirectMessageHelper::parseContactFromText(det.fromEmail), det.imapAccount,
                                                       QliqUserDao::selectOneBy(QliqUserDao::IdColumn, msg->toUserId).email, msg->subject, "delivered", det.deliveredTimeStamp, additionalMessage);
        } else {
            QLOG_SUPPORT() << uuid << " does not exist";
        }
        break;

    //default:
        //QLOG_SUPPORT() << "Unknown Status " << status << "message id " << msg->messageId ;
    }

    delete msg;
}

void QliqDirect::onSendMessage(const MessageItem &message)
{
    QLOG_SUPPORT() << "onSendMessage(toQliqUser:" << message.toQliqUser << ", toEmail:" << message.toEmail << ")";

    if (!message.toQliqUser.isEmpty()) {
        if (!message.attachmentPath.isEmpty()) {
            QLOG_SUPPORT() << "Message has attachment, adding it to upload queue";
            d->addMessageToUploadQueue(message);
            if (!d->isUploadInProgress) {
                d->isUploadInProgress = true;
                d->sendNextInQueue();
            }
            return;
        }
        d->sendMessage(message);

    } else if (!message.toEmail.isEmpty()) {
        QLOG_SUPPORT() << "Message is for unknown contact, calling get_contact_info";
        QliqDirectContact c = QliqDirectMessageHelper::parseContactFromText(message.toEmail);
        QString emailKey = c.emailAddress.toLower();
        d->pendingInvitationMessageMap.insert(emailKey, message);
        //if (!d->pendingInvitationMessageMap.keys().contains(emailKey)) {
            d->webClient->getContactInfo("", c.emailAddress);
        //}
    } else {
        QLOG_FATAL() << "Both toQliqUser and toEmail are empty for MessageItem";
    }
}

void QliqDirect::onCreateMultipartyChatFinished(int id, const QString &multipartyQliqId, const QString &errorMsg)
{
    if (!errorMsg.isEmpty()) {
        QLOG_ERROR() << "Cannot Create Multiparty message : err " << errorMsg;
    } else {
        foreach (const MultipartyChatItem& i, d->MultipartyChatItems) {
            if (i.id == id) {
                d->conn->sendMessage(multipartyQliqId, i.text, false, QliqDirectMessageHelper::intToPriority(i.priority), QliqDirectMessageHelper::intToType(i.type), i.subject, 0, i.attachmentPath, i.restApiMessageUuid);
            }
        }
    }
}

void QliqDirect::onChatMessageAttachmentStatusChanged(core::connect::ChatMessageAttachmentSharedPtr attachment)
{
    core::connect::ChatMessage *msg = core::connect::DBHelperConversation::getMessageWithUuid(attachment->messageUuid);

    switch (attachment->status) {
    case core::connect::UploadedAttachmentStatus:
        QLOG_SUPPORT() << "upload finished, starting next item. Items in queue = " << d->uploadMessageQueue.size();
//        d->clearAttachmentFiles(attachment);
        d->isUploadInProgress = false;
        if (d->uploadMessageQueue.size() > 0) {
            d->isUploadInProgress = true;
            d->sendNextInQueue();
        }
        break;
    case core::connect::UploadFailedAttachmentStatus:
        QLOG_ERROR() << "failed to upload : " << "id: " << attachment->id << "\nreq id: " << attachment->requestId << "\nfile name: "
                 << attachment->originalPath << "\ntemp file: " << attachment->localPath;
        if (MessageQliqDirectOriginDao::hasRowsForMessageUuid(attachment->messageUuid)) {
            messageOriginDetails det = MessageQliqDirectOriginDao::originDetailsForMessageUuid(attachment->messageUuid);
            if (det.interfaceType == MessageItem::ImapiInterface)
                d->imapInterface.sendStatusUpdateEmail(QliqDirectMessageHelper::parseContactFromText(det.fromEmail), det.imapAccount,
                                                       QliqUserDao::selectOneBy(QliqUserDao::IdColumn, msg->toUserId).email, msg->subject, "Failed", QDateTime::currentDateTime());
        } else {
            QLOG_ERROR() << attachment->messageUuid << " does not exist";
        }

        if (d->uploadMessageQueue.size() > 0) {
            d->isUploadInProgress = true;
            d->sendNextInQueue();
        }
        break;
    case core::connect::UploadingAttachmentStatus:
        d->isUploadInProgress = true;
        QLOG_SUPPORT() << "starting to upload " << attachment->url;
        break;
    }
    msg = 0;
}

int QliqDirect::Private::createMultipartyChat(const QSet<QString> &selectedIds, const QString &subject)
{
    return conn->createMultiPartyChat(selectedIds, subject);
}

void QliqDirect::Private::addMessageToUploadQueue(const MessageItem& message)
{
    uploadMessageQueue.append(message);
}

void QliqDirect::Private::sendNextInQueue()
{
    QLOG_SUPPORT() << "Sending next message from upload queue";
    MessageItem i = uploadMessageQueue.takeFirst();
    sendMessage(i);
}

void QliqDirect::Private::sendMessage(const MessageItem& message)
{
    // if required for Multiparty distribution
//    if (selectedIds.size() > 1) {
//        int reqID = createMultipartyChat(selectedIds.toSet(), subject);
//        //otherwise can't use the return Id from onCreateMultipartyChatFinished to match the correct Id
//        MultipartyChatItem i(reqID -1);
//        i.selectedIds = selectedIds;
//        i.text = text;
//        i.priority = priority;
//        i.type = type;
//        i.subject = subject;
//        i.attachmentPath = attachmentPath;
//        MultipartyChatItems.append(i);
//        return;
//    }
    QString impersonatedFromQliqId;
    if (!message.fromContact.emailAddress.isEmpty()) {
        impersonatedFromQliqId = QliqUserDao::selectOneByEmailNotDeleted(message.fromContact.emailAddress).qliqId;
        if (impersonatedFromQliqId.isEmpty()) {
            QLOG_ERROR() << "Cannot find qliq id of user to impersonate from:" << message.fromContact.emailAddress;
        }
    }
    QLOG_SUPPORT() << "Sending message to:" << message.toQliqUser << "(" << message.toEmail << ")" << "predefined uuid:" << message.restApiMessageUuid << "predefined conversation uuid:" << message.restApiConversationUuid << "impersonated from:" << impersonatedFromQliqId << "(" << message.fromContact.emailAddress << ")";

    //bool isRedirect = impersonatedFromQliqId.isEmpty();
    int conversationId = 0;
    if (message.restApiConversationUuid.isEmpty()) {
        conversationId = ConversationDao::conversationIdWithBroadcastFlag(message.toQliqUser, message.subject, Conversation::NotBroadcastType);
    } else {
        conversationId = ConversationDao::selectOneBy(ConversationDao::UuidColumn, message.restApiConversationUuid).id;
    }

    if (conversationId != 0) {
        ::Conversation c = ConversationDao::selectOneBy(ConversationDao::IdColumn, conversationId);
        if (c.redirectQliqId != impersonatedFromQliqId) {
            QLOG_SUPPORT() << "Creating a new conversation because 'from' changed (old:" << c.redirectQliqId << "new:" << impersonatedFromQliqId << ")";
            conversationId = 0;
        }
    }

    if (conversationId == 0) {
        ::Conversation c = conn->createConversation(message.toQliqUser, message.subject, Conversation::NotBroadcastType, message.restApiConversationUuid);
        c.redirectQliqId = impersonatedFromQliqId;
        ConversationDao::update(c);
        conversationId = c.id;
    }

    core::connect::ChatMessage *msg = conn->sendMessage(message.toQliqUser, message.text, message.requireAck, QliqDirectMessageHelper::intToPriority(message.priority),
                                                        QliqDirectMessageHelper::intToType(message.type), message.subject, conversationId, message.attachmentPath, message.restApiMessageUuid, impersonatedFromQliqId);
    qDebug() << "Sent";
    if (msg) {
        switch (message.interfaceType)
        {
        case MessageItem::ImapiInterface:
            MessageQliqDirectOriginDao::insertOrUpdateRowsForMessageUuid(msg->metadata.uuid, message.interfaceType, QDateTime::fromTime_t(msg->lastSentAt),
                                                                         message.imapAccount, ((QliqDirectContact)message.fromContact).toString());
            break;
        case MessageItem::RestApiInterface:
            MessageQliqDirectOriginDao::insertOrUpdateRowsForMessageUuid(msg->metadata.uuid, message.interfaceType, QDateTime::fromTime_t(msg->lastSentAt),
                                                                         message.apiKeyHash, message.restApiMessageUuid);
            break;
        }
    }
}

void QliqDirect::Private::clearAttachmentFiles(core::connect::ChatMessageAttachmentSharedPtr attachment)
{
    QDir d (attachment->originalPath);
    d.remove(attachment->originalPath);
}
