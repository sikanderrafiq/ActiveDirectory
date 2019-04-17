#include "AdSip.h"
#include <QVariantMap>
#include <QsLog.h>
#include "json/qt-json/qtjson.h"
#include "sip/QliqSip.hpp"
#include "json/schema/Message.h"
#include "qliqdirect/service/ad/qliqDirectAD.h"
#include "qliqdirect/service/ad/ActiveDirectoryEventDao.h"
#include "qliqdirect/service/ad/AdHelper.h"
#include "dao/ActiveDirectoryDao.h"

#define COMMAND_USER_CHECK_CREDENTIALS "user-check-credentials"

#define LOG_AUTH_EVENT(category, message) \
    LOG_AD_EVENT(ActiveDirectoryEvent::AuthType, category, message, QSqlDatabase::database())

using namespace ActiveDirectory;

AdSip::AdSip(QObject *parent) :
    QObject(parent),
    m_sip(nullptr),
    m_ad(nullptr),
    m_enabled(false)
{
    m_ad = new ActiveDirectoryApi();
}

AdSip::~AdSip()
{
    delete m_ad;
}

void AdSip::setSip(QliqSip *sip)
{
    if (sip) {
        if (sip != m_sip) {
            QLOG_SUPPORT() << "Connecting AdSip with QliqSip";
            if (!connect(sip, SIGNAL(messageReceived(QString,QString,QVariantMap,QVariantMap)), SLOT(onSipMessageReceived(QString,QString,QVariantMap,QVariantMap)))) {
                QLOG_ERROR() << "Couldn't connect signal";
            }
        }
    }
    m_sip = sip;
}

QliqSip *AdSip::sip() const
{
    return m_sip;
}

void AdSip::setActiveDirectory(ActiveDirectoryApi *ad)
{
    m_ad = ad;
}

void AdSip::setConfig(const AdConfig &config)
{
    m_adConfig = config;
}

bool AdSip::isAuthorizationRequest(const QString &command)
{
    return command == "user-authentication";
}

void AdSip::onSipMessageReceived(const QString &to, const QString &from, const QVariantMap &message, const QVariantMap &incomingExtraHeaders)
{
    Q_UNUSED(to)
    Q_UNUSED(from)

    const QString& command = message.value(MESSAGE_MESSAGE_COMMAND).toString();
    bool isTestCredentials = false;
    Credentials credentials;
    ActiveDirectory::ExtendedAuthenticationError extendedError;
    int res = 0;

    if (isAuthorizationRequest(command)) {
        int responseCode = 500;
        QMap<QString, QString> outgoingExtraHeaders;
        bool ok = processAuthRequestOrTestCredentials(message, isTestCredentials, &credentials, &res, &extendedError);
        if (ok) {
            if (res == static_cast<long>(ActiveDirectoryApi::OkAuthStatus)) {
                responseCode = 200;
            } else if (res == static_cast<long>(ActiveDirectoryApi::InvalidCredentialsAuthStatus)) {
                // Because of some problem on SIP/webserver Krishna wants to send 200 for error too
                //responseCode = 401;
                responseCode = 200;

                if (extendedError.code == AD_AUTH_ERR_INVALID_PASSWORD && !m_adConfig.forgotPasswordUrl.isEmpty()) {
                    outgoingExtraHeaders["X-auth-action-label"] = "Forgot Password";
                    outgoingExtraHeaders["X-auth-action-url"] = m_adConfig.forgotPasswordUrl;
                } else if (extendedError.code == AD_AUTH_ERR_PASSWORD_EXPIRED && !m_adConfig.changePasswordUrl.isEmpty()) {
                    outgoingExtraHeaders["X-auth-action-label"] = "Change Password";
                    outgoingExtraHeaders["X-auth-action-url"] = m_adConfig.changePasswordUrl;
                }

                outgoingExtraHeaders["X-auth-error-code"] = extendedError.knownCodeName;
                outgoingExtraHeaders["X-auth-error-message"] = extendedError.message;
            }

            if (!SUCCEEDED(res)) {
                outgoingExtraHeaders["X-extended-auth-error"] = extendedError.fullText;
            }
        }

        QLOG_SUPPORT() << "Authentication result for user:" << credentials.userName << "is:" << res << "SIP status code:" << responseCode << "extra:" << outgoingExtraHeaders;
        const QString& callId = incomingExtraHeaders.value(QliqSip::headerCallId()).toString();
        m_sip->sendMessageResponseCode(responseCode, callId, outgoingExtraHeaders);

    } else if (command == COMMAND_USER_CHECK_CREDENTIALS) {
        isTestCredentials = true;
        bool ok = processAuthRequestOrTestCredentials(message, isTestCredentials, &credentials, &res, &extendedError);
        if (ok) {
            if (res == static_cast<long>(ActiveDirectoryApi::OkAuthStatus)) {
                //LOG_AUTH_EVENT(ActiveDirectoryEvent::InformationCategory, "No password nor account change for user: " + credentials.userName);

            } else if (res == static_cast<long>(ActiveDirectoryApi::InvalidCredentialsAuthStatus)) {
                const QVariantMap& data = message.value(MESSAGE_MESSAGE_DATA).toMap();
                QString qliqId = data.value("qliq_id").toString().trimmed();
                //QLOG_ERROR() << "Credential check for user:" << credentials.userName << "(qliq id:" << qliqId << ") detected invalid credentials";

                DbUser u = ActiveDirectoryUserDao::selectOneBy(ActiveDirectoryUserDao::QliqIdColumn, qliqId, 0);
                u.isSentToWebserver = false;
                u.setPasswordChangedFlag(true);
                ActiveDirectoryUserDao::update(u);
                //LOG_AUTH_EVENT(ActiveDirectoryEvent::InformationCategory, "Detected invalid credentials for user: " + credentials.userName + " extended error: " + errorMsg + " code: " + QString::number(errorCode));
            }
        }
    }
}

bool AdSip::processAuthRequestOrTestCredentials(const QVariantMap& message, bool isTestCredentials,
                                                ActiveDirectory::Credentials *credentials, int *res,
                                                ActiveDirectory::ExtendedAuthenticationError *extendedError)
{
    bool ret = false;
    try {
        const QString requestName = isTestCredentials ? COMMAND_USER_CHECK_CREDENTIALS : "auth";
        const QVariantMap& data = message.value(MESSAGE_MESSAGE_DATA).toMap();

        credentials->userName = data.value("userName").toString().trimmed();
        credentials->password = data.value("password").toString().trimmed();
        credentials->domain = ActiveDirectoryUserDao::domainHost(credentials->userName);

        QString distinguishedName = data.value("distinguishedName").toString().trimmed();
        QString qliqId = data.value("qliq_id").toString().trimmed();

        if (credentials->userName.isEmpty()) {
            throw QString("No userName in " + requestName + " request"); //: " + Json::toJson(message));
        } else if (credentials->password.isEmpty()) {
            throw QString("No password in "  + requestName +  " request"); //: " + Json::toJson(message));
        } else if (isTestCredentials && qliqId.isEmpty()) {
            throw QString("No qliqId in "  + requestName + " request"); //: " + Json::toJson(message));
        } else if (credentials->domain.isEmpty()) {
            bool exists = ActiveDirectoryUserDao::exists(ActiveDirectoryUserDao::UserPrincipalNameColumn, credentials->userName);
            throw QString("Unable to determine domain host name for user: " + credentials->userName + QString(" (exists in database: %1)").arg(exists));
        } else if (!m_enabled) {
            throw QString("Received " + requestName + " request but AdSip is disabled");
        }

        if (m_adConfig.enableDistinguishedNameBaseAuth) {
            if (distinguishedName.isEmpty()) {
                LOG_AUTH_EVENT(ActiveDirectoryEvent::ErrorCategory, "No distinguishedName in " + requestName + " request, using userName instead"); //: " + Json::toJson(message));
            }
        } else {
            distinguishedName = "";
        }

        LOG_AUTH_EVENT(ActiveDirectoryEvent::InformationCategory, "Received " + requestName + " request for user: " + credentials->userName);

        if (isTestCredentials) {
            DbUser u = ActiveDirectoryUserDao::selectOneBy(ActiveDirectoryUserDao::QliqIdColumn, qliqId, 0);
            if (u.isEmpty() || u.isDeleted) {
                QString msg = QString("The user: %1 is %2, no need to update password status").arg(credentials->userName).arg(u.isDeleted ? "already deleted" : "not present in local AD database");
                LOG_AUTH_EVENT(ActiveDirectoryEvent::InformationCategory, msg);
            }
        }

        ret = true;
        *res = m_ad->authenticateUser(*credentials, distinguishedName, &extendedError->fullText, QSqlDatabase::database());
        if (*res == static_cast<long>(ActiveDirectoryApi::OkAuthStatus)) {
            LOG_AUTH_EVENT(ActiveDirectoryEvent::InformationCategory, "User: " + credentials->userName + " successfully authenticated");

        } else if (*res == static_cast<long>(ActiveDirectoryApi::InvalidCredentialsAuthStatus)) {
            // For description of some popular extended errors:
            // http://ldapwiki.willeke.com/wiki/Common%20Active%20Directory%20Bind%20Errors
            if (m_ad->extendedAuthenticationError(extendedError->fullText, extendedError) == false) {
                // If cannot get details, then send what we know for sure, that is invalid credentials error, regardless the root cause
                // http://www.selfadsi.org/errorcodes.htm
                QLOG_ERROR() << "Cannot get extended authentication error";
                extendedError->knownCodeName = "invalid-credentials";
                extendedError->message = "Invalid credentials error";
            }
            LOG_AUTH_EVENT(ActiveDirectoryEvent::ErrorCategory, ("Logon failure for user: " + credentials->userName + " code: " + extendedError->knownCodeName + ", message: " + extendedError->message));

        } else if (*res == static_cast<long>(ActiveDirectoryApi::ServerUnreachableAuthStatus)) {
            LOG_AUTH_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot " + requestName + " for user: " + credentials->userName + " because server is not reachable, extended error: " + extendedError->message + " code: " + QString::number(extendedError->code));

        } else {
            QString errorMsg = AdHelper::errorMessage(*res);
            LOG_AUTH_EVENT(ActiveDirectoryEvent::ErrorCategory, "Logon failure for user: " + credentials->userName + " error: " + QString::number(*res) + ", message: " + errorMsg);
        }
    } catch (const QString& errorMessage) {
        LOG_AUTH_EVENT(ActiveDirectoryEvent::ErrorCategory, errorMessage);
    } catch (...) {
        QLOG_FATAL() << "Unexpected exception thrown in " << __PRETTY_FUNCTION__;
    }

    return ret;
}
