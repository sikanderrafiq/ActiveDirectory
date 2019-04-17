#include "AdToWebPusher.h"
#include <QMutexLocker>
#include <QsLog.h>
#include "dao/ActiveDirectoryDao.h"
#include "ScimClient.h"
#include "Scim.h"
#include "json/qt-json/qtjson.h"
#include "ActiveDirectoryEventDao.h"

#define LOG_WEB_EVENT(category, message) \
    LOG_AD_EVENT(ActiveDirectoryEvent::WebserverType, category, message, m_db)

using namespace ActiveDirectory;

// Helper methods to convert a custom pointer to/from QVariant
template <class T> class VariantPointer
{
public:
    static T* pointer(const QVariant& v)
    {
    return  (T *) v.value<void *>();
    }

    static QVariant variant(T* ptr)
    {
    return qVariantFromValue((void *) ptr);
    }
};

AdToWebPusher::AdToWebPusher(QObject *parent) :
    QObject(parent),
    m_needToCloseDb(false),
    m_scimClient(NULL),
    m_shouldStop(false),
    m_userSkip(0),
    m_groupSkip(0),
    m_isRequestInProgress(false),
    m_isPushInProgress(false),
    m_previousSyncTotalChangesCount(0)
{
    resetStatCounters();
}

AdToWebPusher::~AdToWebPusher()
{
    if (m_needToCloseDb) {
        QString connectionName = m_db.connectionName();
        QLOG_SUPPORT() << "Closing db connection:" << connectionName;
        m_db.close();
        QSqlDatabase::removeDatabase(connectionName);
    }
}

void AdToWebPusher::setDatabase(const QSqlDatabase &db)
{
    m_db = db;
    m_needToCloseDb = true;
}

void AdToWebPusher::setScimClient(ScimClient *sc)
{
    m_scimClient = sc;
    connect(m_scimClient, SIGNAL(createUserFinished(int,QString,QVariant)), SLOT(onCreateUserFinished(int,QString,QVariant)));
    connect(m_scimClient, SIGNAL(getUserFinished(int,QString,QVariant)), SLOT(onGetUserFinished(int,QString,QVariant)));
    connect(m_scimClient, SIGNAL(updateUserFinished(int,QString,QVariant)), SLOT(onUpdateUserFinished(int,QString,QVariant)));
    connect(m_scimClient, SIGNAL(deleteUserFinished(int,QString,QVariant)), SLOT(onDeleteUserFinished(int,QString,QVariant)));

    connect(m_scimClient, SIGNAL(createGroupFinished(int,QString,QVariant)), SLOT(onCreateGroupFinished(int,QString,QVariant)));
    connect(m_scimClient, SIGNAL(getGroupFinished(int,QString,QVariant)), SLOT(onGetGroupFinished(int,QString,QVariant)));
    connect(m_scimClient, SIGNAL(updateGroupFinished(int,QString,QVariant)), SLOT(onUpdateGroupFinished(int,QString,QVariant)));
    connect(m_scimClient, SIGNAL(deleteGroupFinished(int,QString,QVariant)), SLOT(onDeleteGroupFinished(int,QString,QVariant)));
}

void AdToWebPusher::resetSkipValues()
{
    m_userSkip = m_groupSkip = 0;
}

void AdToWebPusher::deleteAllUsers()
{
    QList<DbUser> users = ActiveDirectoryUserDao::selectAll(0, m_db);
    foreach (const DbUser& u, users) {
        if (!u.qliqId.isEmpty()) {
            QVariant callerData = VariantPointer<RequestContext>::variant(new RequestContext(u));
            m_scimClient->deleteUser(u.qliqId, callerData);
        }
    }
}

ActiveDirectoryProgressAndStatus AdToWebPusher::progress() const
{
    ActiveDirectoryProgressAndStatus copy;
    {
        QMutexLocker lock(&m_progressMutex);
        copy = m_progress;
    }
    return copy;
}

void AdToWebPusher::run()
{
}

bool AdToWebPusher::pushOne()
{
    if (m_isRequestInProgress) {
        QLOG_SUPPORT() << "Not starting a new push because previous one is still in progress";
        return false;
    }

    if (pushOneGroup()) {
        return true;
    } else {
        return pushOneUser();
    }
}

bool AdToWebPusher::pushOneUser()
{
skip_and_retry:
    DbUser u = ActiveDirectoryUserDao::selectOneNotSentToWebserver(m_userSkip, m_db);
    if (!u.isEmpty()) {
        if (u.webserverError != 0 && u.webserverError / 100 != 2) {
            QLOG_SUPPORT() << "Skiping user, login:" << u.login() << "qliq id:" << u.qliqId << "because of previous webserver error:" << u.webserverError << "skip:" << m_userSkip;
            m_userSkip++;
            goto skip_and_retry;
        }

        QVariant callerData = VariantPointer<RequestContext>::variant(new RequestContext(u));

        if (u.isDeleted) {
            if (u.qliqId.isEmpty()) {
                // Probably the user does not yet exist on the webserver.
                // However we could try to get the user by "filter=userName eq 'xxx'" and delete if exists
                u.isSentToWebserver = true;
                u.webserverError = 0;
                ActiveDirectoryUserDao::update(u, m_db);

                RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
                delete ctx;

                return pushOneUser();
            } else {
                QLOG_SUPPORT() << "Deleting user, login:" << u.login() << "qliq id:" << u.qliqId;
                m_isRequestInProgress = true;
                m_scimClient->deleteUser(u.qliqId, callerData);
            }
        } else {
            m_isRequestInProgress = true;
            u.groups = ActiveDirectoryGroupDao::groupsOfUser(u, m_db);

            u.avatar = ActiveDirectoryUserDao::avatar(u, m_db);

            if (u.qliqId.isEmpty()) {
                QLOG_SUPPORT() << "Creating user, login:" << u.login();
                m_scimClient->createUser(Scim::toJson(u), callerData, u.avatar);
            } else {
                QLOG_SUPPORT() << "Updating user, login:" << u.login() << "qliq id:" << u.qliqId;
                m_scimClient->updateUser(u.qliqId, Scim::toJson(u), callerData, u.avatar);
            }
        }
        return true;
    } else {
        //logEvent(ActiveDirectoryEvent::InformationCategory, "No user changes in local database to push to the cloud");
        QLOG_SUPPORT() << "No user changes in local database to push to the cloud";
        return false;
    }
}

bool AdToWebPusher::pushOneGroup()
{
skip_and_retry:
    DbGroup g = ActiveDirectoryGroupDao::selectOneNotSentToWebserver(m_groupSkip, m_db);
    if (!g.isEmpty()) {
        if (g.webserverError != 0 && g.webserverError / 100 != 2) {
            QLOG_SUPPORT() << "Skiping group, name:" << g.displayName() << "qliq id:" << g.qliqId << "because of previous webserver error:" << g.webserverError << "skip:" << m_groupSkip;
            m_groupSkip++;
            goto skip_and_retry;
        }

        QVariant callerData = VariantPointer<RequestContext>::variant(new RequestContext(g));

        if (g.isDeleted) {
            if (g.qliqId.isEmpty()) {
                // Probably the group does not yet exist on the webserver.
                // However we could try to get the group by "filter=userName eq 'xxx'" and delete if exists
                g.isSentToWebserver = true;
                g.webserverError = 0;
                ActiveDirectoryGroupDao::update(g, m_db);

                RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
                delete ctx;

                return pushOneGroup();
            } else {
                QLOG_SUPPORT() << "Deleting group, name:" << g.displayName() << "qliq id:" << g.qliqId;
                m_isRequestInProgress = true;
                m_scimClient->deleteGroup(g.qliqId, callerData);
            }
        } else {
            m_isRequestInProgress = true;
            if (g.qliqId.isEmpty()) {
                QLOG_SUPPORT() << "Creating group, name:" << g.displayName();
                m_scimClient->createGroup(Scim::toJson(g), callerData);
            } else {
                QLOG_SUPPORT() << "Updating group, name:" << g.displayName() << "qliq id:" << g.qliqId;
                m_scimClient->updateGroup(g.qliqId, Scim::toJson(g), callerData);
            }
        }
        return true;
    } else {
        //logEvent(ActiveDirectoryEvent::InformationCategory, "No group changes in local database to push to the cloud");
        QLOG_SUPPORT() << "No group changes in local database to push to the cloud";
        return false;
    }
}

void AdToWebPusher::startPushing()
{
    LOG_WEB_EVENT(ActiveDirectoryEvent::InformationCategory, "Push to the cloud started");
    m_shouldStop = false;
    m_groupSkip = m_userSkip = 0;
    resetStatCounters();
    ActiveDirectoryUserDao::clearWebserverErrorNotIn(ScimClient::permanentErrors(), m_db);
    ActiveDirectoryGroupDao::clearWebserverErrorNotIn(ScimClient::permanentErrors(), m_db);

    startPushingWithoutClearingWebserverError();
}

void AdToWebPusher::startPushingWithoutClearingWebserverError()
{
    m_isPushInProgress = true;
    if (!pushOne()) {
        removeDanglingUsers();
        //logEvent(ActiveDirectoryEvent::InformationCategory, "Pushing finished because nothing to push");
        QLOG_SUPPORT() << "Pushing finished because nothing to push";
        emitPushingFinished();
    }
}

void AdToWebPusher::removeDanglingUsers()
{
    foreach (const QString& groupGuid, m_deletedGroupGuids) {
        ActiveDirectoryGroupDao::removeAllUsersFromGroup(groupGuid, m_db);
        m_deletedGroupGuids.removeOne(groupGuid);
    }
}

void AdToWebPusher::stopPushing()
{
    LOG_WEB_EVENT(ActiveDirectoryEvent::InformationCategory, "Push cancelled");
    m_shouldStop = true;
}

void AdToWebPusher::onCreateUserFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    if (ctx == nullptr) {
        QLOG_FATAL() << "AdToWebPusher::onCreateUserFinished: RequestContext is null";
        return;
    }

    bool error = true;
    DbUser u = ActiveDirectoryUserDao::selectOneBy(ActiveDirectoryUserDao::ObjectGuidColumn, ctx->user.objectGuid, 0, m_db);
    if (!u.isEmpty()) {
        QVariantMap json = Json::parse(response).toMap();
        if (json.isEmpty()) {
            LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot parse JSON response from the server (create user), status code: " + QString::number(httpStatusCode) + ", response: " + response);
        } else {
            if (httpStatusCode == ScimClient::CreatedResponseCode) {
                QString qliqId = json.value("id").toString();
                if (qliqId.isEmpty()) {
                    LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot read qliq id ('id' field) from server (create user): " + response);
                } else {
                    u.qliqId = qliqId;
                    u.isSentToWebserver = true;
                    u.webserverError = 0;
                    u.setPasswordChangedFlag(false);
                    ActiveDirectoryUserDao::update(u, m_db);
                    error = false;
                    QLOG_SUPPORT() << "Created user on the web, qliq id:" << qliqId << "login:" << u.userPrincipalName;
                    m_createdUsersCount++;
                    incrementPushedUserChangesCount();
                }
            } else if (httpStatusCode == ScimClient::ConflictResponseCode) {
                QString qliqId = json.value("id").toString();
                QLOG_ERROR() << "Create user webservice call returned conflict. Trying to GET and UPDATE the user now, objectGuid:" << ctx->user.objectGuid << "login:" << u.userPrincipalName << ", qliq id:" << qliqId;
                ctx->isResolvingConflict = true;
                m_scimClient->getUser(qliqId, callerData);
                ctx = NULL; // don't delete yet
                error = false;
            } else if (httpStatusCode == ScimClient::BadRequestResponseCode || httpStatusCode == ScimClient::MandatoryFieldMissingResponseCode) {
                LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Create user webservice call returned 'bad request' code: " + QString::number(httpStatusCode) + ". Marking the user as invalid, objectGuid: " + ctx->user.objectGuid + ", login: " + u.userPrincipalName + " userPrincipalName: " + u.userPrincipalName + " first name: " + u.firstName() + " last name: " + u.lastName());
                u.validState = httpStatusCode;
                ActiveDirectoryUserDao::update(u, m_db);
            }
        }
        if (error) {
            m_failedUsersCount++;
            onError(httpStatusCode, ctx);
        }
    } else {
        QLOG_ERROR() << "Got web response for create user but cannot find user with objectGuid:" << ctx->user.objectGuid;
    }

    if (ctx) {
        onRequestFinished(httpStatusCode, ctx);
    }
}

void AdToWebPusher::onCreateGroupFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    if (ctx == nullptr) {
        QLOG_FATAL() << "AdToWebPusher::onCreateGroupFinished: RequestContext is null";
        return;
    }

    bool error = true;
    DbGroup u = ActiveDirectoryGroupDao::selectOneBy(ActiveDirectoryGroupDao::ObjectGuidColumn, ctx->group.objectGuid, 0, m_db);
    if (!u.isEmpty()) {
        QVariantMap json = Json::parse(response).toMap();
        if (json.isEmpty()) {
            LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot parse JSON response from the server (create group), status code: " + QString::number(httpStatusCode) + ", response: " + response);
        } else {
            if (httpStatusCode == ScimClient::CreatedResponseCode) {
                QString qliqId = json.value("id").toString();
                if (qliqId.isEmpty()) {
                    LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot read qliq id ('id' field) from server (create group): " + response);
                } else {
                    u.qliqId = qliqId;
                    u.isSentToWebserver = true;
                    u.webserverError = 0;
                    ActiveDirectoryGroupDao::update(u, m_db);
                    error = false;
                    QLOG_SUPPORT() << "Created group on the web, qliq id:" << qliqId << "name:" << u.displayName();
                    m_createdGroupsCount++;
                }
            } else if (httpStatusCode == ScimClient::ConflictResponseCode) {
                QString qliqId = json.value("id").toString();
                QLOG_ERROR() << "Create group webservice call returned conflict. Trying to GET and UPDATE the group now, objectGuid:" << ctx->group.objectGuid << ", qliq id:" << qliqId << ", name:" << u.displayName();
                ctx->isResolvingConflict = true;
                m_scimClient->getGroup(qliqId, callerData);
                ctx = NULL; // don't delete yet
                error = false;
            } else if (httpStatusCode == ScimClient::BadRequestResponseCode || httpStatusCode == ScimClient::MandatoryFieldMissingResponseCode) {
                LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Create group webservice call returned code: " + QString::number(httpStatusCode) + ". Marking the group as invalid, objectGuid:" + ctx->group.objectGuid + ", name:" + u.displayName());
                u.validState = httpStatusCode;
                ActiveDirectoryGroupDao::update(u, m_db);
            }
        }
        if (error) {
            m_failedGroupsCount++;
            onError(httpStatusCode, ctx);
        }
    } else {
        QLOG_ERROR() << "Got web response for create group but cannot find group with objectGuid:" << ctx->group.objectGuid;
    }

    if (ctx) {
        onRequestFinished(httpStatusCode, ctx);
    }
}

void AdToWebPusher::onGetUserFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    bool error = true;
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    DbUser u = ActiveDirectoryUserDao::selectOneBy(ActiveDirectoryUserDao::ObjectGuidColumn, ctx->user.objectGuid, 0, m_db);
    if (!u.isEmpty()) {
        QVariantMap json = Json::parse(response).toMap();
        if (json.isEmpty()) {
            LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot parse JSON response from the server (get user), status code: " + QString::number(httpStatusCode) + ", response: " + response);
        } else {
            if (httpStatusCode == 200) {
                QString qliqId = json.value("id").toString();
                if (qliqId.isEmpty()) {
                    LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot read qliq id ('id' field) from server (get user): " + response);
                } else {
                    ctx->user.qliqId = qliqId;
                    ActiveDirectoryUserDao::update(u, m_db);

                    if (ctx->isResolvingConflict) {
                        json = Scim::removeAllUserFields(json);
                        json.unite(Scim::toJsonMap(u));
                        m_scimClient->updateUser(qliqId, Json::toJson(json), callerData);
                        ctx = NULL; // don't delete yet
                    }
                    error = false;
                }
            }
        }
        if (error) {
            onError(httpStatusCode, ctx);
        }
    } else {
        QLOG_ERROR() << "Got web response for get user but cannot find user with objectGuid:" << ctx->user.objectGuid;
    }

    if (ctx) {
        onRequestFinished(httpStatusCode, ctx);
    }
}

void AdToWebPusher::onGetGroupFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    bool error = true;
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    DbGroup u = ActiveDirectoryGroupDao::selectOneBy(ActiveDirectoryGroupDao::ObjectGuidColumn, ctx->group.objectGuid, 0, m_db);
    if (!u.isEmpty()) {
        QVariantMap json = Json::parse(response).toMap();
        if (json.isEmpty()) {
            LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot parse JSON response from the server (get group), status code: " + QString::number(httpStatusCode) + ", response: " + response);
        } else {
            if (httpStatusCode == 200) {
                QString qliqId = json.value("id").toString();
                if (qliqId.isEmpty()) {
                    LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot read qliq id ('id' field) from server (get group): " + response);
                } else {
                    ctx->group.qliqId = qliqId;
                    ActiveDirectoryGroupDao::update(u, m_db);

                    if (ctx->isResolvingConflict) {
                        json = Scim::removeAllGroupFields(json);
                        json.unite(Scim::toJsonMap(u));
                        m_scimClient->updateGroup(qliqId, Json::toJson(json), callerData);
                        ctx = NULL; // don't delete yet
                    }
                    error = false;
                }
            }
        }
        if (error) {
            onError(httpStatusCode, ctx);
        }
    } else {
        QLOG_ERROR() << "Got web response for get group but cannot find group with objectGuid:" << ctx->group.objectGuid;
    }

    if (ctx) {
        onRequestFinished(httpStatusCode, ctx);
    }
}

void AdToWebPusher::onUpdateUserFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    bool error = true;
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    DbUser u = ActiveDirectoryUserDao::selectOneBy(ActiveDirectoryUserDao::ObjectGuidColumn, ctx->user.objectGuid, 0, m_db);
    if (!u.isEmpty()) {
        QVariantMap json = Json::parse(response).toMap();
        if (json.isEmpty()) {
            LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot parse JSON response from the server (update user), status code: " + QString::number(httpStatusCode) + ", response: " + response);
        } else {
            if (httpStatusCode == 200) {
                QString qliqId = json.value("id").toString();
                if (qliqId.isEmpty()) {
                    LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot read qliq id ('id' field) from server (update user): " + response);
                } else {
                    if (ctx->isResolvingConflict) {
                    }

                    u.qliqId = qliqId;
                    u.isSentToWebserver = true;
                    u.webserverError = 0;
                    u.setPasswordChangedFlag(false);
                    ActiveDirectoryUserDao::update(u, m_db);
                    error = false;
                    QLOG_SUPPORT() << "Updated user on the web, qliq id:" << qliqId << "login:" << u.userPrincipalName;
                    m_updatedUsersCount++;
                    incrementPushedUserChangesCount();
                }
            } else if (httpStatusCode == 404) {
                QString qliqId = json.value("id").toString();
                LOG_WEB_EVENT(ActiveDirectoryEvent::WarningCategory, "Update user webservice call returned 404. Marking the user as cloud-deleted and ignored now, qliq id: " + qliqId + ", login:" + u.userPrincipalName);
                ctx->isResolvingConflict = false;

                u.qliqId = ctx->user.qliqId = "";
                u.isDeleted = true;
                u.isSentToWebserver = true;
                u.webserverError = 404;
                u.setPasswordChangedFlag(false);
                ActiveDirectoryUserDao::update(u, m_db);
                error = false;
                m_deletedUsersCount++;
                incrementPushedUserChangesCount();
            } else if (httpStatusCode == ScimClient::BadRequestResponseCode || httpStatusCode == ScimClient::MandatoryFieldMissingResponseCode) {
                QLOG_ERROR() << "Update user webservice call returned code: " << httpStatusCode << ". Marking the user as invalid, objectGuid:" << ctx->user.objectGuid << ", qliq id:" << u.qliqId << ", name:" << u.userPrincipalName;
                u.validState = httpStatusCode;
                ActiveDirectoryUserDao::update(u, m_db);
            }
        }
        if (error) {
            m_failedUsersCount++;
            onError(httpStatusCode, ctx);
        }
    } else {
        QLOG_ERROR() << "Got web response for update user but cannot find user with objectGuid:" << ctx->user.objectGuid;
    }

    if (ctx) {
        onRequestFinished(httpStatusCode, ctx);
    }
}

void AdToWebPusher::onUpdateGroupFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    bool error = true;
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    DbGroup g = ActiveDirectoryGroupDao::selectOneBy(ActiveDirectoryGroupDao::ObjectGuidColumn, ctx->group.objectGuid, 0, m_db);
    if (!g.isEmpty()) {
        QVariantMap json = Json::parse(response).toMap();
        if (json.isEmpty()) {
            LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot parse JSON response from the server (update group), status code: " + QString::number(httpStatusCode) + ", response: " + response);
        } else {
            if (httpStatusCode == 200) {
                QString qliqId = json.value("id").toString();
                if (qliqId.isEmpty()) {
                    LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot read qliq id ('id' field) from server (update group): " + response);
                } else {
                    if (ctx->isResolvingConflict) {
                    }

                    g.qliqId = qliqId;
                    g.isSentToWebserver = true;
                    g.webserverError = 0;
                    ActiveDirectoryGroupDao::update(g, m_db);
                    error = false;
                    QLOG_SUPPORT() << "Updated group on the web, qliq id:" << qliqId << "name:" << g.displayName();
                    m_updatedGroupsCount++;
                }
            } else if (httpStatusCode == 404) {
                QString qliqId = json.value("id").toString();
                LOG_WEB_EVENT(ActiveDirectoryEvent::WarningCategory, "Update group webservice call returned 404. Marking the group as cloud-deleted and ignored now, qliq id: " + qliqId + ", name:" + g.displayName());
                ctx->isResolvingConflict = false;

                g.qliqId = ctx->group.qliqId = "";
                g.isDeleted = true;
                g.isSentToWebserver = true;
                g.webserverError = 404;
                ActiveDirectoryGroupDao::update(g, m_db);
                error = false;
                m_deletedGroupsCount++;
            } else if (httpStatusCode == ScimClient::BadRequestResponseCode || httpStatusCode == ScimClient::MandatoryFieldMissingResponseCode) {
                QLOG_ERROR() << "Update group webservice call returned code: " << httpStatusCode << ". Marking the group as invalid, objectGuid:" << ctx->group.objectGuid << ", qliq id:" << g.qliqId << ", name:" << g.displayName();
                g.validState = httpStatusCode;
                ActiveDirectoryGroupDao::update(g, m_db);
            }
        }
        if (error) {
            m_failedGroupsCount++;
            onError(httpStatusCode, ctx);
        }
    } else {
        QLOG_ERROR() << "Got web response for update group but cannot find group with objectGuid:" << ctx->group.objectGuid;
    }

    onRequestFinished(httpStatusCode, ctx);
}

void AdToWebPusher::onDeleteUserFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    if (httpStatusCode == ScimClient::OkResponseCode) {
        QLOG_SUPPORT() << "Deleted user on webserver, login:" << ctx->user.login() << "qliq id:" << ctx->user.qliqId;
        bool ret = ActiveDirectoryUserDao::delete_(ctx->user, m_db);
        if (ret) {
            // If user is deleted from active_directory_user table, then remove its entry from
            // active_directory_user_group_membership table as well.
            ActiveDirectoryGroupDao::removeUserFromAllGroups(ctx->user, m_db);
        }
        m_deletedUsersCount++;
        incrementPushedUserChangesCount();
    } else if (httpStatusCode == ScimClient::NotFoundResponseCode) {
        QLOG_SUPPORT() << "User already doesn't exist on webserver, login:" << ctx->user.login() << "qliq id:" << ctx->user.qliqId;
        bool ret = ActiveDirectoryUserDao::delete_(ctx->user, m_db);
        if (ret) {
            ActiveDirectoryGroupDao::removeUserFromAllGroups(ctx->user, m_db);
        }
    } else {
        QLOG_ERROR() << "Cannot delete user on webserver, error:" << httpStatusCode << "login:" << ctx->user.login() << "qliq id:" << ctx->user.qliqId;
        m_failedUsersCount++;
        onError(httpStatusCode, ctx);
    }
    onRequestFinished(httpStatusCode, ctx);
}

void AdToWebPusher::onDeleteGroupFinished(int httpStatusCode, const QString &response, const QVariant &callerData)
{
    RequestContext *ctx = VariantPointer<RequestContext>::pointer(callerData);
    if (httpStatusCode == ScimClient::OkResponseCode) {
        QLOG_SUPPORT() << "Deleted group on webserver, name:" << ctx->group.displayName() << "qliq id:" << ctx->group.qliqId;
        ActiveDirectoryGroupDao::delete_(ctx->group, m_db);
        ForestGroupMembershipDao::delete_(ctx->group.objectGuid, m_db);
        m_deletedGroupGuids.append(ctx->group.objectGuid);
        m_deletedGroupsCount++;
    } else if (httpStatusCode == ScimClient::NotFoundResponseCode) {
        QLOG_SUPPORT() << "Group already doesn't exist on webserver, name:" << ctx->group.displayName() << "qliq id:" << ctx->group.qliqId;
        ActiveDirectoryGroupDao::delete_(ctx->group, m_db);
        ForestGroupMembershipDao::delete_(ctx->group.objectGuid, m_db);
        m_deletedGroupGuids.append(ctx->group.objectGuid);
    } else {
        QLOG_ERROR() << "Cannot delete group on webserver, error:" << httpStatusCode << "name:" << ctx->group.displayName() << "qliq id:" << ctx->group.qliqId;
        m_failedGroupsCount++;
        onError(httpStatusCode, ctx);
    }
    onRequestFinished(httpStatusCode, ctx);
}

void AdToWebPusher::onError(int httpStatusCode, AdToWebPusher::RequestContext *ctx)
{
    if (ScimClient::isNetworkError(httpStatusCode)) {
        LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Interrupting pushing because of network error: " + QString::number(httpStatusCode));
        m_shouldStop = true;
    } else {
        if (ctx->isUser()) {
            if (httpStatusCode >= 300) {
                LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cloud returned error for user: " + ctx->user.login() + " error: " + QString::number(httpStatusCode));
                ctx->user.webserverError = httpStatusCode;
                ActiveDirectoryUserDao::update(ctx->user, m_db);
            }
        } else {
            if (httpStatusCode >= 300) {
                LOG_WEB_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cloud returned error for group: " + ctx->group.displayName() + " error: " + QString::number(httpStatusCode));
                ctx->group.webserverError = httpStatusCode;
                ActiveDirectoryGroupDao::update(ctx->group, m_db);
            }
        }
    }
}

void AdToWebPusher::onRequestFinished(int httpStatusCode, AdToWebPusher::RequestContext *ctx)
{
    m_isRequestInProgress = false;
    delete ctx;
    continueRun();
}

void AdToWebPusher::continueRun()
{
    if (!m_shouldStop) {
        startPushingWithoutClearingWebserverError();
    } else {
        LOG_WEB_EVENT(ActiveDirectoryEvent::WarningCategory, "Push cancelled");
        emitPushingFinished();
    }
}

void AdToWebPusher::resetStatCounters()
{
    m_createdGroupsCount = m_updatedGroupsCount = m_deletedGroupsCount = m_failedGroupsCount = 0;
    m_createdUsersCount = m_updatedUsersCount = m_deletedUsersCount = m_failedUsersCount = 0;
    m_pushedUserChangesCount = 0;
    m_pushStartTime = QDateTime::currentDateTime();

    {
        QMutexLocker lock(&m_progressMutex);
        m_progress.reset();
        m_progress.text = "Idle";
    }
}

void AdToWebPusher::emitPushingFinished()
{
    m_isPushInProgress = false;
    emit pushingFinished();

    {
        QMutexLocker lock(&m_progressMutex);
        m_progress.reset();
        m_progress.text = "Idle";
    }
    QString msg = "Push to cloud ";
    if (m_shouldStop)
        msg += "cancelled";
    else
        msg += "finished";

    if (m_createdGroupsCount || m_updatedGroupsCount || m_deletedGroupsCount || m_failedGroupsCount) {
        msg += ". GROUPS:";
        if (m_createdGroupsCount > 0) {
            msg += " created: " + QString::number(m_createdGroupsCount);
        }
        if (m_updatedGroupsCount > 0) {
            msg += " updated: " + QString::number(m_updatedGroupsCount);
        }
        if (m_deletedGroupsCount > 0) {
            msg += " deleted: " + QString::number(m_deletedGroupsCount);
        }
        if (m_failedGroupsCount > 0) {
            msg += " failed: " + QString::number(m_failedGroupsCount);
        }
    }

    if (m_createdUsersCount || m_updatedUsersCount || m_deletedUsersCount || m_failedUsersCount) {
        msg += ", USERS:";
        if (m_createdUsersCount > 0) {
            msg += " created: " + QString::number(m_createdUsersCount);
        }
        if (m_updatedUsersCount > 0) {
            msg += " updated: " + QString::number(m_updatedUsersCount);
        }
        if (m_deletedUsersCount > 0) {
            msg += " deleted: " + QString::number(m_deletedUsersCount);
        }
        if (m_failedUsersCount > 0) {
            msg += " failed: " + QString::number(m_failedUsersCount);
        }
    }
    msg += ". Elapsed time: " +  QString::number(m_pushStartTime.secsTo(QDateTime::currentDateTime()) / 60) + " minutes";
    LOG_WEB_EVENT(ActiveDirectoryEvent::InformationCategory, msg);
}

void AdToWebPusher::incrementPushedUserChangesCount()
{
    QMutexLocker lock(&m_progressMutex);

    ++m_pushedUserChangesCount;
    ++m_progress.value;
    m_progress.text = QString("Cloud Sync %1 users").arg(m_pushedUserChangesCount);

    if (m_pushedUserChangesCount == 1 || m_pushedUserChangesCount % 100 == 0 || m_progress.value > m_progress.maximum) {
        int leftCount = qMax(0, ActiveDirectoryUserDao::countNotSentToWebserver(m_db) - m_userSkip);
        LOG_WEB_EVENT(ActiveDirectoryEvent::InformationCategory, QString("Pushed %1 user changes to the cloud, %2 more to go").arg(m_pushedUserChangesCount).arg(leftCount));
        m_progress.maximum = leftCount;
        m_progress.value = 0;
    }
}
