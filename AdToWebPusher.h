#ifndef ADTOWEBPUSHER_H
#define ADTOWEBPUSHER_H
#include <QObject>
#include <QSqlDatabase>
#include <QMutex>
#include "qliqDirectAD.h"
#include "ActiveDirectoryEvent.h"

class ScimClient;

class AdToWebPusher : public QObject
{
    Q_OBJECT
public:
    explicit AdToWebPusher(QObject *parent = 0);
    ~AdToWebPusher();

    void setDatabase(const QSqlDatabase& db);
    void setScimClient(ScimClient *sc);
    bool isPushInProgress() const { return m_isPushInProgress;}
    void resetSkipValues();
    // debug
    void deleteAllUsers();

    ActiveDirectory::ActiveDirectoryProgressAndStatus progress() const;

public slots:
    void run();
    bool pushOne();
    bool pushOneUser();
    bool pushOneGroup();
    void startPushing();
    void stopPushing();

signals:
    void pushingFinished();

private slots:
    void onCreateUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void onCreateGroupFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void onGetUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void onGetGroupFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void onUpdateUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void onUpdateGroupFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void onDeleteUserFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);
    void onDeleteGroupFinished(int httpStatusCode, const  QString& response, const QVariant& callerData);

private:
    struct RequestContext {
        DbUser user;
        DbGroup group;
        bool isResolvingConflict;

        RequestContext() :
            isResolvingConflict(false)
        {}

        RequestContext(const DbUser& user) :
            user(user),
            isResolvingConflict(false)
        {}

        RequestContext(const DbGroup& group) :
            group(group),
            isResolvingConflict(false)
        {}

        bool isUser() const {return !user.isEmpty();}
        bool isGroup() const {return !group.isEmpty();}
    };

    void startPushingWithoutClearingWebserverError();
    void onError(int httpStatusCode, RequestContext *ctx);
    void onRequestFinished(int httpStatusCode, RequestContext *ctx);
    void continueRun();
    void resetStatCounters();
    void emitPushingFinished();
    void incrementPushedUserChangesCount();
    /*
     * This function will remove group-user record for users whose group is removed, but
     * those users are still added in other group and present in active_directory_user table.
     * Only remove the entries for deleted groups (i.e. the user is dangling w.r.t. that group)
     */
    void removeDanglingUsers();

    QSqlDatabase m_db;
    bool m_needToCloseDb;
    ScimClient *m_scimClient;
    bool m_shouldStop;
    int m_userSkip, m_groupSkip;
    bool m_isRequestInProgress, m_isPushInProgress;
    int m_createdGroupsCount, m_updatedGroupsCount, m_deletedGroupsCount, m_failedGroupsCount;
    int m_createdUsersCount, m_updatedUsersCount, m_deletedUsersCount, m_failedUsersCount, m_pushedUserChangesCount;
    QDateTime m_pushStartTime;
    mutable QMutex m_progressMutex;
    ActiveDirectory::ActiveDirectoryProgressAndStatus m_progress;
    int m_previousSyncTotalChangesCount;
    QStringList m_deletedGroupGuids;
};

#endif // ADTOWEBPUSHER_H
