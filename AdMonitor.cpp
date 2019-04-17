#include "AdMonitor.h"
#include <QTimer>
#include <QSettings>
#include <QEventLoop>
#include <QMutexLocker>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QsLog.h>
#include "iads.h"
#include "json/qt-json/qtjson.h"
#include "qliqDirectAD.h"
#include "db/Database.h"
#include "db/DatabaseUtil.h"
#include "dao/ActiveDirectoryDao.h"
#include "ScimClient.h"
#include "Scim.h"
#include "AdToWebPusher.h"
#include "db/Database.h"
#include "WebClient.h"
#include "ActiveDirectoryEventDao.h"
#include "ui/viewmodels/LoginViewModel.h"
#include "AdHelper.h"
#include "qliqdirect/shared/config/QliqDirectConfigFile.h"
#include "ActiveDirectoryDomainControllerManager.h"
#include "qliqdirect/shared/ActiveDirectoryDataTypes.h"

// Redefine macros to use C++ cast and avoid compiler warnings
#undef SUCCEEDED
#undef FAILED
#define SUCCEEDED(hr) (static_cast<HRESULT>(hr) >= 0)
#define FAILED(hr) (static_cast<HRESULT>(hr) < 0)

#define LOG_SYNC_EVENT(category, message) \
    LOG_AD_EVENT(ActiveDirectoryEvent::AdSyncType, category, message, m_db)

using namespace ActiveDirectory;

AdMonitor *AdMonitor::s_instance = nullptr;

AdMonitor::AdMonitor(WebClient *webClient, QObject *parent) :
    QObject(parent),
    m_webClient(webClient),
    m_shouldStop(false),
    m_ad(nullptr),
    m_webPusher(nullptr),
    m_timer(nullptr),
    m_isSyncInProgress(false),
    m_forceFullSyncRequested(false),
    m_syncCount(0),
    m_wasAuthErrorReported(false),
    m_wasConnectionErrorReported(false),
    m_anomalyDetectionStatus(AnomalyDetectionStatus::NoAnomaly),
    m_initialAnomalyPresentUserCount(0),
    m_anomalyNotPresentUserCount(0),
    m_anomalyNotPresentGroupCount(0),
    m_previousSyncTotalChangesCount(0),
    m_anomalyResumeRequested(false),
    m_domainControllerManager(nullptr)
{
    s_instance = this;
    ActiveDirectoryEventDao::configureEventLogFile();
}

AdMonitor::~AdMonitor()
{
    QLOG_SUPPORT() << "AdMonitor destructor called";
    deleteChildObjects();
    ActiveDirectoryEventDao::closeEventLogFile();

    if (s_instance == this) {
        s_instance = nullptr;
    }
}

void AdMonitor::setConfig(const AdConfig &newConfig)
{
    bool wasStopped = false;
    bool isFullSyncRequired = false;

//    if (m_syncCount == 0) {
//        deleteEventLog();
//    }

    if (m_isSyncInProgress) {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "AD config changed while sync is in progress, stopping AD thread");

        wasStopped = true;
        requestStop();
        waitForStopped();

        setProgress("Stopped due to config change");
    }

    if (!newConfig.enableAvatars) {
        if (m_adConfig.enableAvatars) {
            LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "Avatar support is switched off, deleting all avatars");
            ActiveDirectoryUserDao::deleteAllAvatars();
        }
    } else {
        if (!m_adConfig.enableAvatars && m_syncCount > 0) {
            LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "Avatar support is switched on, triggering a full sync");
            isFullSyncRequired = true;
        }
    }

    if (newConfig.enableDistinguishedNameBaseAuth && !m_adConfig.enableDistinguishedNameBaseAuth && m_syncCount > 0) {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "DN auth is switched on, triggering a full sync");
        isFullSyncRequired = true;
    }

    if (newConfig.enableSubgroups == false) {
        int deleted = ActiveDirectoryGroupDao::markDeletedAndNotSentGroupsWithQliqId();
        LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "AD subgroups are disabled, deleted " + QString::number(deleted) + " existing groups");
    }

    Scim::setSubgroupsEnabled(newConfig.enableSubgroups);

    if (isFullSyncRequired) {
        // Reset last full sync date time column for all sync contexts
        SyncContextDao::updateColumn(SyncContextDao::LastFullSyncDateTimeColumn, QDateTime());
    }

    m_adConfig = newConfig;
    if (m_adConfig.isEnabled && m_syncCount > 0) {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "Active Directory config changed");
    }

    // Save forests in database, but we want this to happen on AdMonitor thread only
    // so we queue method call here
    queueSaveForestData(newConfig.forests);

    if (wasStopped) {
        QLOG_SUPPORT() << "Restarting AdMonitor after saving new config";
        requestStart();
    }
}

const AdConfig& AdMonitor::config() const
{
    return m_adConfig;
}

//void AdMonitor::waitForStopped()
//{
//    if (isRunning()) {
//        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "Waiting for AdMonitor thread to stop");
//        unsigned long _3mins = 1000 * 60 * 3;

//  //      lock.unlock();
//        if (!m_thread->wait(_3mins)) {
//            LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, "Couldn't stop AdMonitor thread");
//            m_thread->terminate();
//            m_isThreadRunning = false;
//        } else {
//            LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "AdMonitor thread stopped");
//        }
//}

bool AdMonitor::isRunning() const
{
    //return m_thread != nullptr && m_thread->isRunning();
    return m_isSyncInProgress;
}

void AdMonitor::requestSync(bool isResume, bool full)
{
    // TODO: what if anomaly detected and full sync forced?
    m_anomalyResumeRequested = isResume;

    if (m_forceFullSyncRequested) {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "Full Sync is already scheduled, please wait for it to finish");
    } else {
        if (m_shouldStop) {
            LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "The service is being stopped, cannot request Full Sync in this state");
        } else {
            m_forceFullSyncRequested = full;
            QString syncType = full ? "Full" : "Delta";

            if (m_isSyncInProgress) {
                LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, syncType + " Sync requested by user (need to cancel a sync that is already in progress)");
                m_shouldStop = true;

                setProgress("Stopped due to a new full sync request");
            } else {
                LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, syncType + " Sync requested by user");
                queueSingleRun();
            }
        }
    }
}

void AdMonitor::manualyClearAnomalyFlag()
{
    QLOG_SUPPORT() << "Clear anomaly flag requested by admin";
    clearAnomalyFlag();
    if (!m_isSyncInProgress) {
        m_progress.reset();
    }
    queueSingleRun();
}

void AdMonitor::clearAnomalyFlag()
{
    m_initialAnomalyPresentUserCount = 0;
    m_anomalyNotPresentUserCount = 0;
    m_anomalyNotPresentGroupCount = 0;
    m_anomalyMessage.clear();
    m_anomalyDetectionStatus = AnomalyDetectionStatus::NoAnomaly;
}

bool AdMonitor::shouldDoFullSync(SyncContext *context, const Forest& forestConfig, const DomainController& activeDomainController)
{
    bool doFullSync = false;
    QString reason;
    const QString groupInfo = forestConfig.syncGroup + ", DC: " + activeDomainController.host;

    if (m_forceFullSyncRequested) {
        doFullSync = true;
        reason = "full sync requested";
    } else if (!context->lastFullSyncDateTime.isValid()) {
        doFullSync = true;
        reason = "config changed";
    } else if (context->lastFullSyncDateTime.date().day() != QDate::currentDate().day()) {
        doFullSync = true;
        reason = "last full sync older 1 day";
    }

    if (doFullSync) {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, QString("Full sync started for main group: %1 (reason: %2)").arg(groupInfo).arg(reason));
        context->highestCommittedUSN.clear();
        doFullSync = true;

        m_progress.text = "Full Sync started";
    } else {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "Delta sync started for main group: " + groupInfo);
        m_progress.text = "Delta Sync started";
    }
    return doFullSync;
}

void AdMonitor::waitForStopped()
{
    m_mutex.lock();
    if (m_isSyncInProgress) {
        m_stoppedWaitCondition.wait(&m_mutex);
    }
    m_mutex.unlock();
}

void AdMonitor::queueSaveForestData(const QVector<Forest> &forests)
{
    QVariantList list = Forest::toList(forests);
    QMetaObject::invokeMethod(this, "saveForests", Qt::QueuedConnection, Q_ARG(QVariantList, list));
}


bool AdMonitor::resetSyncDatabase()
{
    // TODO: in regard to stopping AdMonitor this code is still not thread safe.

    // WARNING: if we use QSqlDatabase() then transaction cannot begin!
    QSqlDatabase db = QSqlDatabase::database();

    bool wasStopped = false;
    AdMonitor *adMonitor = instance();
    if (adMonitor) {
        if (adMonitor->m_isSyncInProgress) {
            LOG_AD_EVENT(ActiveDirectoryEvent::AdSyncType, ActiveDirectoryEvent::WarningCategory,
                         "Request to reset sync database while sync is in progress, stopping AD thread", db);

            wasStopped = true;
            adMonitor->requestStop();
            adMonitor->waitForStopped();

            adMonitor->setProgress("Stopped because reseting local sync database");
        }
    }

    bool ok = DatabaseUtil::inTransaction(db,"reset AD sync database", [](QSqlDatabase db) -> bool {
        ActiveDirectoryUserDao::deleteAll(db);
        ActiveDirectoryGroupDao::deleteAll(db);
        ActiveDirectoryEventDao::deleteAll(db);
        DomainControllerManager::deleteForestDatabaseTablesAndSyncContextWithoutTransaction(db);
        return true;
    });

    if (ok) {
        LOG_AD_EVENT(ActiveDirectoryEvent::AdSyncType, ActiveDirectoryEvent::WarningCategory,
                     "Reset local sync database", db);

        if (adMonitor) {
            if (adMonitor->m_webPusher) {
                adMonitor->m_webPusher->resetSkipValues();
            }
            if (adMonitor->m_domainControllerManager) {
                adMonitor->m_domainControllerManager->reset();
            }

            adMonitor->setConfig(adMonitor->m_adConfig);
        }
    }

    if (wasStopped) {
        QLOG_SUPPORT() << "Restarting AdMonitor after reseting sync database";
        adMonitor->requestStart();
    }

    return ok;
}


long AdMonitor::testGroupName(const ActiveDirectory::Forest& config, int pageSize, QVariantList *results, QString *errorMsg, std::function<void (const QVariantMap&)> partialResultCallback)
{
    Q_UNUSED(pageSize);

    QString domain = config.primaryDomainController().host;
    QLOG_SUPPORT() << "Testing group name" << config.syncGroup << "on DC:" << domain;

    if (config.syncGroup.isEmpty()) {
        *errorMsg = "Main group is not configured, cannot continue";
        QLOG_ERROR() << *errorMsg;
        return -1;
    }

    QString mainGroupObjectGuid;
    DbGroup mainGroup;

    QList<AdGroupContext> groupContexts;

    ActiveDirectory::Credentials credentials;
    credentials.userName = config.userName;
    credentials.password = config.password;
    credentials.domain = domain;

    QString filter = QString("(&(objectClass=group)(CN=%1))").arg(config.syncGroup);
    ActiveDirectoryApi ad;
    SyncContext context;
    long ret;
    ret = ad.retrieveGroups(credentials, 1, filter, &context, [&mainGroupObjectGuid,&mainGroup,&groupContexts,&results,&partialResultCallback](AdGroup& g) -> bool {
        mainGroupObjectGuid = g.objectGuid;
        mainGroup = DbGroup(g);

        QVariantMap map;
        map["objectGuid"] = g.objectGuid;
        map["userPrincipalName"] = g.cn;
        map["cn"] = g.cn;
        map["class"] = "group";
        results->append(map);

        if (partialResultCallback)
            partialResultCallback(map);

        AdGroupContext ctx;
        ctx.objectGuid = g.objectGuid;
        ctx.distinguishedName = g.distinguishedName;
        ctx.cn = g.cn;
        ctx.isUsnChanged = true;
        groupContexts.append(ctx);
        return false;
    }, nullptr);

    // TODO: check if main group exists. What if error or not found?
    if (!SUCCEEDED(ret)) {
        QString err;
        if (ret == static_cast<long>(ActiveDirectoryApi::InvalidCredentialsAuthStatus)) {
            err = "Invalid credentials";
        } else {
            err = AdHelper::errorMessage(ret);
        }
        *errorMsg = "Cannot retrieve main group, error: " + err;
        QLOG_ERROR() << *errorMsg;
        return ret;
    }

    if (mainGroupObjectGuid.isEmpty()) {
        *errorMsg = "Main group is empty";
        QLOG_ERROR() << *errorMsg;
        return -2;
    }

    // For testing retrieve only so much groups or users
    const int sampleEntitiesCount = 3;
    QString mainGroupDN = mainGroup.distinguishedName;

    filter = QString("(&(objectClass=group)(memberOf=%1))").arg(mainGroupDN);
    context.highestCommittedUSN = "";
    int count = 0;
    ret = ad.retrieveGroups(credentials, sampleEntitiesCount, filter, &context, [&groupContexts,&count,&results,&partialResultCallback](AdGroup& g) -> bool {
        count++;
        if (count > sampleEntitiesCount) {
            return false;
        }

        QVariantMap map;
        map["objectGuid"] = g.objectGuid;
        map["userPrincipalName"] = g.cn;
        map["cn"] = g.cn;
        map["class"] = "group";
        results->append(map);

        if (partialResultCallback)
            partialResultCallback(map);

        AdGroupContext ctx;
        ctx.objectGuid = g.objectGuid;
        ctx.distinguishedName = g.distinguishedName;
        ctx.cn = g.cn;
        ctx.isUsnChanged = true;
        groupContexts.append(ctx);
        return true;
    });

    if (!SUCCEEDED(ret)) {
        *errorMsg = "Cannot retrieve subgroup, error: " + AdHelper::errorMessage(ret);
        QLOG_ERROR() << *errorMsg;
        return ret;
    }

    for (AdGroupContext& groupContext: groupContexts) {
        filter = QString("(&(objectClass=user)(objectcategory=person)(memberOf=%1))").arg(groupContext.distinguishedName);

        context.highestCommittedUSN = "";
        int count = 0;
        ret = ad.retrieveUsers(credentials, sampleEntitiesCount, filter, &context, [&count,&results,&partialResultCallback](AdUser& u) -> bool {
                count++;
                if (count > sampleEntitiesCount) {
                    return false;
                }
                const QVariantMap& userMap = u.toMap();
                results->append(userMap);
                if (partialResultCallback)
                    partialResultCallback(userMap);

                return true;
        }, nullptr, false);
        if (!SUCCEEDED(ret)) {
            break;
        }
    }

    if (!SUCCEEDED(ret)) {
        *errorMsg = "Cannot retrieve users, error: " + AdHelper::errorMessage(ret);
        QLOG_ERROR() << *errorMsg;
        return ret;
    }
    return ret;
}

QString AdMonitor::getAdSyncStatus() const
{
    QVariantMap map;
    map["isAdSyncInProgress"] = m_isSyncInProgress;
    if (m_webPusher) {
        map["isWebPushInProgress"] = m_webPusher->isPushInProgress();
        map["webPushProgress"] = m_webPusher->progress().toMap();
    }

    map["isAnomalyDetected"] = (m_anomalyDetectionStatus == AnomalyDetectionStatus::PersistentAnomaly);
    map["anomalyMessage"] = m_anomalyMessage;
    map["anomalyNotPresentUserCount"] = m_anomalyNotPresentUserCount;
    map["anomalyNotPresentGroupCount"] = m_anomalyNotPresentGroupCount;
    //map["anomalyDetectionStatus"] = static_cast<int>(m_anomalyDetectionStatus);
    map["adSyncProgress"] = m_progress.toMap();

    return Json::toJson(map);
}

void AdMonitor::deleteEventLog()
{
    QLOG_SUPPORT() << "Deleting event log upon user request";
    ActiveDirectoryEventDao::deleteAll();
    ActiveDirectoryEventDao::deleteLogFile();
}

QString AdMonitor::loadEventLogAsJson(int offset, int count)
{
    QString json;
    QList<ActiveDirectoryEvent> events = ActiveDirectoryEventDao::select(offset, count, QSqlDatabase::database());
    for (const ActiveDirectoryEvent& e: events) {
        if (json.isEmpty()) {
            json = "[" + e.toJson();
        } else {
            json += "," + e.toJson();
        }
    }
    if (json.isEmpty()) {
        json = "[";
    }
    json += "]";
    return json;
}

void AdMonitor::requestStart()
{
    m_shouldStop = false;
    QMetaObject::invokeMethod(this, "start", Qt::QueuedConnection);
}

void AdMonitor::run()
{
#ifdef Q_OS_WIN
    QLOG_SUPPORT() << "AdMonitor thread id: " << GetCurrentThreadId();
#endif
    singleRun();
}

// Also called indirectly from queueSingleRun()
void AdMonitor::singleRun()
{
    {
        QMutexLocker lock(&m_mutex);
        if (m_isSyncInProgress) {
            return;
        }
        if (!m_anomalyResumeRequested && m_anomalyDetectionStatus == AnomalyDetectionStatus::PersistentAnomaly) {
            QLOG_ERROR() << "Skipping sync because in persistent anomaly state";
            return;
        }
        m_isSyncInProgress = true;
    }
    m_syncCount++;
    m_lastSyncStartDateTime = QDateTime::currentDateTime();
    m_progress.reset();
    m_progress.text = "Running";
    m_progress.maximum = 0;
    m_previousSyncTotalChangesCount = 0;

    createChildObjects();

    int days = 30;
    int deletedEvents = ActiveDirectoryEventDao::deleteOlderThenDays(days, m_db);
    if (deletedEvents > 0) {
        QLOG_SUPPORT() << "Deleted" << deletedEvents << "events older then" << days << "days";
    }

    // This will block until all changes are saved in local db or m_shouldStop is true
    retrieveAdChanges();

    if (m_shouldStop) {
        {
            QMutexLocker lock(&m_mutex);
            m_isSyncInProgress = false;
            m_stoppedWaitCondition.wakeAll();
        }
        if (m_forceFullSyncRequested) {
            // If both shouldStop and forceFullSync then shouldStop was triggered in
            m_shouldStop = false;

            m_syncCount++;
            m_lastSyncStartDateTime = QDateTime::currentDateTime();
            retrieveAdChanges();
        } else {
            emit stopped();
        }
    } else {
        if (m_anomalyDetectionStatus == AnomalyDetectionStatus::NoAnomaly) {
            // TODO: keep pushing but skip deletions
            m_webPusher->startPushing();
        } else {
            QMutexLocker lock(&m_mutex);
            m_isSyncInProgress = false;
            m_stoppedWaitCondition.wakeAll();
        }
    }
    m_forceFullSyncRequested = false;
    m_anomalyResumeRequested = false;
}

void AdMonitor::stop()
{
//    QMutexLocker lock(m_threadMutex);
    QLOG_SUPPORT() << "AdMonitor::stop() called";

    m_shouldStop = true;
    m_forceFullSyncRequested = false;
    m_anomalyResumeRequested = false;
    if (m_timer) {
        QLOG_SUPPORT() << "Stoping sync timer";
        m_timer->stop();
    }
    if (m_webPusher) {
        m_webPusher->stopPushing();
    }
    if (!m_isSyncInProgress) {
        onPushingToWebFinished();
    }
}

void AdMonitor::start()
{
    createChildObjects();
    m_shouldStop = false;
    m_timer->start();
    onSyncIntervalTimerTimedOut();
}

void AdMonitor::requestStop()
{
    m_shouldStop = true;
    m_forceFullSyncRequested = false;
    m_anomalyResumeRequested = false;
    QMetaObject::invokeMethod(this, "stop", Qt::QueuedConnection);
}

void AdMonitor::onPushingToWebFinished()
{
    {
        QMutexLocker lock(&m_mutex);
        m_isSyncInProgress = false;
        m_stoppedWaitCondition.wakeAll();
    }

    if (m_shouldStop) {
        emit stopped();
    }
}

void AdMonitor::onSyncIntervalTimerTimedOut()
{
    if (m_isSyncInProgress || m_shouldStop || (!m_adConfig.isEnabled) || (m_adConfig.syncIntervalMins < 1)) {
        QString logMsg = "Sync timer fired but ";
        if (m_isSyncInProgress) {
            logMsg += "another sync is already in progress";
        } else if (m_shouldStop) {
            logMsg += "stop requested and in progress";
        } else if (!m_adConfig.isEnabled) {
            logMsg += "AD is no longer enabled";
        } else if (m_adConfig.syncIntervalMins < 1) {
            logMsg += "sync interval is below 1, invalid";
        } else {
            logMsg += "ERROR unforseen condition";
        }
        QLOG_SUPPORT() << logMsg;
        return;
    }

    // This will rotate the log file if needed
    ActiveDirectoryEventDao::configureEventLogFile();

    int secsTo = m_lastSyncStartDateTime.secsTo(QDateTime::currentDateTime());
    int minsTo = secsTo / 60;
//#ifndef QT_NO_DEBUG
//    if (true) {
//#else
    if (m_forceFullSyncRequested || minsTo >= m_adConfig.syncIntervalMins) {
//#endif
        //LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "Automatic sync started");
        qDebug() << "minsTo" << minsTo << "interval" << m_adConfig.syncIntervalMins;
        singleRun();
    } else {
        if (m_anomalyDetectionStatus != AnomalyDetectionStatus::PersistentAnomaly) {
            QString text = QString("Last sync: %1 changes detected, next run in ").arg(m_previousSyncTotalChangesCount);
            if (minsTo > 0) {
                text += QString("%1 mins").arg(minsTo);
            } else {
                //m_progress.text = QString("Next run in less then a minute");
                //text += QString("%1 secs").arg(secsTo);
                text += "about a minute";
            }
            setProgress(text);
        }
    }
}

void AdMonitor::createChildObjects()
{
    if (m_ad) {
        return;
    }

    QLOG_SUPPORT() << "AdMonitor creating child objects, starting sync timer";

    // If monitor is to be used in a bg thread this method must be called on that thread
    m_ad = new ActiveDirectoryApi();
    m_webPusher = new AdToWebPusher();

    ScimClient *scimClient = new ScimClient(m_webPusher);
    scimClient->setWebServerAddress(m_adConfig.webServerAddress);
    scimClient->setApiKey(m_adConfig.apiKey);

    m_db = Database::instance()->clone("ActiveDirectoryThreadDB");

    m_domainControllerManager = new DomainControllerManager();
    m_domainControllerManager->setDatabase(m_db);
    m_domainControllerManager->load();

    m_webPusher->setScimClient(scimClient);
    m_webPusher->setDatabase(m_db);

    connect(m_webPusher, SIGNAL(pushingFinished()), SLOT(onPushingToWebFinished()));

    m_timer = new QTimer(m_webPusher);
    m_timer->setInterval(1000 * 60);
    m_timer->setSingleShot(false);
    m_timer->start();
    connect(m_timer, SIGNAL(timeout()), SLOT(onSyncIntervalTimerTimedOut()));

    if (!m_pendingForests.isEmpty()) {
        saveForests(m_pendingForests);
    }
}

void AdMonitor::deleteChildObjects()
{
    QLOG_SUPPORT() << "AdMonitor deleting child objects";
    delete m_timer;
    m_timer = nullptr;
    delete m_ad;
    m_ad = nullptr;
    delete m_webPusher;
    m_webPusher = nullptr;
}

void AdMonitor::retrieveAdChanges()
{
    int presentUsersBeforeSync = ActiveDirectoryUserDao::AdBaseDao::count(ActiveDirectoryUserDao::AdStatusColumn, DbEntity::PresentAdStatus, m_db);
    m_progress.maximum = presentUsersBeforeSync;

    Forest forestConfig;
    DomainController activeDomainController;
    m_domainControllerManager->resetIteration();

    while (!m_shouldStop && m_domainControllerManager->nextForest(&forestConfig, &activeDomainController)) {
        retrieveForestChanges(forestConfig, activeDomainController);
    }
}

void AdMonitor::retrieveForestChanges(const ActiveDirectory::Forest &forestConfig, const ActiveDirectory::DomainController& activeDomainController)
{
    if (forestConfig.syncGroup.isEmpty()) {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, "Active Directory sync failed because main group is not configured");
        setProgress("Error: main group is not configured");
        return;
    }

    QString mainGroupObjectGuid;
    DbGroup mainGroup;
    bool isAllDataSynced = false;
    // TODO: test for big groups above pageSize
    const int pageSize = 1000;

    QDateTime startTime = QDateTime::currentDateTime();
    Stats groupStats, userStats;
    // In case previous sync was incomplete the 2 counts will be incorrect (many entities will have UnknownAdStatus)
    groupStats.inDbBeforeSync = ActiveDirectoryGroupDao::countWithStatusAndOfForest(DbEntity::PresentAdStatus, forestConfig.objectGuid, m_db);
    userStats.inDbBeforeSync = ActiveDirectoryUserDao::countWithStatusAndOfForest(DbEntity::PresentAdStatus, forestConfig.objectGuid, m_db);

    //set status DbEntity::UnknownAdStatus to all groups of this forest only. This is used to identify which group(s) are deleted
    ActiveDirectoryUserDao::setStatusForPresentUsersOfForest(DbEntity::UnknownAdStatus, forestConfig.objectGuid, m_db);
    ActiveDirectoryGroupDao::setStatusForGroupsOfForest(DbEntity::UnknownAdStatus, forestConfig.objectGuid, m_db);

    auto context = SyncContextDao::selectOneByAnd({{SyncContextDao::ForestGuidColumn, forestConfig.objectGuid},
                                                   {SyncContextDao::DomainControllerHostColumn, activeDomainController.host}}, 0, m_db);
    context.forestGuid = forestConfig.objectGuid;
    context.dcHost = activeDomainController.host;

    // https://docs.microsoft.com/en-us/windows/desktop/AD/polling-for-changes-using-usnchanged
    QString highestCommittedUSNForSync = context.highestCommittedUSN;
    QString highestCommittedUSNFromServer;
    bool doFullSync = shouldDoFullSync(&context, forestConfig, activeDomainController);
    if (doFullSync) {
        highestCommittedUSNForSync = "";
    }

    QLOG_SUPPORT() << "Retrieving changes from AD. Highest USN from db:" << context.highestCommittedUSN;

    QList<AdGroupContext> groupContexts;

    // Code to handle main group and subgroups is basically the same,
    // this is why we use a shared lambda
    bool isMainGroup = true;
    auto processGroupLambda = [this, &isMainGroup, &mainGroupObjectGuid, &groupContexts, &groupStats, &forestConfig](AdGroup& g) -> bool {
        if (m_shouldStop) {
            return false;
        }
        ++groupStats.total;
        bool isNewGroup = false, isChanged = false;
        if (isMainGroup) {
            g.debugPrint();
            mainGroupObjectGuid = g.objectGuid;
        }
        bool r = processGroup(groupContexts, isMainGroup, g, &isNewGroup, &isChanged);

        ForestGroupMembershipDao::save(forestConfig.objectGuid, g.objectGuid, m_db);

        if (isNewGroup) {
            groupStats.new_++;
        } else if (!g.isDeleted && isChanged) {
            groupStats.changed++;
        }
        if (!g.isDeleted && !g.isValid()) {
            groupStats.invalid++;
        }
        return r;
    };

    QString filter = QString("(&(objectClass=group)(CN=%1))").arg(forestConfig.syncGroup);
    context.highestCommittedUSN = "";

    Credentials credentials;
    credentials.userName = forestConfig.userName;
    credentials.password = forestConfig.password;
    credentials.domain = activeDomainController.host;

    long ret, groupRetCode;
    ret = groupRetCode = m_ad->retrieveGroups(credentials, 1, filter, &context, processGroupLambda, nullptr);

    // TODO: check if main group exists. What if error or not found?
    if (!mainGroupObjectGuid.isEmpty()) {
        mainGroup = ActiveDirectoryGroupDao::selectOneBy(ActiveDirectoryGroupDao::ObjectGuidColumn, mainGroupObjectGuid, 0, m_db);
        if (mainGroup.isEmpty()) {
            LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, "Cannot load main group from db. Probably the db is corrupted");
        }
    }

    if (SUCCEEDED(groupRetCode)) {
        highestCommittedUSNFromServer = context.highestCommittedUSN;
    }

    if (SUCCEEDED(groupRetCode) && !mainGroup.isEmpty()) {
        QString mainGroupDN = mainGroup.distinguishedName;

        filter = QString("(&(objectClass=group)(memberOf=%1))").arg(mainGroupDN);
        context.highestCommittedUSN = "";
        int count = 0;
        // retrieve sub groups
        isMainGroup = false;
        ret = groupRetCode = m_ad->retrieveGroups(credentials, 100, filter, &context, processGroupLambda, &count);
        QLOG_SUPPORT() << "Retrieved subgroups count:" << count << "error:" << groupRetCode;

        long userRetCode = 0;
        for (AdGroupContext& groupContext: groupContexts) {
            if (m_shouldStop) {
                break;
            }

            filter = QString("(&(objectClass=user)(objectcategory=person)(memberOf=%1))").arg(groupContext.distinguishedName);
            if (doFullSync) {
                groupContext.isUsnChanged = true;
            }

            // TODO: isUsnChanged doesn't work in case we have multiple DC
            if (groupContext.isUsnChanged || highestCommittedUSNForSync.isEmpty()) {
                QLOG_SUPPORT() << "Querying for all members of" << groupContext.distinguishedName << "(is full sync?" << doFullSync << ")";
                context.highestCommittedUSN = "";
                // If some users of this group has PresentAdStatus status, then its means these users are present
                // in some other group of the forest which is already processed
                ActiveDirectoryUserDao::setStatusForMemberOfGroup(DbEntity::PresentInOtherGroups, DbEntity::PresentAdStatus, groupContext.objectGuid, m_db);
            } else {
                QLOG_SUPPORT() << "Group uSNChanged is the same, marking all existing memebers as present";
                ActiveDirectoryUserDao::setStatusForMemberOfGroup(DbEntity::PresentAdStatus, DbEntity::UnknownAdStatus, groupContext.objectGuid, m_db);
                context.highestCommittedUSN = highestCommittedUSNForSync;
                QLOG_SUPPORT() << "Querying for members of" << groupContext.distinguishedName << "since uSNChanged" << context.highestCommittedUSN;
            }

            int count = 0;
            ret = userRetCode = m_ad->retrieveUsers(credentials, 100, filter, &context, [this,&userStats,doFullSync](AdUser& u) -> bool {
                    if (m_shouldStop) {
                        return false;
                    }

                    ++userStats.total;
                    bool isNew = false, isChanged = false;
                    bool r = processUser(u, &isNew, &isChanged);
                    if (isNew) {
                        userStats.new_++;
                    } else if (!u.isDeleted && isChanged) {
                        userStats.changed++;
                    }
                    if (!u.isDeleted && !u.isValid()) {
                        userStats.invalid++;
                    }
                    if (userStats.total % 100 == 0) {
                        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, QString("Retrieved %1 users so far").arg(userStats.total));
                    }
                    m_progress.text = QString("%1, %2 users").arg(doFullSync ? "Full AD Sync" : "Delta AD Sync").arg(userStats.total);
                    m_progress.value = userStats.total;
                    return r;

            }, &count, m_adConfig.enableAvatars);
            QLOG_SUPPORT() << "Retrieved user count:" << count << "error:" << userRetCode;

            if (SUCCEEDED(userRetCode) && groupContext.isUsnChanged) {
                // removed records from active_directory_user_group_membership for users which are not present in this group now
                ActiveDirectoryGroupDao::removeUsersFromGroup(groupContext.objectGuid, m_db);
                //update group usn_changed property after successfully retrieving users of the group
                ActiveDirectoryGroupDao::updateUSNChanged(groupContext.objectGuid, groupContext.uSNChanged, m_db);
            }
        } // for (AdGroupContext& groupContext: groupContexts)

        if (!m_shouldStop && groupRetCode == 0 && userRetCode == 0) {
            isAllDataSynced = true;

            // Retrieve deleted users
            context.highestCommittedUSN = highestCommittedUSNForSync;
            ret = m_ad->retrieveDeletedUsers(credentials, pageSize, &context, [this,&userStats](QVector<QString>& objectGuids) -> bool {
                int rowsAffected = ActiveDirectoryUserDao::markDeleted(objectGuids, m_db);
                userStats.deleted += rowsAffected;
                QLOG_SUPPORT() << "Tombstone container search found" << objectGuids.size() << "deleted users and" << rowsAffected << "got deleted in db now";
                return true;
            }, &count);
        }
    } else {
        QLOG_ERROR() << "Main group is empty and query return code is:" << groupRetCode;
        if (SUCCEEDED(groupRetCode)) {
            LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, "There is no main group present, deleting all existing groups and users from db");
            isAllDataSynced = true;
        }
    }

    // TIME CRITICAL BUG: Its repro rate may be very less (10% or even less than it)
    // When execution control is in AdMonitor::retrieveAdChanges and "Save Changes" button is presssed
    // m_shouldStop turned to true as AdMonitor::requestStop function called
    // All users status set to DbEntity::UnknownAdStatus due to call ActiveDirectoryUserDao::setStatusForPresentUsersOfForest
    // but users can not retrieved from groups as m_shouldStop=true terminate group(s) or users retrieval process
    // In this case, calling to ActiveDirectoryUserDao::selectNotPresentInAdAndOfForest function marked all users for deletion
    // and anomaly warning banner is shown (which is not required)
    // To gracefully handle this case, check for flag m_shouldStop value
    // If m_shouldStop is true, then do not process it further
    if (m_shouldStop) {
        return;
    }

    if (SUCCEEDED(ret)) {
        m_wasAuthErrorReported = m_wasConnectionErrorReported = false;

        QString msg, anomalyMsg;
        if (isAllDataSynced) {
            int deletedRowsLimit = 10;
            QList<DbUser> deletedUsersList = ActiveDirectoryUserDao::selectNotPresentInAdAndOfForest(forestConfig.objectGuid, deletedRowsLimit, m_db);
            QList<DbGroup> deletedGroupsList = ActiveDirectoryGroupDao::selectNotPresentInAdAndOfForest(forestConfig.objectGuid, deletedRowsLimit, m_db);
            userStats.deleted  += ActiveDirectoryUserDao::markDeletedAllWithStatusAndOfForest(forestConfig.objectGuid, DbEntity::UnknownAdStatus, m_db);
            groupStats.deleted += ActiveDirectoryGroupDao::deleteMainGroupsNotPresentInAdOfForest(forestConfig.objectGuid, m_db);
            groupStats.deleted += ActiveDirectoryGroupDao::markDeletedAllWithStatusAndOfForest(forestConfig.objectGuid, DbEntity::UnknownAdStatus, m_db);
            QLOG_SUPPORT() << "Deleted users after AD sync:" << userStats.deleted << ", deleted groups:" << groupStats.deleted;

            groupStats.inDbAfterSync = ActiveDirectoryGroupDao::countWithStatusAndOfForest(DbEntity::PresentAdStatus, forestConfig.objectGuid, m_db);
            userStats.inDbAfterSync = ActiveDirectoryUserDao::countWithStatusAndOfForest(DbEntity::PresentAdStatus, forestConfig.objectGuid, m_db);

            if (!deletedUsersList.isEmpty()) {
                QStringList logins, groupNames;
                foreach (const DbUser& u, deletedUsersList) {
                    logins.append(u.login().isEmpty() ? "account: " + u.accountName : u.login());
                }
                foreach (const DbGroup& g, deletedGroupsList) {
                    groupNames.append(g.displayName().isEmpty() ? "cn: " + g.cn : g.displayName());
                }
                QLOG_SUPPORT() << "Sample (limit " << deletedRowsLimit << ") deleted groups: " << groupNames.join("; ") << ", deleted users: " + logins.join("; ");
                QLOG_SUPPORT() << "Sample (limit 10) deleted users: " + logins.join("; ");


                if (m_adConfig.enableAnomalyDetection) {
                    anomalyMsg = detectPotentialAnomaly(forestConfig, userStats, groupStats);
                } else {
                    if (m_anomalyDetectionStatus != AnomalyDetectionStatus::PersistentAnomaly) {
                        m_anomalyDetectionStatus = AnomalyDetectionStatus::NoAnomaly;
                    }
                }
            } else {
                m_anomalyNotPresentUserCount = 0;
            }

            if (m_anomalyResumeRequested && m_anomalyNotPresentUserCount == 0 && m_anomalyDetectionStatus != AnomalyDetectionStatus::NoAnomaly) {
                QLOG_SUPPORT() << "Clearing anomaly because on resume sync now all users are present";
                clearAnomalyFlag();
            }

            msg = "Active Directory sync completed";
        } else if (m_shouldStop) {
            msg = "Active Directory sync cancelled";
        } else {
            msg = "Active Directory sync incomplete";
            // TODO: what in this case? Some groups/users have NotPresent status which is not actually correct
        }

        msg += ". GROUPS " + formatStats(groupStats);
        msg += ". USERS " + formatStats(userStats);

        msg += ". Elapsed time: " +  QString::number(startTime.secsTo(QDateTime::currentDateTime()) / 60) + " minutes";
        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, msg);

        if (!anomalyMsg.isEmpty()) {
            LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, anomalyMsg);

            if (m_anomalyDetectionStatus == AnomalyDetectionStatus::FirstSeenAnomaly) {
                setProgress("Possible anomaly detected, it will be verified during next run");
            } else {
                setProgress("Anomaly detected, paused");
            }
        } else {
            int changesOfUsers = userStats.new_ + userStats.changed + userStats.deleted;
            int changesOfGroups = groupStats.new_ + groupStats.changed + groupStats.deleted;
            m_previousSyncTotalChangesCount = changesOfUsers + changesOfGroups;
            setProgress(QString("Just finished, %1 changes detected").arg(m_previousSyncTotalChangesCount));
        }

        // If stopped, reached page limit or got no results we cannot save the highest USN from AD because it will not be
        // equal to highest USN of what we have in db (that one will be lower)
        // TODO: test for big groups above pageSize
        if (isAllDataSynced) {
            context.highestCommittedUSN = highestCommittedUSNFromServer;
            QLOG_SUPPORT() << "highest USN from db after sync:" << context.highestCommittedUSN << "(saved)";
        }
        if (!m_shouldStop) {
            context.lastFullSyncDateTime = QDateTime::currentDateTime();
            SyncContextDao::insertOrUpdate(&context, m_db);
        }
    } else {
        handleAdError(ret, activeDomainController.host);

        setProgress("AD error");
    }
}

QString AdMonitor::detectPotentialAnomaly(const ActiveDirectory::Forest& forestConfig, Stats userStats, Stats groupStats)
{
    Q_UNUSED(forestConfig)

    QString anomalyMsg;
    int nowDeletedUsers = userStats.deleted;
    int requiredBeforeSyncUserCount = userStats.inDbBeforeSync;
    if (m_anomalyDetectionStatus == AnomalyDetectionStatus::FirstSeenAnomaly) {
        requiredBeforeSyncUserCount = qMax(requiredBeforeSyncUserCount, m_initialAnomalyPresentUserCount);
        nowDeletedUsers = ActiveDirectoryUserDao::AdBaseDao::count(
                        QList<int>() << ActiveDirectoryUserDao::AdStatusColumn << ActiveDirectoryUserDao::IsSentToWebServerColumn,
                        QVariantList() << DbEntity::NotPresentAdStatus << 0);
    }

    // Krishna: when more than 20 or 5% (whichever is larger) of the total users do not show up in AD Sync.
    float percentThreshold = static_cast<float>(m_adConfig.anomalyDetectionPercentThreshold) / 100.f;
    int anomalyThreshold = static_cast<int>(requiredBeforeSyncUserCount * percentThreshold);
    if (requiredBeforeSyncUserCount >= m_adConfig.anomalyDetectionUserCountThreshold) {
        anomalyThreshold = qMax(m_adConfig.anomalyDetectionUserCountThreshold, anomalyThreshold);
    }

    if (requiredBeforeSyncUserCount >= anomalyThreshold && anomalyThreshold >= m_adConfig.anomalyDetectionUserCountThreshold) {
        if (nowDeletedUsers >= anomalyThreshold) {
            if (m_anomalyDetectionStatus == AnomalyDetectionStatus::NoAnomaly) {
                anomalyMsg = QString("Anomaly detected (initial), not present users: %1, previously present: %2, threshold: %3").arg(nowDeletedUsers).arg(userStats.inDbBeforeSync).arg(anomalyThreshold);
                m_anomalyDetectionStatus = AnomalyDetectionStatus::FirstSeenAnomaly;
                m_initialAnomalyPresentUserCount = requiredBeforeSyncUserCount;
            } else if (m_anomalyDetectionStatus == AnomalyDetectionStatus::FirstSeenAnomaly) {
                anomalyMsg = QString("Anomaly detected (second), not present users: %1, previously present: %2, threshold: %3").arg(nowDeletedUsers).arg(userStats.inDbBeforeSync).arg(anomalyThreshold);
                m_anomalyDetectionStatus = AnomalyDetectionStatus::PersistentAnomaly;
                onPersistentAnomalyDetected(nowDeletedUsers);
            }
        } else {
            if (m_anomalyDetectionStatus == AnomalyDetectionStatus::FirstSeenAnomaly) {
                m_anomalyDetectionStatus = AnomalyDetectionStatus::NoAnomaly;
                QString msg = QString("Initial anomaly cancelled, not present users: %1, previously present: %2, threshold: %3, present before initial anomaly: %4").arg(nowDeletedUsers).arg(userStats.inDbBeforeSync).arg(anomalyThreshold).arg(m_initialAnomalyPresentUserCount);
                LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, msg);
            }
        }
    }
    m_anomalyNotPresentUserCount = nowDeletedUsers;
    m_anomalyNotPresentGroupCount = groupStats.deleted;
    return anomalyMsg;
}

void AdMonitor::queueSingleRun()
{
    QMetaObject::invokeMethod(this, "singleRun", Qt::QueuedConnection);
}


// This method is called indirectly by QMetaObject::invokeMethod() from queueSaveForestData()
bool AdMonitor::saveForests(const QVariantList& list)
{
    QVector<Forest> forests = Forest::fromList(list);
    return saveForests(forests);
}

bool AdMonitor::saveForests(const QVector<Forest> &forests)
{
    bool ret = false;
    if (m_db.isValid()) {
        ret = m_domainControllerManager->saveForests(forests);
        if (ret) {
            // TODO: delete groups and users of deleted forests
            // TODO: determine if full sync is needed
            LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "Forest configurations saved in db, sync will be started");
            m_pendingForests.clear();
            queueSingleRun();
        }
    } else {
        m_pendingForests = forests;
        QLOG_WARN() << "Cannot save new forest configuration because m_db is not ready yet. Configuration change is kept pending";
    }
    return ret;
}

bool AdMonitor::processGroup(QList<AdMonitor::AdGroupContext> &groupContexts, bool isMainGroup, AdGroup &g,
                             bool *outStatIsNewGroup, bool *outStatIsChanged)
{
    if (m_shouldStop) {
        QLOG_ERROR() << "Stop requested, cancelling AD group enumeration";
        return false;
    }

    g.debugPrint();

    bool ignore = false;
    AdGroupContext groupContext;
    groupContext.objectGuid = g.objectGuid;
    groupContext.cn = g.cn;
    groupContext.distinguishedName = g.distinguishedName;
    groupContext.isUsnChanged = true;
    groupContext.uSNChanged = g.uSNChanged;

    if (ActiveDirectoryGroupDao::exists(ActiveDirectoryGroupDao::ObjectGuidColumn, g.objectGuid, m_db)) {
        QLOG_SUPPORT() << "Existing group" << g.cn;
        DbGroup dbGroup = ActiveDirectoryGroupDao::selectOneBy(ActiveDirectoryGroupDao::ObjectGuidColumn, g.objectGuid, 0, m_db);
        if (dbGroup.webserverError == 404) {
            ignore = true;
            g.validState = dbGroup.validState;
            LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "Ignoring cloud-deleted group: " + dbGroup.displayName());
        } else {
            dbGroup.status = DbEntity::PresentAdStatus;
            bool changed = (dbGroup.uSNChanged != g.uSNChanged);
            groupContext.isUsnChanged = changed;
            if (changed) {
                changed = !dbGroup.isEqual(g);
                QLOG_SUPPORT() << "uSNChanged changed for group:" << dbGroup.displayName() << "need to scan members, did group's attributes of interest change? " << changed;
            } else {
                QLOG_SUPPORT() << "uSNChanged not changed for group:" << dbGroup.displayName() << "no need to scan members";
            }
            if (changed) {
                QLOG_SUPPORT() << "Group '" << dbGroup.displayName() << "' was changed";
            }

            if (m_adConfig.enableSubgroups == false) {
                g.isDeleted = true;
                if (dbGroup.isDeleted == false) {
                    changed = true;
                    QLOG_SUPPORT() << "Deleting already pushed group because subgroups are disabled in config:" << dbGroup.displayName();
                }
            } else {
                // If group doesn't have qliq id it could be because previously subgroups where disabled
                // we make sure the group is pushed to webserver now.
                if (changed == false && dbGroup.isDeleted && g.isDeleted == false) {
                    dbGroup.isSentToWebserver = false;
                    changed = true;
                    QLOG_SUPPORT() << "Undeleting group because subgroups are enabled now" << dbGroup.displayName();
                }
            }

            // Copy just AdGroup part of the object, leaving db fields intact
            QString prevUsnChanged = dbGroup.uSNChanged;
            dbGroup.AdGroup::operator=(g);
            if (groupContext.isUsnChanged) {
                // if usn_change property changed, then don't update it in db at this point.
                // it will be updated in db after successfully retrieving users of this group
                dbGroup.uSNChanged = prevUsnChanged;
            }
            if (dbGroup.isSentToWebserver && changed) {
                dbGroup.isSentToWebserver = false;
            }
            if (isMainGroup) {
                dbGroup.isSentToWebserver = true;
            }
            if (changed && ScimClient::permanentErrors().contains(dbGroup.webserverError)) {
                QLOG_SUPPORT() << "Clearing permanent webserver error (" << dbGroup.webserverError << ") for group because AD data changed" << dbGroup.displayName();
                dbGroup.webserverError = 0;
            }
            g.validState = dbGroup.validState = Scim::isValid(dbGroup, nullptr) ? AdEntity::ValidState : AdEntity::InvalidState;
            ActiveDirectoryGroupDao::update(dbGroup, m_db);
            *outStatIsNewGroup = false;
            *outStatIsChanged = changed;
        }
    } else {
        QLOG_SUPPORT() << "New group" << g.cn;
        DbGroup dbGroup(g);
        dbGroup.status = DbEntity::PresentAdStatus;

        if (isMainGroup || m_adConfig.enableSubgroups == false) {
            dbGroup.isSentToWebserver = true;
        }
        g.validState = dbGroup.validState = Scim::isValid(dbGroup, nullptr) ? AdEntity::ValidState : AdEntity::InvalidState;
        ActiveDirectoryGroupDao::insert(dbGroup, m_db);
        *outStatIsNewGroup = true;
        *outStatIsChanged = false;
    }

    if (!ignore) {
        groupContexts.append(groupContext);
    }
    return true;
}

bool AdMonitor::processUser(AdUser &u, bool *outStatIsNew, bool *outStatIsChanged)
{
    if (m_shouldStop) {
        QLOG_ERROR() << "Stop requested, cancelling AD user enumeration";
        return false;
    }

    // if user account is disabled, then dont add it into db if removed already
    if ((u.userAccountControl & ADS_USER_FLAG_ENUM::ADS_UF_ACCOUNTDISABLE) &&
        !ActiveDirectoryUserDao::exists(ActiveDirectoryUserDao::ObjectGuidColumn, u.objectGuid, m_db)) {
        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "User account is disabled: " + u.accountName);
        return true;
    }

    if (u.userPrincipalName.isEmpty()) {
        u.validState = AdEntity::InvalidState;
        LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, "Skipping user without userPrincipalName attribute, accountName: " + u.accountName + " " + u.toString());
    } else {
        DbUser dbUser;
        QList<DbGroup> currentGroups;
        QSet<QString> currentGroupIds;
        QString validationErrorMessage;

        for (const QString& groupDn: u.memberOf) {
            DbGroup group = ActiveDirectoryGroupDao::selectOneBy(ActiveDirectoryGroupDao::DistinguishedNameColumn, groupDn, 0, m_db);
            if (!group.isEmpty()) {
                currentGroups.append(group);
                currentGroupIds.insert(group.objectGuid);
            }
        }

        if (u.isDisabled()) {
            // Treat disabled same as deleted
            u.isDeleted = true;
        }

        if (ActiveDirectoryUserDao::exists(ActiveDirectoryUserDao::ObjectGuidColumn, u.objectGuid, m_db)) {
            QLOG_SUPPORT() << "Existing user" << u.login();
            dbUser = ActiveDirectoryUserDao::selectOneBy(ActiveDirectoryUserDao::ObjectGuidColumn, u.objectGuid, 0, m_db);
            if (dbUser.webserverError == 404) {
                LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "Ignoring cloud-deleted user: " + dbUser.toString());
                u.validState = dbUser.validState;
            } else {
                bool changed = !dbUser.isEqual(u);
                if (!changed) {
                    QSet<QString> previousGroupsIds = ActiveDirectoryGroupDao::groupIdsOfUser(dbUser, m_db);
                    if (previousGroupsIds != currentGroupIds) {
                        changed = true;
                        QLOG_SUPPORT() << "User" << dbUser.login() << "groups were changed";
                    }
                } else {
                    QLOG_SUPPORT() << "User" << dbUser.login() << "was changed";

                    if (!dbUser.pwdLastSet.isEmpty() && (dbUser.pwdLastSet != u.pwdLastSet)) {
                        u.setPasswordChangedFlag(true);
                        QLOG_SUPPORT() << "Password changed for" << dbUser.login();
                        LOG_SYNC_EVENT(ActiveDirectoryEvent::InformationCategory, "Password change detected for user: " + dbUser.login());
                    }
                }
                // Copy just AdUser part of the object, leaving db fields intact
                dbUser.AdUser::operator=(u);
                if (dbUser.isSentToWebserver && changed) {
                    dbUser.isSentToWebserver = false;
                }
                dbUser.status = DbEntity::PresentAdStatus;
                if (changed && ScimClient::permanentErrors().contains(dbUser.webserverError)) {
                    QLOG_SUPPORT() << "Clearing permanent webserver error (" << dbUser.webserverError << ") for user because AD data changed" << dbUser.login();
                    dbUser.webserverError = 0;
                }
                u.validState = dbUser.validState = Scim::isValid(dbUser, &validationErrorMessage) ? AdEntity::ValidState : AdEntity::InvalidState;
                ActiveDirectoryUserDao::update(dbUser, m_db);
                ActiveDirectoryGroupDao::removeUserFromAllGroups(dbUser, m_db);
                *outStatIsNew = false;
                *outStatIsChanged = changed;
            }
        } else {
            QLOG_SUPPORT() << "New user" << u.login();
            dbUser = DbUser(u);
            dbUser.status = DbEntity::PresentAdStatus;
            u.validState = dbUser.validState = Scim::isValid(dbUser, &validationErrorMessage) ? AdEntity::ValidState : AdEntity::InvalidState;
            ActiveDirectoryUserDao::insert(dbUser, m_db);
            dbUser = ActiveDirectoryUserDao::selectOneBy(ActiveDirectoryUserDao::ObjectGuidColumn, u.objectGuid, 0, m_db);
            *outStatIsNew = true;
            *outStatIsChanged = false;
        }

        if (!u.isDeleted) {
            if (!u.isValid()) {
                LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, "Invalid user detected " + u.toString() + ", error: " + validationErrorMessage);
            } else if (!u.mail.isEmpty() && !LoginViewModel::isValidEmail(u.mail)) {
                LOG_SYNC_EVENT(ActiveDirectoryEvent::WarningCategory, "'mail' attribute with value '" + u.mail + "' is not a valid e-mail for user: " + u.toString());
            }
        }

        for (const DbGroup& group: currentGroups) {
            ActiveDirectoryGroupDao::addUserToGroup(dbUser, group, m_db);
        }
    }
    u.debugPrint();
    return true;
}

void AdMonitor::handleAdError(long ret, const QString& domain)
{
    const QString impactPart = "Impact: Authentication and Directory Sync no longer work\n\n. Please resolve the issue by updating the AD configuration using qliqDIRECT Manager. Make sure that you test the configuration before saving.";
    QLOG_ERROR() << "Cannot execute AD search, error:" << QString::number(ret, 16) << m_ad->lastErrorMessage();

    if (ret == static_cast<long>(ActiveDirectoryApi::InvalidCredentialsAuthStatus)) {
        QString errorMsg;
        int code;
        m_ad->extendedAuthenticationError(ret, &code, &errorMsg);
        QLOG_ERROR() << "Extended auth error:" << errorMsg;

        errorMsg = QString("%1 (AD error code: 0x%2, extended code: 0x%3)").arg(errorMsg).arg(ret, 0, 16).arg(code, 0, 16);
        QString msg = "qliqDIRECT is unable to login to Active Directory: " + domain + " \nReason: " + errorMsg + "\n" + impactPart;
        LOG_SYNC_EVENT(ActiveDirectoryEvent::ErrorCategory, msg);

        if (!m_wasAuthErrorReported) {
            m_wasAuthErrorReported = true;
#ifndef AD_PLAYGROUND
            sendServiceProblem("qliqDirect (Active Directory)", msg, true);
#endif
        }
    } else if (ret == static_cast<long>(ActiveDirectoryApi::ServerUnreachableAuthStatus)) {
        if (!m_wasConnectionErrorReported) {
            m_wasConnectionErrorReported = true;
            QString msg = QString("qliqDIRECT is unable to connect to the Active Directory: %1\nReason: (AD error code: %2)\n").arg(domain).arg(ret) + impactPart;
            LOG_AD_EVENT(ActiveDirectoryEvent::AdSyncType, ActiveDirectoryEvent::ErrorCategory, msg, m_db);
#ifndef AD_PLAYGROUND
            sendServiceProblem("qliqDirect (Active Directory)", msg, true);
#endif
        }
    }
}

void AdMonitor::sendServiceProblem(const QString &subject, const QString &message, bool isError)
{
    // Post it to WebClient's thread
    QMetaObject::invokeMethod(m_webClient, "sendServiceProblem", Qt::QueuedConnection, Q_ARG(QString, subject), Q_ARG(QString, message), Q_ARG(bool, isError));
}

void AdMonitor::onPersistentAnomalyDetected(int notPresentUsers)
{
    QString msg = QString("qliqDirect detected that your Active Directory is missing %1 users, "
                          "that were present during previous sync.\n\nTo be on the safe side, "
                          "deletion of the users from qliqCONNECT group was paused. "
                          "Please open 'qliqDirect Manager' on your machine and confirm if the users "
                          "should be actually deleted.").arg(notPresentUsers);
    sendServiceProblem("qliqDirect (Active Directory): Anomaly Detected", msg, true);

    m_anomalyMessage = QString("Active Directory is missing %1 users, "
                               "that were present during previous sync. Is that normal?\n"
                               "Please review your qliqDirect and Active Directory configuration.\n"
                               "Click the 'Resume' button when you believe the issue is resolved.").arg(notPresentUsers);
}

void AdMonitor::setProgress(const QString &text, int maximum)
{
    m_progress.text = text;
    m_progress.maximum = maximum;
}

QString AdMonitor::formatStats(const Stats& stats)
{
    QString ret = QString("changes to sync: %1, retrieved: %2").arg(stats.allChanges()).arg(stats.total);
    if (stats.new_ > 0) {
        ret += ", new: " + QString::number(stats.new_);
    }
    if (stats.changed > 0) {
        ret += ", changed: " + QString::number(stats.changed);
    }
    if (stats.deleted > 0) {
        ret += ", not present: " + QString::number(stats.deleted);
    }
    if (stats.invalid > 0) {
        ret += ", invalid: " + QString::number(stats.invalid);
    }
    if (stats.inDbBeforeSync) {
        ret += ", existed in database: " + QString::number(stats.inDbBeforeSync);
    }
    if (stats.inDbAfterSync) {
        ret += ", kept in database: " + QString::number(stats.inDbAfterSync);
    }
    return ret;
}

AdMonitor *AdMonitor::instance()
{
    return s_instance;
}
