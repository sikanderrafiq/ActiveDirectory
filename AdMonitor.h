#ifndef ADMONITOR_H
#define ADMONITOR_H
#include <functional>
#include <QObject>
#include <QDateTime>
#include <QSqlDatabase>
#include <QMutex>
#include <QWaitCondition>
#include <QFile>
#include "AdConfig.h"
#include "ActiveDirectoryEvent.h"

class QMutex;
class QThread;
class QTimer;

class ActiveDirectoryApi;
class AdToWebPusher;
class AdUser;
class AdGroup;
class WebClient;
namespace ActiveDirectory {
class DomainController;
class DomainControllerManager;
class Forest;
struct SyncContext;
}

class AdMonitor : public QObject
{
    Q_OBJECT
public:
    explicit AdMonitor(WebClient *webClient, QObject *parent = 0);
    ~AdMonitor();

    void setConfig(const AdConfig& config);
    const AdConfig& config() const;
    bool isRunning() const;
    void requestSync(bool isResume, bool full);
    void manualyClearAnomalyFlag();
    void waitForStopped();
    void queueSaveForestData(const QVector<ActiveDirectory::Forest> &forests);

    // methods to control the process for debug purposes
    void setSyncPaused(bool paused);

    static bool resetSyncDatabase();
    static long testGroupName(const ActiveDirectory::Forest& config, int pageSize, QVariantList *results, QString *errorMsg, std::function<void (const QVariantMap&)> partialResultCallback);

    QString getAdSyncStatus() const;

    static void deleteEventLog();
    static QString loadEventLogAsJson(int offset, int count = 30);

signals:
    void stopped();

public slots:
    void requestStart();
    void requestStop();

private slots:
    void onPushingToWebFinished();
    void onSyncIntervalTimerTimedOut();
    // This method is called indirectly by QMetaObject::invokeMethod() from queueSaveForestData()
    bool saveForests(const QVariantList& forests);
    void stop();
    void start();
    void run();
    void singleRun();

private:
    struct AdGroupContext {
        QString objectGuid;
        QString cn;
        QString distinguishedName;
        bool isUsnChanged;
        QString uSNChanged;

        AdGroupContext() :
            isUsnChanged(false)
        {}
    };
    enum class AnomalyDetectionStatus {
        NoAnomaly,
        FirstSeenAnomaly,
        PersistentAnomaly
    };

    struct Stats {
        int total = 0, new_ = 0, changed = 0, deleted = 0, invalid = 0;
        int inDbBeforeSync = 0, inDbAfterSync = 0;

        int allChanges() const { return new_ + changed + deleted; }
    };

    void createChildObjects();
    void deleteChildObjects();
    void retrieveAdChanges();
    void retrieveForestChanges(const ActiveDirectory::Forest& forestConfig, const ActiveDirectory::DomainController& activeDomainController);
    bool processGroup(QList<AdGroupContext>& groupContexts, bool isMainGroup, AdGroup& g, bool *outStatIsNewGroup, bool *outStatIsChanged);
    bool processUser(AdUser& u, bool *outStatIsNew, bool *outStatIsChanged);
    void handleAdError(long ret, const QString& domain);
    void sendServiceProblem(const QString& subject, const QString& message, bool isError);
    void onPersistentAnomalyDetected(int notPresentUsers);
    void setProgress(const QString& text, int maximum = -1);
    void clearAnomalyFlag();
    bool shouldDoFullSync(ActiveDirectory::SyncContext *context, const ActiveDirectory::Forest& forestConfig, const ActiveDirectory::DomainController& activeDomainController);
    void insertForestGroupMembershipIfNeeded(const QString& forestGuid, const QString& groupGuid);
    QString detectPotentialAnomaly(const ActiveDirectory::Forest& forestConfig, Stats userStats, Stats groupStats);
    void queueSingleRun();
    bool saveForests(const QVector<ActiveDirectory::Forest>& forests);
    static QString formatStats(const Stats& stats);
    static AdMonitor *instance();

    WebClient *m_webClient;
    bool m_shouldStop;
    ActiveDirectoryApi *m_ad;
    AdToWebPusher *m_webPusher;
    QTimer *m_timer;
    AdConfig m_adConfig;
    bool m_isSyncInProgress;
    bool m_forceFullSyncRequested;
    QDateTime m_lastSyncStartDateTime;
    QDateTime m_lastSyncEndDateTime;
    int m_syncCount;
    bool m_wasAuthErrorReported, m_wasConnectionErrorReported;
    QMutex m_mutex;
    QWaitCondition m_stoppedWaitCondition;
    QSqlDatabase m_db;
    // Anomaly detection
    AnomalyDetectionStatus m_anomalyDetectionStatus;
    int m_initialAnomalyPresentUserCount;
    int m_anomalyNotPresentUserCount;
    int m_anomalyNotPresentGroupCount;
    QString m_anomalyMessage;
    ActiveDirectory::ActiveDirectoryProgressAndStatus m_progress;
    int m_previousSyncTotalChangesCount;
    bool m_anomalyResumeRequested;
    ActiveDirectory::DomainControllerManager *m_domainControllerManager;
    QVector<ActiveDirectory::Forest> m_pendingForests;

    static AdMonitor *s_instance;
};

#endif // ADMONITOR_H
