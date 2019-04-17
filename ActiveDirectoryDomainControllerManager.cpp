#include "ActiveDirectoryDomainControllerManager.h"
#include <QString>
#include <QDebug>
#include <QsLog.h>
#include "dao/ActiveDirectoryDao.h"
#include "db/DatabaseUtil.h"
#include "json/qt-json/qtjson.h"
#include "AdForestComparator.h"

namespace ActiveDirectory {

namespace  {

bool updateDatabaseWithForestChanges(QSqlDatabase db, QVector<ForestComparator::ForestWithChange> changes)
{
    return DatabaseUtil::inTransaction(db, "update AD forests", [&changes](QSqlDatabase db) -> bool {
        foreach (const auto& fc, changes) {
            QLOG_SUPPORT() << "Processing changes for forest" << fc.forest.objectGuid;

            if (hasChange(fc, ForestComparator::Added)) {
                QLOG_SUPPORT() << "This is a new forest (added)";
                ForestDao::insert(fc.forest, db);
                // Domain controllers will be added in a loop below
            } else if (hasChange(fc, ForestComparator::Deleted)) {
                QLOG_SUPPORT() << "This forest is deleted now";
                ActiveDirectoryUserDao::markDeletedAllOfForest(fc.forest.objectGuid, db);
                ActiveDirectoryGroupDao::deleteMainGroupsOfForest(fc.forest.objectGuid, db);
                ActiveDirectoryGroupDao::markDeletedAllOfForest(fc.forest.objectGuid, db);
                ForestGroupMembershipDao::deleteOfForest(fc.forest.objectGuid, db);
                ForestDao::delete_(ForestDao::ObjectGuidColumn, fc.forest.objectGuid, db);
                SyncContextDao::delete_(SyncContextDao::ForestGuidColumn, fc.forest.objectGuid, db);
            } else {
                if (hasChange(fc, ForestComparator::CredentialsChanged)) {
                    QLOG_SUPPORT() << "Credentials changed for forest";
                    ForestDao::updateColumn(ForestDao::UserNameCoumn, fc.forest.userName, fc.forest, db);
                    ForestDao::updateColumn(ForestDao::PasswordColumn, fc.forest.password, fc.forest, db);
                }
                if (hasChange(fc, ForestComparator::SyncGroupChanged)) {
                    QLOG_SUPPORT() << "Sync group changed for forest, full sync is pending";
                    ForestDao::updateColumn(ForestDao::SyncGroupColumn, fc.forest.syncGroup, fc.forest, db);
                    SyncContextDao::delete_(SyncContextDao::ForestGuidColumn, fc.forest.objectGuid, db);
                }
            }

            foreach (const auto& dcc, fc.domainControllerChanges) {
                switch (dcc.change) {
                case ForestComparator::DomainControllerWithChange::Added:
                    QLOG_SUPPORT() << "Domain controller added" << dcc.domainContoller.host << "is primary:" << dcc.domainContoller.isPrimary;
                    ForestDomainControllerMembershipDao::insert(fc.forest.objectGuid, dcc.domainContoller, db);
                    break;
                case ForestComparator::DomainControllerWithChange::IsPrimaryChanged:
                    QLOG_SUPPORT() << "Domain controller changed" << dcc.domainContoller.host << "now primary:" << dcc.domainContoller.isPrimary;
                    ForestDomainControllerMembershipDao::updateIsPrimary(fc.forest.objectGuid, dcc.domainContoller, db);
                    break;
                case ForestComparator::DomainControllerWithChange::Deleted:
                    QLOG_SUPPORT() << "Domain controller deleted" << dcc.domainContoller.host << "was primary:" << dcc.domainContoller.isPrimary;
                    ForestDomainControllerMembershipDao::delete_(fc.forest.objectGuid, dcc.domainContoller, db);
                    // Delete sync context for that dc
                    SyncContextDao::delete_(SyncContextDao::DomainControllerHostColumn, dcc.domainContoller.host, db);
                    break;
                }
            }
        }
        return true;
    });
}

} // anonymous namespace

DomainControllerManager::DomainControllerManager() :
    m_forestIndex(-1),
    m_isLoaded(false)
{
}

void DomainControllerManager::resetIteration()
{
    m_forestIndex = -1;
}

/*
 * Get next forest configuration to be process for fetching
 * all forest data (i.e. users, groups, sub groups, deleted users/groups etc.).
 * This configuration includes only one domain controller preferably primary domain
 * controller. If primary domain controller is not available, then additional domain
 * controller is used if specified.
 */
bool DomainControllerManager::nextForest(Forest *outForest, DomainController *outActiveDomainController)
{
    if (!m_isLoaded) {
        QLOG_ERROR() << "Forest configuration is not loaded (in nextForest()), loading now";
        load();
    }

    m_forestIndex++;
    if (m_forestIndex < m_forests.size()) {
        Forest forest = m_forests[m_forestIndex];

        for (int i = 0; i < forest.domainControllers.size(); ++i) {
            DomainController& dc = forest.domainControllers[i];
            if (isServerAccessible(&dc, forest)) {
                *outForest = forest;
                *outActiveDomainController = dc;
                return true;
            }
        }

        // TODO: here send email to admin that we cannot connect to any of domain controllers of this forest
    }
    return false;
}

/*
 * Check domain controller is accessible or not
 */
bool DomainControllerManager::isServerAccessible(DomainController *domainController, const Forest& config)
{
    QString errorMsg;
    QString dnsName;
    ActiveDirectoryApi ad;
    QLOG_SUPPORT() << "Checking accessibility of domain controller:" << domainController->host;
    long hr = ad.isServerAccessible(domainController->host, &dnsName, &errorMsg, m_db);
    bool ret = false;
    if (SUCCEEDED(hr)) {
        QLOG_SUPPORT() << "Domain controller:" << domainController->host << "is accessible with full name:" << dnsName;

        // update fullServerName in active_directory_forest_dc_membership. This is required
        // as active_directory_sync_context table identify domain controller with fullServerName
        if (domainController->dnsName.isEmpty()) {
            domainController->dnsName = dnsName;
            ForestDomainControllerMembershipDao::updateServerName(config.objectGuid, *domainController, m_db);
        }
        ret = true;
    } else {
        QLOG_ERROR() << "Domain controller:" << domainController->host << "is not accessible with error:" << hr;
    }
    return ret;
}

bool DomainControllerManager::saveForests(QVector<Forest> forests)
{
    if (!m_isLoaded) {
        QLOG_ERROR() << "Forest configuration is not loaded (in saveForests()), loading now";
        load();
    }

    QLOG_SUPPORT() << "New forests (count" << forests.size() << ", old count" << m_forests.size() << ") to save";
    bool ret = true;

    // qD Manager validates configuration so it should no be possible to have invalid one
    // However this is critical so we do extra check here anyway
    QString errorMessage;
    for (int i = 0; i < forests.size(); ) {
        if (!forests[i].isValid(&errorMessage)) {
            QLOG_FATAL() << "Removing invalid forest configuration, error:" << errorMessage << "forest:" << forests[i].toString();
            forests.remove(i);
        } else {
            ++i;
        }
    }

    QVector<ForestComparator::ForestWithChange> changes;
    bool anyChange = ForestComparator::compare(m_forests, forests, &changes);
    if (anyChange) {
        ret = updateDatabaseWithForestChanges(m_db, changes);
        if (ret) {
            m_forests = forests;
        }
    } else {
        QLOG_SUPPORT() << "There is no change in forest configuration to apply";
    }

    return ret;
}

QVector<Forest> DomainControllerManager::forests() const
{
    return m_forests;
}

void DomainControllerManager::setDatabase(const QSqlDatabase& db)
{
    m_db = db;
}

// Load forest configuration from database and cache it
void DomainControllerManager::load()
{
    m_forests.clear();

    QList<QString> forestGuids = ForestDomainControllerMembershipDao::selectForestGuids(m_db);
    foreach (const QString& forestGuid, forestGuids) {
        Forest forest = ForestDao::selectOneBy(ForestDao::ObjectGuidColumn, forestGuid, 0, m_db);
        if (!forest.isEmpty()) {
            forest.domainControllers = ForestDomainControllerMembershipDao::selectOfForest(forestGuid, m_db);

            // Empty DC should not be possible, but just in case test for it
            for (int i = 0; i < forest.domainControllers.size(); ) {
                if (forest.domainControllers[i].host.trimmed().isEmpty()) {
                    forest.domainControllers.removeAt(i);
                    QLOG_FATAL() << "Empty DC found for forest" << forestGuid;
                } else {
                    ++i;
                }
            }

            forest.sortDomainControllersByPrimary();
            m_forests.append(forest);
        } else {
            QLOG_ERROR() << "Cannot load forest with guid " << forestGuid << "from database but it has domain controllers";
        }
    }

    m_isLoaded = true;
    QLOG_SUPPORT() << "Loaded forest configuration from database";
}

void DomainControllerManager::reset()
{
    m_forests.clear();
    m_isLoaded = false;
}

bool DomainControllerManager::deleteForestDatabaseTablesAndSyncContextWithoutTransaction(QSqlDatabase db)
{
    bool ret = true;
    ret &= ForestDao::deleteAll(db);
    ret &= ForestDomainControllerMembershipDao::deleteAll(db);
    ret &= ForestGroupMembershipDao::deleteAll(db);
    ret &= SyncContextDao::deleteAll(db);
    return ret;
}

} // namespace ActiveDirectory
