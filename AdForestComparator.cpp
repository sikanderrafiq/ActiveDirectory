#include "AdForestComparator.h"
#include <cassert>
#include <QsLog.h>

namespace ActiveDirectory {

bool ForestComparator::compare(const QVector<Forest> &previousForests, const QVector<Forest> &currentForests, QVector<ForestComparator::ForestWithChange> *changes)
{
    bool hasChanges = false;
    changes->clear();
    QMap<QString, Forest> currentMap = toMap(currentForests);
    QMap<QString, Forest> previousMap = toMap(previousForests);

    foreach (const QString& forestGuid, currentMap.keys()) {
        const Forest& previousForest = previousMap.value(forestGuid);
        const Forest& currentForest = currentMap.value(forestGuid);

        ForestWithChange forestChange;
        forestChange.forest = currentForest;
        forestChange.changes = compare(previousForest, currentForest, &forestChange.domainControllerChanges);
        if (forestChange.changes != NotChanged) {
            hasChanges = true;
            changes->append(forestChange);
        }

        if (!previousForest.isEmpty()) {
            // We are done with this previous forest
            previousMap.remove(forestGuid);
        }
    }

    // At this point previousMap contains only forests that should be deleted
    foreach (const QString& forestGuid, previousMap.keys()) {
        ForestWithChange forestChange;
        forestChange.forest = previousMap.value(forestGuid);
        forestChange.changes = Deleted;

        QMap<QString, DomainController> previousControllersMap = toMap(forestChange.forest.domainControllers);
        if (!previousControllersMap.empty()) {
            if (processDeletedDomainControllersMap(previousControllersMap, &forestChange.domainControllerChanges)) {
                forestChange.changes |= DomainControllerDeleted;
            }
        }

        hasChanges = true;
        changes->append(forestChange);
    }

    return hasChanges;
}

int ForestComparator::compare(const Forest &previous, const Forest &current, QVector<ForestComparator::DomainControllerWithChange> *dcChanges)
{
    int ret = NotChanged;
    if (previous.objectGuid.isEmpty()) {
        ret = Added;
    } else {
        assert(previous.objectGuid == current.objectGuid);

        if ((previous.userName != current.userName) || (previous.password != current.password)) {
            ret |= CredentialsChanged;
        }

        if (previous.syncGroup != current.syncGroup) {
            ret |= SyncGroupChanged;
        }
    }

    dcChanges->clear();
    QMap<QString, DomainController> currentMap = toMap(current.domainControllers);
    QMap<QString, DomainController> previousMap = toMap(previous.domainControllers);
    foreach (const QString& hostName, currentMap.keys()) {
        if (hostName.isEmpty()) {
            // Shouldn't happen
            QLOG_BUG() << "Domain controller with empty host in current forest";
            continue;
        }

        if (previousMap.contains(hostName)) {
            DomainController previousDc = previousMap.value(hostName);
            DomainController currentDc = currentMap.value(hostName);
            if (currentDc.isPrimary != previousDc.isPrimary) {
                // isPrimary changed, we don't care about fullServerName here
                DomainControllerWithChange dcChange;
                dcChange.domainContoller = currentDc;
                dcChange.change = DomainControllerWithChange::IsPrimaryChanged;
                dcChanges->append(dcChange);
                ret |= DomainControllerChanged;
            } else {
                // No change
            }
            // Either way we are done with this previous DC
            previousMap.remove(hostName);
        } else {
            // New, added dc
            DomainControllerWithChange dcChange;
            dcChange.domainContoller = currentMap.value(hostName);
            dcChange.change = DomainControllerWithChange::Added;
            dcChanges->append(dcChange);
            ret |= DomainControllerAdded;
        }
    }

    // At this point previousMap contains only DC that should be deleted
    if (!previousMap.empty()) {
        if (processDeletedDomainControllersMap(previousMap, dcChanges)) {
            ret |= DomainControllerDeleted;
        }
    }
    return ret;
}

bool ForestComparator::processDeletedDomainControllersMap(const QMap<QString, DomainController> &previousMap, QVector<ForestComparator::DomainControllerWithChange> *dcChanges)
{
    bool ret = false;
    DomainControllerWithChange dcChange;
    dcChange.change = DomainControllerWithChange::Deleted;

    foreach (const QString& hostName, previousMap.keys()) {
        if (hostName.isEmpty()) {
            // Shouldn't happen
            QLOG_BUG() << "Domain controller with empty host in previous forest";
            continue;
        }
        dcChange.domainContoller = previousMap.value(hostName);
        dcChanges->append(dcChange);
        ret = true;
    }

    return ret;
}

QMap<QString, Forest> ForestComparator::toMap(const QVector<Forest> &forests)
{
    QMap<QString, Forest> map;
    foreach (const auto& f, forests) {
        map[f.objectGuid] = f;
    }
    return map;
}

QMap<QString, DomainController> ForestComparator::toMap(const QList<DomainController> &controllers)
{
    QMap<QString, DomainController> map;
    foreach (const auto& dc, controllers) {
        map[dc.host] = dc;
    }
    return map;
}

QString ForestComparator::changedToString(int c)
{
    QString ret;

#define TEST_FOR_CHANGE(value) \
    if  (c & value) {ret += #value; ret += ' ';}

    TEST_FOR_CHANGE(Added);
    TEST_FOR_CHANGE(Deleted);
    TEST_FOR_CHANGE(CredentialsChanged);
    TEST_FOR_CHANGE(DomainControllerAdded);
    TEST_FOR_CHANGE(DomainControllerChanged);
    TEST_FOR_CHANGE(DomainControllerDeleted);
    TEST_FOR_CHANGE(SyncGroupChanged);
    return ret;
}

bool hasChange(const ForestComparator::ForestWithChange &forestChange, int change)
{
    return (forestChange.changes & change) == change;
}

} // namespace ActiveDirectory
