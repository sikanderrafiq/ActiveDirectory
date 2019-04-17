#ifndef ADFORESTCOMPARATOR_H
#define ADFORESTCOMPARATOR_H
#include <QVector>
#include "qliqdirect/shared/ActiveDirectoryDataTypes.h"

namespace ActiveDirectory {

class ForestComparator {
public:
    // Forest can be: unchanged, added, deleted or changed
    // The change can be:
    // - credentials
    // - sync group
    // - domain controller:
    // -- added
    // -- deleted
    // -- primary flag changed

    //namespace ChangeType {
    enum Changed {
        NotChanged              = 0,
        Added                   = (1 << 0),
        Deleted                 = (1 << 1),
        CredentialsChanged      = (1 << 2),
        DomainControllerAdded   = (1 << 3),
        DomainControllerChanged = (1 << 4),
        DomainControllerDeleted = (1 << 5),
        SyncGroupChanged        = (1 << 6),
    };

    static QString changedToString(int c);

    struct DomainControllerWithChange {
        enum Change {
            Added,
            Deleted,
            IsPrimaryChanged
        };
        DomainController domainContoller;
        Change change;

        DomainControllerWithChange()
        {}

        DomainControllerWithChange(const DomainController& domainContoller, Change change) :
            domainContoller(domainContoller), change(change)
        {}
    };

    struct ForestWithChange {
        Forest forest;
        int changes;
        QVector<DomainControllerWithChange> domainControllerChanges;

        ForestWithChange() :
            changes(0)
        {}

        ForestWithChange(const Forest& forest, int changes) :
            forest(forest), changes(changes)
        {}
    };

    static bool compare(const QVector<Forest>& previousForests, const QVector<Forest>& currentForests, QVector<ForestWithChange> *changes);
    static int compare(const Forest& previous, const Forest& current, QVector<DomainControllerWithChange> *dcChanges);

    static bool processDeletedDomainControllersMap(const QMap<QString, DomainController>& previousMap,
                                                   QVector<DomainControllerWithChange> *dcChanges);

    static QMap<QString, Forest> toMap(const QVector<Forest>& forests);
    static QMap<QString, DomainController> toMap(const QList<DomainController>& controllers);
};

bool hasChange(const ForestComparator::ForestWithChange& forestChange, int change);

} // namespace ActiveDirectory

#endif // ADFORESTCOMPARATOR_H
