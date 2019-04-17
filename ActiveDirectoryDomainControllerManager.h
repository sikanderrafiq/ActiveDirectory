#ifndef ACTIVEDIRECTORYDOMAINCONTROLLERMANAGER_H
#define ACTIVEDIRECTORYDOMAINCONTROLLERMANAGER_H
#include <QVector>
#include <QSqlDatabase>
#include "qliqDirectAD.h"
#include "qliqdirect/shared/ActiveDirectoryDataTypes.h"

namespace ActiveDirectory {

class DomainControllerManager {
public:
    DomainControllerManager();

    bool nextForest(Forest *outForest, DomainController *outActiveDomainController);
    void resetIteration();

    bool saveForests(QVector<Forest> forests);
    QVector<Forest> forests() const;

    // Methods from ForestConfigurationLoader
    void setDatabase(const QSqlDatabase& db);
    void load();
    void reset();

    static bool deleteForestDatabaseTablesAndSyncContextWithoutTransaction(QSqlDatabase db);

private:
    bool isServerAccessible(DomainController *dc, const Forest& config);
    void saveForest(const QVariant& item);

private:
    int m_forestIndex;
    QSqlDatabase m_db;
    bool m_isLoaded;
    QVector<Forest> m_forests;
};

} // namespace ActiveDirectory

#endif // ACTIVEDIRECTORYDOMAINCONTROLLERMANAGER_H
