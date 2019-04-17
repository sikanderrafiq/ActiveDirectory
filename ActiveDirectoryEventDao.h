#ifndef ACTIVEDIRECTORYEVENTDAO_H
#define ACTIVEDIRECTORYEVENTDAO_H
#include <QList>
#include "dao/ActiveDirectoryDao.h"
#include "ActiveDirectoryEvent.h"

// Insert AD event to db and also write to log file
// Implemented as a macro to preserve file name and line number in log
#define LOG_AD_EVENT(type, category, message, db) \
{ \
    ActiveDirectoryEventDao::insert(type, category, message, db); \
\
    if (category == ActiveDirectoryEvent::ErrorCategory) { \
        QLOG_ERROR() << message; \
    } else { \
        QLOG_SUPPORT() << message; \
    } \
}

namespace ActiveDirectory {

class ActiveDirectoryEventDao : public AdBaseDao<ActiveDirectoryEvent>
{
public:
    enum Column {
        IdColumn,
        TypeColumn,
        TimestampColumn,
        DurationColumn,
        MessageColumn,
        CategoryColumn,
        ColumnCount
    };

    static int insert(const ActiveDirectoryEvent& obj, QSqlDatabase db);
    static int insert(ActiveDirectoryEvent::Type type, ActiveDirectoryEvent::Category category,
                      const QString& message, QSqlDatabase db);
    static QList<ActiveDirectoryEvent> select(int offset, int limit, QSqlDatabase db);
    static int deleteOlderThenDays(int days, QSqlDatabase db);

    static QString eventLogFilePath();
    static void configureEventLogFile();
    static void closeEventLogFile();
    static void deleteLogFile();
};

} // namespace ActiveDirectory

#endif // ACTIVEDIRECTORYEVENTDAO_H
