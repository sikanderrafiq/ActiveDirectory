#ifndef ACTIVEDIRECTORYEVENT_H
#define ACTIVEDIRECTORYEVENT_H
#include <QDateTime>
#include <QVariantMap>

namespace ActiveDirectory {

struct ActiveDirectoryEvent
{
    enum Type {
        UnknownType,
        AdSyncType,
        WebserverType,
        AuthType
    };

    enum Category {
        UnknownCategory = 0,
        InformationCategory = 1,
        WarningCategory = 2,
        ErrorCategory = 3
    };

    unsigned int id;
    Type type;
    QDateTime timestamp;
    unsigned int duration;
    QString message;
    Category category;

    ActiveDirectoryEvent() :
        id(0), type(UnknownType), duration(0), category(UnknownCategory)
    {}

    bool isEmpty() const;

    static QString toString(Category cat);
    static Category categoryFromString(const QString& string);
    static QString toString(Type type);
    static Type typeFromString(const QString& string);

    QString toJson() const;
    QString toTextFileString() const;
    static ActiveDirectoryEvent fromMap(const QVariantMap& map);
    static ActiveDirectoryEvent fromJson(const QString& json);
    static ActiveDirectoryEvent fromTextFileString(const QString& text);
};

struct ActiveDirectoryProgressAndStatus {
    int value;
    int maximum;
    QString text;

    ActiveDirectoryProgressAndStatus();
    void reset();
    QVariantMap toMap() const;
    static ActiveDirectoryProgressAndStatus fromMap(const QVariantMap& map);
    static ActiveDirectoryProgressAndStatus fromJson(const QString& json);
};

} // namespace ActiveDirectory

#endif // ACTIVEDIRECTORYEVENT_H
