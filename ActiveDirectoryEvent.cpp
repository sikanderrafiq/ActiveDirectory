#include "ActiveDirectoryEvent.h"
#include <QStringList>
#include "json/qt-json/qtjson.h"

namespace ActiveDirectory {

bool ActiveDirectoryEvent::isEmpty() const
{
    return timestamp.isNull();
}

QString ActiveDirectoryEvent::toString(ActiveDirectoryEvent::Category cat)
{
    switch (cat) {
    case InformationCategory:
        return "Info";
    case WarningCategory:
        return "Warning";
    case ErrorCategory:
        return "Error";
    default:
        return "";
    }
}

ActiveDirectoryEvent::Category ActiveDirectoryEvent::categoryFromString(const QString &string)
{
    if (string == "Info") {
        return InformationCategory;
    } else if (string == "Warning") {
        return WarningCategory;
    } else if (string == "Error") {
        return ErrorCategory;
    } else {
        return UnknownCategory;
    }
}

QString ActiveDirectoryEvent::toString(ActiveDirectoryEvent::Type type)
{
    switch (type) {
    case AdSyncType:
        return "AD Sync";
    case WebserverType:
        return "Cloud Sync";
    case AuthType:
        return "Authentication";
    default:
        return "";
    }
}

ActiveDirectoryEvent::Type ActiveDirectoryEvent::typeFromString(const QString &string)
{
    if (string == "AD Sync") {
        return AdSyncType;
    } else if (string == "Cloud Sync") {
        return WebserverType;
    } else if (string == "Authentication") {
        return AuthType;
    } else {
        return UnknownType;
    }
}

QString ActiveDirectoryEvent::toJson() const
{
    QString ret = "{\"id\":" + QString::number(id) + ",\"type\":" + QString::number(type) + ",\"category\":" + QString::number(category) +
            ",\"timestamp\":" + QString::number(timestamp.toTime_t()) + ",\"message\":\"" + message + "\"}";
    return ret;
}

QString ActiveDirectoryEvent::toTextFileString() const
{
    QString msg = message;
    msg.replace("\r\n", "\\n");
    msg.replace("\n", "\\n");
    return timestamp.toString("hh:mm:ss ap MMM-dd") + " | " + toString(type) + " | " + toString(category) + " | " + msg;
}

ActiveDirectoryEvent ActiveDirectoryEvent::fromMap(const QVariantMap &map)
{
    ActiveDirectoryEvent e;
    e.id = map.value("id").toInt();
    e.type = (ActiveDirectoryEvent::Type) map.value("type").toInt();
    e.category = (ActiveDirectoryEvent::Category) map.value("category").toInt();
    e.timestamp = QDateTime::fromTime_t(map.value("timestamp").toUInt());
    e.message = map.value("message").toString();
    return e;
}

ActiveDirectoryEvent ActiveDirectoryEvent::fromJson(const QString &json)
{
    QVariantMap map = Json::parse(json).toMap();
    return fromMap(map);
}

ActiveDirectoryEvent ActiveDirectoryEvent::fromTextFileString(const QString &text)
{
    QStringList fields = text.split(" | ");
    ActiveDirectoryEvent e;
    if (fields.size() >= 4) {
        e.id = 0;
        e.timestamp = QDateTime::fromString(fields[0], "hh:mm:ss ap MMM-dd");
        e.type = typeFromString(fields[1]);
        e.category = categoryFromString(fields[2]);
        e.message = fields[3].replace("\\n", "\n");
    }
    return e;
}

ActiveDirectoryProgressAndStatus::ActiveDirectoryProgressAndStatus()
{
    reset();
}

void ActiveDirectoryProgressAndStatus::reset()
{
    value = 0;
    maximum = -1;
    text.clear();
}

QVariantMap ActiveDirectoryProgressAndStatus::toMap() const
{
    QVariantMap map;
    map["value"] = value;
    map["maximum"] = maximum;
    map["text"] = text;
    return map;
}

ActiveDirectoryProgressAndStatus ActiveDirectoryProgressAndStatus::fromMap(const QVariantMap &map)
{
    ActiveDirectoryProgressAndStatus ret;
    ret.value = map.value("value").toInt();
    ret.maximum = map.value("maximum").toInt();
    ret.text = map.value("text").toString();
    return ret;
}

ActiveDirectoryProgressAndStatus ActiveDirectoryProgressAndStatus::fromJson(const QString &json)
{
    QVariantMap map = Json::parse(json).toMap();
    return fromMap(map);
}

} // namespace ActiveDirectory
