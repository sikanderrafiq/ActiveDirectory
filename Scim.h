#ifndef SCIM_H
#define SCIM_H
#include <QString>
#include <QVariantMap>
#include "qliqDirectAD.h"

class Scim
{
public:
    static QVariantMap toJsonMap(const DbUser& user);
    static QString toJson(const DbUser& user);
    static QVariantMap& removeAllUserFields(QVariantMap& map);
    static bool isValid(const DbUser& user, QString *errorMessage);

    static QVariantMap toJsonMap(const DbGroup& group);
    static QString toJson(const DbGroup& group);
    static QVariantMap& removeAllGroupFields(QVariantMap& map);
    static bool isValid(const DbGroup& group, QString *errorMessage);

    static void setSubgroupsEnabled(bool enabled);
};

#endif // SCIM_H
