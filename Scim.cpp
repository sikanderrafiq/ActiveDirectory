#include "Scim.h"
#include <QStringList>
#include "json/qt-json/qtjson.h"

namespace {
static bool m_subgroupsEnabled = false;

QString formattedName(const DbUser &user)
{
    QString ret = user.displayName;

    if (ret.isEmpty()) {
        if (!user.firstNameOrFakeIt().isEmpty()) {
            ret = user.firstNameOrFakeIt();
        }
        if (!user.middleName.isEmpty()) {
            if (!ret.isEmpty()) {
                ret += " ";
            }
            ret += user.middleName;
        }
        if (!user.lastNameOrFakeIt().isEmpty()) {
            if (!ret.isEmpty()) {
                ret += " ";
            }
            ret += user.lastNameOrFakeIt();
        }
    }
    return ret;
}
} // namespace

/*
 * user must have:
- userPrincipalName
- givenName (first name)
- sn (last name)
*/
bool Scim::isValid(const DbUser &user, QString *errorMessage)
{
    if (user.objectGuid.isEmpty()) {
        // If objectGuid is empty then this record must be corrupted
        if (errorMessage) {
            *errorMessage = "'objectGuid' attribute is empty";
        }
        return false;
    }

    if (user.userPrincipalName.isEmpty()) {
        // This translates to SCIM 'userName', required by SCIM
        if (errorMessage) {
            *errorMessage = "'userPrincipalName' attribute is empty";
        }
        return false;
    }

    if (user.firstName().isEmpty()) {
        if (errorMessage) {
            *errorMessage = "'givenName' attribute is empty";
        }
        return false;
    }

    if (user.lastName().isEmpty()) {
        if (errorMessage) {
            *errorMessage = "'sn' attribute is empty";
        }
        return false;
    }

    return true;
}

QVariantMap Scim::toJsonMap(const DbUser &user)
{
    const QString userSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
    const QString enterpriseSchema = "urn:scim:schemas:extension:enterprise:1.0";
    QVariantList schemas = QVariantList() << userSchema;
    QVariantMap ret;
    ret["externalId"] = user.objectGuid;

    if (!user.userPrincipalName.isEmpty()) {
        ret["userName"] = user.userPrincipalName;
    }

    QVariantMap name;
    name["formatted"] = formattedName(user);
    name["givenName"] = user.firstNameOrFakeIt();
    name["familyName"] = user.lastNameOrFakeIt();
    if (!user.middleName.isEmpty()) {
        name["middleName"] = user.middleName;
    }
    ret["name"] = name;

    if (!user.title.isEmpty()) {
        ret["title"] = user.title;
    }

    if (!user.phone().isEmpty()) {
        QVariantList phoneNumbers;
        QVariantMap number;
        if (!user.telephoneNumber.isEmpty()) {
            number["value"] = user.telephoneNumber;
            number["type"] = "work";
            phoneNumbers.append(number);
        }
        if (!user.mobile.isEmpty()) {
            number["value"] = user.mobile;
            number["type"] = "mobile";
            phoneNumbers.append(number);
        }
        ret["phoneNumbers"] = phoneNumbers;
    }

    if (!user.mail.isEmpty()) {
        QVariantList emails;
        QVariantMap email;
        email["value"] = user.mail;
        email["type"] = "work";
        email["primary"] = true;
        emails.append(email);
        ret["emails"] = emails;
    }

    QStringList userAccountControl;
    if (user.isDisabled()) {
        userAccountControl.append("account-disabled");
    }
    if (user.isLocked()) {
        userAccountControl.append("account-locked");
    }
    if (user.isPasswordExpired()) {
        userAccountControl.append("password-expired");
    }
    if (user.isPasswordCannotChange()) {
        userAccountControl.append("password-cant-change");
    }
    if (user.isPasswordChanged()) {
        userAccountControl.append("password-changed");
    }
    if (!userAccountControl.isEmpty()) {
        ret["userAccountControl"] = userAccountControl.join(";");
    }

    // Krishna wants this to be sent to webserver
    ret["pwdLastSet"] = user.pwdLastSet;
    ret["distinguishedName"] = user.distinguishedName;

    if (m_subgroupsEnabled && !user.groups.isEmpty()) {
        QVariantList groups;

        for (const DbGroup& group: user.groups) {
            QVariantMap entry;
            entry["value"] = group.qliqId;
            entry["display"] = AdEntity::extractTopLevelCn(group.cn);
            entry["$ref"] = "/Groups/" + group.qliqId;
            groups.append(entry);
        }
        ret["groups"] = groups;
    }

    QVariantMap enterprise;
    if (!user.employeeNumber.isEmpty()) {
        enterprise["employeeNumber"] = user.employeeNumber;
    }
    if (!user.organization.isEmpty()) {
        enterprise["organization"] = user.organization;
    }
    if (!user.division.isEmpty()) {
        enterprise["division"] = user.division;
    }
    if (!user.department.isEmpty()) {
        enterprise["department"] = user.department;
    }

    if (!enterprise.isEmpty()) {
        schemas << enterpriseSchema;
        ret[enterpriseSchema] = enterprise;
        // Currently qliq server doesn't follow SCIM standard and requires the field to be at parent object level
        ret.unite(enterprise);
    }
    ret["schemas"] = schemas;

    return ret;
}

QString Scim::toJson(const DbUser &user)
{
    return Json::toJson(toJsonMap(user));
}

QVariantMap &Scim::removeAllUserFields(QVariantMap &map)
{
    map.remove("externalId");
    map.remove("userName");
    map.remove("name");
    map.remove("title");
    map.remove("phoneNumbers");
    map.remove("emails");
    map.remove("groups");
    map.remove("employeeNumber");
    map.remove("organization");
    map.remove("division");
    map.remove("department");
    return map;
}

QVariantMap &Scim::removeAllGroupFields(QVariantMap &map)
{
    map.remove("externalId");
    map.remove("displayName");
    return map;
}

bool Scim::isValid(const DbGroup &group, QString *errorMessage)
{
    if (group.objectGuid.isEmpty()) {
        // If objectGuid is empty then this record must be corrupted
        if (errorMessage) {
            *errorMessage = "'objectGuid' attribute is empty";
        }
        return false;
    }

    if (group.cn.isEmpty()) {
        if (errorMessage) {
            *errorMessage = "'cn' attribute is empty";
        }
        return false;
    }

    return true;
}

void Scim::setSubgroupsEnabled(bool enabled)
{
    m_subgroupsEnabled = enabled;
}

QVariantMap Scim::toJsonMap(const DbGroup &group)
{
    QVariantMap ret;
    ret["schemas"] = QVariantList() << "urn:ietf:params:scim:schemas:core:2.0:Group";
    ret["externalId"] = group.objectGuid;

    if (!group.cn.isEmpty()) {
        ret["displayName"] = group.displayName();
    }
    return ret;
}

QString Scim::toJson(const DbGroup &group)
{
    return Json::toJson(toJsonMap(group));
}
