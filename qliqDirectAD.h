#ifndef QLIQDIRECTAD_H
#define QLIQDIRECTAD_H
#include <functional>
#include <qt_windows.h>
#include <QVariantMap>
#include <QDateTime>
#include <QStringList>
#include <QCryptographicHash>
#include "qliqdirectad_global.h"

#define AD_AUTH_ERR_INVALID_PASSWORD 0x52e
#define AD_AUTH_ERR_PASSWORD_EXPIRED 0x532
#define AD_AUTH_ERR_PASSWORD_NOT_SET 0x773

class QSqlDatabase;

namespace ActiveDirectory {
struct Credentials;
struct SyncContext;

struct ExtendedAuthenticationError {
    QString fullText;
    int code = 0;
    QString message;
    QString knownCodeName;
};

}

// Common attributes for user and group objects
struct AdEntity {
    QString objectGuid;
    QString distinguishedName;
    QString cn;
    QString accountName;
    QStringList objectClasses;
    QStringList memberOf;   // contains full paths, ie: CN=Staff,CN=Users,DC=dir,DC=qliq,DC=com
    QString uSNChanged;
    bool isDeleted;
    int validState; // AdEntityValidSate or webserver error when locally valid but rejected by server

    enum State {
        InvalidState = 0,
        ValidState = 1,
    };

    AdEntity() :
        isDeleted(false), validState(InvalidState)
    {}

    inline bool isEmpty() const
    {
        return objectGuid.isEmpty();
    }

    bool isGroup() const
    {
        return objectClasses.contains("group");
    }

    bool isUser() const
    {
        return objectClasses.contains("user");
    }

    void debugPrint() const;

    // For a DN String CN=..,CN=..,OU=..,DC=.. returns value of the first CN
    static QString extractTopLevelCn(const QString& path);

    bool isEqual(const AdEntity& other) const;

    bool isValid() const
    {
        return validState == AdEntity::ValidState;
    }
};

struct AdUser : public AdEntity {
    // persisted attributes
    QString userPrincipalName;  // login@domain.com
    QString givenName;
    QString middleName;
    QString sn;
    QString displayName;
    QString mail;
    QString telephoneNumber;
    QString mobile;
    QString title;
    QString employeeNumber;
    QString organization;
    QString division;
    QString department;
    // Good explanation of this field: http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm
    int userAccountControl;
    // Some flags are stored in this computed field (password expired, account locked)
    // https://msdn.microsoft.com/en-us/library/ms677840(v=vs.85).aspx
    int userAccountControlComputed;
    QByteArray avatar;
    QString avatarMd5;
    QString pwdLastSet;
    QString password;

    // qliq special bit flag to mark users with changed password
    // to be set in 'userAccountControl'
    enum ADS_QLIQ_EXTENDED_USER_FLAG {
        ADS_UF_QLIQ_PASSWORD_CHANGED = 0x4
    };

    AdUser() :
        userAccountControl(0),
        userAccountControlComputed(0)
    {}

    AdUser(const AdUser&) = default;

    bool operator==(const AdUser& u) const
    {
        if (this == &u) {
            return true;
        }
        return objectGuid == u.objectGuid && distinguishedName == u.distinguishedName && userPrincipalName == u.userPrincipalName &&
               givenName == u.givenName && middleName == u.middleName && sn == u.sn && displayName == u.displayName &&
               mail == u.mail && telephoneNumber == u.telephoneNumber && mobile == u.mobile &&
               title == u.title && isDeleted == u.isDeleted && userAccountControl == u.userAccountControl && userAccountControlComputed == u.userAccountControlComputed &&
               employeeNumber == u.employeeNumber && organization == u.organization && department == u.department &&
               division == u.division && avatarMd5 == u.avatarMd5 && pwdLastSet == u.pwdLastSet;
    }

    bool areBaseAdFieldsEqual(const AdUser& u) const
    {
        return (*this == u);
    }

    bool isEqual(const AdUser& other) const
    {
        return areBaseAdFieldsEqual(other) && (pwdLastSet == other.pwdLastSet);
    }

    QVariantMap toMap() const
    {
        QVariantMap map;
        map["objectGuid"] = objectGuid;
        map["distinguishedName"] = distinguishedName;
        map["userPrincipalName"] = userPrincipalName;
        map["givenName"] = givenName;
        map["middleName"] = middleName;
        map["sn"] = sn;
        map["displayName"] = displayName;
        map["mail"] = mail;
        map["telephoneNumber"] = telephoneNumber;
        map["mobile"] = mobile;
        map["title"] = title;
        map["isDeleted"] = isDeleted;
        map["userAccountControl"] = userAccountControl;
        map["employeeNumber"] = employeeNumber;
        map["organization"] = organization;
        map["department"] = department;
        map["division"] = division;
        map["class"] = "user";
        return map;
    }

    bool isDisabled() const;
    bool isLocked() const;
    bool isPasswordExpired() const;
    bool isPasswordCannotChange() const;
    bool isPasswordChanged() const;
    void setPasswordChangedFlag(bool on);

    QStringList memberOfJustNames() const;

    // The attributes above use LDAP names, below are helper methods to translate to more obvious names
    inline QString firstName() const {return givenName;}
    inline QString lastName() const {return sn;}
    inline QString phone() const
    {
        if (mobile.isEmpty()) {
            return telephoneNumber;
        } else {
            return mobile;
        }
    }
    inline QString login() const {return userPrincipalName;}

    QString firstNameOrFakeIt() const;
    QString lastNameOrFakeIt() const;
    QString toString() const;

    bool equals(const AdUser& u) const
    {
        return objectGuid == u.objectGuid && userPrincipalName == u.userPrincipalName &&
               givenName == u.givenName && middleName == u.middleName && sn == u.sn &&
               displayName == u.displayName && mail == u.mail && telephoneNumber == u.telephoneNumber;
    }

    void computeAvatarMd5()
    {
        if (!avatar.isEmpty()) {
            avatarMd5 = QCryptographicHash::hash(avatar, QCryptographicHash::Md5).toHex();
        } else {
            avatarMd5.clear();
        }
    }

    void debugPrint() const;
};

struct DbEntity {
    enum AdStatus {
        UnknownAdStatus,
        PresentAdStatus,
        NotPresentAdStatus,
        PresentInOtherGroups  // to identify user which is deleted from one group, but present in other groups of the forest
    };

    bool isSentToWebserver;
    int webserverError;
    QString qliqId;
    AdStatus status;

    DbEntity() :
        isSentToWebserver(false),
        webserverError(0),
        status(UnknownAdStatus)
    {}
};

struct DbGroup;

struct DbUser : public AdUser, public DbEntity {
    QList<DbGroup> groups;

    DbUser() = default;

    explicit DbUser(const AdUser& other) :
        AdUser(other)
    {}
};

struct DbUserAvatar {
    QString userObjectGuid;
    QByteArray avatar;
    QString avatarMd5;

    DbUserAvatar()
    {}

    explicit DbUserAvatar(const QString& userObjectGuid) :
        userObjectGuid(userObjectGuid)
    {}

    inline bool isEmpty() const
    {
        return userObjectGuid.isEmpty();
    }
};

// http://msdn.microsoft.com/en-us/library/ms676913(v=vs.85).aspx
struct AdGroup  : public AdEntity {
    QStringList members;

    bool isEqual(const AdGroup& other) const;
};

struct DbGroup : public AdGroup, public DbEntity {

    DbGroup() = default;

    explicit DbGroup(const AdGroup& other) :
        AdGroup(other)
    {}

    QString displayName() const;
    void debugPrint() const;
};

struct AdUserOrGroup {
    AdUser user;
    AdGroup group;

    bool isUser() const {return !user.isEmpty() && user.isUser();}
    bool isGroup() const {return !group.isEmpty() && group.isGroup();}
};

class ActiveDirectoryApi {
public:
    enum AuthStatus {
        OkAuthStatus = 0,
        ServerUnreachableAuthStatus = 0x8007203a,
        InvalidCredentialsAuthStatus = 0x8007052e,
        OtherErrorAuthStatus = 3
    };

    typedef std::function<bool (AdUser&)> ProcessUserCallback;
    typedef std::function<bool (QVector<QString>&)> ProcessDeletedUserCallback;
    typedef std::function<bool (AdGroup&)> ProcessGroupCallback;

    ActiveDirectoryApi();
    ~ActiveDirectoryApi();

    long isServerAccessible(const QString& domain, QString *outDnsName, QString *outErrorMessage, QSqlDatabase db);
    long authenticateUser(const ActiveDirectory::Credentials& credentials, const QString& distinguishedName, QString *outErrorMessage, QSqlDatabase db);
    long retrieveUsers(const ActiveDirectory::Credentials& credentials, int pageSize, const QString& searchFilter,
                       ActiveDirectory::SyncContext *inOutContext, ProcessUserCallback callback,
                       int *count = nullptr, bool isAvatarEnabled = false);
    long retrieveGroups(const ActiveDirectory::Credentials& credentials, int pageSize, const QString& searchFilter,
                       ActiveDirectory::SyncContext *inOutContext, ProcessGroupCallback callback,
                       int *count = nullptr);

    long retrieveDeletedUsers(const ActiveDirectory::Credentials& credentials, int pageSize,
                              ActiveDirectory::SyncContext *inOutContext, ProcessDeletedUserCallback callback, int *count = nullptr);

    QString lastErrorMessage() const;
    DWORD lastErrorCode() const;
    bool extendedAuthenticationError(long hr, int *outExtendedCode, QString *outErrorMsg, QString *outErrorCodeString = nullptr);
    bool extendedAuthenticationError(const QString& errorMessageText, int *outExtendedCode, QString *outErrorMsg, QString *outErrorCodeString = nullptr);
    bool extendedAuthenticationError(const QString& errorMessageText, ActiveDirectory::ExtendedAuthenticationError *outError);
    bool extendedAuthenticationError(long hr, ActiveDirectory::ExtendedAuthenticationError *outError);
    void logLastError(const QString& message);
    DWORD getLastError(QString *errorMessage, QString *providerName = NULL);

private:
    void storeLastError(DWORD hr);

    QString m_lastErrorMessage;
    DWORD m_lastErrorCode;
};

#endif // QLIQDIRECTAD_H
