#include "qliqDirectAD.h"
#include <stdio.h>
#include <activeds.h>
#include <QString>
#include <QList>
#include <QScopedPointer>
#include <QRegExp>
#include <QSqlDatabase>
#include <ntdsapi.h>
#include <windows.h>
#include <wchar.h>
#include <sddl.h>
#include <QsLog.h>
#include "qliqdirect/service/ad/AdConfig.h"
#include "qliqdirect/service/ad/AdHelper.h"
#include "ActiveDirectoryEventDao.h"

// 64-bit integer can be [-9,223,372,036,854,775,808, 9,223,372,036,854,775,808]
#define _64BIT_DIGIT_COUNT 60

//typedef enum  {
//  ADS_UF_SCRIPT                                  = 1,        // 0x1
//  ADS_UF_ACCOUNTDISABLE                          = 2,        // 0x2
//  ADS_UF_HOMEDIR_REQUIRED                        = 8,        // 0x8
//  ADS_UF_LOCKOUT                                 = 16,       // 0x10
//  ADS_UF_PASSWD_NOTREQD                          = 32,       // 0x20
//  ADS_UF_PASSWD_CANT_CHANGE                      = 64,       // 0x40
//  ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED         = 128,      // 0x80
//  ADS_UF_TEMP_DUPLICATE_ACCOUNT                  = 256,      // 0x100
//  ADS_UF_NORMAL_ACCOUNT                          = 512,      // 0x200
//  ADS_UF_INTERDOMAIN_TRUST_ACCOUNT               = 2048,     // 0x800
//  ADS_UF_WORKSTATION_TRUST_ACCOUNT               = 4096,     // 0x1000
//  ADS_UF_SERVER_TRUST_ACCOUNT                    = 8192,     // 0x2000
//  ADS_UF_DONT_EXPIRE_PASSWD                      = 65536,    // 0x10000
//  ADS_UF_MNS_LOGON_ACCOUNT                       = 131072,   // 0x20000
//  ADS_UF_SMARTCARD_REQUIRED                      = 262144,   // 0x40000
//  ADS_UF_TRUSTED_FOR_DELEGATION                  = 524288,   // 0x80000
//  ADS_UF_NOT_DELEGATED                           = 1048576,  // 0x100000
//  ADS_UF_USE_DES_KEY_ONLY                        = 2097152,  // 0x200000
//  ADS_UF_DONT_REQUIRE_PREAUTH                    = 4194304,  // 0x400000
//  ADS_UF_PASSWORD_EXPIRED                        = 8388608,  // 0x800000
//  ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION  = 16777216 // 0x1000000
//} ADS_USER_FLAG_ENUM;

// Attributes that we are interested in
#define LDAP_ATTR_NAME L"name"                            // The name used by LDAP clients, such as the ADSI LDAP provider, to read and write the attribute by using the LDAP protocol.
#define LDAP_ATTR_GIVEN_NAME L"givenName"                 // Given-Name: Contains the given name (first name) of the user.
#define LDAP_ATTR_MIDDLE_NAME L"middleName"               // OtherName: Specifies a name in addition to a user's given name and surname, such as the user's middle name
#define LDAP_ATTR_DISTINGUISHED_NAME L"distinguishedName"
#define LDAP_ATTR_SN L"sn"                                // Surname: This attribute contains the family or last name for a user.
#define LDAP_ATTR_DISPLAY_NAME L"displayName"
#define LDAP_ATTR_MAIL L"mail"                            // EmailAddress: Specifies the user's e-mail address
#define LDAP_ATTR_TELEPHONE_NUMBER L"telephoneNumber"     // OfficePhone: Specifies the user's office telephone number
#define LDAP_ATTR_MOBILE L"mobile"                         // MobilePhone: Specifies the user's mobile phone number
#define LDAP_ATTR_TITLE L"title"
#define LDAP_ATTR_USER_PRINCIPAL_NAME L"userPrincipalName" // UserPrincipalName: Each user account has a user principal name (UPN) in the format <user>@<DNS-domain-name>
#define LDAP_ATTR_USN_CHANGED L"uSNChanged"
#define LDAP_ATTR_OBJECT_GUID L"objectGUID"
#define LDAP_ATTR_IS_DELETED L"isDeleted"
#define LDAP_ATTR_USER_ACCOUNT_CONTROL L"userAccountControl"
#define LDAP_ATTR_USER_ACCOUNT_CONTROL_COMPUTED L"msDS-User-Account-Control-Computed"
#define LDAP_ATTR_CN L"cn"                                  // object name
#define LDAP_ATTR_ACCOUNT_NAME L"sAMAccountName"            // login
#define LDAP_ATTR_PASSWORD L"unicodePwd"
#define LDAP_ATTR_MEMBER_OF L"memberOf"                     // The distinguished name of the groups to which this object belongs.
#define LDAP_ATTR_MEMBER L"member"                     // The list of distinguished names for the user, group, and contact objects that are members of the group
#define LDAP_ATTR_OBJECT_CLASS L"objectClass"
#define LDAP_ATTR_EMPLOYEE_NUMBER L"employeeNumber"
#define LDAP_ATTR_ORGANIZATION L"o"
#define LDAP_ATTR_DIVISION L"division"
#define LDAP_ATTR_DEPARTMENT L"department"
#define LDAP_ATTR_THUMBNAIL_PHOTO L"thumbNailPhoto"
#define LDAP_ATTR_JPEG_PHOTO L"jpegPhoto"
#define LDAP_ATTR_PWD_LAST_SET L"pwdLastSet"

#define LOG_ADS_ERROR(_message_) \
    { \
        QString errorMessage, providerName; \
        DWORD error = ActiveDirectoryApi::getLastError(&errorMessage, &providerName); \
        QLOG_ERROR() << _message_ << "error:" << error << ":" << errorMessage << "provider:" << providerName; \
    }

using namespace ActiveDirectory;

namespace {
const _GUID UIADs = {0xFD8256D0, 0xFD15, 0x11CE, {0xAB, 0xC4, 0x02, 0x60, 0x8C, 0x9E, 0x75, 0x53}};
const _GUID UIDirectorySearch = {0x109BA8EC, 0x92F0, 0x11D0, {0xA7, 0x90, 0x00, 0xC0, 0x4F, 0xD8, 0xD5, 0xA8}};

typedef std::function<bool (AdUserOrGroup&)> ProcessUserOrGroupCallback;

enum SearchObjectClass {
    AnyObjectClass,
    UserObjectClass,
    GroupObjectClass
};

VOID BuildGUIDString(WCHAR *szGUID, DWORD destLen, LPBYTE pGUID, DWORD srcLen);

inline const WCHAR *q2cwstr(const QString& str)
{
    return reinterpret_cast<const WCHAR *>(str.utf16());
}

inline const WCHAR *q2wstr(const QString& str)
{
    return reinterpret_cast<const WCHAR *>(str.utf16());
}

inline QString wstr2q(const WCHAR *wstr)
{
    return QString::fromWCharArray(wstr, wcslen(wstr));
}

struct ComReleaseDeleter {
    static inline void cleanup(IUnknown *pointer)
    {
        if (pointer) {
            pointer->Release();
        }
    }
};

void getAdColumnCaseIgnoreString(IDirectorySearch *pSearch, ADS_SEARCH_HANDLE hSearch, LPCWSTR name, QString *out)
{
    out->clear();
    ADS_SEARCH_COLUMN col;
    HRESULT hr = pSearch->GetColumn(hSearch, (LPWSTR)name, &col);
    if (SUCCEEDED(hr)) {
        const ADSTYPE expectedType = ADSTYPE_CASE_IGNORE_STRING;
        if (col.dwADsType == expectedType) {
            *out = wstr2q(col.pADsValues->CaseIgnoreString);
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(name) << "' expected type:" << expectedType << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }
}

HRESULT getAdColumnGuid(IDirectorySearch *pSearch, ADS_SEARCH_HANDLE hSearch, LPCWSTR name, QString *out)
{
    out->clear();
    ADS_SEARCH_COLUMN col;
    HRESULT hr = pSearch->GetColumn(hSearch, (LPWSTR) name, &col);
    if (SUCCEEDED(hr)) {
        if ((col.dwADsType == ADSTYPE_OCTET_STRING) && col.pADsValues && (col.pADsValues->OctetString.lpValue)) {
            WCHAR szGUID[40];
            BuildGUIDString(szGUID, sizeof szGUID, (LPBYTE) col.pADsValues->OctetString.lpValue, col.pADsValues->OctetString.dwLength);
            *out = wstr2q(szGUID);
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(name) << "' expected type:" << ADSTYPE_OCTET_STRING << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }
    return hr;
}

HRESULT getAdColumnInteger(IDirectorySearch *pSearch, ADS_SEARCH_HANDLE hSearch, LPCWSTR name, QString *out)
{
    out->clear();
    ADS_SEARCH_COLUMN col;
    HRESULT hr = pSearch->GetColumn(hSearch, (LPWSTR) name, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_LARGE_INTEGER) {
            // so we allocate a proper buffer to represent it as a string
            char buffer[_64BIT_DIGIT_COUNT + 1];
            sprintf(buffer, "%I64d", col.pADsValues->LargeInteger.QuadPart);
            *out = buffer;
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(name) << "' expected type:" << ADSTYPE_LARGE_INTEGER << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }
    return hr;
}


void fillAdEntity(IDirectorySearch *pSearch, ADS_SEARCH_HANDLE hSearch, AdEntity *entity)
{
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_CN, &entity->cn);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_ACCOUNT_NAME, &entity->accountName);

    ADS_SEARCH_COLUMN col;
    HRESULT hr;

    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_OBJECT_GUID, &col);
    if (SUCCEEDED(hr)) {
        if ((col.dwADsType == ADSTYPE_OCTET_STRING) && col.pADsValues && (col.pADsValues->OctetString.lpValue)) {
            WCHAR szGUID[40];
            BuildGUIDString(szGUID, sizeof szGUID, (LPBYTE) col.pADsValues->OctetString.lpValue, col.pADsValues->OctetString.dwLength);
            entity->objectGuid = wstr2q(szGUID);
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_OBJECT_GUID) << "' expected type:" << ADSTYPE_OCTET_STRING << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }

    hr = pSearch->GetColumn(hSearch, LDAP_ATTR_DISTINGUISHED_NAME, &col);
    if (SUCCEEDED(hr)) {
        const ADSTYPE expectedType = ADSTYPE_DN_STRING;
        if (col.dwADsType == expectedType) {
            entity->distinguishedName = wstr2q(col.pADsValues->DNString);
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_DISTINGUISHED_NAME) << "' expected type:" << ADSTYPE_DN_STRING << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }


    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_USN_CHANGED, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_LARGE_INTEGER) {
            // so we allocate a proper buffer to represent it as a string
            char buffer[_64BIT_DIGIT_COUNT + 1];
            sprintf(buffer, "%I64d", col.pADsValues->LargeInteger.QuadPart);
            entity->uSNChanged = buffer;
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_USN_CHANGED) << "' expected type:" << ADSTYPE_LARGE_INTEGER << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }

    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_MEMBER_OF, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_DN_STRING) {
            PADSVALUE value = col.pADsValues;
            for (DWORD i = 0; i < col.dwNumValues; ++i) {
                QString DNString = wstr2q(value->DNString);
                entity->memberOf.append(DNString);
                value++;
            }
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_MEMBER_OF) << "' expected type:" << ADSTYPE_DN_STRING << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }

    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_OBJECT_CLASS, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
            PADSVALUE value = col.pADsValues;
            for (DWORD i = 0; i < col.dwNumValues; ++i) {
                QString string = wstr2q(value->CaseIgnoreString);
                entity->objectClasses.append(string);
                value++;
            }
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_OBJECT_CLASS) << "' expected type:" << ADSTYPE_CASE_IGNORE_STRING << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }
}

void fillAdUser(IDirectorySearch *pSearch, ADS_SEARCH_HANDLE hSearch, AdUser *user, bool isAvatarEnabled)
{
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_GIVEN_NAME, &user->givenName);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_MIDDLE_NAME, &user->middleName);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_SN, &user->sn);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_DISPLAY_NAME, &user->displayName);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_MAIL, &user->mail);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_TELEPHONE_NUMBER, &user->telephoneNumber);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_TITLE, &user->title);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_USER_PRINCIPAL_NAME, &user->userPrincipalName);

    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_MOBILE, &user->mobile);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_PASSWORD, &user->password);

    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_EMPLOYEE_NUMBER, &user->employeeNumber);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_ORGANIZATION, &user->organization);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_DIVISION, &user->division);
    getAdColumnCaseIgnoreString(pSearch, hSearch, LDAP_ATTR_DEPARTMENT, &user->department);

    ADS_SEARCH_COLUMN col;
    HRESULT hr;

    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_USER_ACCOUNT_CONTROL_COMPUTED, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_INTEGER) {
            user->userAccountControlComputed = col.pADsValues->Integer;
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_USER_ACCOUNT_CONTROL_COMPUTED) << "' expected type:" << ADSTYPE_INTEGER << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }

    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_USER_ACCOUNT_CONTROL, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_INTEGER) {
            user->userAccountControl = col.pADsValues->Integer;
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_USER_ACCOUNT_CONTROL) << "' expected type:" << ADSTYPE_INTEGER << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }

    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_PWD_LAST_SET, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_LARGE_INTEGER) {
            // so we allocate a proper buffer to represent it as a string
            char buffer[_64BIT_DIGIT_COUNT + 1];
            sprintf(buffer, "%I64d", col.pADsValues->LargeInteger.QuadPart);
            user->pwdLastSet = buffer;
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_PWD_LAST_SET) << "' expected type:" << ADSTYPE_LARGE_INTEGER << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }

    if (isAvatarEnabled) {
        std::array<LPCWSTR, 2> avatarAttributes = {LDAP_ATTR_THUMBNAIL_PHOTO, LDAP_ATTR_JPEG_PHOTO};
        for (auto attrib: avatarAttributes) {
            hr = pSearch->GetColumn(hSearch, (LPWSTR) attrib, &col);
            if (SUCCEEDED(hr)) {
                if (col.dwADsType == ADSTYPE_OCTET_STRING) {
                    user->avatar.clear();
                    user->avatar.append((char *)col.pADsValues->OctetString.lpValue, col.pADsValues->OctetString.dwLength);
                    user->computeAvatarMd5();
                } else {
                    QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(attrib) << "' expected type:" << ADSTYPE_OCTET_STRING << "but got:" << col.dwADsType;
                }
                pSearch->FreeColumn(&col);

                if (!user->avatar.isEmpty()) {
                    break; // found avatar
                }
            }
        }
    }
}

void fillAdGroup(IDirectorySearch *pSearch, ADS_SEARCH_HANDLE hSearch, AdGroup *group)
{
    ADS_SEARCH_COLUMN col;
    HRESULT hr;

    hr = pSearch->GetColumn(hSearch, (LPWSTR) LDAP_ATTR_MEMBER, &col);
    if (SUCCEEDED(hr)) {
        if (col.dwADsType == ADSTYPE_DN_STRING) {
            PADSVALUE value = col.pADsValues;
            for (DWORD i = 0; i < col.dwNumValues; ++i) {
                QString DNString = wstr2q(value->DNString);
                group->members.append(DNString);
                value++;
            }
        } else {
            QLOG_ERROR() << "Cannot read ADS column '" << wstr2q(LDAP_ATTR_MEMBER) << "' expected type:" << ADSTYPE_DN_STRING << "but got:" << col.dwADsType;
        }
        pSearch->FreeColumn(&col);
    }
}

QString joinSearchFilterWithUSNChanged(QString filter, QString *errorMsg = nullptr)
{
    // http://www.ietf.org/rfc/rfc2254.txt
    const QString uSNChanged = "uSNChanged>=%1";

    filter = filter.trimmed();

    if (!filter.startsWith("(")) {
        if (errorMsg) {
            *errorMsg = "Search filter should start with '('";
        }
        return "";
    }
    if (filter.contains("uSNChanged")) {
        if (errorMsg) {
            *errorMsg = "Search filter cannot contain 'uSNChanged'";
        }
        return "";
    }

    QChar operatorChar = filter.at(1);
    if (operatorChar == QChar('&')) {
        // (&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))
        return "(&(" + uSNChanged + ")" + filter.mid(2);
    } else {
        return "(&(" + uSNChanged + ")(" + filter.mid(1) + ")";
    }
}

//********************************************************************
// DoUSNSyncSearch
//********************************************************************
HRESULT DoUSNSyncSearch(
        const Credentials& credentials,
    QString *pPrevInvocationID,  // GUID string for DC's invocationID
    QString *pPrevHighUSN,       // Highest USN from previous sync
    QString *pDcName,                // Name of DC to bind to
    DWORD pageSize,
    const QString& customSearchFilter,
    ProcessUserOrGroupCallback callback,
    int *count = nullptr,
    bool isAvatarEnabled = false)
{
    void HUGEP *pArray;
    WCHAR szGUID[40];
    INT64 iLowerBoundUSN;
    HRESULT hr = E_FAIL;
    DWORD dwCount = 0;
    VARIANT var;
    BOOL bUpdate = TRUE;
    QString defaultNamingContext;
    QString serverPath;
    QString dsPath;

    // Wrap COM references in a scoped pointer with custom deleter
    // so we don't need to remember to Release() them when going out of scope.
    QScopedPointer<IADs, ComReleaseDeleter> pDCService, pRootDSE;
    QScopedPointer<IDirectorySearch, ComReleaseDeleter> pSearch;

    if (count) {
        *count = 0;
    }

    // Validate input parameters.
    if (!pPrevInvocationID || !pPrevHighUSN || !pDcName)
    {
        if (!pPrevInvocationID) {
            QLOG_ERROR() << "Cannot execute search: pPrevInvocationID is missing";
        }
        if (!pPrevHighUSN) {
            QLOG_ERROR() << "Cannot execute search: pPrevHighUSN is missing";
        }
        if (!pDcName) {
            QLOG_ERROR() << "Cannot execute search: pDcName is missing";
        }

        return E_INVALIDARG;
    }

    VariantInit(&var);

    {
        IADs *out;
        QString adsPath = "LDAP://";
        if (!credentials.domain.isEmpty()) {
            adsPath += credentials.domain;
            if (!adsPath.endsWith("/")) {
                adsPath += "/";
            }
        }
        adsPath += "rootDSE";

        hr = ADsOpenObject(q2cwstr(adsPath),
                        q2cwstr(credentials.userName),
                        q2cwstr(credentials.password),
                        ADS_SECURE_AUTHENTICATION,
                        UIADs,
                        (void**)&out);
        if (FAILED(hr)) {
            QLOG_ERROR() << "Failed to bind to root:" << AdHelper::errorMessage(hr);
            return hr;
        }
        pRootDSE.reset(out);
    }

    // Get the name of the DC connected to.
    hr = pRootDSE->Get((LPWSTR) L"DnsHostName", &var);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to get DnsHostName:" << AdHelper::errorMessage(hr);
        return hr;
    }
    QString newDcName = wstr2q(var.bstrVal);
    VariantClear(&var);
    QLOG_SUPPORT() << "Connected to ActiveDirectory host:" << newDcName;

    // Compare it to the DC name from the previous USN sync operation.
    // If not the same, perform a full synchronization.
    if (pDcName->toLower() != newDcName.toLower()) {
        bUpdate = FALSE;
        QLOG_SUPPORT() << "New DC name detected, performing a full sync. Old DC:" << *pDcName << "new DC:" << newDcName;
        *pDcName = newDcName;
    }
    serverPath = QString("LDAP://%1/").arg(*pDcName);

    // Bind to the DC service object to get the invocationID.
    // The dsServiceName property of root DSE contains the distinguished
    // name of this DC service object.

    hr = pRootDSE->Get((LPWSTR) L"dsServiceName", &var);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to get dsServiceName:" << AdHelper::errorMessage(hr);
        return hr;
    }
    QString dsServiceName = wstr2q(var.bstrVal);
    VariantClear(&var);
    dsPath = serverPath + dsServiceName;

    {
        IADs *out;
        hr = ADsOpenObject(q2cwstr(dsPath),
                        q2cwstr(credentials.userName),
                        q2cwstr(credentials.password),
                        ADS_SECURE_AUTHENTICATION,
                        UIADs,
                        (void**)&out);
        if (FAILED(hr))
        {
            QLOG_ERROR() << "Failed to bind to the DC (" << dsPath  << ") service object:" << AdHelper::errorMessage(hr);
            return hr;
        }
        pDCService.reset(out);
    }

    // Get the invocationID GUID from the service object.
    hr = pDCService->Get((LPWSTR) L"invocationID", &var);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to get \"invocationID\":" << AdHelper::errorMessage(hr);
        return hr;
    }

    hr = SafeArrayAccessData((SAFEARRAY*)(var.parray), (void HUGEP* FAR*)&pArray);
    if (FAILED(hr)) {
        VariantClear(&var);
        QLOG_ERROR() << "Failed to get hugep of \"invocationId\":" << AdHelper::errorMessage(hr);
        return hr;
    }

    {
        DWORD invocationIdLen = 0;
        LONG lowerBound, upperBound;
        hr = SafeArrayGetLBound(var.parray, 1, &lowerBound);
        if (FAILED(hr)) {
            QLOG_ERROR() << "Cannot get lower bound of SafeArray:" << AdHelper::errorMessage(hr);
            return hr;
        } else {
            hr = SafeArrayGetUBound(var.parray, 1, &upperBound);
            if (FAILED(hr)) {
                QLOG_ERROR() << "Cannot get upper bound of SafeArray:" << AdHelper::errorMessage(hr);
                return hr;
            } else {
                invocationIdLen = upperBound - lowerBound + 1;
                BuildGUIDString(szGUID, sizeof szGUID, (LPBYTE)pArray, invocationIdLen);
            }
        }
    }
    VariantClear(&var);

    // Compare the invocationID GUID to the GUID string from the previous
    // synchronization. If not the same, this is a different DC or the DC
    // was restored from backup; perform a full synchronization.
    if (_wcsicmp(szGUID, (const WCHAR *)pPrevInvocationID->utf16()) != 0) {
        bUpdate = FALSE;
        *pPrevInvocationID = QString::fromWCharArray(szGUID, wcslen(szGUID));
        QLOG_SUPPORT() << "New invocationId detected, doing a full sync";
    }

    // If previous high USN is an empty string, handle this as a full synchronization.
    if (pPrevHighUSN->isEmpty()) {
        QLOG_SUPPORT() << "No previous HighUSN, doing a full sync";
        bUpdate = FALSE;
    }

    // Set the lower bound USN to zero if this is a full synchronization.
    // Otherwise, set it to the previous high USN plus one.
    if (bUpdate == FALSE) {
        iLowerBoundUSN = 0;
    } else {
        iLowerBoundUSN = _wtoi64(q2cwstr(*pPrevHighUSN)) + 1; // Convert the string to an integer.
    }

    // Get and save the current high USN.
    hr = pRootDSE->Get((LPWSTR) L"highestCommittedUSN", &var);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to get \"highestCommittedUSN\":" << AdHelper::errorMessage(hr);
        return hr;
    }
    *pPrevHighUSN = QString::fromWCharArray(var.bstrVal, wcslen(var.bstrVal));
    VariantClear(&var);
    QLOG_DEBUG() <<  "Current highestCommittedUSN:" << *pPrevHighUSN;

    hr = pRootDSE->Get((LPWSTR) L"defaultNamingContext", &var);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to get \"defaultNamingContext\":" << AdHelper::errorMessage(hr);
        return hr;
    }
    defaultNamingContext = wstr2q(var.bstrVal); // DC=dir,DC=qliqsoft,DC=com
    dsPath = serverPath + defaultNamingContext;
    VariantClear(&var);

    {
        IDirectorySearch *out;
        hr = ADsOpenObject(q2cwstr(dsPath),
                        q2cwstr(credentials.userName),
                        q2cwstr(credentials.password),
                        ADS_SECURE_AUTHENTICATION,
                        UIDirectorySearch,
                        (void**)&out);
        if (FAILED(hr)) {
            QLOG_ERROR() << "Failed to get IDirectorySearch:" << AdHelper::errorMessage(hr);
            return hr;
        }
        pSearch.reset(out);
    }

    // Set up the scope and page size search preferences.
    ADS_SEARCHPREF_INFO arSearchPrefs[4];
    arSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    arSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
    arSearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;

    arSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    arSearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
    arSearchPrefs[1].vValue.Integer = pageSize;

    // Sort by usnChanged so we can properly sync based on that attribute as tei
    ADS_SORTKEY sortKey;
    sortKey.pszAttrType = (LPWSTR)LocalAlloc(LPTR, wcslen(LDAP_ATTR_USN_CHANGED)*sizeof(WCHAR) + sizeof(WCHAR));
    wcscpy((wchar_t *)sortKey.pszAttrType, (const wchar_t *) LDAP_ATTR_USN_CHANGED);
    sortKey.fReverseorder = FALSE;
    sortKey.pszReserved = 0;
    arSearchPrefs[2].dwSearchPref = ADS_SEARCHPREF_SORT_ON;
    arSearchPrefs[2].vValue.dwType = ADSTYPE_PROV_SPECIFIC;
    arSearchPrefs[2].vValue.ProviderSpecific.dwLength = sizeof sortKey;
    arSearchPrefs[2].vValue.ProviderSpecific.lpValue = (LPBYTE)&sortKey;

    hr = pSearch->SetSearchPreference(arSearchPrefs, 3);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to set search prefs:" << AdHelper::errorMessage(hr);
        return hr;
    }

    QString searchFilter;
    {
        char lowerBoundUSN[_64BIT_DIGIT_COUNT + 1];
        sprintf(lowerBoundUSN, "%I64d", iLowerBoundUSN);

        if (customSearchFilter.trimmed().isEmpty()) {
            //*customSearchFilter = AdConfig::defaultSearchFilter();
            QLOG_FATAL() << "No search filter provided";
        }
        QString errorMsg;
        searchFilter = QString(joinSearchFilterWithUSNChanged(customSearchFilter, &errorMsg)).arg(lowerBoundUSN);
        if (searchFilter.isEmpty()) {
            QLOG_ERROR() << "Invalid custom search filter:" << customSearchFilter << "error:" << errorMsg;
        }
    }

    // Attributes to retrieve
    std::vector<LPCWSTR> szAttributeNames =
    {
        LDAP_ATTR_DISTINGUISHED_NAME,
        LDAP_ATTR_NAME,
        LDAP_ATTR_GIVEN_NAME,
        LDAP_ATTR_MIDDLE_NAME,
        LDAP_ATTR_SN,
        LDAP_ATTR_DISPLAY_NAME,
        LDAP_ATTR_MAIL,
        LDAP_ATTR_TELEPHONE_NUMBER,
        LDAP_ATTR_MOBILE,
        LDAP_ATTR_TITLE,
        LDAP_ATTR_USER_PRINCIPAL_NAME,
        LDAP_ATTR_USN_CHANGED,
        LDAP_ATTR_OBJECT_GUID,
        LDAP_ATTR_IS_DELETED,
        LDAP_ATTR_USER_ACCOUNT_CONTROL,
        LDAP_ATTR_USER_ACCOUNT_CONTROL_COMPUTED,
        LDAP_ATTR_CN,
        LDAP_ATTR_PASSWORD,
        LDAP_ATTR_ACCOUNT_NAME,
        LDAP_ATTR_MEMBER_OF,
//        LDAP_ATTR_MEMBER,
        LDAP_ATTR_OBJECT_CLASS,
        LDAP_ATTR_EMPLOYEE_NUMBER,
        LDAP_ATTR_ORGANIZATION,
        LDAP_ATTR_DIVISION,
        LDAP_ATTR_DEPARTMENT,
        LDAP_ATTR_PWD_LAST_SET
    };

    if (isAvatarEnabled) {
        szAttributeNames.push_back(LDAP_ATTR_THUMBNAIL_PHOTO);
        szAttributeNames.push_back(LDAP_ATTR_JPEG_PHOTO);
    }

    QLOG_SUPPORT() << "Performing AD search with filter:" << searchFilter;

    // Search for the objects indicated by the search filter.
    ADS_SEARCH_HANDLE hSearch = NULL;
    //hr = pSearch->ExecuteSearch((LPWSTR)searchFilter.utf16(), (LPWSTR *) szAttributeNames.data(), dwAttributes, &hSearch);
    hr = pSearch->ExecuteSearch((LPWSTR) q2cwstr(searchFilter), (LPWSTR *) szAttributeNames.data(), szAttributeNames.size(), &hSearch);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to set execute search:" << AdHelper::errorMessage(hr);
        return hr;
    }

    hr = pSearch->GetFirstRow(hSearch);

    while (SUCCEEDED(hr) && hr != S_ADS_NOMORE_ROWS) {
        if (count) {
            *count = *count + 1;
        }

        AdUserOrGroup entity;
        fillAdEntity(pSearch.data(), hSearch, &entity.user);
        if (entity.user.isUser()) {
            fillAdUser(pSearch.data(), hSearch, &entity.user, isAvatarEnabled);
        } else {
            entity.group.AdEntity::operator=(entity.user);
            fillAdGroup(pSearch.data(), hSearch, &entity.group);
        }

        if (!callback(entity)) {
            pSearch->AbandonSearch(hSearch);
            break;
        }

        dwCount++;
        hr = pSearch->GetNextRow(hSearch);
    }
    pSearch->CloseSearchHandle(hSearch);
    hSearch = NULL;

    wprintf(L"dwCount: %d\n", dwCount);

    if (hr == S_ADS_NOMORE_ROWS) {
        // This isn't an error
        hr = 0;
    }

    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to retrieve search row #" << dwCount << ": " << AdHelper::errorMessage(hr);
    }

    // If this is a full synchronization, the operation is complete.
    if (!bUpdate || (dwCount == pageSize)) {
        return hr;
    }

    pageSize -= dwCount;

    return hr;
}

HRESULT propertyVal(const QScopedPointer<IADs, ComReleaseDeleter>& pRootDSE, const QString& property, QString& value)
{
    if (NULL == pRootDSE) {
        return E_INVALIDARG;
    }

    VARIANT var;
    VariantInit(&var);

    HRESULT hr = pRootDSE->Get((LPWSTR) q2cwstr(property), &var);
    if (FAILED(hr)) {
        QLOG_ERROR() << QString("Failed to get property %1: error: ").arg(property) << AdHelper::errorMessage(hr);
        return hr;
    }
    value = wstr2q(var.bstrVal);
    VariantClear(&var);
    return hr;
}


//***************************************************************************
//
//  GetDeletedObjectsContainer()
//
//  Binds to the Deleted Object container.
//
//***************************************************************************
HRESULT GetDeletedObjectsContainer(const QString& userName,
                                   const QString& password,
                                   const QString& domain,
                                   QScopedPointer<IDirectorySearch, ComReleaseDeleter> *ppContainer)
{
    HRESULT hr;
    QScopedPointer<IADs, ComReleaseDeleter> pRootDSE;

    {
        IADs *out;
        QString adsPath = "LDAP://";
        if (!domain.isEmpty()) {
            adsPath += domain;
            if (!adsPath.endsWith("/")) {
                adsPath += "/";
            }
        }
        adsPath += "rootDSE";

        hr = ADsOpenObject(q2cwstr(adsPath),
                           q2cwstr(userName),
                           q2cwstr(password),
                           ADS_SECURE_AUTHENTICATION,
                           UIADs,
                           (void**)&out);
        if (FAILED(hr)) {
            QLOG_ERROR() << "Failed to bind to root:" << AdHelper::errorMessage(hr);
            return hr;
        }
        pRootDSE.reset(out);
    }

    QString defaultNamingContext;
    hr = propertyVal(pRootDSE, "defaultNamingContext", defaultNamingContext);
    if (FAILED(hr)) {
        return hr;
    }

    //i.e. "LDAP://132.148.241.147/<WKGUID=18e2ea80684f11d2b9aa00c04f79f805,DC=qliqsoft2,DC=com>"
    QString deletedContainerPath = QString("LDAP://%1/<WKGUID=%2,%3>")
            .arg(domain)
            .arg(wstr2q(GUID_DELETED_OBJECTS_CONTAINER_W))
            .arg(defaultNamingContext);

    {
        IDirectorySearch *out;
        // Bind to the deleted object container
        hr = ADsOpenObject(q2cwstr(deletedContainerPath),
                        q2cwstr(userName),
                        q2cwstr(password),
                        ADS_FAST_BIND | ADS_SECURE_AUTHENTICATION,
                        UIDirectorySearch,
                        (LPVOID*)&out);

        if (FAILED(hr)) {
            QLOG_ERROR() << "Failed to bind to deleted object containter: " << deletedContainerPath << AdHelper::errorMessage(hr);
            return hr;
        }
        ppContainer->reset(out);
    }
    return hr;
}


//********************************************************************
// BuildGUIDString
// Routine that makes the GUID a string in directory service bind form.
//********************************************************************
VOID BuildGUIDString(WCHAR *szGUID, DWORD destLen, LPBYTE pGUID, DWORD srcLen)
{
    WCHAR buf[4];

    wcscpy_s(szGUID, 1, L"");
    for (DWORD i = 0; i < srcLen; i++) {
        swprintf_s(buf, L"%02x", pGUID[i]);
        wcscat_s(szGUID, destLen, buf);
    }
}

} // anonymous namespace

ActiveDirectoryApi::ActiveDirectoryApi()
{
    HRESULT ret = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (ret != S_OK && ret != S_FALSE) {
        QLOG_ERROR() << "CoInitializeEx() error:" << ret;
    }
}

ActiveDirectoryApi::~ActiveDirectoryApi()
{
    CoUninitialize();
}

long ActiveDirectoryApi::isServerAccessible(const QString& domain, QString *outDnsName, QString *outErrorMessage, QSqlDatabase db)
{
    IADs *pRootDSE = NULL;

    QString adsPath = "LDAP://";
    if (!domain.isEmpty()) {
        adsPath += domain;
        if (!adsPath.endsWith("/")) {
            adsPath += "/";
        }
    }
    adsPath += "rootDSE";

    QString errorMessage;
    HRESULT hr = ADsGetObject(q2cwstr(adsPath), UIADs, (void**)&pRootDSE);
    if (SUCCEEDED(hr)) {
        VARIANT var;
        hr = pRootDSE->Get((LPWSTR) L"DnsHostName", &var);
        if (SUCCEEDED(hr)) {
            *outDnsName = wstr2q(var.bstrVal);
            VariantClear(&var);
        }
        pRootDSE->Release();
        errorMessage = "None";
    } else {
        errorMessage = AdHelper::errorMessage(hr);
        if (outErrorMessage) {
            *outErrorMessage = errorMessage;
        }
    }
    LOG_AD_EVENT(ActiveDirectoryEvent::AuthType, ActiveDirectoryEvent::InformationCategory,
                 QString("Server reachability check using path: %1,  HRESULT: %2, Error: %3").arg(adsPath).arg(hr).arg(errorMessage), db);
    return hr;
}

long ActiveDirectoryApi::authenticateUser(const Credentials& credentials, const QString& distinguishedName,
                                          QString *outErrorMessage, QSqlDatabase db)
{
    bool useDn = !distinguishedName.isEmpty();
    long result = OtherErrorAuthStatus;
    IADs *pRootDSE = NULL;
    HRESULT hr;

    QString adsPath = "LDAP://";
    if (!credentials.domain.isEmpty()) {
        adsPath += credentials.domain;
        if (!adsPath.endsWith("/")) {
            adsPath += "/";
        }
    }

    if (useDn) {
        adsPath += distinguishedName;
    } else {
        adsPath += "rootDSE";
    }


    QString debugPassword = "[masked]";
#ifndef QT_NO_DEBUG
    debugPassword = credentials.password;
#endif
    LOG_AD_EVENT(ActiveDirectoryEvent::AuthType, ActiveDirectoryEvent::InformationCategory,
                 "Trying to authenticate user: " + credentials.userName + " using path: " + adsPath, db);

    hr = ADsOpenObject(q2wstr(adsPath), q2wstr(credentials.userName), q2wstr(credentials.password),
                       ADS_SECURE_AUTHENTICATION, UIADs, (void**)&pRootDSE);

    if (SUCCEEDED(hr)) {
        pRootDSE->Release();
        result = OkAuthStatus;
        if (outErrorMessage) {
           outErrorMessage->clear();
        }
    } else {
        QString errorMessage = AdHelper::errorMessage(hr);
        QLOG_ERROR() << "Cannot authenticate user:" << credentials.userName << "in domain:" << credentials.domain << "error:" << errorMessage;
        result = hr;
        if (outErrorMessage) {
            *outErrorMessage = QString("HR 0x%1: %2").arg(hr, 1, 16).arg(errorMessage);
        }
    }

    return result;
}

long ActiveDirectoryApi::retrieveUsers(const Credentials& credentials, int pageSize, const QString& searchFilter, SyncContext *inOutContext, ActiveDirectoryApi::ProcessUserCallback callback, int *count, bool isAvatarEnabled)
{
    if (!searchFilter.contains("objectClass=user")) {
        QLOG_WARN() << "User filter doesn't contains 'objectClass=user', filter:" << searchFilter;
    }

#ifdef USER_BASED_SEARCH_FILTER_ONLY
    if (!inOutContext->highUSN.isEmpty()) {
        if (inOutContext->searchFilter != searchFilter) {
            QLOG_SUPPORT() << "Detected search filter change, reseting highUSN";
            inOutContext->highUSN.clear();
        }
    }
#endif
    long hr = DoUSNSyncSearch(credentials, &inOutContext->invocationId, &inOutContext->highestCommittedUSN, &inOutContext->dcDnsName, (DWORD)pageSize, searchFilter, [&](AdUserOrGroup &userOrGroup) -> bool {
        if (userOrGroup.isUser()) {
            return callback(userOrGroup.user);
        } else {
            return true;
        }
    }, count, isAvatarEnabled);
    if (SUCCEEDED(hr)) {
        m_lastErrorCode = 0;
        m_lastErrorMessage = "";
    } else {
        QString errorMessage;
        getLastError(&errorMessage);
    }
    return hr;
}

long ActiveDirectoryApi::retrieveGroups(const Credentials& credentials, int pageSize, const QString &searchFilter, SyncContext *inOutContext, ActiveDirectoryApi::ProcessGroupCallback callback, int *count)
{
    if (!searchFilter.contains("objectClass=group")) {
        QLOG_WARN() << "Group filter doesn't contains 'objectClass=group', filter:" << searchFilter;
    }
    long hr = DoUSNSyncSearch(credentials, &inOutContext->invocationId, &inOutContext->highestCommittedUSN, &inOutContext->dcDnsName, (DWORD)pageSize, searchFilter, [&](AdUserOrGroup &userOrGroup) -> bool {
        if (userOrGroup.isGroup()) {
            return callback(userOrGroup.group);
        } else {
            return true;
        }
    }, count);
    if (SUCCEEDED(hr)) {
        m_lastErrorCode = 0;
        m_lastErrorMessage = "";
    } else {
        QString errorMessage;
        getLastError(&errorMessage);
    }
    return hr;
}

long ActiveDirectoryApi::retrieveDeletedUsers(const ActiveDirectory::Credentials& credentials,
                                              int pageSize,
                                              ActiveDirectory::SyncContext *inOutContext,
                                              ProcessDeletedUserCallback callback,
                                              int *count)
{
    if (count) {
        *count = 0;
    }

    QString searchFilter = "(&(objectClass=user)(isDeleted=TRUE)(cn=*)";
    if (!inOutContext->highestCommittedUSN.isEmpty()) {
        searchFilter += "(uSNChanged>=" + inOutContext->highestCommittedUSN + ")";
    }
    searchFilter += ")";

    QScopedPointer<IDirectorySearch, ComReleaseDeleter> pDeletedObjectsSearch;
    long hr = GetDeletedObjectsContainer(credentials.userName, credentials.password, credentials.domain, &pDeletedObjectsSearch);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to bind to deleted object containter: " << AdHelper::errorMessage(hr);
        return hr;
    }

    ADS_SEARCH_HANDLE hSearch;

    // Only search for direct child objects of the container as Deleted Objects container is only one level
    ADS_SEARCHPREF_INFO rgSearchPrefs[3];
    rgSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    rgSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
    rgSearchPrefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL;

    // Search for deleted objects.
    rgSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_TOMBSTONE;
    rgSearchPrefs[1].vValue.dwType = ADSTYPE_BOOLEAN;
    rgSearchPrefs[1].vValue.Boolean = TRUE;

    // Set the page size.
    rgSearchPrefs[2].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    rgSearchPrefs[2].vValue.dwType = ADSTYPE_INTEGER;
    rgSearchPrefs[2].vValue.Integer = pageSize;

    // Set the search preference
    hr = pDeletedObjectsSearch->SetSearchPreference(rgSearchPrefs, ARRAYSIZE(rgSearchPrefs));
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to set search preferences: " << AdHelper::errorMessage(hr);
        return hr;
    }

    // Set the attributes to retrieve.
    LPWSTR rgAttributes[] = {
        LDAP_ATTR_USN_CHANGED,
        LDAP_ATTR_OBJECT_GUID
    };

    // Execute the search
    hr = pDeletedObjectsSearch->ExecuteSearch((LPWSTR) q2cwstr(searchFilter), rgAttributes, ARRAYSIZE(rgAttributes), &hSearch);
    if (FAILED(hr)) {
        QLOG_ERROR() << "Failed to execute search for deleted object container: " << AdHelper::errorMessage(hr);
        return hr;
    }

    // Retrieved deleted users
    QVector<QString> objectGuids;
    while(S_OK == (hr = pDeletedObjectsSearch->GetNextRow(hSearch)))
    {
        if (count) {
            *count = *count + 1;
        }

        QString usn_Changed, objectGuid;
        getAdColumnInteger(pDeletedObjectsSearch.data(), hSearch, LDAP_ATTR_USN_CHANGED, &usn_Changed);
        if (SUCCEEDED(getAdColumnGuid(pDeletedObjectsSearch.data(), hSearch, LDAP_ATTR_OBJECT_GUID, &objectGuid))) {
            objectGuids.append(objectGuid);
        }
    }

    if (objectGuids.size() > 0) {
        callback(objectGuids);
    }

    // cleanup.
    pDeletedObjectsSearch->CloseSearchHandle(hSearch);
    hSearch = NULL;
    return hr;
}


QString ActiveDirectoryApi::lastErrorMessage() const
{
    return m_lastErrorMessage;
}

DWORD ActiveDirectoryApi::lastErrorCode() const
{
    return m_lastErrorCode;
}

bool ActiveDirectoryApi::extendedAuthenticationError(long hr, int *outExtendedCode, QString *outErrorMsg, QString *outErrorCodeString)
{
    QString errorMessageText = AdHelper::errorMessage(hr);
    return extendedAuthenticationError(errorMessageText, outExtendedCode, outErrorMsg, outErrorCodeString);
}

bool ActiveDirectoryApi::extendedAuthenticationError(const QString& errorMessageText, int *outExtendedCode, QString *outErrorMsg, QString *outErrorCodeString)
{
    *outExtendedCode = 0;
    *outErrorMsg = "";

    bool ret = false;
    QRegExp securityErrorRx("AcceptSecurityContext error, data ([0-9A-Fa-f]+),");
    securityErrorRx.setMinimal(true);
    if (securityErrorRx.indexIn(errorMessageText) != -1) {
        QString msg;
        QString errorHexCode = securityErrorRx.cap(1);
        bool ok;
        int error = errorHexCode.toInt(&ok, 16);
        if (ok) {
            // http://ldapwiki.willeke.com/wiki/Common%20Active%20Directory%20Bind%20Errors
            switch (error) {
            case 0x525:
                msg = "User does not exist";
                if (outErrorCodeString) {
                    *outErrorCodeString = "user-not-found";
                }
                break;
            case AD_AUTH_ERR_INVALID_PASSWORD:
                msg = "Invalid password";
                if (outErrorCodeString) {
                    *outErrorCodeString = "invalid-password";
                }
                break;
            case 0x52f:
                msg = "Account restrictions are preventing signing in";
                if (outErrorCodeString) {
                    *outErrorCodeString = "account-restrictions";
                }
                break;
            case 0x530:
                msg = "Logon time restriction violation";
                if (outErrorCodeString) {
                    *outErrorCodeString = "time-restrictions";
                }
                break;
            case 0x531:
                msg = "Not allowed to log on to this computer";
                if (outErrorCodeString) {
                    *outErrorCodeString = "computer-restrictions";
                }
                break;
            case AD_AUTH_ERR_PASSWORD_EXPIRED:
                msg = "Password has expired";
                if (outErrorCodeString) {
                    *outErrorCodeString = "password-expired";
                }
                break;
            case 0x533:
                msg = "Account is disabled";
                if (outErrorCodeString) {
                    *outErrorCodeString = "account-disabled";
                }
                break;
            case 0x568:
                msg = "During a logon attempt, the user security context accumulated too many security IDs";
                if (outErrorCodeString) {
                    *outErrorCodeString = "too-many-security-ids";
                }
                break;
            case 0x701:
                msg = "Account has expired";
                if (outErrorCodeString) {
                    *outErrorCodeString = "account-expired";
                }
                break;
            case AD_AUTH_ERR_PASSWORD_NOT_SET:
                msg = "User password must be changed before logging on LDAP";
                if (outErrorCodeString) {
                    *outErrorCodeString = "password-must-change";
                }
                break;
            case 0x775:
                msg = "Account is locked out";
                if (outErrorCodeString) {
                    *outErrorCodeString = "account-locked";
                }
                break;
            default:
                msg = "Active Directory error: " + QString::number(error);
                if (outErrorCodeString) {
                    *outErrorCodeString = "ad-error " + QString::number(error);
                }
                break;
            }
            if (!msg.isEmpty()) {
                QLOG_ERROR() << "Extended error" << error << "description:" << msg;
                if (outErrorMsg) {
                    *outErrorMsg = msg;
                }
            }
            if (outExtendedCode) {
                *outExtendedCode = error;
            }
            ret = true;
        } else {
            QLOG_ERROR() << "Cannot read AcceptSecurityContext error code, cannot parse hex number:" << errorHexCode << "text:" << errorMessageText;
        }
    } else {
        QLOG_ERROR() << "Cannot match AcceptSecurityContext error code regex:" << errorMessageText;
    }
    return ret;
}

bool ActiveDirectoryApi::extendedAuthenticationError(const QString &errorMessageText, ExtendedAuthenticationError *outError)
{
    outError->fullText = errorMessageText;
    return extendedAuthenticationError(errorMessageText, &outError->code, &outError->message, &outError->knownCodeName);
}

bool ActiveDirectoryApi::extendedAuthenticationError(long hr, ExtendedAuthenticationError *outError)
{
    QString errorMessageText = AdHelper::errorMessage(hr);
    return extendedAuthenticationError(errorMessageText, outError);
}

DWORD ActiveDirectoryApi::getLastError(QString *errorMessage, QString *providerName)
{
    DWORD dwLastError = 0;
    WCHAR szErrorBuf[MAX_PATH];
    WCHAR szNameBuf[MAX_PATH];

    // Get extended error value.
    HRESULT hr = ADsGetLastError(&dwLastError, szErrorBuf, sizeof szErrorBuf, szNameBuf, sizeof szNameBuf);
    if (SUCCEEDED(hr)) {
        if (errorMessage) {
            *errorMessage = QString::fromWCharArray(szErrorBuf, wcslen(szErrorBuf));
        }
        if (providerName) {
            *providerName = QString::fromWCharArray(szNameBuf, wcslen(szNameBuf));
        }
        m_lastErrorMessage = QString::fromWCharArray(szErrorBuf, wcslen(szErrorBuf));
    } else {
        if (errorMessage) {
            errorMessage->clear();
        }
        if (providerName) {
            providerName->clear();
        }
        m_lastErrorMessage = "";
    }
    m_lastErrorCode = dwLastError;
    return dwLastError;
}

void ActiveDirectoryApi::storeLastError(DWORD hr)
{
    m_lastErrorCode = hr;
    m_lastErrorMessage = AdHelper::errorMessage(hr);
}

void ActiveDirectoryApi::logLastError(const QString &message)
{
    QString errorMessage, providerName;
    DWORD error = getLastError(&errorMessage, &providerName);
    QLOG_ERROR() << message << "error:" << error << ":" << errorMessage << "provider:" << providerName;
}

QString AdUser::firstNameOrFakeIt() const
{
    if (firstName().isEmpty()) {
        if (userPrincipalName.contains("@")) {
            return userPrincipalName.left(userPrincipalName.indexOf("@"));
        } else {
            return "No_Names_in_AD";
        }
    } else {
        return firstName();
    }
}

QString AdUser::lastNameOrFakeIt() const
{
    if (lastName().isEmpty()) {
        if (userPrincipalName.contains("@")) {
            return userPrincipalName.mid(userPrincipalName.indexOf("@") + 1);
        } else if (!objectGuid.isEmpty()) {
            return objectGuid;
        } else {
            return "Please_Fix";
        }
    } else {
        return lastName();
    }
}

QString AdUser::toString() const
{
    return "logon: " + userPrincipalName + ", first name: " + givenName + ", last name: " + sn + ", e-mail: " + mail;
}

void AdUser::debugPrint() const
{
    AdEntity::debugPrint();
    qDebug() << "givenName:" << givenName;
    qDebug() << "middleName:" << middleName;
    qDebug() << "sn:" << sn;
    qDebug() << "displayName:" << displayName;
    qDebug() << "mail:" << mail;
    qDebug() << "telephoneNumber:" << telephoneNumber;
    qDebug() << "mobile:" << mobile;
    qDebug() << "title:" << title;
    qDebug() << "userPrincipalName:" << userPrincipalName;
    qDebug() << "password:" << password;
    qDebug() << "userAccountControl:         0x" << QString::number(userAccountControl, 16);
    qDebug() << "userAccountControlComputed: 0x" << QString::number(userAccountControlComputed, 16);
    qDebug() << "pwdLastSet:" << pwdLastSet;
    qDebug() << "isDisabled:" << isDisabled();
    qDebug() << "isLocked:" << isLocked();
    qDebug() << "isPasswordExpired:" << isPasswordExpired();
    qDebug() << "employeeNumber:" << employeeNumber;
    qDebug() << "organization:" << organization;
    qDebug() << "department:" << department;
    qDebug() << "division:" << division;
    qDebug() << "avatar size:" << avatar.size();
    qDebug() << " ";
}

QString DbGroup::displayName() const
{
    return extractTopLevelCn(cn);
}

void DbGroup::debugPrint() const
{
    AdEntity::debugPrint();
    qDebug() << "members:" << members;
    qDebug() << " ";
}

bool AdUser::isDisabled() const
{
    return (userAccountControl & ADS_UF_ACCOUNTDISABLE) == ADS_UF_ACCOUNTDISABLE;
}

bool AdUser::isLocked() const
{
    return (userAccountControlComputed & ADS_UF_LOCKOUT) == ADS_UF_LOCKOUT;
}

bool AdUser::isPasswordExpired() const
{
    return (userAccountControlComputed & ADS_UF_PASSWORD_EXPIRED) == ADS_UF_PASSWORD_EXPIRED;
}

bool AdUser::isPasswordCannotChange() const
{
    return (userAccountControl & ADS_UF_PASSWD_CANT_CHANGE) == ADS_UF_PASSWD_CANT_CHANGE;
}

bool AdUser::isPasswordChanged() const
{
    return (userAccountControl & ADS_UF_QLIQ_PASSWORD_CHANGED) == ADS_UF_QLIQ_PASSWORD_CHANGED;
}

void AdUser::setPasswordChangedFlag(bool on)
{
    if (on) {
        userAccountControl |= ADS_UF_QLIQ_PASSWORD_CHANGED;
    } else {
        userAccountControl &= ~ADS_UF_QLIQ_PASSWORD_CHANGED;
    }
}

QString AdEntity::extractTopLevelCn(const QString &path)
{
    static QRegExp rx;
    if (rx.isEmpty()) {
        rx.setPattern("CN=(.+),");
        rx.setMinimal(true);
    }
    if (rx.exactMatch(path)) {
        return rx.cap(1);
    } else {
        return path;
    }
}

bool AdEntity::isEqual(const AdEntity &o) const
{
    return objectGuid == o.objectGuid && distinguishedName == o.distinguishedName && cn == o.cn &&
           accountName == o.accountName && isDeleted == o.isDeleted;
}

void AdEntity::debugPrint() const
{
    qDebug() << "objectGuid:" << objectGuid;
    qDebug() << "distinguishedName:" << distinguishedName;
    qDebug() << "cn:" << cn;
    qDebug() << "accountName:" << accountName;
    qDebug() << "objectClasses:" << objectClasses;
    qDebug() << "memberOf:" << memberOf;
    qDebug() << "uSNChanged:" << uSNChanged;
    qDebug() << "isDeleted:" << isDeleted;
}


bool AdGroup::isEqual(const AdGroup &o) const
{
    return objectGuid == o.objectGuid && cn == o.cn && isDeleted == o.isDeleted;
}

/*
QVariantMap ActiveDirectoryForest::toMap() const
{
    QVariantMap map;
    map["objectGuid"] = objectGuid;
    map["userName"] = userName;
    map["password"] = password;
    map["syncGroup"] = syncGroup;
    return map;
}

ActiveDirectoryForest ActiveDirectoryForest::fromMap(const QVariantMap& map)
{
    ActiveDirectoryForest forest;
    forest.objectGuid = map.value("objectGuid").toString();
    if (forest.objectGuid.isEmpty()) {
        forest.objectGuid = core::Metadata::generateUuid();
    }
    forest.userName = map.value("userName").toString();
    forest.password = map.value("password").toString();
    forest.syncGroup = map.value("syncGroup").toString();
    return forest;
}
*/
