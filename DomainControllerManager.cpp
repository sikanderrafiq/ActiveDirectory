#include "DomainControllerManager.h"
#include <QString>
#include <QMessageBox>
#include <QDebug>
#include <iads.h>
#include <wtypes.h>
#include <Winsock2.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <ntdsapi.h>
#include <windows.h>
#include <Lm.h>


DomainControllerManager::DomainControllerManager()
{
}

inline const WCHAR *q2cwstr(const QString& str)
{
    return reinterpret_cast<const WCHAR *>(str.utf16());
}


void DomainControllerManager::openDC()
{
    IADsOpenDSObject *pDSO = NULL;
    HRESULT hr = S_OK;

    hr = ADsGetObject(L"LDAP:", IID_IADsOpenDSObject, (void**) &pDSO);
    if (SUCCEEDED(hr))
    {
        IDispatch *pDisp;
        hr = pDSO->OpenDSObject(OLESTR("LDAP://DC=qliqsoft2, DC=com"),
                           OLESTR("D2User1@qliqsoft2.com"),
                           OLESTR("ActiveDir1"),
                           ADS_SECURE_AUTHENTICATION,
                           &pDisp);
        pDSO->Release();
        if (SUCCEEDED(hr))
        {
            IADs *pADs;
            hr = pDisp->QueryInterface(IID_IADs, (void**) &pADs);
            pDisp->Release();
            if (SUCCEEDED(hr))
            {
            // Perform an object manipulation here.
                pADs->Release();
            }
        }
    }

}

void DomainControllerManager::openDCEnumeration()
{
    DWORD dwRet;
    PDOMAIN_CONTROLLER_INFO pdcInfo;

    LPCSTR server1 = "s132-148-245-214.secureserver.net";
    LPCSTR server2 = "s132-148-241-147.secureserver.net";
    LPCSTR domainName  = "qliqsoft.com";
    LPCSTR domainName2 = "qliqsoft2.com";

    //dwRet = DsGetDcName(computerName, domainName, NULL, NULL, 0, &pdcInfo);
    dwRet = DsGetDcName(server2, domainName2, NULL, NULL, DS_PDC_REQUIRED, &pdcInfo);
    if (NO_ERROR == dwRet) {
        //LPSTR
        QString domainNam2 = pdcInfo->DomainName;
        int iii=0;
    } else if (dwRet == ERROR_ACCESS_DENIED) {
        int iii=0;
    }

    // Free the DOMAIN_CONTROLLER_INFO structure.
    NetApiBufferFree(pdcInfo);

    // Open the enumeration.
    HANDLE hGetDc;
    dwRet = DsGetDcOpen(domainName2,
                        DS_NOTIFY_AFTER_SITE_RECORDS,
                        NULL,
                        NULL,
                        NULL,
                        0,
                        &hGetDc);

    if (ERROR_SUCCESS == dwRet) {
        LPTSTR pszDnsHostName;

        /*
        Enumerate each domain controller
        */
        while(TRUE)
        {
            ULONG ulSocketCount;
            LPSOCKET_ADDRESS rgSocketAddresses;

            dwRet = DsGetDcNext(
                hGetDc,
                &ulSocketCount,
                &rgSocketAddresses,
                &pszDnsHostName);

            if (ERROR_SUCCESS == dwRet) {
                qDebug() << "pszDnsHostName: "<<pszDnsHostName;

                // Free the allocated string.
                NetApiBufferFree(pszDnsHostName);

                // Free the socket address array.
                LocalFree(rgSocketAddresses);
            }
            else if (ERROR_NO_MORE_ITEMS == dwRet) {
                qDebug() << "The end of the list has been reached.";
                break;
            } else if (ERROR_FILEMARK_DETECTED == dwRet) {
                /*
                DS_NOTIFY_AFTER_SITE_RECORDS was specified in
                DsGetDcOpen and the end of the site-specific
                records was reached.
                */
                qDebug() << "End of site-specific domain controllers\n";
                continue;
            } else {
                // Some other error occurred.
                break;
            }
        }

        // Close the enumeration.
        DsGetDcCloseW(hGetDc);
    }

    int iiii=0;
}

