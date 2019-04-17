#ifndef ADSIP_H
#define ADSIP_H
#include <QObject>
#include <QVariantMap>
#include "AdConfig.h"
#include "ActiveDirectoryEvent.h"

class QSqlDatabase;

class ActiveDirectoryApi;
class QliqSip;
namespace ActiveDirectory {
    struct ExtendedAuthenticationError;
}

class AdSip : public QObject
{
    Q_OBJECT
public:
    explicit AdSip(QObject *parent = 0);
    ~AdSip();

    void setSip(QliqSip *sip);
    QliqSip *sip() const;
    void setActiveDirectory(ActiveDirectoryApi *ad);
    void setConfig(const AdConfig& config);
    void setEnabled(bool on) {m_enabled = on;}

    static bool isAuthorizationRequest(const QString& command);

signals:

public slots:

private slots:
    void onSipMessageReceived(const QString& to, const QString& from, const QVariantMap& message, const QVariantMap& extraHeaders);

private:
    bool processAuthRequestOrTestCredentials(const QVariantMap& message, bool isTestCredentials,
                                             ActiveDirectory::Credentials *credentials, int *res,
                                             ActiveDirectory::ExtendedAuthenticationError *extendedError);

    QliqSip *m_sip;
    ActiveDirectoryApi *m_ad;
    bool m_enabled;
    AdConfig m_adConfig;
};

#endif // ADSIP_H
