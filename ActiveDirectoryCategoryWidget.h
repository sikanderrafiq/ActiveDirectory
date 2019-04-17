#ifndef ACTIVEDIRECTORYCATEGORYWIDGET_H
#define ACTIVEDIRECTORYCATEGORYWIDGET_H
#include <QStackedWidget>
#include "qliqdirect/manager/QliqDirectCategoryController.h"

class QStringListModel;
class QModelIndex;
class QTableWidget;

class AdConfig;
class AdAuthTestWidget;
class AdResumeAnomalyDialog;
class ActiveDirectoryApi;
class ForestDialog;
namespace ActiveDirectory {
struct Forest;
}
namespace Ui {
class ActiveDirectoryCategoryWidget;
}

class ActiveDirectoryCategoryWidget : public QStackedWidget, public QliqDirectCategoryController
{
    Q_OBJECT
public:
    explicit ActiveDirectoryCategoryWidget(QWidget *parent = 0);
    ~ActiveDirectoryCategoryWidget() override;

    // CategoryWidget interface
    QString categoryName() const override;
    QList<QWidget *> pages() const override;
    bool savePage(QWidget *page, const OriginalStateMap& originalStateMap) override;
    void onPageChanged(QWidget *previousPage, QWidget *currentPage) override;
    QWidget *permanentTopWidget() const override;
    bool isPermanentTopWidgetVisible() const override;

    // Optional low level state methods because we keep state of adForestConfigurationTableWidget
    // outside of it in instance variable
    QSet<QWidget *> ignoredWidgets(QWidget *page) const override;
    void saveOriginalStateForPage(QWidget *page, OriginalStateMap& originalStateMap) override;
    void restoreSavedPageState(QWidget *page, const OriginalStateMap& originalStateMap) override;

    void setRpc(QxtRPCPeer *rpc) override;
    void onConnectedToService(QliqServiceType serviceType) override;
    void onDisconnectedFromService(QliqServiceType serviceType) override;
    void onReadConfigFile(QliqDirectConfigFile& configFile) override;

private slots:
    // UI
    void onAdEnabledChecked(bool checked);
    void onAdResetSyncDatabaseClicked();
    void onDeltaSyncClicked();
    void onAdAutoAcceptNewUsersChecked(bool checked);
    void onAdEnabledAuthToggled(bool checked);
    void onAdAuthTestToolClicked();
    void onAdAnomalyResumeClicked();
    void onAdEnableAnomalyDetectionCheckBoxChecked(bool checked);
    void onAddNewForestConfigButtonClicked();

    void onTestCredentialsClicked(const ActiveDirectory::Forest& forest);
    void onTestMainGroup(const ActiveDirectory::Forest& forest);
    // Forest table context menu
    void onTestForestCredentialsTriggered();
    void onTestForestSyncGroupTriggered();
    void onEditForestTriggered();
    void onDeleteForestTriggered();

    // RPC
    void onGotAdStatus(const QString& json);
    void onAdTestAdminCredentialsResponse(bool success, const QString& error);
    void onAdResetSyncDatabaseResponse(bool success, const QString& error);
    void reloadAdConfig(QliqDirectConfigFile& configFile);
    void onRpcReloadAdConfigResponse(bool error, const QString& errorMessage);
    void onSyncStatusTimedOut();

private:
    enum class Column {
        Guid,
        PrimaryDomainController,
        AdditionalDomainControllers,
        Username,
        Password,
        SyncGroup,
        ColumnCount
    };

    void setApiKeyUiVisible(bool visible);
    void setAdAnomalyMode(bool on);
    void resetTestAdButtons();
    bool validateAdConfigFromUi(AdConfig *out, bool showMessageBox = true);
    bool validateForests(bool showMessageBox);

    void uiToAdConfig(AdConfig *out);
    void initForestConfigurationTable();

    void setForests(const QVector<ActiveDirectory::Forest>& forests);
    void connectForestDialog(ForestDialog *dialog);
    void setForestForTableRow(const ActiveDirectory::Forest& forest, int row);
    bool validateTableCurrentRow(int *row);
    void addOrUpdateForestInTable(const ActiveDirectory::Forest& forest, int row = -1);

    Ui::ActiveDirectoryCategoryWidget *ui;
    AdAuthTestWidget *m_adAuthTestWidget;
    AdResumeAnomalyDialog *m_adResumeAnomalyDialog;
    QTimer *m_rpcAdStatusTimer;
    AdConfig *m_adConfig;
    QWeakPointer<ForestDialog> m_forestDialog;
    QVector<ActiveDirectory::Forest> m_forests;
};

#endif // ACTIVEDIRECTORYCATEGORYWIDGET_H
