#include "ActiveDirectoryCategoryWidget.h"
#include <QMovie>
#include <QTimer>
#include <QMessageBox>
#include <QProgressBar>
#include <QStringListModel>
#include <QMenu>
#include <QModelIndex>
#include <QVariant>
#include <QxtRPCPeer>
#include "QsLog.h"
#include "json/qt-json/qtjson.h"
#include "qliqdirect/RpcConstants.h"
#include "qliqdirect/shared/config/QliqDirectConfigFile.h"
#include "qliqdirect/manager/AdAuthTestWidget.h"
#include "qliqdirect/manager/AdSearchFilterTestWidget.h"
#include "qliqdirect/manager/AdResumeAnomalyDialog.h"
#include "qliqdirect/service/ad/ActiveDirectoryEvent.h"
#include "qliqdirect/service/ad/AdConfig.h"
#include "json/qt-json/qtjson.h"
#include "qliqdirect/shared/ActiveDirectoryDataTypes.h"
#include "ForestDialog.h"
#include "ui_ActiveDirectoryCategoryWidget.h"

#define AD_TIMER_SHORT_INTERVAL 1000
#define AD_TIMER_LONG_INTERVAL (1000 * 60)
#define SETTINGS_ACTIVE_DIRECTORY_GROUP "activeDirectory"
#define MINIMUM_COLUMN_WIDTH 150

using namespace ActiveDirectory;

ActiveDirectoryCategoryWidget::ActiveDirectoryCategoryWidget(QWidget *parent) :
    QStackedWidget(parent),
    ui(new Ui::ActiveDirectoryCategoryWidget),
    m_adAuthTestWidget(nullptr),
    m_adResumeAnomalyDialog(nullptr),
    m_rpcAdStatusTimer(nullptr),
    m_adConfig(new AdConfig())
{
    ui->setupUi(this);
    ui->adAnomalyFrame->setVisible(false);
#ifdef QT_NO_DEBUG
    ui->deltaSyncButton->setVisible(false);
#endif
    setApiKeyUiVisible(false);
    setAdAnomalyMode(false);

    QMovie *movie = new QMovie(this);
    movie->setFileName(":/gfx/ajax-loader.gif");
    movie->start();
    ui->adTestProgressIndicatorLabel->setMovie(movie);
    ui->adTestProgressIndicatorLabel->hide();

    QMovie *movie2 = new QMovie(this);
    movie2->setFileName(":/gfx/utils/spinner-16.gif");
    ui->adProgressIconLabel->setMovie(movie2);
    movie2->start();
    ui->adProgressIconLabel->hide();
    ui->adProgressTextLabel->setText("");
    ui->adProgressTextLabel->hide();

    connect(ui->enableActiveDirectoryCheckBox, SIGNAL(clicked(bool)), SLOT(onAdEnabledChecked(bool)));
    connect(ui->adResetLocalSyncDbButton, SIGNAL(clicked()), SLOT(onAdResetSyncDatabaseClicked()));
    connect(ui->deltaSyncButton, SIGNAL(clicked()), SLOT(onDeltaSyncClicked()));
    connect(ui->adAutoAcceptNewUsersCheckBox, SIGNAL(toggled(bool)), SLOT(onAdAutoAcceptNewUsersChecked(bool)));
    connect(ui->adEnableAuthCheckBox, SIGNAL(toggled(bool)), SLOT(onAdEnabledAuthToggled(bool)));
    connect(ui->adAuthTestButton, SIGNAL(clicked(bool)), SLOT(onAdAuthTestToolClicked()));
    connect(ui->adAnomalyResumeButton, SIGNAL(clicked(bool)), SLOT(onAdAnomalyResumeClicked()));
    connect(ui->adEnableAnomalyDetectionCheckBox, SIGNAL(toggled(bool)), SLOT(onAdEnableAnomalyDetectionCheckBoxChecked(bool)));
    connect(ui->adAddNewForestConfigButton, SIGNAL(clicked(bool)), SLOT(onAddNewForestConfigButtonClicked()));

    initForestConfigurationTable();

    m_rpcAdStatusTimer = new QTimer(this);
    m_rpcAdStatusTimer->setSingleShot(false);
    m_rpcAdStatusTimer->setInterval(AD_TIMER_LONG_INTERVAL);
    connect(m_rpcAdStatusTimer, SIGNAL(timeout()), this, SLOT(onSyncStatusTimedOut()));
    m_rpcAdStatusTimer->start();
}

ActiveDirectoryCategoryWidget::~ActiveDirectoryCategoryWidget()
{
    delete m_adAuthTestWidget;
    delete ui;
}

void ActiveDirectoryCategoryWidget::initForestConfigurationTable()
{
    ui->adForestConfigurationTableWidget->addGearHeaderColumn();

    // Hide 'Additional Controllers', 'Username' and 'Password' columns
#ifdef QT_NO_DEBUG
    ui->adForestConfigurationTableWidget->setColumnHidden(static_cast<int>(Column::Guid), true);
    ui->adForestConfigurationTableWidget->setColumnHidden(static_cast<int>(Column::AdditionalDomainControllers), true);
    ui->adForestConfigurationTableWidget->setColumnHidden(static_cast<int>(Column::Username), true);
    ui->adForestConfigurationTableWidget->setColumnHidden(static_cast<int>(Column::Password), true);
    ui->adForestConfigurationTableWidget->setStrechColumn(static_cast<int>(Column::SyncGroup));
#endif

    QFont font = ui->adForestConfigurationTableWidget->font();
    QFontMetrics fm(font);
    int textWidth = fm.width(" Primary Domain Controller ");
    ui->adForestConfigurationTableWidget->setColumnWidth(0, textWidth);

    QMenu *menu = new QMenu(ui->adForestConfigurationTableWidget);
    menu->addAction("Test Credentials", this, SLOT(onTestForestCredentialsTriggered()));
    menu->addAction("Test Sync Group", this, SLOT(onTestForestSyncGroupTriggered()));
    menu->addAction("Edit", this, SLOT(onEditForestTriggered()));
    menu->addAction("Delete", this, SLOT(onDeleteForestTriggered()));
    ui->adForestConfigurationTableWidget->setMenu(menu);
}

void ActiveDirectoryCategoryWidget::setForests(const QVector<Forest> &forests)
{
    m_forests = forests;
    ui->adForestConfigurationTableWidget->clearContents();
    ui->adForestConfigurationTableWidget->setRowCount(0);
    for (int i = 0; i < m_forests.size(); ++i) {
        const auto forest = m_forests[i];
        ui->adForestConfigurationTableWidget->appendRow();
        setForestForTableRow(forest, i);
    }
}

QString ActiveDirectoryCategoryWidget::categoryName() const
{
    return "Active Directory Integration";
}

QList<QWidget *> ActiveDirectoryCategoryWidget::pages() const
{
    ui->adBasicTab->setWindowTitle("Basic Settings");
    ui->adAdvancedTab->setWindowTitle("Advanced Settings");
    ui->adEventLogWidget->setWindowTitle("Event Log");

    return QList<QWidget *>()
            << ui->adBasicTab
            << ui->adAdvancedTab
            << ui->adEventLogWidget;
}

bool ActiveDirectoryCategoryWidget::savePage(QWidget *page, const OriginalStateMap &)
{
    bool ret = true;
    if (page == ui->adBasicTab || page == ui->adAdvancedTab) {
        AdConfig newConfig;
        if (validateAdConfigFromUi(&newConfig)) {
            *m_adConfig = newConfig;
            QLOG_SUPPORT() << "Saving new config:" << newConfig.toString();
            {
                QliqDirectConfigFile configFile;
                configFile.setGroupValues(SETTINGS_ACTIVE_DIRECTORY_GROUP, newConfig.toMap());
            }
            if (checkConnectedAndShowWarning(this)) {
                setLongSaveStarted();
                m_rpc->call(RPC_ACTIVE_DIRECTORY_RELOAD_CONFIG);
            }
        } else {
            if (page == ui->adAdvancedTab) {
                QMessageBox::warning(this, "QliqDIRECT Manager", "Please enter a valid configuration in the <b>Basic Settings</b> category first");
            }
            ret = false;
        }
    }
    return ret;
}

void ActiveDirectoryCategoryWidget::onPageChanged(QWidget *previousPage, QWidget *currentPage)
{
    Q_UNUSED(previousPage)
    ui->enableActiveDirectoryCheckBox->setVisible(currentPage != ui->adEventLogWidget);

    if (currentPage == ui->adEventLogWidget) {
        if (!ui->adEventLogWidget->isInProgress()) {
            ui->adEventLogWidget->refresh();
        }
    } else {
//        if (currentPage->layout()->indexOf(ui->enableActiveDirectoryCheckBox) == -1) {
//            QVBoxLayout *layout = dynamic_cast<QVBoxLayout *>(currentPage->layout());
//            if (layout) {
//                layout->insertWidget(0, ui->enableActiveDirectoryCheckBox);
//            }
//        }
    }
}

QWidget *ActiveDirectoryCategoryWidget::permanentTopWidget() const
{
    return ui->permanentTopPage;
}

bool ActiveDirectoryCategoryWidget::isPermanentTopWidgetVisible() const
{
    return true;
}

QSet<QWidget *> ActiveDirectoryCategoryWidget::ignoredWidgets(QWidget *page) const
{
    return QSet<QWidget *>() << ui->adForestConfigurationTableWidget;
}

void ActiveDirectoryCategoryWidget::saveOriginalStateForPage(QWidget *page, OriginalStateMap &originalStateMap)
{
    if (page == ui->adBasicTab) {
        originalStateMap[ui->adForestConfigurationTableWidget] = Forest::toList(m_forests);
    }
}

void ActiveDirectoryCategoryWidget::restoreSavedPageState(QWidget *page, const OriginalStateMap &originalStateMap)
{
    if (page == ui->adBasicTab) {
        QVector<Forest> forests = Forest::fromList(originalStateMap.QMap<QWidget *, QVariant>::value(ui->adForestConfigurationTableWidget).toList());
        setForests(forests);
    }
}

void ActiveDirectoryCategoryWidget::setRpc(QxtRPCPeer *rpc)
{
    RpcCategoryController::setRpc(rpc);
    ui->adEventLogWidget->setRpc(rpc);

    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_RELOAD_CONFIG_RESPONSE, this, SLOT(onRpcReloadAdConfigResponse(bool,QString)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_TEST_ADMIN_CREDENTIALS_RESPONSE, this, SLOT(onAdTestAdminCredentialsResponse(bool,QString)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_RESET_LOCAL_DATABASE_RESPONSE, this, SLOT(onAdResetSyncDatabaseResponse(bool,QString)));
    rpc->attachSlot(RPC_ACTIVE_DIRECTORY_GET_SYNC_STATUS_RESPONSE, this, SLOT(onGotAdStatus(QString)));
}

void ActiveDirectoryCategoryWidget::onConnectedToService(QliqServiceType serviceType)
{
    RpcCategoryController::onConnectedToService(serviceType);

    if (serviceType == QliqServiceType::QliqDirect) {
        resetTestAdButtons();

        m_rpc->call(RPC_ACTIVE_DIRECTORY_GET_SYNC_STATUS);

        if (isActiveCategory()) {
            if (m_rpcAdStatusTimer) {
                // We start app with LONG_INTERVAL if connected while already on AD tab then let's make the status more realtime
                m_rpcAdStatusTimer->setInterval(AD_TIMER_SHORT_INTERVAL);
            }
        }
    }
}

void ActiveDirectoryCategoryWidget::onDisconnectedFromService(QliqServiceType serviceType)
{
    RpcCategoryController::onDisconnectedFromService(serviceType);

    resetTestAdButtons();
    ui->adEventLogWidget->onDisconnectedFromServer();
}

void ActiveDirectoryCategoryWidget::onReadConfigFile(QliqDirectConfigFile &configFile)
{
    reloadAdConfig(configFile);
}

void ActiveDirectoryCategoryWidget::onAdEnabledChecked(bool checked)
{
    //setPageDirty(m_currentPage, true);
}

void ActiveDirectoryCategoryWidget::onAdResetSyncDatabaseClicked()
{
    if (!checkConnectedAndShowWarning(this)) {
        return;
    }
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("qliqDirect");
    msgBox.setText("Do you want to reset the local sync database too?");
    QPushButton *noButton = msgBox.addButton("Sync only", QMessageBox::NoRole);
    QPushButton *resetButton = msgBox.addButton("Reset database", QMessageBox::YesRole);
    msgBox.exec();
    if (msgBox.clickedButton() == resetButton) {
        QLOG_SUPPORT() << "Reset local database triggered by user";
        m_rpc->call(RPC_ACTIVE_DIRECTORY_RESET_LOCAL_DATABASE);
    }
    QLOG_SUPPORT() << "Force full sync triggered by user";
    const bool full = true;
    const bool isResume = false;
    m_rpc->call(RPC_ACTIVE_DIRECTORY_FORCE_SYNC, isResume, full);
}

void ActiveDirectoryCategoryWidget::onDeltaSyncClicked()
{
    if (!checkConnectedAndShowWarning(this)) {
        return;
    }
    QLOG_SUPPORT() << "Delta sync triggered by user";
    const bool full = false;
    const bool isResume = false;
    m_rpc->call(RPC_ACTIVE_DIRECTORY_FORCE_SYNC, isResume, full);
}

void ActiveDirectoryCategoryWidget::onAdAutoAcceptNewUsersChecked(bool checked)
{
    ui->adInvitationSubjectLineEdit->setEnabled(checked);
}

void ActiveDirectoryCategoryWidget::onAdEnabledAuthToggled(bool checked)
{
    ui->adAuthSettingsWidget->setEnabled(checked);
}

void ActiveDirectoryCategoryWidget::onAdAuthTestToolClicked()
{
    if (!m_adAuthTestWidget) {
        m_adAuthTestWidget = new AdAuthTestWidget();
    }
    m_adAuthTestWidget->showNormal();
}

void ActiveDirectoryCategoryWidget::onAdAnomalyResumeClicked()
{
    AdConfig adConfig;
    if (validateAdConfigFromUi(&adConfig) && checkConnectedAndShowWarning(this)) {
        QLOG_SUPPORT() << "Anomaly resolution: resume clicked";
        const bool full = true;
        const bool isResume = true;
        m_rpc->call(RPC_ACTIVE_DIRECTORY_FORCE_SYNC, isResume, full);

        if (!m_adResumeAnomalyDialog) {
            m_adResumeAnomalyDialog = new AdResumeAnomalyDialog(this);
            m_adResumeAnomalyDialog->setWindowModality(Qt::WindowModal);
            if (m_adResumeAnomalyDialog->exec() == QDialog::Accepted) {
                QLOG_SUPPORT() << "Anomaly resolution: ignore and sync request by user";
                m_rpc->call(RPC_ACTIVE_DIRECTORY_DO_CLEAR_ANOMALY_FLAG);
            } else {
                QLOG_SUPPORT() << "Anomaly resolution cancelled by user";
            }
            delete m_adResumeAnomalyDialog;
            m_adResumeAnomalyDialog = nullptr;
        }
    }
}

void ActiveDirectoryCategoryWidget::onAdEnableAnomalyDetectionCheckBoxChecked(bool checked)
{
    ui->adEnableAnomalyDetectionContainer->setEnabled(checked);
}

void ActiveDirectoryCategoryWidget::onGotAdStatus(const QString &json)
{
    QString progressText;
    QVariantMap map = Json::parse(json).toMap();
    if (map.value("isWebPushInProgress").toBool()) {
        ActiveDirectoryProgressAndStatus progress = ActiveDirectoryProgressAndStatus::fromMap(map.value("webPushProgress").toMap());
        progressText = progress.text;
    }

    if (map.value("isAdSyncInProgress").toBool()) {
        ActiveDirectoryProgressAndStatus progress = ActiveDirectoryProgressAndStatus::fromMap(map.value("adSyncProgress").toMap());
        progressText = progress.text;
    }

    if (progressText.isEmpty()) {
        ui->adProgressIconLabel->hide();
        ui->adProgressTextLabel->hide();
    } else {
        ui->adProgressIconLabel->show();
        ui->adProgressTextLabel->show();
        ui->adProgressTextLabel->setText(progressText);
    }

    bool isAnomalyDetected = map.value("isAnomalyDetected").toBool();
    if (isAnomalyDetected) {
        ui->adAnomalyTextLabel->setText(map.value("anomalyMessage").toString());
    }

    if (m_adResumeAnomalyDialog) {
        ActiveDirectoryProgressAndStatus progress = ActiveDirectoryProgressAndStatus::fromMap(map.value("adSyncProgress").toMap());
        m_adResumeAnomalyDialog->setText(progress.text);

        QProgressBar *progressBar = m_adResumeAnomalyDialog->progressBar();
        progressBar->setVisible(progress.maximum > -1);
        progressBar->setMaximum(qMax(0, progress.maximum));
        if (progress.maximum > 0) {
            progressBar->setValue(progress.value);
        } else {
            progressBar->setValue(0);
        }

        int anomalyNotPresentUserCount = map.value("anomalyNotPresentUserCount").toInt();
        int anomalyNotPresentGroupCount = map.value("anomalyNotPresentGroupCount").toInt();

        if (!isAnomalyDetected) {
            QLOG_SUPPORT() << "Anomaly resolution: anomaly no longer present";
            m_adResumeAnomalyDialog->reject();
        } else if (progress.maximum == -1) {
            QLOG_SUPPORT() << "Anomaly resolution: anomaly still present, missing user count:" << anomalyNotPresentUserCount << ", missing group count:" << anomalyNotPresentGroupCount;
            m_adResumeAnomalyDialog->setTitleText("The anomaly still presists");
            m_adResumeAnomalyDialog->setText("Not present user count: " + QString::number(anomalyNotPresentUserCount) +
                                             "\nNot present group count: " + QString::number(anomalyNotPresentGroupCount));
            m_adResumeAnomalyDialog->setButtonBoxVisible(true);
        }
    }
    setAdAnomalyMode(isAnomalyDetected);
}

void ActiveDirectoryCategoryWidget::onAdTestAdminCredentialsResponse(bool success, const QString &error)
{
    resetTestAdButtons();

    if (success) {
        QMessageBox::information(this, "Success", "The Active Directory credentials are valid");
    } else {
        QMessageBox msgBox(this);
        msgBox.setWindowTitle("Failure");
        msgBox.setText("Active Directory error: " + error);
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
    }
}

void ActiveDirectoryCategoryWidget::onAdResetSyncDatabaseResponse(bool success, const QString &error)
{
    if (success) {
        QMessageBox::information(this, "Success", "The Active Directory sync database was reset");
    } else {
        QMessageBox msgBox(this);
        msgBox.setWindowTitle("Failure");
        msgBox.setText("Cannot reset Active Directory sync database error: " + error);
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
    }
}

void ActiveDirectoryCategoryWidget::reloadAdConfig(QliqDirectConfigFile& configFile)
{
    AdConfig newConfig = AdConfig::loadFromConfigFile(configFile);
    newConfig.rewriteOldSingleServerAsForestToConfigFile();

    ui->enableActiveDirectoryCheckBox->setChecked(newConfig.isEnabled);

    ui->adApiKeyEdit->setText(newConfig.apiKey);
    ui->adSyncIntervalSpinBox->setValue(newConfig.syncIntervalMins);
    ui->adAutoAcceptNewUsersCheckBox->setChecked(newConfig.autoAcceptNewUsers);
    ui->adSyncSubgroupsCheckBox->setChecked(newConfig.enableSubgroups);
    ui->adChangePasswordUrlEdit->setText(newConfig.changePasswordUrl);
    ui->adForgotPasswordUrlEdit->setText(newConfig.forgotPasswordUrl);
    ui->adEnableAvatarsCheckBox->setChecked(newConfig.enableAvatars);
    // Because toggled slot is not called for some reason
    ui->adEnableAuthCheckBox->setChecked(newConfig.enableAuth);
    ui->adAuthSettingsWidget->setEnabled(ui->adEnableAuthCheckBox->isChecked());
    ui->adEnableDnAuthCheckBox->setChecked(newConfig.enableDistinguishedNameBaseAuth);
    ui->adInvitationSubjectLineEdit->setText(newConfig.invitationMessageSubject);
    ui->adEnableAnomalyDetectionCheckBox->setChecked(newConfig.enableAnomalyDetection);
    ui->adAnomalyDetectionPerscentSpinBox->setValue(newConfig.anomalyDetectionPercentThreshold);
    ui->adAnomalyDetectionMinimumCountSpinBox->setValue(newConfig.anomalyDetectionUserCountThreshold);
    *m_adConfig = newConfig;

    // Show API key UI elements only in case API key is missing in config
    setApiKeyUiVisible(newConfig.apiKey.isEmpty());

    setForests(newConfig.forests);
}

void ActiveDirectoryCategoryWidget::onRpcReloadAdConfigResponse(bool error, const QString &errorMessage)
{
    Q_UNUSED(error)

    setLongSaveFinished(errorMessage);
//    if (error) {
//        QMessageBox::warning(this, "Error", "Cannot save Active Directory settings:\n" + errorMessage);
//    } else {
//        QMessageBox::information(this, "Success", "Active Directory settings saved");
    //    }
}

void ActiveDirectoryCategoryWidget::onSyncStatusTimedOut()
{
    if (m_isRpcConnected) {
        if (m_adConfig->isEnabled) {
            m_rpc->call(RPC_ACTIVE_DIRECTORY_GET_SYNC_STATUS);
        }
    }
}

void ActiveDirectoryCategoryWidget::setApiKeyUiVisible(bool visible)
{
    ui->adApiKeyLabel->setVisible(visible);
    ui->adApiKeyEdit->setVisible(visible);
}

void ActiveDirectoryCategoryWidget::setAdAnomalyMode(bool on)
{
    if (ui->adAnomalyFrame->isVisible() != on) {
        QLOG_ERROR() << "Anomaly mode changed:" << on;
    }
    ui->adResetLocalSyncDbButton->setEnabled(!on);
    ui->adAnomalyFrame->setVisible(on);
}

void ActiveDirectoryCategoryWidget::resetTestAdButtons()
{
    if (m_forestDialog) {
        m_forestDialog.data()->resetTestAdButton();
    }
    ui->adTestProgressIndicatorLabel->hide();
}

bool ActiveDirectoryCategoryWidget::validateAdConfigFromUi(AdConfig *out, bool showMessageBox)
{
    AdConfig newConfig;
    newConfig.isEnabled = ui->enableActiveDirectoryCheckBox->isChecked();

    newConfig.apiKey = ui->adApiKeyEdit->text().trimmed();
    newConfig.webServerAddress = m_adConfig->webServerAddress;
    newConfig.syncIntervalMins = ui->adSyncIntervalSpinBox->value();
    newConfig.autoAcceptNewUsers = ui->adAutoAcceptNewUsersCheckBox->isChecked();
    newConfig.enableSubgroups = ui->adSyncSubgroupsCheckBox->isChecked();
    newConfig.changePasswordUrl = ui->adChangePasswordUrlEdit->text().trimmed();
    newConfig.forgotPasswordUrl = ui->adForgotPasswordUrlEdit->text().trimmed();
    newConfig.enableAvatars = ui->adEnableAvatarsCheckBox->isChecked();
    newConfig.enableAuth = ui->adEnableAuthCheckBox->isChecked();
    newConfig.enableDistinguishedNameBaseAuth = ui->adEnableDnAuthCheckBox->isChecked();
    newConfig.invitationMessageSubject = ui->adInvitationSubjectLineEdit->text().trimmed();
    newConfig.enableAnomalyDetection = ui->adEnableAnomalyDetectionCheckBox->isChecked();
    newConfig.anomalyDetectionPercentThreshold = ui->adAnomalyDetectionPerscentSpinBox->value();
    newConfig.anomalyDetectionUserCountThreshold = ui->adAnomalyDetectionMinimumCountSpinBox->value();

    if (newConfig.isEnabled) {
        if (!validateForests(showMessageBox)) {
            return false;
        }
        newConfig.forests = m_forests;

        if (newConfig.apiKey.isEmpty()) {
            if (showMessageBox) {
                QMessageBox::warning(this, "Error", "API key cannot be empty");
            }
            return false;
        }
    }
    *out = newConfig;
    return true;
}

void ActiveDirectoryCategoryWidget::uiToAdConfig(AdConfig *out)
{
    AdConfig newConfig;
    newConfig.isEnabled = ui->enableActiveDirectoryCheckBox->isChecked();

    newConfig.apiKey = ui->adApiKeyEdit->text().trimmed();
    newConfig.webServerAddress = m_adConfig->webServerAddress;
    newConfig.syncIntervalMins = ui->adSyncIntervalSpinBox->value();
    newConfig.autoAcceptNewUsers = ui->adAutoAcceptNewUsersCheckBox->isChecked();
    newConfig.enableSubgroups = ui->adSyncSubgroupsCheckBox->isChecked();
    newConfig.changePasswordUrl = ui->adChangePasswordUrlEdit->text().trimmed();
    newConfig.forgotPasswordUrl = ui->adForgotPasswordUrlEdit->text().trimmed();
    newConfig.enableAvatars = ui->adEnableAvatarsCheckBox->isChecked();
    newConfig.enableAuth = ui->adEnableAuthCheckBox->isChecked();
    newConfig.enableDistinguishedNameBaseAuth = ui->adEnableDnAuthCheckBox->isChecked();
    newConfig.invitationMessageSubject = ui->adInvitationSubjectLineEdit->text().trimmed();
    newConfig.enableAnomalyDetection = ui->adEnableAnomalyDetectionCheckBox->isChecked();
    newConfig.anomalyDetectionPercentThreshold = ui->adAnomalyDetectionPerscentSpinBox->value();
    newConfig.anomalyDetectionUserCountThreshold = ui->adAnomalyDetectionMinimumCountSpinBox->value();
    newConfig.forests = m_forests;
    *out = newConfig;
}

/*
 * Validate Foret configurations so that mandatory configurations are not empty and return all
 * configurations in json text format.
 */
bool ActiveDirectoryCategoryWidget::validateForests(bool showMessageBox)
{
    bool invalid = false;
    for (int i = 0; i < m_forests.size(); ++i) {
        const Forest& f = m_forests[i];
        QString errorMessage;
        if (!f.isValid(&errorMessage)) {
            invalid = true;
            if (showMessageBox) {
                errorMessage += "\nFor forest in row " + QString::number(i);
                QMessageBox::warning(this, "Error", errorMessage);
            }
        }
    }
    return !invalid;
}

void ActiveDirectoryCategoryWidget::onAddNewForestConfigButtonClicked()
{
    ForestDialog dialog(this);
    connectForestDialog(&dialog);
    if (dialog.exec() == QDialog::Accepted) {
        addOrUpdateForestInTable(dialog.forest());
    }
}

void ActiveDirectoryCategoryWidget::connectForestDialog(ForestDialog *dialog)
{
    m_forestDialog = dialog;
    connect(dialog, SIGNAL(testCredentialsClicked(ActiveDirectory::Forest)), SLOT(onTestCredentialsClicked(ActiveDirectory::Forest)));
    connect(dialog, SIGNAL(testMainGroup(ActiveDirectory::Forest)), SLOT(onTestMainGroup(ActiveDirectory::Forest)));
}

void ActiveDirectoryCategoryWidget::setForestForTableRow(const Forest &forest, int row)
{
    auto table = ui->adForestConfigurationTableWidget;
    table->setText(row, static_cast<int>(Column::Guid), forest.objectGuid);
    table->setText(row, static_cast<int>(Column::PrimaryDomainController), forest.primaryDomainController().host);
    table->setText(row, static_cast<int>(Column::Username), forest.userName);
    table->setText(row, static_cast<int>(Column::Password), forest.password);
    table->setText(row, static_cast<int>(Column::SyncGroup), forest.syncGroup);

    QStringList list;
    foreach (const DomainController& dc, forest.domainControllers) {
        if (!dc.isPrimary) {
            list.append(dc.host);
        }
    }
    table->setText(row, static_cast<int>(Column::AdditionalDomainControllers), list.join("; "));
}

bool ActiveDirectoryCategoryWidget::validateTableCurrentRow(int *row)
{
    *row = ui->adForestConfigurationTableWidget->currentRow();
    return (*row >= 0 && *row < m_forests.size());
}

/*
 * Forest configuration will be added or edited.
 *  map:        New or edited forest configuration
  * row:        Row index is only valid when editing existing entry, else it is -1 for new
 */
void ActiveDirectoryCategoryWidget::addOrUpdateForestInTable(const ActiveDirectory::Forest& forest, int row)
{
    bool changed = true;
    if (row == -1) {
        row = ui->adForestConfigurationTableWidget->appendRow();
        m_forests.append({});
    } else {
        const Forest& existing = m_forests[row];
        if (existing == forest) {
            changed = false;
        }
    }

    if (changed) {
        setForestForTableRow(forest, row);
        m_forests[row] = forest;
        setPageDirty(currentPage(), true);
    }
}

/*
 * Send request to qliqDirectService for admin credentials test
 */
void ActiveDirectoryCategoryWidget::onTestCredentialsClicked(const ActiveDirectory::Forest& forest)
{
    if (checkConnectedAndShowWarning(this)) {
        ui->adTestProgressIndicatorLabel->show();
        m_rpc->call(RPC_ACTIVE_DIRECTORY_TEST_ADMIN_CREDENTIALS, forest.toMap());
    }
}

/*
 * This function will launch Forest Configuration widget in 'Edit' mode
 */
void ActiveDirectoryCategoryWidget::onEditForestTriggered()
{
    int row;
    if (validateTableCurrentRow(&row)) {
        ForestDialog dialog(this);
        connectForestDialog(&dialog);
        dialog.setForest(m_forests[row]);
        if (dialog.exec() == QDialog::Accepted) {
            addOrUpdateForestInTable(dialog.forest(), row);
        }
    }
}

/*
 * Forest configuration deleted
 */
void ActiveDirectoryCategoryWidget::onDeleteForestTriggered()
{
    int row;
    if (validateTableCurrentRow(&row)) {
        auto ret = QMessageBox::warning(this, "qliqDIRECT Manager", "Are you sure you want to delete this forest?", QMessageBox::Yes | QMessageBox::No);
        if (ret == QMessageBox::Yes) {
            ui->adForestConfigurationTableWidget->removeRow(row);
            m_forests.remove(row);
            setPageDirty(currentPage(), true);
        }
    }
}

void ActiveDirectoryCategoryWidget::onTestForestCredentialsTriggered()
{
    int row;
    if (validateTableCurrentRow(&row)) {
        onTestCredentialsClicked(m_forests[row]);
    }
}

void ActiveDirectoryCategoryWidget::onTestForestSyncGroupTriggered()
{
    int row;
    if (validateTableCurrentRow(&row)) {
        onTestMainGroup(m_forests[row]);
    }
}

/*
 * Test sync group functionality
 */
void ActiveDirectoryCategoryWidget::onTestMainGroup(const ActiveDirectory::Forest& forest)
{
    if (checkConnectedAndShowWarning(this)) {
        AdSearchFilterTestWidget dialog(m_rpc, this);
        dialog.setForest(forest);
        dialog.onExecuteButtonClicked();
        dialog.exec();
    }
}
