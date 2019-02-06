#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "DomainControllerManager.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    m_domainControllerManager = new DomainControllerManager();
    //m_domainControllerManager->openDCEnumeration();
    m_domainControllerManager->openDC();

}

MainWindow::~MainWindow()
{
    delete ui;
}
