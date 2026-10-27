#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "anim.h"
#include "secondmainwindow.h"

#include <QCheckBox>
#include <QListWidget>

#include <pcap.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // a single radio button is auto-exclusive and could never be unchecked otherwise
    ui->allRadioButton->setAutoExclusive(false);

    connect(ui->startButton, &QPushButton::pressed, this, [this]() { anim::animateButton(ui->startButton); });
    connect(ui->allRadioButton, &QRadioButton::pressed, this, [this]() {
        anim::animateRadioButton(ui->allRadioButton);
    });
    for (QCheckBox *box : protocolBoxes()) {
        connect(box, &QCheckBox::pressed, this, [box]() { anim::animateCheckBox(box); });
        connect(box, &QCheckBox::clicked, this, &MainWindow::syncAllButton);
    }

    connect(ui->allRadioButton, &QRadioButton::clicked, this, &MainWindow::selectAllProtocols);
    connect(ui->startButton, &QPushButton::clicked, this, &MainWindow::startCapture);
    connect(ui->deviceList, &QListWidget::itemDoubleClicked, this, &MainWindow::startCapture);

    syncAllButton();
    loadDevices();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::loadDevices()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t *devs = nullptr;

    if (pcap_findalldevs(&devs, errbuf) == -1) {
        ui->statusbar->showMessage(tr("Cannot list devices: %1").arg(QString::fromLocal8Bit(errbuf)));
        return;
    }

    for (pcap_if_t *dev = devs; dev != nullptr; dev = dev->next) {
        ui->deviceList->addItem(QString::fromLocal8Bit(dev->name));
    }
    pcap_freealldevs(devs);
}

QList<QCheckBox *> MainWindow::protocolBoxes() const
{
    return {ui->tcpCheckBox, ui->udpCheckBox, ui->icmpCheckBox};
}

void MainWindow::startCapture()
{
    const QListWidgetItem *item = ui->deviceList->currentItem();
    if (item == nullptr || !item->isSelected()) {
        ui->statusbar->showMessage("Choose dev");
        return;
    }

    CaptureSettings settings;
    settings.device = item->text().toStdString();
    settings.tcp = ui->tcpCheckBox->isChecked();
    settings.udp = ui->udpCheckBox->isChecked();
    settings.icmp = ui->icmpCheckBox->isChecked();

    if (!settings.tcp && !settings.udp && !settings.icmp) {
        ui->statusbar->showMessage("Choose protocol");
        return;
    }
    ui->statusbar->clearMessage();

    auto *captureWindow = new SecondMainWindow(settings, this);
    connect(captureWindow, &QDialog::finished, this, &QWidget::show);
    connect(captureWindow, &QDialog::finished, captureWindow, &QObject::deleteLater);
    hide();
    captureWindow->show();
}

void MainWindow::selectAllProtocols(bool checked)
{
    for (QCheckBox *box : protocolBoxes()) {
        box->setChecked(checked);
    }
}

void MainWindow::syncAllButton()
{
    bool allChecked = true;
    for (const QCheckBox *box : protocolBoxes()) {
        allChecked = allChecked && box->isChecked();
    }
    ui->allRadioButton->setChecked(allChecked);
}
