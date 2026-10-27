#include "secondmainwindow.h"
#include "ui_secondmainwindow.h"
#include "anim.h"

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QThread>

namespace {
// older rows are dropped so a long capture or a flood does not eat all the memory
constexpr int MAX_ROWS = 20000;

constexpr int PAYLOAD_ROLE = Qt::UserRole;
constexpr int THREAT_ROLE = Qt::UserRole + 1;
}

SecondMainWindow::SecondMainWindow(const CaptureSettings &settings, QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::SecondMainWindow)
    , settings(settings)
{
    ui->setupUi(this);
    // a single radio button is auto-exclusive and could never be unchecked otherwise
    ui->threatsOnlyButton->setAutoExclusive(false);

    connect(ui->stopButton, &QPushButton::pressed, this, [this]() { anim::animateButton(ui->stopButton); });
    connect(ui->startButton, &QPushButton::pressed, this, [this]() { anim::animateButton(ui->startButton); });
    connect(ui->backButton, &QPushButton::pressed, this, [this]() { anim::animateButton(ui->backButton); });
    connect(ui->saveButton, &QPushButton::pressed, this, [this]() { anim::animateButton(ui->saveButton); });
    connect(ui->threatsOnlyButton, &QRadioButton::pressed, this, [this]() { anim::animateRadioButton(ui->threatsOnlyButton); });

    connect(ui->stopButton, &QPushButton::clicked, this, &SecondMainWindow::stopCapture);
    connect(ui->startButton, &QPushButton::clicked, this, &SecondMainWindow::restartCapture);
    connect(ui->backButton, &QPushButton::clicked, this, &SecondMainWindow::reject);
    connect(ui->saveButton, &QPushButton::clicked, this, &SecondMainWindow::saveJson);
    connect(ui->packetTable, &QTableWidget::cellClicked, this, &SecondMainWindow::showPayload);
    connect(ui->filterEdit, &QLineEdit::textChanged, this, &SecondMainWindow::applyFilter);
    connect(ui->threatsOnlyButton, &QRadioButton::toggled, this, &SecondMainWindow::applyFilter);

    startCapture();
}

SecondMainWindow::~SecondMainWindow()
{
    stopWorker();
    delete ui;
}

void SecondMainWindow::done(int result)
{
    stopWorker();
    QDialog::done(result);
}

void SecondMainWindow::startCapture()
{
    json.clear();

    thread = new QThread(this);
    worker = new PacketWorker(settings);
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &PacketWorker::startCapture);
    connect(worker, &PacketWorker::finished, thread, &QThread::quit);
    connect(worker, &PacketWorker::packetsCaptured, this, &SecondMainWindow::insertPackets);
    connect(worker, &PacketWorker::statReady, ui->statsView, &QTextEdit::setPlainText);
    connect(worker, &PacketWorker::jsonReady, this, [this](const QByteArray &data) { json = data; });
    connect(worker, &PacketWorker::captureError, this, &SecondMainWindow::showCaptureError);

    thread->start();
    setRunning(true);
}

void SecondMainWindow::stopWorker()
{
    if (!thread) return;

    worker->stopCapture();
    thread->quit();
    thread->wait();

    // the thread is finished, so the worker can be deleted from here
    delete worker;
    delete thread;
    worker = nullptr;
    thread = nullptr;
}

void SecondMainWindow::stopCapture()
{
    stopWorker();
    setRunning(false);
}

void SecondMainWindow::setRunning(bool running)
{
    ui->stopButton->setEnabled(running);
    ui->startButton->setEnabled(!running);
    ui->saveButton->setEnabled(!running);
    ui->filterEdit->setEnabled(!running);
    ui->threatsOnlyButton->setEnabled(!running);

    const QString device = QString::fromStdString(settings.device);
    ui->statusLabel->setText((running ? "Running " : "Stopped ") + device);
}

void SecondMainWindow::insertPackets(const QVector<PacketData> &packets)
{
    QTableWidget *table = ui->packetTable;
    table->setUpdatesEnabled(false);

    for (const PacketData &packData : packets) {
        const int row = table->rowCount();
        table->insertRow(row);

        auto *protocolItem = new QTableWidgetItem(packData.protocol);
        protocolItem->setData(PAYLOAD_ROLE, packData.payload);
        protocolItem->setData(THREAT_ROLE, packData.threat);

        table->setItem(row, 0, protocolItem);
        table->setItem(row, 1, new QTableWidgetItem(packData.type));
        table->setItem(row, 2, new QTableWidgetItem(packData.srcDst));
    }

    const int excess = table->rowCount() - MAX_ROWS;
    if (excess > 0) table->model()->removeRows(0, excess);

    table->setUpdatesEnabled(true);
}

void SecondMainWindow::showCaptureError(const QString &message)
{
    QMessageBox::critical(this, tr("Capture error"), message);
    reject();
}

void SecondMainWindow::restartCapture()
{
    const auto answer = QMessageBox::question(this, tr("Start new capture"),
        tr("Captured packets will be cleared. Save them first?"),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Save);

    if (answer == QMessageBox::Cancel) return;
    if (answer == QMessageBox::Save && !saveJson()) return;

    ui->threatsOnlyButton->setChecked(false);
    ui->filterEdit->clear();
    ui->packetTable->setRowCount(0);
    ui->statsView->clear();
    ui->payloadView->clear();

    startCapture();
}

bool SecondMainWindow::saveJson()
{
    const QString defaultPath = QDir::currentPath() + "/data.json";
    const QString fileName = QFileDialog::getSaveFileName(this, tr("Select json file"),
        defaultPath, tr("JSON Files (*.json);;All Files (*)"));
    if (fileName.isEmpty()) return false;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate) || file.write(json) != json.size()) {
        QMessageBox::warning(this, tr("Save failed"),
                             tr("Cannot write %1: %2").arg(fileName, file.errorString()));
        return false;
    }
    return true;
}

void SecondMainWindow::showPayload(int row, int)
{
    const QTableWidgetItem *item = ui->packetTable->item(row, 0);
    if (!item) return;
    ui->payloadView->setPlainText(formatHexDump(item->data(PAYLOAD_ROLE).toByteArray()));
}

void SecondMainWindow::applyFilter()
{
    const QString text = ui->filterEdit->text();
    const bool threatsOnly = ui->threatsOnlyButton->isChecked();
    QTableWidget *table = ui->packetTable;

    for (int row = 0; row < table->rowCount(); ++row) {
        const QTableWidgetItem *first = table->item(row, 0);
        bool match = !threatsOnly || (first && first->data(THREAT_ROLE).toBool());

        if (match && !text.isEmpty()) {
            match = false;
            for (int column = 0; column < table->columnCount(); ++column) {
                const QTableWidgetItem *item = table->item(row, column);
                if (item && item->text().contains(text, Qt::CaseInsensitive)) {
                    match = true;
                    break;
                }
            }
        }
        table->setRowHidden(row, !match);
    }
}
