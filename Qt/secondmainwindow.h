#ifndef SECONDMAINWINDOW_H
#define SECONDMAINWINDOW_H

#include "../packetHandlers/packetworker.h"

#include <QByteArray>
#include <QDialog>
#include <QVector>

class QThread;

namespace Ui {
class SecondMainWindow;
}

class SecondMainWindow : public QDialog
{
    Q_OBJECT

public:
    explicit SecondMainWindow(const CaptureSettings &settings, QWidget *parent = nullptr);
    ~SecondMainWindow();

    // Back button, Esc and the window close button all end up here
    void done(int result) override;

private slots:
    void insertPackets(const QVector<PacketData> &packets);

    void showCaptureError(const QString &message);

    void stopCapture();

    void restartCapture();

    bool saveJson();

    void showPayload(int row, int column);

    void applyFilter();

private:
    void startCapture();

    // stops the capture thread and waits for it, safe to call when nothing is running
    void stopWorker();

    void setRunning(bool running);

    Ui::SecondMainWindow *ui;
    CaptureSettings settings;
    QThread *thread = nullptr;
    PacketWorker *worker = nullptr;
    QByteArray json;
};

#endif // SECONDMAINWINDOW_H
