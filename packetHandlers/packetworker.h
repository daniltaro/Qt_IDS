#ifndef PACKETWORKER_H
#define PACKETWORKER_H

#include "packethandler.h"

#include <QObject>
#include <QVector>

#include <pcap.h>
#include <atomic>
#include <memory>
#include <mutex>

// Runs the capture loop in its own thread and hands packets to the GUI in batches.
class PacketWorker : public QObject
{
    Q_OBJECT
public:
    explicit PacketWorker(const CaptureSettings &settings);
    ~PacketWorker();

    // thread-safe, can be called from the GUI thread while startCapture() is running
    void stopCapture();

public slots:
    void startCapture();

signals:
    void packetsCaptured(const QVector<PacketData> &);

    void statReady(const QString &);

    // emitted once, after the capture loop has ended
    void jsonReady(const QByteArray &);

    void captureError(const QString &);

    void finished();

private:
    static void onPacket(u_char *user, const pcap_pkthdr *header, const u_char *packet);

    void flush();

    CaptureSettings settings;
    std::unique_ptr<PacketHandler> handler;
    QVector<PacketData> batch;

    std::mutex handleMutex;
    pcap_t *handle = nullptr;
    std::atomic<bool> stopRequested{false};
};

#endif // PACKETWORKER_H
