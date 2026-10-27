#include "packetworker.h"

#include <chrono>

namespace {
constexpr int SNAPLEN = 2048;
// pcap_dispatch returns at least this often, so batches are flushed even on a quiet interface
constexpr int READ_TIMEOUT_MS = 100;
constexpr auto FLUSH_INTERVAL = std::chrono::milliseconds(200);
constexpr int MAX_BATCH = 500;
}

PacketWorker::PacketWorker(const CaptureSettings &settings)
    : settings(settings) {
    qRegisterMetaType<PacketData>();
    qRegisterMetaType<QVector<PacketData>>();
}

PacketWorker::~PacketWorker() {
    std::lock_guard<std::mutex> guard(handleMutex);
    if (handle) pcap_close(handle);
}

void PacketWorker::startCapture() {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t *pcap = pcap_open_live(settings.device.c_str(), SNAPLEN, 1, READ_TIMEOUT_MS, errbuf);
    if (!pcap) {
        emit captureError(QString::fromLocal8Bit(errbuf));
        emit finished();
        return;
    }

    const int linkType = pcap_datalink(pcap);
    if (!PacketHandler::isLinkTypeSupported(linkType)) {
        const char *name = pcap_datalink_val_to_name(linkType);
        pcap_close(pcap);
        emit captureError(QString("%1: link type %2 is not supported")
                              .arg(QString::fromStdString(settings.device),
                                   name ? QString::fromLocal8Bit(name) : QString::number(linkType)));
        emit finished();
        return;
    }

    handler = std::make_unique<PacketHandler>(linkType, settings);
    {
        std::lock_guard<std::mutex> guard(handleMutex);
        handle = pcap;
    }

    auto lastFlush = std::chrono::steady_clock::now();
    while (!stopRequested) {
        const int rc = pcap_dispatch(pcap, -1, &PacketWorker::onPacket, reinterpret_cast<u_char *>(this));
        if (rc == PCAP_ERROR_BREAK) break;
        if (rc == PCAP_ERROR) {
            emit captureError(QString::fromLocal8Bit(pcap_geterr(pcap)));
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        if (batch.size() >= MAX_BATCH || now - lastFlush >= FLUSH_INTERVAL) {
            flush();
            lastFlush = now;
        }
    }

    flush();
    emit statReady(handler->statistic());
    emit jsonReady(QByteArray::fromStdString(handler->json()));

    {
        std::lock_guard<std::mutex> guard(handleMutex);
        pcap_close(handle);
        handle = nullptr;
    }
    emit finished();
}

void PacketWorker::stopCapture() {
    stopRequested = true;
    std::lock_guard<std::mutex> guard(handleMutex);
    if (handle) pcap_breakloop(handle);
}

void PacketWorker::onPacket(u_char *user, const pcap_pkthdr *header, const u_char *packet) {
    auto *self = reinterpret_cast<PacketWorker *>(user);
    if (auto packData = self->handler->handle(header, packet)) {
        self->batch.push_back(std::move(*packData));
    }
}

void PacketWorker::flush() {
    if (batch.isEmpty()) return;
    emit packetsCaptured(batch);
    batch.clear();
    emit statReady(handler->statistic());
}
