#ifndef PACKETWORKER_H
#define PACKETWORKER_H

#include "basehandler.h"

#include <pcap.h>

class PacketWorker : public QObject
{
    Q_OBJECT
public:
    PacketWorker(const std::string& dev, bool tcp, bool icmp, bool udp, bool all);
    ~PacketWorker();

public slots:
    void startCapture();

    void stopCapture();

signals:
    void packetCaptured(const PacketData&);

    void statReady(const QString&);

    void linkTypeError();

    void finished();

private:
    pcap_t* handle = nullptr;
    pcap_dumper_t* dumper = nullptr;
    std::string dev;
    bool all, tcp, udp, icmp;
    std::string jsonPath;
    PacketData packData;

};

#endif // PACKETWORKER_H
