#ifndef PACKETWORKER_H
#define PACKETWORKER_H

#include <pcap.h>
#include "basehandler.h"

class PacketWorker : public QObject
{
    Q_OBJECT
public:
    PacketWorker(const std::string& dev, bool tcp, bool icmp, bool udp, bool all,
                 const std::string& json_file_name);

    ~PacketWorker();

public slots:
    void startCapture();

    void stopCapture();

signals:
    void packetCaptured(PacketData);

    void statReady(QString);

    void finished();

private:
    pcap_t* handle = nullptr;
    UserData data{};
    std::string dev;
    bool all, tcp, udp, icmp;
    std::string jsonPath;
    PacketData packData;


};

#endif // PACKETWORKER_H
