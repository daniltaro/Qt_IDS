#ifndef BASEHANDLER_H
#define BASEHANDLER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <QString>
#include <fstream>
#include <iostream>
#include <QString>
#include <QObject>
#include "../threatDetector/threatdetector.h"

enum protocolType {
    ALL = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1,
};

struct PacketData{
    QString protocol;
    QString type;
    QString srcDst;
    QString hex;
};

class BaseHandler : public QObject{
    Q_OBJECT
protected:
    int pack_count = 0;

    PacketData packData;

    threatDetector threatDec;

    bool all_packets;
    bool tcp_prot;
    bool udp_prot;
    bool icmp_prot;

    mutable bool commaFlag = false;

    std::map<protocolType, int> protocolCounter;
    std::map<std::string, int> ipv4Counter;

public:
    explicit BaseHandler(bool all,  bool tcp,
                bool udp,  bool icmp);

    QString getPayload(const u_char *payload, const uint32_t &len) const;

    //main func where packets are captured
    virtual void Handle( const struct pcap_pkthdr
            *header, const u_char *packet) = 0;

    // emitting main statistic for textEdit
    void printStatistic();

    //getting buffer ready for save
    virtual void saveJsonStatistic(const struct pcap_pkthdr *header, const u_char *packet,
                               bool flag, const std::string& type) const = 0;

    virtual ~BaseHandler() {}

    //calls a Handle
    static void StaticHandle(u_char *user,
        const struct pcap_pkthdr *header, const u_char *packet);

signals:
    void packetCaptured(const PacketData&);

    void statReady(const QString&);
};

#endif//BASEHANDLER_H
