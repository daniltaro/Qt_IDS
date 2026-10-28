#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include <QByteArray>
#include <QMetaType>
#include <QString>

#include <pcap.h>
#include <cstddef>
#include <map>
#include <optional>
#include <string>

#include "../threatDetector/threatdetector.h"

enum protocolType {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

struct CaptureSettings {
    std::string device;
    bool tcp = false;
    bool udp = false;
    bool icmp = false;
};

struct PacketData {
    QString protocol;
    QString type; // threat labels or "-"
    QString srcDst;
    QByteArray payload;
    bool threat = false;
};
Q_DECLARE_METATYPE(PacketData)

// formats bytes as "0x0000: 47 45 54 ...  | GET..." lines
QString formatHexDump(const QByteArray &data);

// Parses IPv4 packets of one link type, runs them through the threat detector
// and keeps statistics and a JSON log of everything it has shown.
class PacketHandler {
public:
    PacketHandler(int linkType, const CaptureSettings &settings);

    static bool isLinkTypeSupported(int linkType);

    // nothing for packets that are not IPv4, are malformed or have a protocol that was not selected
    std::optional<PacketData> handle(const pcap_pkthdr *header, const u_char *packet);

    QString statistic() const;

    // JSON array with one object per handled packet
    std::string json() const;

private:
    // finds where the IPv4 datagram starts, false for other network protocols
    bool ipv4Offset(const u_char *packet, std::size_t len, std::size_t &offset) const;

    bool isSelected(uint8_t protocol) const;

    void saveJson(const pcap_pkthdr *header, const std::string &protocol,
                  const std::string &srcIP, const std::string &dstIP,
                  int srcPort, int dstPort, const std::string &threats);

    int linkType;
    CaptureSettings settings;
    threatDetector threatDec;

    int pack_count = 0;
    std::map<protocolType, int> protocolCounter;
    std::map<std::string, int> ipv4Counter;

    std::string jsonRecords;
};

#endif //PACKETHANDLER_H
