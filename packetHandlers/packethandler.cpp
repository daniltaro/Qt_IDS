#include "packethandler.h"
#include "../headers/ethernetheader.h"
#include "../headers/icmpheader.h"
#include "../headers/ipv4header.h"
#include "../headers/tcpheader.h"
#include "../headers/udpheader.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>
#include <vector>
#include <nlohmann/json.hpp>

namespace {
// the statistic lists only the busiest hosts, it is redrawn several times a second
constexpr std::size_t MAX_STAT_HOSTS = 20;

std::string formatTimestamp(const timeval &ts) {
    const std::time_t seconds = ts.tv_sec;
    std::tm local{};
    localtime_r(&seconds, &local);

    char date[32];
    std::strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &local);

    char result[48];
    std::snprintf(result, sizeof(result), "%s.%06d", date, static_cast<int>(ts.tv_usec));
    return result;
}

QString endpoint(const std::string &ip, int port) {
    QString result = QString::fromStdString(ip);
    if (port >= 0) result += ":" + QString::number(port);
    return result;
}
}

QString formatHexDump(const QByteArray &data) {
    if (data.isEmpty()) return QStringLiteral("no payload");

    QString hex;
    for (qsizetype i = 0; i < data.size(); i += 16) {
        hex += QString("0x%1: ").arg(static_cast<qlonglong>(i), 4, 16, QChar('0'));

        for (qsizetype j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                const auto byte = static_cast<uchar>(data[i + j]);
                hex += QString("%1 ").arg(static_cast<uint>(byte), 2, 16, QChar('0'));
            } else {
                hex += "   ";
            }
        }

        hex += " | ";

        for (qsizetype j = 0; j < 16 && i + j < data.size(); ++j) {
            const auto ch = static_cast<uchar>(data[i + j]);
            hex += (ch >= 32 && ch <= 126) ? QChar(ch) : QChar('.');
        }
        hex += '\n';
    }
    return hex;
}

PacketHandler::PacketHandler(int linkType, const CaptureSettings &settings)
    : linkType(linkType), settings(settings) {}

bool PacketHandler::isLinkTypeSupported(int linkType) {
    return linkType == DLT_EN10MB || linkType == DLT_NULL || linkType == DLT_LOOP;
}

bool PacketHandler::ipv4Offset(const u_char *packet, std::size_t len, std::size_t &offset) const {
    switch (linkType) {
    case DLT_EN10MB: {
        EthernetHeader ethernetHeader;
        if (!EthernetHeader::parse(packet, len, ethernetHeader)) return false;
        if (ethernetHeader.type() != EthernetHeader::TYPE_IPV4) return false;
        offset = EthernetHeader::SIZE;
        return true;
    }
    case DLT_NULL:
    case DLT_LOOP: {
        // 4-byte address family: host byte order for DLT_NULL, network byte order for DLT_LOOP
        uint32_t family = 0;
        if (packet == nullptr || len < sizeof(family)) return false;
        std::memcpy(&family, packet, sizeof(family));
        if (linkType == DLT_LOOP) family = ntohl(family);
        if (family != AF_INET) return false;
        offset = sizeof(family);
        return true;
    }
    default:
        return false;
    }
}

bool PacketHandler::isSelected(uint8_t protocol) const {
    switch (protocol) {
    case TCP: return settings.tcp;
    case UDP: return settings.udp;
    case ICMP: return settings.icmp;
    default: return false;
    }
}

std::optional<PacketData> PacketHandler::handle(const pcap_pkthdr *header, const u_char *packet) {
    if (header == nullptr || packet == nullptr) return std::nullopt;

    const std::size_t len = header->caplen;
    std::size_t linkOffset = 0;
    if (!ipv4Offset(packet, len, linkOffset)) return std::nullopt;

    const u_char *ip = packet + linkOffset;
    std::size_t ipLen = len - linkOffset;

    Ipv4Header ipv4Header;
    if (!Ipv4Header::parse(ip, ipLen, ipv4Header)) return std::nullopt;

    const uint8_t protocol = ipv4Header.protocolType();
    if (!isSelected(protocol)) return std::nullopt;

    // short ethernet frames are padded, the padding is not part of the datagram
    if (ipv4Header.totalLength() >= ipv4Header.headerLength() && ipv4Header.totalLength() < ipLen) {
        ipLen = ipv4Header.totalLength();
    }

    const u_char *transport = ip + ipv4Header.headerLength();
    const std::size_t transportLen = ipLen - ipv4Header.headerLength();
    const auto ts = threatDetector::toTimestamp(header->ts);
    const std::string srcIP = ipv4Header.getSrcIP();
    const std::string dstIP = ipv4Header.getDstIP();

    std::string protocolName;
    std::string threats;
    std::size_t transportHeaderLen = 0;
    int srcPort = -1;
    int dstPort = -1;

    switch (protocol) {
    case TCP: {
        protocolName = "TCP";
        if (ipv4Header.isLaterFragment()) break;

        TCPHeader tcpHeader;
        if (!TCPHeader::parse(transport, transportLen, tcpHeader)) return std::nullopt;
        transportHeaderLen = tcpHeader.headerLength();
        srcPort = tcpHeader.getSrcPort();
        dstPort = tcpHeader.getDstPort();
        threats = threatDec.inspectTCP(srcIP, dstIP, tcpHeader.getDstPort(), tcpHeader.getFlag(), ts);
        break;
    }
    case UDP: {
        protocolName = "UDP";
        if (ipv4Header.isLaterFragment()) break;

        UDPHeader udpHeader;
        if (!UDPHeader::parse(transport, transportLen, udpHeader)) return std::nullopt;
        transportHeaderLen = UDPHeader::SIZE;
        srcPort = udpHeader.getSrcPort();
        dstPort = udpHeader.getDstPort();
        threats = threatDec.inspectUDP(srcIP, dstIP, udpHeader.getSrcPort(), udpHeader.getDstPort(), ts);
        break;
    }
    case ICMP: {
        protocolName = "ICMP";
        if (ipv4Header.isLaterFragment()) break;

        ICMPHeader icmpHeader;
        if (!ICMPHeader::parse(transport, transportLen, icmpHeader)) return std::nullopt;
        transportHeaderLen = std::min(icmpHeader.headerLength(), transportLen);
        threats = threatDec.inspectICMP(dstIP, icmpHeader.getType(), ts);
        break;
    }
    }

    pack_count++;
    protocolCounter[static_cast<protocolType>(protocol)]++;
    ipv4Counter[srcIP]++;
    ipv4Counter[dstIP]++;

    saveJson(header, protocolName, srcIP, dstIP, srcPort, dstPort, threats);

    PacketData packData;
    packData.protocol = QString::fromStdString(protocolName);
    packData.threat = !threats.empty();
    packData.type = packData.threat ? QString::fromStdString(threats) : QStringLiteral("-");
    packData.srcDst = endpoint(srcIP, srcPort) + " -> " + endpoint(dstIP, dstPort);
    packData.payload = QByteArray(reinterpret_cast<const char *>(transport + transportHeaderLen),
                                  static_cast<qsizetype>(transportLen - transportHeaderLen));
    return packData;
}

QString PacketHandler::statistic() const {
    auto count = [this](protocolType protocol) {
        const auto it = protocolCounter.find(protocol);
        return it == protocolCounter.end() ? 0 : it->second;
    };

    QString stat;
    stat += "------------------------------\n";
    stat += "TCP protocols - " + QString::number(count(TCP)) + "\n";
    stat += "UDP protocols - " + QString::number(count(UDP)) + "\n";
    stat += "ICMP protocols - " + QString::number(count(ICMP)) + "\n";
    stat += "Threat count - " + QString::number(threatDec.getThreatCount()) + "\n";
    stat += "Packets count - " + QString::number(pack_count) + "\n";

    std::vector<std::pair<std::string, int>> hosts(ipv4Counter.begin(), ipv4Counter.end());
    const std::size_t shown = std::min(hosts.size(), MAX_STAT_HOSTS);
    std::partial_sort(hosts.begin(), hosts.begin() + shown, hosts.end(),
                      [](const auto &a, const auto &b) { return a.second > b.second; });

    if (shown > 0) stat += "------------------------------\n";
    for (std::size_t i = 0; i < shown; ++i) {
        stat += QString::fromStdString(hosts[i].first) + " - " + QString::number(hosts[i].second) + "\n";
    }
    if (hosts.size() > shown) {
        stat += "... and " + QString::number(hosts.size() - shown) + " more hosts\n";
    }
    stat += "------------------------------\n";
    return stat;
}

std::string PacketHandler::json() const {
    return "[\n" + jsonRecords + "\n]\n";
}

void PacketHandler::saveJson(const pcap_pkthdr *header, const std::string &protocol,
                             const std::string &srcIP, const std::string &dstIP,
                             int srcPort, int dstPort, const std::string &threats) {
    nlohmann::json j;
    j["timestamp"] = formatTimestamp(header->ts);
    j["protocol"] = protocol;
    j["src_ip"] = srcIP;
    j["dst_ip"] = dstIP;
    if (srcPort >= 0) j["src_port"] = srcPort;
    if (dstPort >= 0) j["dst_port"] = dstPort;
    j["length"] = header->len;
    j["threat"] = !threats.empty();
    if (!threats.empty()) j["type"] = threats;

    if (!jsonRecords.empty()) jsonRecords += ",\n";
    jsonRecords += j.dump();
}
