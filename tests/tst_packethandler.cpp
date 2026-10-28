#include <QtTest>

#include "../headers/tcpheader.h"
#include "../packetHandlers/packethandler.h"
#include "packetbuilder.h"

#include <nlohmann/json.hpp>

namespace {
CaptureSettings allProtocols()
{
    CaptureSettings settings;
    settings.device = "test0";
    settings.tcp = true;
    settings.udp = true;
    settings.icmp = true;
    return settings;
}

std::optional<PacketData> handle(PacketHandler &handler, const packet::Bytes &data, long seconds = 1000)
{
    const pcap_pkthdr header = packet::header(data, seconds);
    return handler.handle(&header, data.data());
}

QByteArray toByteArray(const packet::Bytes &data)
{
    return QByteArray(reinterpret_cast<const char *>(data.data()), static_cast<qsizetype>(data.size()));
}

const packet::Bytes HTTP_GET = packet::ethernet(
    packet::ipv4(TCP, packet::tcp(1234, 80, TCPHeader::PSH | TCPHeader::ACK, packet::bytes("GET"))));
}

class TestPacketHandler : public QObject
{
    Q_OBJECT

private slots:
    void supportedLinkTypes();
    void ethernetTcpPacket();
    void truncatedPacketsAreSafe();
    void nonIpv4EthernetIgnored();
    void nullLoopbackChecksFamily();
    void loopLoopbackUsesNetworkOrder();
    void unselectedProtocolIgnored();
    void ethernetPaddingIsNotPayload();
    void laterFragmentHasNoPorts();
    void icmpPayloadStartsAfterTypeSpecificHeader();
    void threatIsReported();
    void jsonContainsEveryPacket();
    void statisticCountsPackets();
    void hexDump();
};

void TestPacketHandler::supportedLinkTypes()
{
    QVERIFY(PacketHandler::isLinkTypeSupported(DLT_EN10MB));
    QVERIFY(PacketHandler::isLinkTypeSupported(DLT_NULL));
    QVERIFY(PacketHandler::isLinkTypeSupported(DLT_LOOP));
    QVERIFY(!PacketHandler::isLinkTypeSupported(DLT_RAW));
}

void TestPacketHandler::ethernetTcpPacket()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());
    const auto packData = handle(handler, HTTP_GET);

    QVERIFY(packData.has_value());
    QCOMPARE(packData->protocol, QString("TCP"));
    QCOMPARE(packData->srcDst, QString("10.0.0.1:1234 -> 10.0.0.2:80"));
    QCOMPARE(packData->payload, QByteArray("GET"));
    QCOMPARE(packData->type, QString("-"));
    QVERIFY(!packData->threat);
}

void TestPacketHandler::truncatedPacketsAreSafe()
{
    // every prefix lives in its own exact-size buffer, so reading past it is caught by ASan
    const std::size_t headers = 14 + 20 + 20;
    PacketHandler handler(DLT_EN10MB, allProtocols());

    for (std::size_t len = 0; len <= HTTP_GET.size(); ++len) {
        const packet::Bytes prefix(HTTP_GET.begin(), HTTP_GET.begin() + static_cast<std::ptrdiff_t>(len));
        const auto packData = handle(handler, prefix);

        if (len < headers) {
            QVERIFY2(!packData.has_value(), qPrintable(QString("length %1").arg(len)));
        } else {
            QVERIFY2(packData.has_value(), qPrintable(QString("length %1").arg(len)));
            QCOMPARE(packData->payload.size(), static_cast<qsizetype>(len - headers));
        }
    }
}

void TestPacketHandler::nonIpv4EthernetIgnored()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());
    const packet::Bytes ipv6 = packet::ethernet(packet::bytes("not an ipv4 datagram at all"), 0x86DD);
    QVERIFY(!handle(handler, ipv6).has_value());
}

void TestPacketHandler::nullLoopbackChecksFamily()
{
    PacketHandler handler(DLT_NULL, allProtocols());
    const packet::Bytes datagram = packet::ipv4(UDP, packet::udp(5000, 6000));

    QVERIFY(handle(handler, packet::loopback(datagram, AF_INET)).has_value());
    QVERIFY(!handle(handler, packet::loopback(datagram, AF_INET6)).has_value());
}

void TestPacketHandler::loopLoopbackUsesNetworkOrder()
{
    PacketHandler handler(DLT_LOOP, allProtocols());
    const packet::Bytes datagram = packet::ipv4(UDP, packet::udp(5000, 6000));

    QVERIFY(handle(handler, packet::loopback(datagram, AF_INET, true)).has_value());
    QVERIFY(!handle(handler, packet::loopback(datagram, AF_INET6, true)).has_value());
}

void TestPacketHandler::unselectedProtocolIgnored()
{
    CaptureSettings settings;
    settings.tcp = true;
    PacketHandler handler(DLT_EN10MB, settings);

    QVERIFY(handle(handler, HTTP_GET).has_value());
    QVERIFY(!handle(handler, packet::ethernet(packet::ipv4(UDP, packet::udp(1, 2)))).has_value());
    QVERIFY(!handle(handler, packet::ethernet(packet::ipv4(ICMP, packet::icmp(8, 0, packet::Bytes(4))))).has_value());
}

void TestPacketHandler::ethernetPaddingIsNotPayload()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());
    // a 28-byte datagram is padded to the 60-byte ethernet minimum
    packet::Bytes frame = packet::ethernet(packet::ipv4(UDP, packet::udp(1, 2)));
    frame.resize(60, 0);

    const auto packData = handle(handler, frame);
    QVERIFY(packData.has_value());
    QVERIFY(packData->payload.isEmpty());
}

void TestPacketHandler::laterFragmentHasNoPorts()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());
    const packet::Bytes frame = packet::ethernet(
        packet::ipv4(TCP, packet::bytes("abcdef"), {10, 0, 0, 1}, {10, 0, 0, 2}, 0x0010));

    const auto packData = handle(handler, frame);
    QVERIFY(packData.has_value());
    QCOMPARE(packData->srcDst, QString("10.0.0.1 -> 10.0.0.2"));
    QCOMPARE(packData->payload, QByteArray("abcdef"));
}

void TestPacketHandler::icmpPayloadStartsAfterTypeSpecificHeader()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());

    const packet::Bytes echo = packet::ethernet(
        packet::ipv4(ICMP, packet::icmp(8, 0, packet::concat(packet::Bytes(4), packet::bytes("ping")))));
    QCOMPARE(handle(handler, echo)->payload, QByteArray("ping"));

    const packet::Bytes timestamp = packet::ethernet(
        packet::ipv4(ICMP, packet::icmp(13, 0, packet::concat(packet::Bytes(16), packet::bytes("xy")))));
    QCOMPARE(handle(handler, timestamp)->payload, QByteArray("xy"));

    // a cut timestamp message must not move the payload start past the captured bytes
    const packet::Bytes cut = packet::ethernet(packet::ipv4(ICMP, packet::icmp(13, 0, packet::Bytes(2))));
    const auto packData = handle(handler, cut);
    QVERIFY(packData.has_value());
    QVERIFY(packData->payload.isEmpty());
}

void TestPacketHandler::threatIsReported()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());
    const packet::Bytes ping = packet::ethernet(packet::ipv4(ICMP, packet::icmp(8, 0, packet::Bytes(4))));

    std::optional<PacketData> packData;
    for (int i = 0; i <= threatDetector::ICMP_FLOOD_THRESHOLD; ++i) {
        packData = handle(handler, ping);
    }

    QVERIFY(packData.has_value());
    QVERIFY(packData->threat);
    QCOMPARE(packData->type, QString("[ICMP FLOOD]"));
}

void TestPacketHandler::jsonContainsEveryPacket()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());
    QCOMPARE(nlohmann::json::parse(handler.json()).size(), std::size_t(0));

    handle(handler, HTTP_GET);
    handle(handler, packet::ethernet(packet::ipv4(ICMP, packet::icmp(0, 0, packet::Bytes(4)))));

    const nlohmann::json records = nlohmann::json::parse(handler.json());
    QCOMPARE(records.size(), std::size_t(2));

    QCOMPARE(records[0]["protocol"].get<std::string>(), std::string("TCP"));
    QCOMPARE(records[0]["src_port"].get<int>(), 1234);
    QCOMPARE(records[0]["dst_port"].get<int>(), 80);
    QCOMPARE(records[0]["threat"].get<bool>(), false);
    QCOMPARE(records[0]["length"].get<std::size_t>(), HTTP_GET.size());

    QCOMPARE(records[1]["protocol"].get<std::string>(), std::string("ICMP"));
    QVERIFY(!records[1].contains("src_port"));
}

void TestPacketHandler::statisticCountsPackets()
{
    PacketHandler handler(DLT_EN10MB, allProtocols());
    handle(handler, HTTP_GET);
    handle(handler, HTTP_GET);

    const QString stat = handler.statistic();
    QVERIFY(stat.contains("TCP protocols - 2"));
    QVERIFY(stat.contains("Packets count - 2"));
    QVERIFY(stat.contains("10.0.0.1 - 2"));
}

void TestPacketHandler::hexDump()
{
    QCOMPARE(formatHexDump(QByteArray()), QString("no payload"));

    const QString dump = formatHexDump(QByteArray("GET\n"));
    QVERIFY(dump.startsWith("0x0000: 47 45 54 0a "));
    QVERIFY(dump.endsWith(" | GET.\n"));

    const QString twoLines = formatHexDump(toByteArray(packet::Bytes(17, 'a')));
    QVERIFY(twoLines.contains("\n0x0010: 61 "));
}

QTEST_APPLESS_MAIN(TestPacketHandler)
#include "tst_packethandler.moc"
