#include <QtTest>

#include "../headers/ethernetheader.h"
#include "../headers/icmpheader.h"
#include "../headers/ipv4header.h"
#include "../headers/tcpheader.h"
#include "../headers/udpheader.h"
#include "packetbuilder.h"

class TestHeaders : public QObject
{
    Q_OBJECT

private slots:
    void ethernetNeedsFullHeader();
    void ipv4ParsesAddressesAndProtocol();
    void ipv4RejectsWrongVersion();
    void ipv4RejectsBadHeaderLength();
    void ipv4DetectsLaterFragments();
    void tcpParsesPortsAndFlags();
    void tcpRejectsBadDataOffset();
    void udpNeedsFullHeader();
    void icmpHeaderLengthDependsOnType();
};

void TestHeaders::ethernetNeedsFullHeader()
{
    const packet::Bytes frame = packet::ethernet({}, 0x86DD);
    EthernetHeader ethernetHeader;

    QVERIFY(!EthernetHeader::parse(frame.data(), frame.size() - 1, ethernetHeader));
    QVERIFY(!EthernetHeader::parse(nullptr, 100, ethernetHeader));
    QVERIFY(EthernetHeader::parse(frame.data(), frame.size(), ethernetHeader));
    QCOMPARE(ethernetHeader.type(), uint16_t(0x86DD));
}

void TestHeaders::ipv4ParsesAddressesAndProtocol()
{
    const packet::Bytes datagram = packet::ipv4(6, packet::tcp(1, 2, 0), {192, 168, 1, 10}, {8, 8, 8, 8});
    Ipv4Header ipv4Header;

    QVERIFY(Ipv4Header::parse(datagram.data(), datagram.size(), ipv4Header));
    QCOMPARE(ipv4Header.protocolType(), uint8_t(6));
    QCOMPARE(ipv4Header.headerLength(), std::size_t(20));
    QCOMPARE(ipv4Header.totalLength(), datagram.size());
    QCOMPARE(QString::fromStdString(ipv4Header.getSrcIP()), QString("192.168.1.10"));
    QCOMPARE(QString::fromStdString(ipv4Header.getDstIP()), QString("8.8.8.8"));
    QVERIFY(!ipv4Header.isLaterFragment());
}

void TestHeaders::ipv4RejectsWrongVersion()
{
    packet::Bytes datagram = packet::ipv4(17, packet::udp(1, 2));
    datagram[0] = 0x65; // version 6
    Ipv4Header ipv4Header;

    QVERIFY(!Ipv4Header::parse(datagram.data(), datagram.size(), ipv4Header));
}

void TestHeaders::ipv4RejectsBadHeaderLength()
{
    packet::Bytes datagram = packet::ipv4(17, packet::udp(1, 2));
    Ipv4Header ipv4Header;

    datagram[0] = 0x44; // IHL 4: shorter than the fixed header
    QVERIFY(!Ipv4Header::parse(datagram.data(), datagram.size(), ipv4Header));

    datagram[0] = 0x4F; // IHL 15: 60 bytes, longer than the captured 28
    QVERIFY(!Ipv4Header::parse(datagram.data(), datagram.size(), ipv4Header));

    QVERIFY(!Ipv4Header::parse(datagram.data(), Ipv4Header::MIN_SIZE - 1, ipv4Header));
}

void TestHeaders::ipv4DetectsLaterFragments()
{
    Ipv4Header ipv4Header;

    const packet::Bytes first = packet::ipv4(17, packet::udp(1, 2), {10, 0, 0, 1}, {10, 0, 0, 2}, 0x2000);
    QVERIFY(Ipv4Header::parse(first.data(), first.size(), ipv4Header));
    QVERIFY(!ipv4Header.isLaterFragment()); // "more fragments" set, offset 0

    const packet::Bytes later = packet::ipv4(17, packet::bytes("data"), {10, 0, 0, 1}, {10, 0, 0, 2}, 0x0010);
    QVERIFY(Ipv4Header::parse(later.data(), later.size(), ipv4Header));
    QVERIFY(ipv4Header.isLaterFragment());
}

void TestHeaders::tcpParsesPortsAndFlags()
{
    const packet::Bytes segment = packet::tcp(1234, 80, TCPHeader::SYN | TCPHeader::ACK);
    TCPHeader tcpHeader;

    QVERIFY(TCPHeader::parse(segment.data(), segment.size(), tcpHeader));
    QCOMPARE(tcpHeader.getSrcPort(), uint16_t(1234));
    QCOMPARE(tcpHeader.getDstPort(), uint16_t(80));
    QCOMPARE(tcpHeader.getFlag(), uint8_t(TCPHeader::SYN | TCPHeader::ACK));
    QCOMPARE(tcpHeader.headerLength(), std::size_t(20));
}

void TestHeaders::tcpRejectsBadDataOffset()
{
    packet::Bytes segment = packet::tcp(1234, 80, 0);
    TCPHeader tcpHeader;

    segment[12] = 0x40; // 16 bytes: shorter than the fixed header
    QVERIFY(!TCPHeader::parse(segment.data(), segment.size(), tcpHeader));

    segment[12] = 0xF0; // 60 bytes of options that were not captured
    QVERIFY(!TCPHeader::parse(segment.data(), segment.size(), tcpHeader));

    QVERIFY(!TCPHeader::parse(segment.data(), TCPHeader::MIN_SIZE - 1, tcpHeader));
}

void TestHeaders::udpNeedsFullHeader()
{
    const packet::Bytes datagram = packet::udp(53, 40000);
    UDPHeader udpHeader;

    QVERIFY(!UDPHeader::parse(datagram.data(), UDPHeader::SIZE - 1, udpHeader));
    QVERIFY(UDPHeader::parse(datagram.data(), datagram.size(), udpHeader));
    QCOMPARE(udpHeader.getSrcPort(), uint16_t(53));
    QCOMPARE(udpHeader.getDstPort(), uint16_t(40000));
}

void TestHeaders::icmpHeaderLengthDependsOnType()
{
    ICMPHeader icmpHeader;

    const packet::Bytes echo = packet::icmp(8, 0);
    QVERIFY(ICMPHeader::parse(echo.data(), echo.size(), icmpHeader));
    QCOMPARE(icmpHeader.headerLength(), std::size_t(8));

    const packet::Bytes timestamp = packet::icmp(13, 0);
    QVERIFY(ICMPHeader::parse(timestamp.data(), timestamp.size(), icmpHeader));
    QCOMPARE(icmpHeader.headerLength(), std::size_t(20));

    const packet::Bytes mask = packet::icmp(17, 0);
    QVERIFY(ICMPHeader::parse(mask.data(), mask.size(), icmpHeader));
    QCOMPARE(icmpHeader.headerLength(), std::size_t(12));

    QVERIFY(!ICMPHeader::parse(echo.data(), ICMPHeader::MIN_SIZE - 1, icmpHeader));
}

QTEST_APPLESS_MAIN(TestHeaders)
#include "tst_headers.moc"
