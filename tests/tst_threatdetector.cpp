#include <QtTest>

#include "../headers/tcpheader.h"
#include "../threatDetector/threatdetector.h"

namespace {
const threatDetector::Timestamp T0 = std::chrono::seconds(1000);
constexpr uint8_t ECHO_REQUEST = 8;
constexpr uint8_t ECHO_REPLY = 0;
constexpr uint8_t SYN = TCPHeader::SYN;
constexpr uint8_t ACK = TCPHeader::ACK;
constexpr uint8_t SYN_ACK = TCPHeader::SYN | TCPHeader::ACK;

QString labels(const std::string &value)
{
    return QString::fromStdString(value);
}
}

class TestThreatDetector : public QObject
{
    Q_OBJECT

private slots:
    void toTimestamp();
    void icmpFloodAboveThreshold();
    void icmpFloodEndsWithWindow();
    void icmpRepliesIgnored();
    void icmpCountedPerHost();
    void synFloodDetected();
    void synAckIsNotSyn();
    void handshakesAreNotFlood();
    void tcpPortScan();
    void serverRepliesAreNotScan();
    void udpFlood();
    void udpPortScan();
    void udpServiceRepliesAreNotScan();
};

void TestThreatDetector::toTimestamp()
{
    timeval tv{};
    tv.tv_sec = 2;
    tv.tv_usec = 500;
    QVERIFY(threatDetector::toTimestamp(tv) == std::chrono::microseconds(2000500));
}

void TestThreatDetector::icmpFloodAboveThreshold()
{
    threatDetector detector;
    for (int i = 0; i < threatDetector::ICMP_FLOOD_THRESHOLD; ++i) {
        QVERIFY(detector.inspectICMP("10.0.0.2", ECHO_REQUEST, T0).empty());
    }

    QCOMPARE(labels(detector.inspectICMP("10.0.0.2", ECHO_REQUEST, T0)), QString("[ICMP FLOOD]"));
    QCOMPARE(labels(detector.inspectICMP("10.0.0.2", ECHO_REQUEST, T0)), QString("[ICMP FLOOD]"));
    // every packet of the flood is flagged, but it is still one incident
    QCOMPARE(detector.getThreatCount(), 1);
}

void TestThreatDetector::icmpFloodEndsWithWindow()
{
    threatDetector detector;
    for (int i = 0; i <= threatDetector::ICMP_FLOOD_THRESHOLD; ++i) {
        detector.inspectICMP("10.0.0.2", ECHO_REQUEST, T0);
    }

    QVERIFY(detector.inspectICMP("10.0.0.2", ECHO_REQUEST, T0 + threatDetector::WINDOW).empty());
    QCOMPARE(detector.getThreatCount(), 1);
}

void TestThreatDetector::icmpRepliesIgnored()
{
    threatDetector detector;
    for (int i = 0; i < 100; ++i) {
        QVERIFY(detector.inspectICMP("10.0.0.2", ECHO_REPLY, T0).empty());
    }
    QCOMPARE(detector.getThreatCount(), 0);
}

void TestThreatDetector::icmpCountedPerHost()
{
    threatDetector detector;
    for (int i = 0; i < threatDetector::ICMP_FLOOD_THRESHOLD; ++i) {
        QVERIFY(detector.inspectICMP("10.0.0.2", ECHO_REQUEST, T0).empty());
        QVERIFY(detector.inspectICMP("10.0.0.3", ECHO_REQUEST, T0).empty());
    }
}

void TestThreatDetector::synFloodDetected()
{
    threatDetector detector;
    std::string last;
    for (int i = 0; i <= threatDetector::SYN_FLOOD_THRESHOLD; ++i) {
        last = detector.inspectTCP("10.0.0.1", "10.0.0.2", 80, SYN, T0);
    }
    QCOMPARE(labels(last), QString("[SYN FLOOD]"));
}

void TestThreatDetector::synAckIsNotSyn()
{
    threatDetector detector;
    for (int i = 0; i < 100; ++i) {
        QVERIFY(detector.inspectTCP("10.0.0.2", "10.0.0.1", 80, SYN_ACK, T0).empty());
    }
    QCOMPARE(detector.getThreatCount(), 0);
}

void TestThreatDetector::handshakesAreNotFlood()
{
    threatDetector detector;
    for (int i = 0; i < 100; ++i) {
        QVERIFY(detector.inspectTCP("10.0.0.1", "10.0.0.2", 443, SYN, T0).empty());
        QVERIFY(detector.inspectTCP("10.0.0.1", "10.0.0.2", 443, ACK, T0).empty());
    }
}

void TestThreatDetector::tcpPortScan()
{
    threatDetector detector;
    std::string last;
    for (uint16_t port = 1; port <= threatDetector::PORT_SCAN_THRESHOLD; ++port) {
        last = detector.inspectTCP("10.0.0.66", "10.0.0.2", port, SYN, T0);
    }
    QVERIFY(!labels(last).contains("[TCP PORT SCANNING]"));

    last = detector.inspectTCP("10.0.0.66", "10.0.0.2", 6000, SYN, T0);
    QVERIFY(labels(last).contains("[TCP PORT SCANNING]"));
}

void TestThreatDetector::serverRepliesAreNotScan()
{
    // a busy server answers our connections on hundreds of ephemeral ports
    threatDetector detector;
    for (int i = 0; i < 500; ++i) {
        const auto port = static_cast<uint16_t>(49152 + i);
        QVERIFY(detector.inspectTCP("93.184.216.34", "10.0.0.1", port, SYN_ACK, T0).empty());
        QVERIFY(detector.inspectTCP("93.184.216.34", "10.0.0.1", port, ACK, T0).empty());
    }
    QCOMPARE(detector.getThreatCount(), 0);
}

void TestThreatDetector::udpFlood()
{
    threatDetector detector;
    for (int i = 0; i < threatDetector::UDP_FLOOD_THRESHOLD; ++i) {
        QVERIFY(detector.inspectUDP("10.0.0.1", "10.0.0.2", 40000, 9999, T0).empty());
    }
    QCOMPARE(labels(detector.inspectUDP("10.0.0.1", "10.0.0.2", 40000, 9999, T0)), QString("[UDP FLOOD]"));
}

void TestThreatDetector::udpPortScan()
{
    threatDetector detector;
    std::string last;
    for (uint16_t port = 1; port <= threatDetector::PORT_SCAN_THRESHOLD + 1; ++port) {
        last = detector.inspectUDP("10.0.0.66", "10.0.0.2", 40000, port, T0);
    }
    QCOMPARE(labels(last), QString("[UDP PORT SCANNING]"));
}

void TestThreatDetector::udpServiceRepliesAreNotScan()
{
    // DNS answers go to a new random port for every query
    threatDetector detector;
    for (int i = 0; i < 300; ++i) {
        const auto port = static_cast<uint16_t>(50000 + i);
        QVERIFY(detector.inspectUDP("8.8.8.8", "10.0.0.1", 53, port, T0).empty());
    }
}

QTEST_APPLESS_MAIN(TestThreatDetector)
#include "tst_threatdetector.moc"
