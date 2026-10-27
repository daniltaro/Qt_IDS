#ifndef THREAT_DETECTOR_H
#define THREAT_DETECTOR_H

#include <sys/time.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>

// Looks for floods and port scans in fixed 5-second windows.
// Counters are kept per host, so a threat label goes to the packets
// that take part in the attack, not to whatever packet arrived next.
class threatDetector {
public:
    using Timestamp = std::chrono::microseconds;

    static constexpr Timestamp WINDOW = std::chrono::seconds(5);

    // ICMP echo requests to one host per window
    static constexpr int ICMP_FLOOD_THRESHOLD = 20;

    // SYNs to one host per window, a flood if less than SYN_ACK_RATIO of them get ACKs
    static constexpr int SYN_FLOOD_THRESHOLD = 20;
    static constexpr double SYN_ACK_RATIO = 0.2;

    // UDP packets to one host per window (QUIC and video calls easily do hundreds per second)
    static constexpr int UDP_FLOOD_THRESHOLD = 5000;

    // distinct ports of one host probed by one source per window
    static constexpr std::size_t PORT_SCAN_THRESHOLD = 100;

    static Timestamp toTimestamp(const timeval &tv);

    // each inspect* returns threat labels like "[SYN FLOOD]", empty if the packet looks fine
    std::string inspectICMP(const std::string &dstIP, uint8_t type, Timestamp ts);

    std::string inspectTCP(const std::string &srcIP, const std::string &dstIP,
                           uint16_t dstPort, uint8_t flags, Timestamp ts);

    std::string inspectUDP(const std::string &srcIP, const std::string &dstIP,
                           uint16_t srcPort, uint16_t dstPort, Timestamp ts);

    // number of incidents: one per host and window, not one per flagged packet
    int getThreatCount() const;

private:
    struct Window {
        Timestamp start{};
        int packets = 0;
        int acks = 0;
        std::set<uint16_t> ports;
        bool reported = false;
    };
    using WindowMap = std::map<std::string, Window>;

    // returns the window for key, starting a new one if the old one is over
    Window &window(WindowMap &map, const std::string &key, Timestamp ts);

    void report(Window &w, std::string &labels, const char *label);

    // forgets hosts that were silent for a whole window
    void dropExpired(Timestamp ts);

    int threatCount = 0;
    Timestamp lastCleanup{};

    WindowMap icmpFlood; // by destination
    WindowMap synFlood;  // by destination
    WindowMap udpFlood;  // by destination
    WindowMap tcpScan;   // by "source -> destination"
    WindowMap udpScan;   // by "source -> destination"
};

#endif //THREAT_DETECTOR_H
