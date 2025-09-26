#ifndef THREAT_DETECTOR_H
#define THREAT_DETECTOR_H

#include <chrono>
#include <pcap.h>
#include <map>
#include <set>

class threatDetector{
    //ICMP
    int icmp_count = 0;
    int threatCount = 0;
    std::chrono::steady_clock::time_point start_timeICMP = std::chrono::steady_clock::now();

    //TCP
    int tcpSYN = 0;
    int tcpACK = 0;
    std::map<std::string, std::set<uint16_t>> TCPscanner;
    std::chrono::steady_clock::time_point start_timeTCP = std::chrono::steady_clock::now();

    //UDP
    int UDP_packets = 0;
    std::map<std::string, std::set<uint16_t>> UDPscanner;
    std::chrono::steady_clock::time_point start_timeUDP = std::chrono::steady_clock::now();

public:
    //checks ICMP packets for suspicious
    bool isSuspiciousICMP(std::string& type);

    void icmpTypeAdd();

    int getThreatCount() const;

    //checks TCP packets for suspicious
    bool isSuspiciousTCP(std::string& type);

    void tcpSYNAdd();

    void tcpACKAdd();

    void udpAdd();

    //checks UDP packets for suspicious
    bool issuspiciousUDP(std::string& type);

    void addIPv4srcDstTCP(const std::string& ip, const u_int16_t& dst_ports);

    void addIPv4srcDstUDP(const std::string& ip, const u_int16_t& dst_ports);
};

#endif //THREAT_DETECTOR_H
