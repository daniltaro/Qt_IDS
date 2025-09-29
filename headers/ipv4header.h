#ifndef IPV4HEADER_H
#define IPV4HEADER_H

#include <pcap.h>
#include <string>

class Ipv4Header {
    u_char versionIHL;
    u_char dscpEcn;
    uint16_t totalLength;
    uint16_t id;
    uint16_t fragOffset;
    u_char ttl;
    u_char protocol;
    uint16_t checkSum;
    u_char srcIP[4];
    u_char dstIP[4];

public:
    u_char protocolType() const;

    u_char versionIHLGet() const;

    std::string getSrcIP() const;

    std::string getDstIP() const;
};

#endif //IPV4HEADER_H
