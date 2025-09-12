#ifndef UDPHEADER_H
#define UDPHEADER_H

#include <pcap.h>

class UDPHeader {
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint16_t len = 0;
    uint16_t checksum = 0;

public:
    void printUDPHeader() const;
    uint16_t getSrcPort() const;
    uint16_t getDstPort() const;
};

#endif //UDPHEADER_H
