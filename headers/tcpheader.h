#ifndef TCPHEADER_H
#define TCPHEADER_H

#include <pcap.h>

class TCPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seq;
    uint32_t ack;
    u_char dataOffsetReserved;
    u_char flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPointer;

public:
    u_char dataOffsetReservedGet() const;

    uint16_t getSrcPort() const;

    uint16_t getDstPort() const;

    u_char getFlag() const;
};

#endif //TCPHEADER_H
