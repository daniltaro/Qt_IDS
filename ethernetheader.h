#ifndef ETHERNETHEADER_H
#define ETHERNETHEADER_H

#include <pcap.h>

class EthernetHeader {
    u_char destMAC[6];
    u_char srcMAC[6];
    uint16_t etherType;

    void printMAC(const u_char *mac) const;

public:
    void printEthernetHeader() const;

    uint16_t type() const;
};

#endif //ETHERNETHEADER_H
