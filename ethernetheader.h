#ifndef ETHERNETHEADER_H
#define ETHERNETHEADER_H

#include <pcap.h>

class EthernetHeader {
    u_char destMAC[6];
    u_char srcMAC[6];
    uint16_t etherType;

public:
    uint16_t type() const;
};

#endif //ETHERNETHEADER_H
