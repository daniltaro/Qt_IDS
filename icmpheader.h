#ifndef ICMPHEADER_H
#define ICMPHEADER_H

#include <pcap.h>

class ICMPHeader {
    u_char type;
    u_char code;
    uint16_t checksum;

public:
    u_char getType() const;
    u_char getCode() const;
};

#endif //ICMPHEADER_H
