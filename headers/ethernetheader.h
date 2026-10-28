#ifndef ETHERNETHEADER_H
#define ETHERNETHEADER_H

#include <cstddef>
#include <cstdint>

class EthernetHeader {
    uint8_t destMAC[6] = {};
    uint8_t srcMAC[6] = {};
    uint16_t etherType = 0;

public:
    static constexpr std::size_t SIZE = 14;
    static constexpr uint16_t TYPE_IPV4 = 0x0800;

    // copies the header out of raw packet bytes, false if there are not enough of them
    static bool parse(const uint8_t *data, std::size_t len, EthernetHeader &out);

    uint16_t type() const;
};

#endif //ETHERNETHEADER_H
