#ifndef TCPHEADER_H
#define TCPHEADER_H

#include <cstddef>
#include <cstdint>

class TCPHeader {
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t dataOffsetReserved = 0;
    uint8_t flag = 0;
    uint16_t window = 0;
    uint16_t checksum = 0;
    uint16_t urgentPointer = 0;

public:
    static constexpr std::size_t MIN_SIZE = 20;

    static constexpr uint8_t FIN = 0x01;
    static constexpr uint8_t SYN = 0x02;
    static constexpr uint8_t RST = 0x04;
    static constexpr uint8_t PSH = 0x08;
    static constexpr uint8_t ACK = 0x10;

    // copies the fixed part of the header and checks the data offset against len
    static bool parse(const uint8_t *data, std::size_t len, TCPHeader &out);

    // header length in bytes, options included
    std::size_t headerLength() const;

    uint16_t getSrcPort() const;

    uint16_t getDstPort() const;

    uint8_t getFlag() const;
};

#endif //TCPHEADER_H
