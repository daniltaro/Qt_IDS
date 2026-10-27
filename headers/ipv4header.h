#ifndef IPV4HEADER_H
#define IPV4HEADER_H

#include <cstddef>
#include <cstdint>
#include <string>

class Ipv4Header {
    uint8_t versionIHL = 0;
    uint8_t dscpEcn = 0;
    uint16_t totalLen = 0;
    uint16_t id = 0;
    uint16_t fragOffset = 0;
    uint8_t ttl = 0;
    uint8_t protocol = 0;
    uint16_t checkSum = 0;
    uint8_t srcIP[4] = {};
    uint8_t dstIP[4] = {};

public:
    static constexpr std::size_t MIN_SIZE = 20;

    // copies the fixed part of the header and checks version and IHL against len
    static bool parse(const uint8_t *data, std::size_t len, Ipv4Header &out);

    uint8_t protocolType() const;

    // header length in bytes, options included
    std::size_t headerLength() const;

    // datagram length from the header, may be 0 for packets captured before TSO
    std::size_t totalLength() const;

    // non-first fragments carry only payload, without a transport header
    bool isLaterFragment() const;

    std::string getSrcIP() const;

    std::string getDstIP() const;
};

#endif //IPV4HEADER_H
