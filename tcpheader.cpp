#include "tcpheader.h"
#include <iostream>

void TCPHeader::printTCPHeader() const {
    const uint8_t dataOffset = (dataOffsetReserved >> 4) * 4;
    std::cout << "dataOffset - " << (int) dataOffset << " bytes\n";
    std::cout << "sequence number - " << ntohl(seq) << std::endl;
    std::cout << "acknowledgment number - " << ntohl(ack) << std::endl;

    std::cout << "source port - ";
    if (ntohs(srcPort) == 7) std::cout << "ECHO\n";
    else if (ntohs(srcPort) == 9) std::cout << "DISCARD\n";
    else if (ntohs(srcPort) == 20 || ntohs(srcPort) == 21) std::cout << "FTP\n";
    else if (ntohs(srcPort) == 22) std::cout << "SSH\n";
    else if (ntohs(srcPort) == 23) std::cout << "Telnet\n";
    else if (ntohs(srcPort) == 25) std::cout << "SMTP\n";
    else if (ntohs(srcPort) == 53) std::cout << "DNS\n";
    else if (ntohs(srcPort) == 80) std::cout << "HTTP\n";
    else if (ntohs(srcPort) == 143) std::cout << "IMAP\n";
    else if (ntohs(srcPort) == 443) std::cout << "HTTPS\n";
    else if (ntohs(srcPort) == 8080) std::cout << "HTTP\n";
    else printf("%d\n", ntohs(srcPort));

    std::cout << "destination port - ";
    if (ntohs(dstPort) == 7) std::cout << "ECHO\n";
    else if (ntohs(dstPort) == 20 || ntohs(dstPort) == 21) std::cout << "FTP\n";
    else if (ntohs(dstPort) == 22) std::cout << "SSH\n";
    else if (ntohs(dstPort) == 23) std::cout << "Telnet\n";
    else if (ntohs(dstPort) == 25) std::cout << "SMTP\n";
    else if (ntohs(dstPort) == 53) std::cout << "DNS\n";
    else if (ntohs(dstPort) == 80) std::cout << "HTTP\n";
    else if (ntohs(dstPort) == 143) std::cout << "IMAP\n";
    else if (ntohs(dstPort) == 443) std::cout << "HTTPS\n";
    else if (ntohs(dstPort) == 8080) std::cout << "HTTP\n";
    else printf("%d\n", ntohs(dstPort));

    std::cout << "flags - ";
    if (flag & 0x01) std::cout << "FIN ";
    if (flag & 0x02) std::cout << "SYN ";
    if (flag & 0x04) std::cout << "RST ";
    if (flag & 0x08) std::cout << "PSH ";
    if (flag & 0x10) std::cout << "ACK ";
    if (flag & 0x20) std::cout << "URG ";
    if (flag & 0x40) std::cout << "ECE ";
    if (flag & 0x80) std::cout << "CWR ";
    std::cout << std::endl;
}

u_char TCPHeader::dataOffsetReservedGet() const {
    return dataOffsetReserved;
}

uint16_t TCPHeader::getSrcPort() const {
    return ntohs(srcPort);
}

uint16_t TCPHeader::getDstPort() const {
    return ntohs(dstPort);
}

u_char TCPHeader::getFlag() const{
    return flag;
}
