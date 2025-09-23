#include "udpheader.h"
#include <iostream>

void UDPHeader::printUDPHeader() const {
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

    std::cout << "length - ";
    printf("%d\n", ntohs(len));
}

uint16_t UDPHeader::getSrcPort() const {
    return ntohs(srcPort);
}

uint16_t UDPHeader::getDstPort() const {
    return ntohs(dstPort);
}
