#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <chrono>
#include <nlohmann/json.hpp>
#include <QDebug>
#include <QString>

#include "ethernethandler.h"
#include "ethernetheader.h"
#include "ipv4header.h"
#include "tcpheader.h"
#include "udpheader.h"
#include "icmpheader.h"

#define ETHERTYPE_IPV4 0x0800
#define LINK_OFFSET 14

using json = nlohmann::json;
extern std::string save_buf;

EthernetHandler::EthernetHandler( bool all,  bool tcp,
                                 bool udp,  bool icmp) {
    all_packets = all;
    tcp_prot = tcp;
    udp_prot = udp;
    icmp_prot = icmp;
}

QString EthernetHandler::getPayload(const u_char *payload, const uint32_t &len) const {
    int offset = 0;
    QString hex;

    for (int i = 0; i < len; i += 16) {
        hex += QString("0x%1: ").arg(offset, 4, 16, QChar('0'));

        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                hex += QString("%1 ").arg(payload[i + j], 2, 16, QChar('0'));
            } else {
                hex += "   ";
            }
        }

        hex += " | ";

        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                const u_char ch = payload[i + j];
                hex += ((ch >= 32 && ch <= 126) ? QChar(ch) : QChar('.'));
            }
        }
        hex += '\n';

        offset += 16;
    }
    return hex;
}

void EthernetHandler::Handle(const struct pcap_pkthdr *header,
                             const u_char *packet) {
    auto *ethernetHeader = (EthernetHeader *) packet;
    if (ethernetHeader->type() != ETHERTYPE_IPV4) return;

    auto *ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);

    const u_char ihl = ipv4Header->versionIHLGet() & 0x0F;
    const uint16_t ipHeaderLength = ihl * 4;

    std::string type = "";
    bool show_packet = false;

    packData.srcDst = QString::fromStdString
        (ipv4Header->getSrcIP() + " -> " + ipv4Header->getDstIP());

    //checking for suspicious
    if((icmp_prot || all_packets) && ipv4Header->protocolType() == 1){
        show_packet = true;
        protocolCounter[ICMP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        if(icmpHeader->getType() == 8){
            threatDec.icmpTypeAdd();
        }

        if(threatDec.isSuspiciousICMP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveStatistic( header, packet, true, type);
        } else {
            packData.type = "-";
            this->saveStatistic( header, packet, false, type);
        }

    } if((tcp_prot || all_packets) && ipv4Header->protocolType() == 6){
        show_packet = true;
        protocolCounter[TCP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstTCP(ipv4Header->getSrcIP(), tcpHeader->getDstPort());

        if (tcpHeader->getFlag() & 0x02) threatDec.tcpSYNAdd();
        else if(tcpHeader->getFlag() & 0x10) threatDec.tcpACKAdd();

        if(threatDec.isSuspiciousTCP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveStatistic(header, packet, true, type);
        } else {
            packData.type = "-";
            this->saveStatistic( header, packet, false, type);
        }

    } if((udp_prot || all_packets) && ipv4Header->protocolType() == 17){
        show_packet = true;
        protocolCounter[UDP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;
        threatDec.udpAdd();

        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstUDP(ipv4Header->getSrcIP(), udpHeader->getDstPort());

        if(threatDec.issuspiciousUDP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveStatistic( header, packet, true, type);
        } else {
            packData.type = "-";
            this->saveStatistic( header, packet, false, type);
        }

    }

    if(show_packet == false) return;
    pack_count++;

    std::cout << "packet len - " << std::dec << header->caplen << "\n\n";
    std::cout << "ETHERNET HEADER:"<< '\n';
    ethernetHeader->printEthernetHeader();
    std::cout << '\n';
    std::cout << "IPV4 HEADER:"<< '\n';
    ipv4Header->printIPv4Header();

    //parse and output
    if (ipv4Header->protocolType() == 6) {
        packData.protocol = "TCP";

        std::cout << '\n';
        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "TCP HEADER:"<< '\n';
        tcpHeader->printTCPHeader();
        const uint8_t dataOffset = (tcpHeader->dataOffsetReservedGet() >> 4) * 4;

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + dataOffset);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength)
            << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << "\n[ " << threatDec.getThreatCount()
                      << " THREAT FOUND ]" << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + dataOffset;
        packData.hex = getPayload(payload, payloadLength);
        emit packetCaptured(packData);
    } else if (ipv4Header->protocolType() == 17) {
        packData.protocol = "UDP";

        std::cout << '\n';
        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "UDP HEADER:"<< '\n';
        udpHeader->printUDPHeader();

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + 8);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength)
            << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << "\n[ " << threatDec.getThreatCount()
                      << " THREAT FOUND ]" << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + 8;
        packData.hex = getPayload(payload, payloadLength);
        emit packetCaptured(packData);
    } else if (ipv4Header->protocolType() == 1) {
        packData.protocol = "ICMP";

        std::cout << '\n';
        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        std::cout << "ICMP HEADER:"<< '\n';
        icmpHeader->printICMPHeader();

        int icmpLen = 8;
        if (icmpHeader->getType() == 5 || icmpHeader->getType() == 11) {
            switch (icmpHeader->getCode()) {
            case 3:
            case 11:
            case 12: icmpLen = 36;
                break;
            case 5: icmpLen = 12;
                break;
            case 13:
            case 14: icmpLen = 20;
                break;
            default: icmpLen = 8;
                break;
            }
        }

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + icmpLen);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength)
            << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            packData.hex = "no payload";
            std::cout << "no payload" << std::endl;
            std::cout << "\n[ " <<  threatDec.getThreatCount()
                      << " THREAT FOUND ]" << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + icmpLen;
        packData.hex = getPayload(payload, payloadLength);
        emit packetCaptured(packData);
    }
    std::cout <<"\n[ " <<  threatDec.getThreatCount()
              <<" THRE AT FOUND ]" << "\n";
}

void EthernetHandler::printStatistic() {
    QString stat;
    stat += "------------------------------\n";
    stat += "TCP protocols - " + QString::number(protocolCounter[TCP]) + "\n";
    stat += "UDP protocols - " +  QString::number(protocolCounter[UDP]) + "\n";
    stat += "ICMP protocols - " + QString::number(protocolCounter[ICMP]) + "\n";
    stat += "Threat count - " + QString::number(threatDec.getThreatCount()) + "\n";
    stat += "Packets count - " + QString::number(pack_count) + "\n";

    for (const auto &entry: ipv4Counter) {
        stat += QString::fromStdString(entry.first) + " - " + QString::number(entry.second) + "\n";
    }
    stat += "------------------------------\n";

    emit statReady(stat);
}

void EthernetHandler::saveGenStatistic() {

    save_buf += "{\n";
    save_buf += "  \"TCP\": " + std::to_string(protocolCounter[TCP]) + ",\n";
    save_buf += "  \"UDP\": " + std::to_string(protocolCounter[UDP]) + ",\n";
    save_buf += "  \"ICMP\": " + std::to_string(protocolCounter[ICMP]) + ",\n";
    save_buf += "   \"IP_Stats\": {\n";

    bool first = true;
    for (const auto &entry: ipv4Counter) {
        if (!first) {
            save_buf +=",\n";
        }
        save_buf += "    \"" + entry.first + "\": " + std::to_string(entry.second);
        first = false;
    }
    save_buf += "\n  },\n";
    save_buf +="  \"timestamp\": \"";
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&time_point);
    time_str.pop_back();
    save_buf += time_str +"\"\n";
    save_buf += "}\n";
}

void EthernetHandler::saveStatistic(const struct pcap_pkthdr *header,
                                    const u_char *packet, bool flag, const std::string& type) const{
    json j;
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&time_point);
    time_str.pop_back();
    j["timestamp"] = time_str;

    auto *ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);
    j["src_ip"] = ipv4Header->getSrcIP();
    j["dst_ip"] = ipv4Header->getDstIP();

    const u_char ihl = ipv4Header->versionIHLGet() & 0x0F;
    const uint16_t ipHeaderLength = ihl * 4;

    if (ipv4Header->protocolType() == 6){
        j["protocol"] = "TCP";
        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        j["src_port"] = tcpHeader->getSrcPort();
        j["dst_port"] = tcpHeader->getDstPort();
    }
    else if (ipv4Header->protocolType() == 17){
        j["protocol"] = "UDP";
        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        j["src_port"] = udpHeader->getSrcPort();
        j["dst_port"] = udpHeader->getDstPort();
    }
    else if (ipv4Header->protocolType() == 1) j["protocol"] = "ICMP";

    j["length"] = header->caplen;
    j["threat"] = flag;
    if(flag) j["type"] = type;

    if(commaFlag) save_buf += ",\n";
    commaFlag = true;

    static std::mutex lock;
    std::lock_guard<std::mutex> lock_g(lock);
    save_buf += j.dump();
}

