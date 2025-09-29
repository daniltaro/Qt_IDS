#include "basehandler.h"
#include "../headers/tcpheader.h"
#include "../headers/icmpheader.h"
#include "../headers/udpheader.h"
#include "../headers/ipv4header.h"

#include <thread>
#include <fstream>
#include <chrono>
#include <nlohmann/json.hpp>

extern std::string save_buf;
using json = nlohmann::json;

BaseHandler::BaseHandler( bool all,  bool tcp,
                                 bool udp,  bool icmp) {
    all_packets = all;
    tcp_prot = tcp;
    udp_prot = udp;
    icmp_prot = icmp;
}

void BaseHandler::StaticHandle(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    BaseHandler *data = reinterpret_cast<BaseHandler *>(args);
    data->Handle(header, packet);
}

QString BaseHandler::getPayload(const u_char *payload, const uint32_t &len) const {
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

void BaseHandler::printStatistic() {
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
