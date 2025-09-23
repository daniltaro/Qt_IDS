#ifndef ETHERNETHANDLER_H
#define ETHERNETHANDLER_H

#include <pcap.h>
#include "threatdetector.h"
#include "basehandler.h"

class EthernetHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;

    void Handle( const struct pcap_pkthdr *header, const u_char *packet);

    void saveStatistic(const struct pcap_pkthdr *header,
                       const u_char *packet, bool flag, const std::string& type) const;
};

#endif //ETHERNETHANDLER_H
