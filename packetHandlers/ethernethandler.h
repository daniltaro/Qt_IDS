#ifndef ETHERNETHANDLER_H
#define ETHERNETHANDLER_H

#include <pcap.h>
#include "../threatDetector/threatdetector.h"
#include "basehandler.h"

class EthernetHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;

    //main func where packets are captured
    void Handle( const struct pcap_pkthdr *header, const u_char *packet);

    //getting buffer ready for save
    void saveJsonStatistic(const struct pcap_pkthdr *header,
                       const u_char *packet, bool flag, const std::string& type) const;
};

#endif //ETHERNETHANDLER_H
