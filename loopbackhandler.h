#ifndef LOOPBACKHANDLER_H
#define LOOPBACKHANDLER_H

#include <pcap.h>
#include "threatdetector.h"
#include "basehandler.h"

class LoopBackHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;

    void Handle(const struct pcap_pkthdr *header, const u_char *packet);

    void saveStatistic(const struct pcap_pkthdr *header,
                       const u_char *packet, bool flag, const std::string& type) const;
};

#endif //LOOPBACKHANDLER_H
