#ifndef LOOPBACKHANDLER_H
#define LOOPBACKHANDLER_H

#include <pcap.h>
#include "threatdetector.h"
#include "basehandler.h"

class LoopBackHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;

    //main func where packets are captured
    void Handle(const struct pcap_pkthdr *header, const u_char *packet);

    //getting buffer ready for save
    void saveJsonStatistic(const struct pcap_pkthdr *header,
                       const u_char *packet, bool flag, const std::string& type) const;
};

#endif //LOOPBACKHANDLER_H
