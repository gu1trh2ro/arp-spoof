#pragma once

#include <pcap.h>
#include <vector>

#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"
#include "session.h"

#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

#pragma pack(pop)

// 상대방의 MAC 주소를 구하기 위한 정상 ARP Request 생성
EthArpPacket makeArpRequest(
    const Mac& aMac,
    const Ip& aIp,
    const Ip& requestedIp
    );

// Sender에게 Target의 MAC이 Attacker의 MAC인 것처럼
// 알려주기 위한 감염 ARP Reply 생성
EthArpPacket makeInfectionReply(
    const Mac& aMac,
    const Mac& sMac,
    const Ip& sIp,
    const Ip& tIp
    );

// ARP 패킷 전송
bool sendArpPacket(
    pcap_t* pcap,
    const EthArpPacket& packet
    );

// ARP Reply를 수신하여 requestedIp에 해당하는 MAC 주소 저장
bool receiveMac(
    pcap_t* pcap,
    const Mac& aMac,
    const Ip& aIp,
    const Ip& requestedIp,
    Mac& resolvedMac
    );

// 특정 IP에 정상 ARP Request를 보내 MAC 주소 조회
bool resolveMac(
    pcap_t* pcap,
    const Mac& aMac,
    const Ip& aIp,
    const Ip& requestedIp,
    Mac& resolvedMac
    );

// 모든 Session의 Sender/Target MAC 주소 조회
bool resolveAllSessionMacs(
    pcap_t* pcap,
    const Mac& aMac,
    const Ip& aIp,
    std::vector<Session>& sessions
    );

// 하나의 Session에 ARP 감염 패킷 전송
bool infectSession(
    pcap_t* pcap,
    const Mac& aMac,
    const Session& session
    );

// 모든 Session에 최초 ARP 감염 패킷 전송
bool infectAllSessions(
    pcap_t* pcap,
    const Mac& aMac,
    const std::vector<Session>& sessions
    );

// Target이 보낸 정상 ARP Reply 등을 감지했을 때
// Sender를 다시 감염시킨다.
void handleArpPacket(
    pcap_t* pcap,
    const EthArpPacket& arpPacket,
    const Mac& aMac,
    const std::vector<Session>& sessions
    );

// Sender의 ARP Table을 정상 정보로 복구하는 ARP Reply 생성
EthArpPacket makeRecoveryReply(
    const Session& session
    );

// 하나의 Session을 정상 상태로 복구
bool recoverSession(
    pcap_t* pcap,
    const Session& session
    );

// 모든 Session을 정상 상태로 복구
bool recoverAllSessions(
    pcap_t* pcap,
    const std::vector<Session>& sessions
    );