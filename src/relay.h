#pragma once

#include <pcap.h>
#include <vector>

#include "mac.h"
#include "session.h"

// 지정한 인터페이스를 pcap live capture로 연다.
pcap_t* openPacketCapture(
    const char* interfaceName
    );

// Ethernet 종류와 관계없이 패킷 하나를 수신하여 vector에 복사한다.
bool receivePacket(
    pcap_t* pcap,
    std::vector<u_char>& packet
    );

// 받은 IPv4 패킷의 Ethernet MAC 주소를 변경하여
// 해당 Session의 Target에게 Relay한다.
bool relayPacket(
    pcap_t* pcap,
    std::vector<u_char>& packet,
    const Mac& aMac,
    const Mac& tMac
    );

// 모든 패킷을 지속해서 수신하고 IPv4 Relay 또는
// ARP 재감염 처리를 수행하는 공통 수신 루프
bool runPacketLoop(
    pcap_t* pcap,
    const Mac& aMac,
    const std::vector<Session>& sessions
    );

// Ctrl+C가 입력되면 공통 패킷 수신 루프의 종료를 요청한다.
void requestPacketLoopStop();