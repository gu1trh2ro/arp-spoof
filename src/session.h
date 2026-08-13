#pragma once

#include <vector>

#include "ip.h"
#include "mac.h"

// 하나의 ARP Spoofing 연결 정보를 저장한다.
//
// sIp, sMac : Sender의 IP/MAC
// tIp, tMac : Target의 IP/MAC
struct Session {
    Ip sIp;
    Ip tIp;
    Mac sMac;
    Mac tMac;
};

// 명령행 인자가 다음 형식인지 검사한다.
//
// send-arp <interface> <sender ip> <target ip>
//          [<sender ip> <target ip> ...]
inline bool isValidSessionArguments(int argc) {
    return argc >= 4 && (argc - 2) % 2 == 0;
}

// 명령행 인자로 받은 Sender/Target IP 쌍을
// Session vector로 변환한다.
inline std::vector<Session> makeSessions(
    int argc,
    char* argv[]
    ) {
    std::vector<Session> sessions;

    for (int i = 2; i < argc; i += 2) {
        Session session;

        session.sIp = Ip(argv[i]);
        session.tIp = Ip(argv[i + 1]);

        sessions.push_back(session);
    }

    return sessions;
}