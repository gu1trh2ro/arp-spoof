#include "interface_utils.h"

#include <cstdio>
#include <cstring>
#include <cstdint>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// 1. 나의 MAC, IP 자동 조회
// 2. 정상 ARP Request 전송
// 3. Sender의 ARP Reply 수신
// 4. Sender MAC 추출
// 5. 감염 패킷을 만들어 Sender에게 전송

// 지정한 인터페이스의 MAC 주소 저장
bool getInterfaceMac(
    const char* interfaceName,
    Mac& mac
    ) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr{};

    std::strncpy(
        ifr.ifr_name,
        interfaceName,
        IFNAMSIZ - 1
        );

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return false;
    }

    mac = Mac{
        reinterpret_cast<const uint8_t*>(
            ifr.ifr_hwaddr.sa_data
            )
    };

    close(sock);
    return true;
}

// 지정한 인터페이스의 IP 주소 저장
bool getInterfaceIp(
    const char* interfaceName,
    Ip& ip
    ) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr{};

    std::strncpy(
        ifr.ifr_name,
        interfaceName,
        IFNAMSIZ - 1
        );

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return false;
    }

    struct sockaddr_in* addr =
        reinterpret_cast<struct sockaddr_in*>(
            &ifr.ifr_addr
            );

    ip = Ip(ntohl(addr->sin_addr.s_addr));

    close(sock);
    return true;
}