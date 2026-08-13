#pragma once

#include "mac.h"
#include "ip.h"

// 지정한 네트워크 인터페이스의 MAC 주소를 가져온다.
bool getInterfaceMac(
    const char* interfaceName,
    Mac& mac
    );

// 지정한 네트워크 인터페이스의 IPv4 주소를 가져온다.
bool getInterfaceIp(
    const char* interfaceName,
    Ip& ip
    );