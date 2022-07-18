#include "arp.h"


static char* arp_request(char* ip) {
	IPAddr DestIP = inet_addr(ip);
	IPAddr SrcIp = INADDR_ANY;
	ULONG MacAddr[2];
	ULONG PhysAddrLen = 6;
    BYTE* bPhysAddr;

	memset(MacAddr, 0xff, sizeof(MacAddr));
	DWORD dwRetVal = SendARP(DestIP, SrcIp, &MacAddr, &PhysAddrLen);
    char* MAC = calloc(CHAR_MAX, sizeof(char));
    char M[121];
    if (dwRetVal == NO_ERROR) {
        bPhysAddr = (BYTE*)&MacAddr;
        if (PhysAddrLen) {
            for (int i = 0; i < (int)PhysAddrLen; i++) {
                if (i == (PhysAddrLen - 1)) {
                    sprintf(M, "%.2X", (int)bPhysAddr[i]);
                    strcat(MAC, M);
                }

                else {
                    sprintf(M,"%.2X:", (int)bPhysAddr[i]);
                    strcat(MAC, M);
                }
            }
            return MAC;
        }
        else {
            return NULL;
        }
    }
    else {
        return NULL;
    }
}


char* get_mac_address(char* ip) {
    return arp_request(ip);
}