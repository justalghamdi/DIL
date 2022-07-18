#include "shared.h"
#include "arp.h"


#define MAX_IANA 255

//#define DEBUG 

char* title;


DWORD WINAPI find_arp(const char *ip) {
	ZeroMemory(title, strlen(title));
	sprintf(title, "[ TOOL BY JUSTALGHAMDI | ARP SCANNING | insta: @justalghamdi ] - STATUS [ %s ]", ip);
	SetConsoleTitle(title);
	char* mac_address = get_mac_address(ip);
	if (mac_address != NULL) {
		printf("IP=%s -> MAC=%s\n", ip, mac_address);
		free(mac_address);
	}
#ifdef DEBUG
	else {
		printf("IP=%s -> MAC=<null>\n", ip);
	}
#endif // DEBUG

	
	ExitThread(0);
}

#define THREADSMAX 255

int main() {
	title = calloc(255,sizeof(char));
	strcat(title ,"[ TOOL BY JUSTALGHAMDI | ARP SCANNING | insta: @justalghamdi ] - STATUS [ <N/A> ]");
	SetConsoleTitle(title);

	/*
	*  ______________________________________________________________________________________________________________________________________________________________________________________ 
	*  |RFC 1918 name  |    IP address range       |     Number of addresses    | Largest CIDR block (subnet mask)  | Host ID size	|	    Mask bits	|	    Classful description		|
	*  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	*  |16-bit block -  192.168.0.0 – 192.168.255.255	     65,536					192.168.0.0/16 (255.255.0.0)		16 bits				16 bits			256 contiguous class C networks	|
	*  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	*/

	int count_threads = 0;
	char ip [30];
	char* _ip;
	HANDLE lpHandles[THREADSMAX];
	HANDLE thread;

	for (int j = 0; j < MAX_IANA; j++) {
		for (int l = 0; l < MAX_IANA; l++) {	
			sprintf(&ip, "192.168.%d.%d", j, l);
			_ip = _strdup(ip);
			thread = CreateThread(NULL, 0, find_arp, _ip, 0, NULL);
			lpHandles[count_threads] = thread;
			if (count_threads >= THREADSMAX) {
				WaitForMultipleObjects(THREADSMAX, lpHandles, TRUE, INFINITE);
				for (int thread_index = 0; thread_index < THREADSMAX; thread_index++) {
					CloseHandle(lpHandles[thread_index]);
				}
				count_threads = 0;
				Sleep(500);
			}
			count_threads++;
		}
	}
}


