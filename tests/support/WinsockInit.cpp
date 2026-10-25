// One WSAStartup for the whole test binary (#1136). Winsock refuses every call
// until it has run, and several tests open sockets before any product code does.
// Compiles to nothing off Windows.
#if defined(_WIN32) || defined(_WIN64)
#include "net_compat.h"

namespace
{
	struct WinsockInit
	{
		WinsockInit()
		{
			WSADATA wsa;
			(void)WSAStartup(MAKEWORD(2, 2), &wsa);
		}
		~WinsockInit() { WSACleanup(); }
	};
	const WinsockInit g_winsockInit;
}
#endif
