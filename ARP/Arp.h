#pragma once

#define HAVE_REMOTE
#include <stdlib.h>
#include <WinSock2.h>
#include <CommCtrl.h>
#include <Windows.h>

#include <pcap.h>
#include <remote-ext.h>

#include "resource.h"
#include "Protocol.h"



extern HWND hwnd;


int StartCheat();
DWORD WINAPI SendArpPacket(LPVOID lpParam);
BOOL FillHeaders();
BOOL MacStrToMac(WCHAR *MacStr, unsigned char *Mac);