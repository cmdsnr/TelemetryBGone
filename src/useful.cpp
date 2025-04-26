#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <netfw.h>
#include <vector>
#include <sstream>
#include <WinDNS.h>
#include <tlhelp32.h>
#include <iphlpapi.h>

typedef unsigned int UINTSEN;

#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Ws2_32.lib")


/*

CONSTANTS

*/
const char* FblockedRecord = "blockedRecords.txt";


/*
FUNCTIONS
*/

UINTSEN ShutProcess(DWORD pid) {
	/*
	Shut Process through PID
	*/
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	UINTSEN exitkill = 9;
	TCHAR tPath[MAX_PATH];
	DWORD size = MAX_PATH;
	if (hProcess == NULL) {
		std::cout << "Failed to OpenProcess: " << GetLastError();
		return -1;
	}
	else if (QueryFullProcessImageName(hProcess,0,tPath,&size)) {
		std::wstring fullPath = tPath;
		std::wstring s32Path = L"C:\\Windows\\System32";
		if (fullPath.find(s32Path) == 0) {
			CloseHandle(hProcess);
			return 1;
		}
	}
	else {
		TerminateProcess(hProcess, exitkill);
		CloseHandle(hProcess);
		return 0;
	}
}

UINTSEN ManageProcessShutDown() {
	/*
	Shut all processes in the snapshot
	*/
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		std::cout << "Invalid Handle Value: " << GetLastError();
		return -1;
	}
	PROCESSENTRY32 pEntry;
	if (Process32First(hSnap, &pEntry)) {
		do {
			ShutProcess(pEntry.th32ProcessID);
		} while (Process32Next(hSnap,&pEntry));
	}

	return 0;
}

BSTR ResolveHost(const char* resolveHost) {
	/*
	DNS --> Returns IP Address.
	*/
	PDNS_RECORD QuerySaver;
	DNS_STATUS Resolve = DnsQuery_A((PCSTR)resolveHost, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &QuerySaver, NULL);

	DWORD ipRaw = QuerySaver->Data.A.IpAddress;
	//convert DWORD to char* then BSTR
	struct in_addr ipStruct;
	ipStruct.S_un.S_addr = ipRaw;
	char* ipChar = inet_ntoa(ipStruct); 

	int len = MultiByteToWideChar(CP_ACP, 0, ipChar, -1, NULL, 0);
	BSTR ipBstr = SysAllocStringLen(NULL, len);
	MultiByteToWideChar(CP_ACP, 0, ipChar, -1, ipBstr, len);
	
	return ipBstr;
}

void ManageTraffic(BSTR recordName, UINTSEN UNDO) {
	/*
	Blocks / Unblocks a record.
	*/
	INetFwPolicy2* pPolicy = nullptr;
	INetFwRules* pRules = nullptr;

	// the firewall policy object
	HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2), (void**)&pPolicy);

	if (FAILED(hr)) return;

	hr = pPolicy->get_Rules(&pRules);
	if (FAILED(hr)) {
		pPolicy->Release();
		return;
	}

	// remove the rule if it already exists
	pRules->Remove(recordName);

	if (UNDO == 1) {
		// undoes everything
		pRules->Release();
		pPolicy->Release();
		return;
	}

	// Add a new block rule
	INetFwRule* Traffic = nullptr;
	CoCreateInstance(CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER, IID_INetFwRule, (void**)&Traffic);

	if (Traffic) {
		BSTR ResolvedHost = ResolveHost((const char*)recordName);
		Traffic->put_Name(recordName);
		Traffic->put_Enabled(VARIANT_TRUE);
		Traffic->put_Action(NET_FW_ACTION_BLOCK);
		Traffic->put_Direction(NET_FW_RULE_DIR_OUT);
		Traffic->put_RemoteAddresses(ResolvedHost);
		Traffic->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
		Traffic->put_Profiles(NET_FW_PROFILE2_ALL);

		pRules->Add(Traffic);
		Traffic->Release();
	}

	pRules->Release();
	pPolicy->Release();
}


BSTR ConvertToBSTR(const std::string& str) {
	/*
	Helper for BSTR conversion
	*/
	int lenW = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
	BSTR bstr = SysAllocStringLen(NULL, lenW - 1);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, bstr, lenW);
	return bstr;
}

UINTSEN IsWindowsRecord(BSTR Record) {
	/*
	Checks if the record has been sent through svchost == Windows Specific Telemetry.
	*/
	DWORD size = 0;
	PMIB_TCPTABLE_OWNER_PID pTCPTABLE = NULL;
	GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	pTCPTABLE = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
	GetExtendedTcpTable(pTCPTABLE, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

	PDNS_RECORD dnsRecord;
	if (DnsQuery_A((PCSTR)Record, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &dnsRecord, NULL) != 0) {
		free(pTCPTABLE);
		return 0;
	}
	DWORD resolvedIP = dnsRecord->Data.A.IpAddress;
	DnsRecordListFree(dnsRecord, DnsFreeRecordList);

	for (DWORD i = 0; i < pTCPTABLE->dwNumEntries; i++) {
		MIB_TCPROW_OWNER_PID row = pTCPTABLE->table[i];
		if (row.dwRemoteAddr == resolvedIP) {
			HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
			if (hProc) {
				TCHAR path[MAX_PATH];
				DWORD pathSize = MAX_PATH;
				if (QueryFullProcessImageName(hProc, 0, path, &pathSize)) {
					std::wstring procPath = path;
					if (procPath.find(L"svchost.exe") != std::wstring::npos) {
						CloseHandle(hProc);
						free(pTCPTABLE);
						return 1;
					}
				}
				CloseHandle(hProc);
			}
		}
	}
	free(pTCPTABLE);
	return 0;
}

void RecordNames_All() {
	/*
	Gets All Outside DNS connections being made & Blocks WinTelemetry.
	*/

	// Flushing DNS
	//system("ipconfig /flushdns");
	//std::cout << "DNS Flushed." << std::endl;


	system("ipconfig /displaydns > dnsSet[TelemetryBGONE].txt");
	std::cout << "Saved DNS. Analyzing. . . . ." << std::endl;
	
	std::string flname = "dnsSet[TelemetryBGONE].txt";
	std::ostringstream stream;
	stream << "Getting DNS Records: " << flname;

	std::string bufferText = stream.str(); //include formatted string here
	std::string bufferFile;
	std::cout << bufferText << std::endl;

	std::fstream Read(flname);
	std::string rcord = "    Record Name . . . . . :";
	std::string rcord2 = "";

	std::ofstream BlockedRecordsFile(FblockedRecord);

	while (getline(Read, bufferFile)) {

		if (bufferFile.substr(0, rcord.length()) == rcord) {
			bufferFile.erase(0, rcord.length() + 1);

			BSTR recordBstr = ConvertToBSTR(bufferFile);
			UINTSEN result = IsWindowsRecord(recordBstr);

			if (result == 0) {
				continue;
			}
			else if (result == 1) { // block if winRecord
				//block the traffic.
				BlockedRecordsFile << bufferFile << "\n"; // keep track of what record has been blocked
				ManageTraffic(recordBstr,0);
			}
			SysFreeString(recordBstr); // free bstr 
		}
	}
	Read.close();
}

void UndoManageTraffic() {
	/*
	Undo the traffic blocked.
	*/
	std::string Buffer;
	std::ifstream ReadBlockedRecordFile(FblockedRecord);
	while (getline(ReadBlockedRecordFile, Buffer)) {
		std::cout << "[+] Undoing: " << Buffer << "\n";
		BSTR recordBstr = ConvertToBSTR(Buffer);
		ManageTraffic(recordBstr, 1);
		SysFreeString(recordBstr);
	}
	return;
}

/*
DNS
*.microsoft.com
*.msftconnecttest.com
*.msftncsi.com
*.office365.com
*.skype.com
*.windowsupdate.com
*.live.com
*.outlook.com


CDNs
*.azureedge.net
*.msecnd.net
*.trafficmanager.net
*.msedge.net
*.akadns.net
*.config.skype.com
*.bing.com
*.microsoftonline.com
*/
