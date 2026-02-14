#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <vector>
#include <sstream>

#include <netfw.h>
#include <WinDNS.h>
#include <tlhelp32.h>
#include <iphlpapi.h>

#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Ws2_32.lib")

typedef unsigned int UINTSEN;

/*
====================================================
CONSTANTS
====================================================
*/

const char* FblockedRecord = "blockedRecords.txt";

/*
====================================================
PROCESS MANAGEMENT
====================================================
*/

UINTSEN ShutProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    UINTSEN exitkill = 9;

    if (!hProcess)
    {
        std::cout << "Failed to OpenProcess: " << GetLastError() << "\n";
        return static_cast<UINTSEN>(-1);
    }

    TCHAR tPath[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageName(hProcess, 0, tPath, &size))
    {
        std::wstring fullPath = tPath;
        std::wstring systemPath = L"C:\\Windows\\System32";

        if (fullPath.find(systemPath) == 0)
        {
            CloseHandle(hProcess);
            return 1;
        }
    }
    else
    {
        TerminateProcess(hProcess, exitkill);
        CloseHandle(hProcess);
        return 0;
    }

    CloseHandle(hProcess);
    return 1;
}

UINTSEN ManageProcessShutDown()
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::cout << "Invalid Handle Value: " << GetLastError() << "\n";
        return static_cast<UINTSEN>(-1);
    }

    PROCESSENTRY32 pEntry{};
    pEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pEntry))
    {
        do
        {
            ShutProcess(pEntry.th32ProcessID);
        }
        while (Process32Next(hSnap, &pEntry));
    }

    CloseHandle(hSnap);
    return 0;
}

/*
====================================================
DNS RESOLUTION
====================================================
*/

BSTR ResolveHost(const char* resolveHost)
{
    PDNS_RECORD queryResult = nullptr;

    DNS_STATUS status = DnsQuery_A(
        resolveHost,
        DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &queryResult,
        NULL
    );

    if (status != 0 || !queryResult)
        return nullptr;

    DWORD ipRaw = queryResult->Data.A.IpAddress;

    in_addr ipStruct{};
    ipStruct.S_un.S_addr = ipRaw;

    char* ipChar = inet_ntoa(ipStruct);

    int len = MultiByteToWideChar(CP_ACP, 0, ipChar, -1, NULL, 0);
    BSTR ipBstr = SysAllocStringLen(NULL, len);

    MultiByteToWideChar(CP_ACP, 0, ipChar, -1, ipBstr, len);

    DnsRecordListFree(queryResult, DnsFreeRecordList);

    return ipBstr;
}

/*
====================================================
FIREWALL MANAGEMENT
====================================================
*/

void ManageTraffic(BSTR recordName, UINTSEN UNDO)
{
    INetFwPolicy2* pPolicy = nullptr;
    INetFwRules* pRules = nullptr;

    HRESULT hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        (void**)&pPolicy
    );

    if (FAILED(hr))
        return;

    hr = pPolicy->get_Rules(&pRules);

    if (FAILED(hr))
    {
        pPolicy->Release();
        return;
    }

    pRules->Remove(recordName);

    if (UNDO == 1)
    {
        pRules->Release();
        pPolicy->Release();
        return;
    }

    INetFwRule* Traffic = nullptr;

    CoCreateInstance(
        CLSID_NetFwRule,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_INetFwRule,
        (void**)&Traffic
    );

    if (Traffic)
    {
        BSTR resolvedHost = ResolveHost((const char*)recordName);

        Traffic->put_Name(recordName);
        Traffic->put_Enabled(VARIANT_TRUE);
        Traffic->put_Action(NET_FW_ACTION_BLOCK);
        Traffic->put_Direction(NET_FW_RULE_DIR_OUT);
        Traffic->put_RemoteAddresses(resolvedHost);
        Traffic->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
        Traffic->put_Profiles(NET_FW_PROFILE2_ALL);

        pRules->Add(Traffic);

        if (resolvedHost)
            SysFreeString(resolvedHost);

        Traffic->Release();
    }

    pRules->Release();
    pPolicy->Release();
}

/*
====================================================
HELPERS
====================================================
*/

BSTR ConvertToBSTR(const std::string& str)
{
    int lenW = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
    BSTR bstr = SysAllocStringLen(NULL, lenW - 1);

    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, bstr, lenW);

    return bstr;
}

UINTSEN IsWindowsRecord(BSTR Record)
{
    DWORD size = 0;

    GetExtendedTcpTable(
        NULL,
        &size,
        TRUE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    );

    auto* tcpTable =
        (PMIB_TCPTABLE_OWNER_PID)malloc(size);

    GetExtendedTcpTable(
        tcpTable,
        &size,
        TRUE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    );

    PDNS_RECORD dnsRecord;

    if (DnsQuery_A((PCSTR)Record, DNS_TYPE_A,
                   DNS_QUERY_BYPASS_CACHE,
                   NULL, &dnsRecord, NULL) != 0)
    {
        free(tcpTable);
        return 0;
    }

    DWORD resolvedIP = dnsRecord->Data.A.IpAddress;
    DnsRecordListFree(dnsRecord, DnsFreeRecordList);

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++)
    {
        auto& row = tcpTable->table[i];

        if (row.dwRemoteAddr == resolvedIP)
        {
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                row.dwOwningPid
            );

            if (hProc)
            {
                TCHAR path[MAX_PATH];
                DWORD pathSize = MAX_PATH;

                if (QueryFullProcessImageName(hProc, 0,
                                              path, &pathSize))
                {
                    std::wstring procPath = path;

                    if (procPath.find(L"svchost.exe") != std::wstring::npos)
                    {
                        CloseHandle(hProc);
                        free(tcpTable);
                        return 1;
                    }
                }

                CloseHandle(hProc);
            }
        }
    }

    free(tcpTable);
    return 0;
}

/*
====================================================
DNS RECORD ANALYSIS
====================================================
*/

void RecordNames_All()
{
    system("ipconfig /displaydns > dnsSet[TelemetryBGONE].txt");

    std::cout << "[+] DNS snapshot saved. Analyzing...\n";

    std::string filename = "dnsSet[TelemetryBGONE].txt";
    std::fstream readFile(filename);

    std::ofstream blockedFile(FblockedRecord);

    const std::string recordPrefix = "    Record Name . . . . . :";
    std::string line;

    while (std::getline(readFile, line))
    {
        if (line.substr(0, recordPrefix.length()) == recordPrefix)
        {
            line.erase(0, recordPrefix.length() + 1);

            BSTR recordBstr = ConvertToBSTR(line);
            UINTSEN result = IsWindowsRecord(recordBstr);

            if (result == 1)
            {
                blockedFile << line << "\n";
                ManageTraffic(recordBstr, 0);
            }

            SysFreeString(recordBstr);
        }
    }

    readFile.close();
}

void UndoManageTraffic()
{
    std::ifstream readFile(FblockedRecord);
    std::string buffer;

    while (std::getline(readFile, buffer))
    {
        std::cout << "[+] Undoing: " << buffer << "\n";

        BSTR recordBstr = ConvertToBSTR(buffer);
        ManageTraffic(recordBstr, 1);
        SysFreeString(recordBstr);
    }
}
