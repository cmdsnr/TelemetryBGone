#include <iostream>
#pragma once
#ifndef USEFUL_H
#define USEFUL_H

typedef unsigned int UINTSEN;

UINTSEN ShutProcess(DWORD pid);
UINTSEN ManageProcessShutDown();
UINTSEN IsWindowsRecord(BSTR Record);


BSTR ConvertToBSTR(const std::string& str);
BSTR ResolveHost(const char* resolveHost);

void ManageTraffic(BSTR recordName, UINTSEN UNDO);
void RecordNames_All();
void UndoManageTraffic();

#endif
