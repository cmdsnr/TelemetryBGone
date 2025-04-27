#include <windows.h>
#include <iostream>
#include "../include/useful.h"

int Test() {
	std::cout << "Not Available yet." << std::endl; 
	return 0;
}

void Prepare() {
	/*
	Closes all software only focusing on system based telemetry
	*/
	char confirm;
	std::cout << "All current running processes will be shutdown in order to properly block potential telemetry.\nMake sure you save anything you might need before confirming.\n Begin? (y/N)";
	std::cin >> confirm;

	if (confirm == 'y') {
	ManageProcessShutDown();
	Sleep(10000); // sleep 10 seconds before starting
	RecordNames_All();
	}
}

void Handler() {
	int UInput;
	std::cout << "Choose An Option Below. (Use Numbers to select option)" << "\n0. Exit\n1. Telemetry (Windows Telemetry Only)\n2. Advanced Telemetry\n3.Undo All Telemetry\nElse Default.\n";
	while (1) {
		std::cin >> UInput;
		switch (UInput) {
		case 0:
			exit(0);
		case 1:
			Prepare();
			break;
		case 2:
			Test();
		case 3:
			UndoManageTraffic();
		default:
			std::cout << "Not An Option." << std::endl;
		}
	}
}

int main() {
	Handler();
}
