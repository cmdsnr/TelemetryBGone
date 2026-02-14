#include <windows.h>
#include <iostream>
#include "../include/useful.h"

int Test()
{
    std::cout << "Not Available yet." << std::endl;
    return 0;
}

void Prepare()
{
    /*
        Closes all non-system processes before beginning
        telemetry inspection and firewall rule creation.
    */

    char confirm = 'n';

    std::cout << "\n[!] WARNING\n";
    std::cout << "All current running processes will be shutdown\n"
              << "in order to properly block potential telemetry.\n"
              << "Make sure you save anything important.\n\n"
              << "Begin? (y/N): ";

    std::cin >> confirm;

    if (confirm == 'y' || confirm == 'Y')
    {
        std::cout << "\n[+] Shutting down processes...\n";
        ManageProcessShutDown();

        std::cout << "[+] Waiting 10 seconds before analysis...\n";
        Sleep(10000);

        std::cout << "[+] Collecting and analyzing DNS records...\n";
        RecordNames_All();

        std::cout << "[+] Operation complete.\n";
    }
    else
    {
        std::cout << "\n[-] Operation cancelled.\n";
    }
}

void Handler()
{
    int UInput = -1;

    while (true)
    {
        std::cout << "\n==============================\n";
        std::cout << "   TelemetryBGone - Menu\n";
        std::cout << "==============================\n";
        std::cout << "0. Exit\n";
        std::cout << "1. Telemetry (Windows Only)\n";
        std::cout << "2. Advanced Telemetry\n";
        std::cout << "3. Undo All Telemetry\n";
        std::cout << "Select option: ";

        std::cin >> UInput;

        if (!std::cin)
        {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << "\n[!] Invalid input.\n";
            continue;
        }

        switch (UInput)
        {
        case 0:
            std::cout << "\nExiting...\n";
            return;

        case 1:
            Prepare();
            break;

        case 2:
            Test();
            break;

        case 3:
            std::cout << "\n[+] Restoring firewall rules...\n";
            UndoManageTraffic();
            std::cout << "[+] Undo complete.\n";
            break;

        default:
            std::cout << "\n[!] Not a valid option.\n";
            break;
        }
    }
}

int main()
{
    Handler();
    return 0;
}
