#include "MyFile.h"
#include <tlhelp32.h>
#include <map>
#include <iterator>
#include <algorithm>

VOID ProcessInfo(std::map <int, std::string> &map) // 
{
	PROCESSENTRY32 pe;
	HANDLE CONST snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &pe);
	char buf[100];
	do
	{
		wcstombs(buf, pe.szExeFile, sizeof(pe.szExeFile));
		std::string conv_name = buf;
		map.insert(std::pair <int, std::string>(pe.th32ProcessID, conv_name));
	} while (Process32Next(snapshot, &pe));
	CloseHandle(snapshot);
}

int main()
{
	std::map <int, std::string> a;
	std::map <int, std::string> b;
	std::map <int, std::string> diff;
	bool isEnd = false;
	ProcessInfo(a);
	std::cout << "           Press any button to end this. \n           ____________________________\n\n";
	while (!isEnd)
	{
		if (_kbhit())
		{
			isEnd = true;
		}
		Sleep(100);
		ProcessInfo(b);

		std::set_difference(b.begin(), b.end(), a.begin(), a.end(),
			std::inserter(diff, diff.begin()));
		if (!diff.empty())
		{
			for (auto item = diff.begin(); item != diff.end(); item++)
			{
				std::cout << "Started: " << item->first << " / " << item->second << "\n";
			}
		}
		diff.clear();

		std::set_difference(a.begin(), a.end(), b.begin(), b.end(),
			std::inserter(diff, diff.begin()));
		if (!diff.empty())
		{
			for (auto item = diff.begin(); item != diff.end(); item++)
			{
				std::cout << "Closed: " << item->first << " / " << item->second << "\n";
			}
		}
		diff.clear();

		a = b;
		b.clear();
	}
	std::cout << "           ____________________________\n\n";
	system("pause");
	return 0;
}

