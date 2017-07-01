#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <stdio.h>
#include <windows.h>
#include <conio.h>
#include <math.h>
#include <thread>


#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS


void Clear_Screen();

class MyFile
{
private:
	std::vector <unsigned char> _data;
	FILE* _file;

public:
	MyFile() : _file(NULL)
	{

	}

	~MyFile()
	{
		_data.clear();
	}

	std::vector <unsigned char> &GetData()
	{
		return _data;
	}

	bool Open(std::string &name)
	{
		_file = fopen(name.c_str(), "rb");

		if (_file != NULL)
		{
			fseek(_file, 0, SEEK_END);
			int size = ftell(_file);
			rewind(_file);
			_data.resize(size);
			fread(_data.data(), 1, size, _file);
			fclose(_file);
		}
		return !_data.empty();
	}

	bool Write(std::string &name)
	{
		_file = fopen(name.c_str(), "wb");
		bool flag = fwrite(_data.data(), 1, _data.size(), _file);
		fclose(_file);
		return !(flag == false);
	}

	void Close()
	{
		fclose(_file);
	}

	bool Clear_Data()
	{
		_data.clear();
		return !_data.empty();
	}

	static bool File_Exists(LPCTSTR path)
	{
		WIN32_FIND_DATA wfd;
		HANDLE hFind = ::FindFirstFile(path, &wfd);
		if (INVALID_HANDLE_VALUE != hFind)
		{
			::FindClose(hFind);
			return true;
		}
		return false;
	}



	static void Open_Message(MyFile &file, std::string path)
	{
		if (!file.Open(path))
		{
			std::cout << "File " << path << " couldn't be opened." << std::endl;
			return;
		}
		else
		{
			std::cout << "File " << path << " opened." << std::endl;
		}
	}

	static void Write_Message(MyFile &file, std::string path, std::string type)
	{
		if (!file.Write(path))
		{
			std::cout << type << " generation failed." << std::endl;
			return;
		}
		else
		{
			std::cout << type << " generation successful." << std::endl;
		}
	}
};

float Get_Time(int begin, int end)
{
	return (end - begin) * 1.0 / 1000;
}

void Clear_Screen()
{
	HANDLE                     hStdOut;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD                      count;
	DWORD                      cellCount;
	COORD                      homeCoords = { 0, 0 };

	hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdOut == INVALID_HANDLE_VALUE) return;

	if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;
	cellCount = csbi.dwSize.X *csbi.dwSize.Y;

	if (!FillConsoleOutputCharacter(
		hStdOut,
		(TCHAR) ' ',
		cellCount,
		homeCoords,
		&count
	)) return;


	if (!FillConsoleOutputAttribute(
		hStdOut,
		csbi.wAttributes,
		cellCount,
		homeCoords,
		&count
	)) return;

	SetConsoleCursorPosition(hStdOut, homeCoords);
}







//void Open_Message(MyFile &file, std::string path)
//{
//	if (!file.Open(path))
//	{
//		std::cout << "File " << path << " couldn't be opened." << std::endl;
//		return;
//	}
//	else
//	{
//		std::cout << "File " << path << " opened." << std::endl;
//	}
//}