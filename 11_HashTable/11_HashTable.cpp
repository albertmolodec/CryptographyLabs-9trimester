#include <MyFile.h>
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\des.h"
#include "..\third-party\src\CryptoPP\modes.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\filters.h"
#include "..\third-party\src\CryptoPP\cbcmac.h"
#include "..\third-party\src\CryptoPP\sha.h"
#include "..\third-party\src\CryptoPP\base64.h"
#include "..\third-party\src\CryptoPP\hex.h"
#include <direct.h>


#define FILE_ATTRIBUTE_READONLY             0x00000001
#define FILE_ATTRIBUTE_HIDDEN               0x00000002
#define FILE_ATTRIBUTE_SYSTEM               0x00000004
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000 
#define STRLEN(x) (sizeof(x)/sizeof(x[0]) - 1)

void Print(std::vector<unsigned char> &text);


class aFile
{
private:
	std::string path;
	std::string file_name;
	std::string alternate_file_name;
	std::string creation_time;
	std::string last_access_time;
	std::string last_write_time;
	int size;
	bool is_readonly;
	bool is_hidden;
	bool is_system;
	bool is_directory;
	bool is_archive;
	bool is_temporary;
	bool is_compressed;
	bool is_encrypted;

public:
	aFile()
	{

	}

	aFile(std::string path, std::string file_name, std::string alternate_file_name, std::string creation_time, std::string last_access_time, std::string last_write_time, int size,
		bool is_readonly, bool is_hidden, bool is_system, bool is_directory, bool is_archive, bool is_temporary, bool is_compressed, bool is_encrypted)
	{
		this->path = path;
		this->file_name = file_name;
		this->alternate_file_name = alternate_file_name;
		this->creation_time = creation_time;
		this->last_access_time = last_access_time;
		this->last_write_time = last_write_time;
		this->size = size;
		this->is_readonly = is_readonly;
		this->is_hidden = is_hidden;
		this->is_system = is_system;
		this->is_directory = is_directory;
		this->is_archive = is_archive;
		this->is_temporary = is_temporary;
		this->is_compressed = is_compressed;
		this->is_encrypted = is_encrypted;
	}

	std::string Get_Creation_Time()
	{
		return creation_time;
	}

	std::string Get_Name()
	{
		return file_name;
	}

	std::string Get_Path()
	{
		return path;
	}

	bool Is_Directory()
	{
		return is_directory;
	}

	int Get_Size()
	{
		return size;
	}

	void Print_Attributes()
	{
		std::cout << "Path: " << path << std::endl;
		std::cout << "File name: " << file_name << std::endl;
		std::cout << "Alt file name: " << alternate_file_name << std::endl;
		std::cout << "Creation time: " << creation_time << std::endl;
		std::cout << "Last access time: " << last_access_time << std::endl;
		std::cout << "Last write time: " << last_write_time << std::endl;
		std::cout << "Size: " << size << std::endl;
		std::cout << "Is readonly: " << is_readonly << std::endl;
		std::cout << "Is hidden: " << is_hidden << std::endl;
		std::cout << "Is system: " << is_system << std::endl;
		std::cout << "Is directory: " << is_directory << std::endl;
		std::cout << "Is archive: " << is_archive << std::endl;
		std::cout << "Is temporary: " << is_temporary << std::endl;
		std::cout << "Is compressed: " << is_compressed << std::endl;
		std::cout << "Is encrypted: " << is_encrypted << std::endl;
	}

	std::string Get_Full_Attr()
	{
		return path + file_name + alternate_file_name + creation_time + last_access_time + last_write_time + std::to_string(size) +
			std::to_string(is_readonly) + std::to_string(is_hidden) + std::to_string(is_directory) + std::to_string(is_archive) +
			std::to_string(is_temporary) + std::to_string(is_compressed) + std::to_string(is_encrypted);
	}

	std::string Time_To_String(FILETIME ftime)
	{
		SYSTEMTIME utc;
		::FileTimeToSystemTime(std::addressof(ftime), std::addressof(utc));

		std::ostringstream stm;
		const auto w2 = std::setw(2);
		stm << std::setfill('0') << std::setw(4) << utc.wYear << '-' << w2 << utc.wMonth
			<< '-' << w2 << utc.wDay << ' ' << w2 << utc.wYear << ' ' << w2 << utc.wHour
			<< ':' << w2 << utc.wMinute << ':' << w2 << utc.wSecond << '.';

		return stm.str();
	}

	void Fill_aFile(aFile &file, std::string path_str)
	{
		WIN32_FIND_DATAA data;
		std::string path = path_str;
		HANDLE hFile = FindFirstFileA(path.c_str(), &data);

		bool is_readonly = false;
		bool is_hidden = false;
		bool is_system = false;
		bool is_directory = false;
		bool is_archive = false;
		bool is_temporary = false;
		bool is_compressed = false;
		bool is_encrypted = false;

		std::string file_name = data.cFileName;
		std::string alternate_file_name = data.cAlternateFileName;
		int file_size = data.nFileSizeLow;

		if (hFile != INVALID_HANDLE_VALUE)
		{
			if (data.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
				is_readonly = true;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
				is_hidden = true;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
				is_system = true;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				is_directory = true;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
				is_archive = true;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY)
				is_temporary = true;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED)
				is_compressed = true;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)
				is_encrypted = true;
		}


		file = aFile(path_str, file_name, alternate_file_name, Time_To_String(data.ftCreationTime), Time_To_String(data.ftLastAccessTime), Time_To_String(data.ftLastWriteTime), file_size,
			is_readonly, is_hidden, is_system, is_directory, is_archive, is_temporary, is_compressed, is_encrypted);

	}



};


class Hash
{
private:
	int block_size = 16;
	std::string str_plain;
	std::vector<unsigned char> hash;
	aFile current_file;
public:
	Hash()
	{

	}

	std::vector<unsigned char> Generate_Hash_SHA256(std::string str_plain)
	{
		std::vector<unsigned char> bytes_plain;
		hash.clear();

		for (int i = 0; i < str_plain.size(); i++)
		{
			bytes_plain.push_back(str_plain[i]);
		}

		hash.resize(block_size);
		CryptoPP::SHA256 sha256;
		CryptoPP::ArraySink cs(&hash[0], hash.size());
		CryptoPP::ArraySource(bytes_plain.data(), bytes_plain.size(), true, new CryptoPP::HashFilter(sha256, new CryptoPP::ArraySink(cs)));

		return hash;
	}

	std::vector<unsigned char> Generate_Hash_My(std::string str_plain)
	{
		std::vector<unsigned char> bytes_plain;
		std::vector<unsigned char> iv;
		hash.clear();

		for (int i = 0; i < str_plain.size(); i++)
		{
			bytes_plain.push_back(str_plain[i]);
		}

		bytes_plain.resize(block_size);

		for (int i = 0; i < block_size; i++)
		{
			unsigned char perem = i << 2;
			int plain_index = i % block_size;
			iv.push_back(bytes_plain[plain_index] * perem + 17);
		}

		for (int i = 0; i < block_size; i++)
		{
			hash.push_back((iv[i]) ^ (i << 5) >> 2);
		}

		if (bytes_plain.size() > block_size)
		{
			for (int i = 0; i < bytes_plain.size(); i++)
			{
				hash[i % block_size] ^= bytes_plain[i];
			}
		}
		else
		{
			for (int i = 0; i < block_size; i++)
			{
				hash[i] ^= bytes_plain[i % bytes_plain.size()];
			}
		}

		return hash;
	}

	void Create_Table(std::vector<std::vector<aFile>> &hash_table, std::string path, int func_type, int i, int j, float alpha)
	{
		WIN32_FIND_DATAA folder_data;
		HANDLE hf;



		hf = FindFirstFile((path + "\\*").c_str(), &folder_data);

		if (hf == INVALID_HANDLE_VALUE)
		{
			return;
		}
		else
		{
			do
			{
				if (current_file.Is_Directory())
				{
					Create_Table(hash_table, path + "\\", func_type, i, j, alpha);
				}

			} while (FindNextFileA(hf, &folder_data)); //&& (((float)i / j) < alpha));
			FindClose(hf);
		}
	}

	void first(std::string path, int func_type)
	{
		current_file.Fill_aFile(current_file, path);
		str_plain = current_file.Get_Full_Attr();
		if (func_type == 1)
		{
			Generate_Hash_SHA256(str_plain);
		}
		else if (func_type == 2)
		{
			Generate_Hash_My(str_plain);
		}

		std::cout << str_plain << std::endl;
	}



};




int main()
{
	aFile obj;
	Hash obj_hash;
	std::string root = "E:\\new";
	std::vector<std::vector<aFile>> hash_table;
	hash_table.resize(65536);
	obj.Fill_aFile(obj, root);
	int func_type = 1;


	std::cout << "Select hash function type: 1 - SHA256, 2 - Albert Molodec's." << std::endl;
	std::cin >> func_type;
	Clear_Screen();

	obj_hash.first(root, func_type);
	obj_hash.Create_Table(hash_table, root, func_type, 0, 0, 1.3);


	//std::cout << "Plain text: " << obj.Get_Full_Attr();
	//std::cout << std::endl;
	//obj.Print_Attributes();

	system("pause");
	return 0;
}













void Print(std::vector<unsigned char> &text)
{
	for (int i = 0; i < text.size(); i++)
	{
		std::cout << text[i];
	}
	std::cout << std::endl;
}