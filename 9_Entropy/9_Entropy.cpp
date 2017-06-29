#include "MyFile.h"
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\sha.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\hex.h"
#include "..\third-party\src\CryptoPP\base64.h"
#include "..\third-party\src\Zip\zip.h"


class Hash
{
private:
	MyFile plaintext;
	MyFile hash;
	MyFile hash_SHA256;
	std::string plaintext_path = "../shared/plaintext.doc";
	std::string hash_path = "../shared/hash_my.txt";
	std::string hash_SHA256_path = "../shared/hash_SHA256.txt";

	std::string Generate_1block(std::string text)
	{
		int block_size = 32;
		std::string result = "";
		std::vector<unsigned char> iv;

		for (int i = 0; i < block_size; i++)
		{
			unsigned char perem = i << 2;
			int plain_index = i % text.size();
			iv.push_back(text[plain_index] * perem + 17);
		}

		for (int i = 0; i < block_size; i++)
		{
			result += (iv[i]) ^ (i / 2);
		}

		if (text.size() > block_size)
		{
			for (int i = 0; i < text.size(); i++)
			{
				result[i % block_size] ^= text[i];
			}
		}
		else
		{
			for (int i = 0; i < block_size; i++)
			{
				result[i] ^= text[i % text.size()];
			}
		}
		return result;
	}
public:
	void Generate_Hash()
	{
		std::cout << "My hash is generating..." << std::endl;
		Open_Message(plaintext, plaintext_path);

		std::string str_plain = "";
		std::string str_hash = "";
		
		int block_size = 32;
		int plain_size = plaintext.GetData().size();
		int full_size = plain_size;
		while (full_size % block_size != 0)
		{
			full_size++;
		}
		plaintext.GetData().resize(full_size);

		for (int i = plain_size; i < full_size; i++)
		{
			plaintext.GetData()[i] = 0;
		}

		for (int j = 0; j < full_size / block_size; j++)
		{
			for (int i = 0; i < block_size; i++)
			{
				str_plain += plaintext.GetData()[block_size * j + i] + j;
			}

			str_hash = Generate_1block(str_plain);

			for (int i = 0; i < block_size; i++)
			{
				hash.GetData().push_back(str_hash[i]);
			}

			str_hash = "";
			str_plain = "";
		}

		Clear_Screen();
		Write_Message(hash, hash_path, "Hash file");
	}

	void Generate_Hash_SHA256()
	{
		std::cout << "Hash SHA256 is generating..." << std::endl;
		Open_Message(plaintext, plaintext_path);
		
		std::string str_plain = "";
		std::string str_hash = "";

		int block_size = 32;
		int plain_size = plaintext.GetData().size();
		int full_size = plain_size;
		while (full_size % block_size != 0)
		{
			full_size++;
		}
		plaintext.GetData().resize(full_size);

		for (int i = plain_size; i < full_size; i++)
		{
			plaintext.GetData()[i] = 0;
		}

		for (int j = 0; j < full_size / block_size; j++)
		{
			for (int i = 0; i < block_size; i++)
			{
				str_plain += plaintext.GetData()[block_size * j + i] + j;
			}

			CryptoPP::SHA256 sha256;
			CryptoPP::StringSource(str_plain, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(str_hash))));

			for (int i = 0; i < block_size; i++)
			{
				hash_SHA256.GetData().push_back(str_hash[i]);
			}

			str_hash = "";
		}

		Clear_Screen();
		Write_Message(hash_SHA256, hash_SHA256_path, "SHA256 file");
	}
};

class Entropy
{
private:
	MyFile text;

	double logarithm(double base, double x)
	{
		return (log(x) / log(base));
	}
public:
	double Get_Entropy8(std::string path)
	{
		text.Open(path);
		int a[256];
		double entropy = 0;
		for (int i = 0; i < 256; i++)
		{
			a[i] = 0;
		}
		uint8_t data = (uint8_t)text.GetData().data();
		for (int i = 0; i < text.GetData().size(); i++)
		{
			a[(int)data]++;
			data++;
		}
		for (int i = 0; i < 256; i++)
		{
			if (a[i] != 0)
				entropy -= (a[i] * 1.0) / ((int)text.GetData().size()) * logarithm(8, a[i] * 1.0 / ((int)text.GetData().size()));
		}

		return entropy;
	}

	double Get_Entropy16(std::string path)
	{
		text.Open(path);
		int a[65536];
		double entropy = 0;
		for (int i = 0; i < 65536; i++)
		{
			a[i] = 0;
		}
		uint16_t *data = (uint16_t*)text.GetData().data();
		for (int i = 0; i < text.GetData().size() / 2; i++)
		{
			a[(int)*data]++;
			data++;
		}

		for (int i = 0; i < 65536; i++)
		{
			if (a[i] != 0)
				entropy -= (a[i] * 1.0) / (text.GetData().size() / 2) * logarithm(16, a[i] * 1.0 / (text.GetData().size() / 2));
		}

		return entropy;
	}

	double Get_Entropy16_Overlay(std::string path)
	{
		text.Open(path);
		int a[65536];
		double entropy = 0;
		for (int i = 0; i < 65536; i++)
		{
			a[i] = 0;
		}
		uint8_t *data = (uint8_t*)text.GetData().data();
		uint16_t *data2 = (uint16_t*)text.GetData().data();

		for (int i = 0; i < text.GetData().size() - 1; i++)
		{
			data2 = (uint16_t*)data;
			a[(int)*data2]++;
			data++;

		}

		for (int i = 0; i < 65536; i++)
		{
			if (a[i] != 0)
				entropy -= (a[i] * 1.0) / (text.GetData().size() - 1) * logarithm(16, a[i] * 1.0 / (text.GetData().size() - 1));
		}

		return entropy;
	}


};

void Zip_File(std::string zip_path, std::string filename_inside, std::string plaintext_path)
{
	TCHAR *str_zip = new TCHAR[zip_path.size() + 1];
	str_zip[zip_path.size()] = 0;
	std::copy(zip_path.begin(), zip_path.end(), str_zip);

	TCHAR *str_filename_inside = new TCHAR[filename_inside.size() + 1];
	str_filename_inside[filename_inside.size()] = 0;
	std::copy(filename_inside.begin(), filename_inside.end(), str_filename_inside);

	TCHAR *str_plaintext_path = new TCHAR[plaintext_path.size() + 1];
	str_plaintext_path[plaintext_path.size()] = 0;
	std::copy(plaintext_path.begin(), plaintext_path.end(), str_plaintext_path);

	HZIP hz = CreateZip(str_zip, 0);
	ZipAdd(hz, str_filename_inside, str_plaintext_path);
	CloseZip(hz);
}

void Select_Type(Entropy &obj, std::string path, std::string name)
{
	int ent_type;
	Clear_Screen();
	std::cout << "Select a type of entropy calculating." << std::endl;
	std::cout << "1) 8 bit" << std::endl;
	std::cout << "2) 16 bit" << std::endl;
	std::cout << "3) 16 bit (with overlay)" << std::endl;
	std::cin >> ent_type;
	Clear_Screen();
	switch (ent_type)
	{
	case 1:
	{
		std::cout << "8 bit entropy of " << name << ": " << obj.Get_Entropy8(path) << std::endl;
		break;
	}
	case 2:
	{
		std::cout << "16 bit entropy of " << name << ": " << obj.Get_Entropy16(path) << std::endl;
		break;
	}
	case 3:
	{
		std::cout << "16 bit entropy  " << name << " (with overlay): " << obj.Get_Entropy16_Overlay(path) << std::endl;
		break;
	}
	}
}

double Compression_Ratio(std::string file_path, std::string zip_path)
{
	MyFile file;
	MyFile zip;
	file.Open(file_path);
	zip.Open(zip_path);
	return (1 - zip.GetData().size() * 1.0 / file.GetData().size()) * 100;
}

int main()
{
	Hash my_hash;
	my_hash.Generate_Hash();
	my_hash.Generate_Hash_SHA256();

	std::string plaintext_path = "../shared/plaintext";
	std::string hash_my_path = "../shared/hash_my";
	std::string hash_SHA256_path = "../shared/hash_SHA256";

	Zip_File(plaintext_path + ".zip", "plaintext.doc", plaintext_path + ".doc");
	Zip_File(hash_my_path + ".zip", "hash_my.txt", hash_my_path + ".txt");
	Zip_File(hash_SHA256_path + ".zip", "hash_SHA256.txt", hash_SHA256_path + ".txt");

	Entropy obj;
	int answer = 1;
	int mode;
	while (answer == 1)
	{
		Clear_Screen();
		std::cout << "What to do? (enter the desired value)" << std::endl;
		std::cout << "1) Calculate entropy of plain text" << std::endl;
		std::cout << "2) Calculate entropy of hashed file (by my function)" << std::endl;
		std::cout << "3) Calculate entropy of hashed file (by SHA256)" << std::endl;
		std::cout << "4) Calculate compression ratio of compressed plain text" << std::endl;
		std::cout << "5) Calculate compression ratio of compressed hashed file (by my function)" << std::endl;
		std::cout << "6) Calculate compression ratio of compressed hashed file (by SHA256)" << std::endl;
		std::cout << std::endl;
		std::cin >> mode;

		Clear_Screen();
		switch (mode)
		{
		case 1:
		{
			std::cout << "Entropy of plain text: ";
			Select_Type(obj, plaintext_path + ".doc", "plain text");
			break;
		}
		case 2:
		{
			std::cout << "Entropy of hashed file (by my function): ";
			Select_Type(obj, hash_my_path + ".txt", "hashed file (by my function)");
			break;
		}
		case 3:
		{
			std::cout << "Entropy of hashed file (by SHA256): ";
			Select_Type(obj, hash_SHA256_path + ".txt", "hashed file (by SHA256)");
			break;
		}
		case 4:
		{
			std::cout << "Compression ratio of compressed plain text: " << Compression_Ratio(plaintext_path + ".doc", plaintext_path + ".zip") << " %";
			
			break;
		}
		case 5:
		{
			std::cout << "Compression ratio of compressed hashed file (by my function): " << Compression_Ratio(hash_my_path + ".txt", hash_my_path + ".zip") << " %";
			break;
		}
		case 6:
		{
			std::cout << "Compression ratio of compressed hashed file (by SHA256): " <<	Compression_Ratio(hash_SHA256_path + ".txt", hash_SHA256_path + ".zip") << " %";
			break;
		}
		}



		std::cout << std::endl << "Again? (1 - Yes, 2 - No)" << std::endl;
		std::cin >> answer;
		Clear_Screen();
	}
	return 0;
}
