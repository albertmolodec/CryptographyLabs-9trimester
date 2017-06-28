#include "MyFile.h"
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\sha.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\hex.h"
#include "..\third-party\src\CryptoPP\base64.h"
#include <iomanip>


class SHA256
{
private:
	MyFile plaintext;
	MyFile hash;
	std::string plaintext_path = "../shared/plaintext.docx";
	std::string hash_path = "../shared/hash_SHA256.txt";
public:
	void Generate_Hash_SHA256()
	{
		std::cout << "Hash is generating..." << std::endl;
		Open_Message(plaintext, plaintext_path);

		int plain_size = plaintext.GetData().size();
		std::string str_plain = "";
		std::string str_hash = "";

		for (int i = 0; i < plain_size; i++)
		{
			str_plain += plaintext.GetData()[i];
		}

		CryptoPP::SHA256 sha256;
		CryptoPP::StringSource(str_plain, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(str_hash))));

		for (int i = 0; i < str_hash.size(); i += 2)
		{
			unsigned char tmp = ((unsigned char)str_hash[i] << 4) + (unsigned char)str_hash[i + 1];
			hash.GetData().push_back(tmp);
		}

		Clear_Screen();
		Write_Message(hash, hash_path, "SHA256 file");
	}


};

int main()
{
	SHA256 obj;
	obj.Generate_Hash_SHA256();
	system("pause");
	return 0;
}
