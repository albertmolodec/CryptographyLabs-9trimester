#include "MyFile.h"
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\rsa.h"
#include "..\third-party\src\CryptoPP\modes.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\filters.h"
#include "..\third-party\src\CryptoPP\base64.h"



class SHA256
{
private:
	MyFile plaintext;
	MyFile ciphertext;
	MyFile decryptedtext;
	MyFile publickey;
	MyFile privatekey;
	std::string plaintext_path = "../shared/plaintext.docx";
	std::string ciphertext_path = "../shared/ciphertext.docx";
	std::string decryptedtext_path = "../shared/decryptedtext.doc";
	std::string publickey_path = "../shared/publickey";
	std::string privatekey_path = "../shared/privatekey";
public:
	SHA256()
	{

	}


};

int main()
{



	system("pause");
	return 0;
}
