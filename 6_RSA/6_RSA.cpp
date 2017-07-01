#include "MyFile.h"
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\rsa.h"
#include "..\third-party\src\CryptoPP\modes.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\filters.h"
#include "..\third-party\src\CryptoPP\base64.h"



class Key
{
private:
	MyFile publickey;
	MyFile privatekey;
	std::string publickey_path = "../shared/publickey";
	std::string privatekey_path = "../shared/privatekey";
public:
	void Generate_Keys()
	{
		std::string str_public;
		std::string str_private;		

		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::InvertibleRSAFunction privkey;

		privkey.Initialize(rng, 1024);
		CryptoPP::Base64Encoder privatekey_sink(new CryptoPP::StringSink(str_private), false);
		privkey.DEREncode(privatekey_sink);
		privatekey_sink.MessageEnd();

		CryptoPP::RSAFunction pubkey(privkey);
		CryptoPP::Base64Encoder publickey_sink(new CryptoPP::StringSink(str_public), false);
		pubkey.DEREncode(publickey_sink);
		publickey_sink.MessageEnd();

		for (int i = 0; i < str_public.size(); i++)
		{
			publickey.GetData().push_back(str_public[i]);
		}
		for (int i = 0; i < str_private.size(); i++)
		{
			privatekey.GetData().push_back(str_private[i]);
		}

		Write_Message(publickey, publickey_path, "Public key");
		Write_Message(privatekey, privatekey_path, "Private key");
		system("pause");
		Clear_Screen();
	}
};


class RSA
{
private:
	MyFile plaintext;
	MyFile ciphertext;
	MyFile decryptedtext;
	MyFile publickey;
	MyFile privatekey;
	std::string plaintext_path = "../shared/plaintext.doc";
	std::string ciphertext_path = "../shared/ciphertext.docx";
	std::string decryptedtext_path = "../shared/decryptedtext.doc";
	std::string publickey_path = "../shared/publickey";
	std::string privatekey_path = "../shared/privatekey";
public:
	RSA()
	{

	}

	void Encryption()
	{
		Clear_Screen();
		int block_size = 64;
		int full_size;
		int plain_size;
		std::string str_plain = "";
		std::string str_publickey = "";
		std::string str_cipher = "";
		CryptoPP::AutoSeededRandomPool rng;

		std::cout << "Encryption in process..." << std::endl;
		Open_Message(plaintext, plaintext_path);
		Open_Message(publickey, publickey_path);

		plain_size = plaintext.GetData().size();
		full_size = plain_size;
		while (full_size % block_size != 0)
		{
			full_size++;
		}
		plaintext.GetData().resize(full_size);
		for (int i = plain_size; i < full_size; i++)
		{
			plaintext.GetData()[i] = 0;
		}

		for (int i = 0; i < publickey.GetData().size(); i++)
		{
			str_publickey += publickey.GetData()[i];
		}

		CryptoPP::StringSource pubString(str_publickey, true, new CryptoPP::Base64Decoder);
		CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubString);

		for (int j = 0; j < full_size / block_size; j++)
		{
			for (int i = 0; i < block_size; i++)
			{
				str_plain += plaintext.GetData()[block_size * j + i];
			}
			CryptoPP::StringSource(str_plain, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(str_cipher)));

			for (int i = 0; i < str_cipher.size(); i++)
			{
				ciphertext.GetData().push_back(str_cipher[i]);
			}
			str_plain = "";
			str_cipher = "";
		}

		Write_Message(ciphertext, ciphertext_path, "Cipher text");
		system("pause");
	}

	void Decryption()
	{
		Clear_Screen();
		int block_size = 128;
		int full_size;
		std::string str_cipher = "";
		std::string str_privatekey = "";
		std::string str_decrypted = "";
		CryptoPP::AutoSeededRandomPool rng;

		std::cout << "Decryption in process..." << std::endl;
		Open_Message(ciphertext, ciphertext_path);
		Open_Message(privatekey, privatekey_path);

		for (int i = 0; i < privatekey.GetData().size(); i++)
		{
			str_privatekey += privatekey.GetData()[i];
		}

		CryptoPP::StringSource privString(str_privatekey, true, new CryptoPP::Base64Decoder);
		CryptoPP::RSAES_OAEP_SHA_Decryptor e(privString);

		full_size = ciphertext.GetData().size();
		for (int j = 0; j < full_size / block_size; j++)
		{
			for (int i = 0; i < block_size; i++)
			{
				str_cipher += ciphertext.GetData()[block_size * j + i];
			}
			CryptoPP::StringSource(str_cipher, true, new CryptoPP::PK_DecryptorFilter(rng, e, new CryptoPP::StringSink(str_decrypted)));

			for (int i = 0; i < str_decrypted.size(); i++)
			{
				decryptedtext.GetData().push_back(str_decrypted[i]);
			}
			str_decrypted = "";
			str_cipher = "";
		}

		Write_Message(decryptedtext, decryptedtext_path, "Decrypted text");
		system("pause");
	}
};

int main()
{
	RSA obj;
	Key keys;
	int begin_time;
	int end_time;

	std::cout << "RSA." << std::endl;
	begin_time = clock();

	keys.Generate_Keys();
	obj.Encryption();
	obj.Decryption();
	end_time = clock();

	Clear_Screen();
	std::string process_time = std::to_string(Get_Time(begin_time, end_time));
	std::cout << "RSA encryption and decryption completed. Time = " << process_time << " seconds." << std::endl;

	system("pause");
	return 0;
}