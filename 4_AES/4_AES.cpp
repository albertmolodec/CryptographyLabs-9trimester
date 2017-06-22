#include "MyFile.h"
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\AES.h"
#include "..\third-party\src\CryptoPP\modes.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\filters.h"
#include "..\third-party\src\CryptoPP\cbcmac.h"


class AES
{
private:
	MyFile plaintext;
	MyFile ciphertext;
	MyFile decryptedtext;
	MyFile key;
	MyFile iv;
	std::string plaintext_path = "../shared/plaintext.docx";
	std::string ciphertext_path = "../shared/ciphertext.docx";
	std::string decryptedtext_path = "../shared/decryptedtext.docx";
	std::string key_path = "../shared/key";
	std::string iv_path = "../shared/iv";
public:
	AES()
	{

	}

	int Encryption()
	{
		std::cout << "Select an encryption method:" << std::endl;
		std::cout << "1) Electronic code book (ECB)" << std::endl;
		std::cout << "2) Cipher block chaining (CBC)" << std::endl;
		std::cout << "3) Cipher feed back (CFB)" << std::endl;
		std::cout << "4) Output feed back (OFB)" << std::endl;
		std::cout << "5) Counter mode (CTR)" << std::endl;

		int mode;
		std::cin >> mode;
		Clear_Screen();

		Open_Message(plaintext, plaintext_path);

		byte key_bytes[CryptoPP::AES::DEFAULT_KEYLENGTH];
		byte iv_bytes[CryptoPP::AES::BLOCKSIZE];

		ciphertext.GetData().resize(plaintext.GetData().size() + CryptoPP::AES::BLOCKSIZE);
		CryptoPP::ArraySink cs(&ciphertext.GetData()[0], ciphertext.GetData().size());

		switch (mode)
		{
		case 1:
		{
			std::cout << "Encryption in ECB mode in process..." << std::endl;
			Generate_Obj(key_bytes, "Key");
			CryptoPP::ECB_Mode< CryptoPP::AES >::Encryption Enc;
			Enc.SetKey(key_bytes, sizeof(key_bytes));
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
			break;
		}
		case 2:
		{
			std::cout << "Encryption in CBC mode in process..." << std::endl;
			Generate_Obj(key_bytes, "Key");
			Generate_Obj(iv_bytes, "IV");
			CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption Enc;
			Enc.SetKeyWithIV(key_bytes, sizeof(key_bytes), iv_bytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
			break;
		}
		case 3:
		{
			std::cout << "Encryption in CFB mode in process..." << std::endl;
			Generate_Obj(key_bytes, "Key");
			Generate_Obj(iv_bytes, "IV");
			CryptoPP::CFB_Mode< CryptoPP::AES >::Encryption Enc;
			Enc.SetKeyWithIV(key_bytes, sizeof(key_bytes), iv_bytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
			break;
		}
		case 4:
		{
			std::cout << "Encryption in OFB mode in process..." << std::endl;
			Generate_Obj(key_bytes, "Key");
			Generate_Obj(iv_bytes, "IV");
			CryptoPP::OFB_Mode< CryptoPP::AES >::Encryption Enc;
			Enc.SetKeyWithIV(key_bytes, sizeof(key_bytes), iv_bytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
			break;
		}
		case 5:
		{
			std::cout << "Encryption in CTR mode in process..." << std::endl;
			Generate_Obj(key_bytes, "Key");
			Generate_Obj(iv_bytes, "IV");
			CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption Enc;
			Enc.SetKeyWithIV(key_bytes, sizeof(key_bytes), iv_bytes);
			CryptoPP::ArraySource(plaintext.GetData().data(), plaintext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs)));
			break;
		}


		}
		ciphertext.GetData().resize(cs.TotalPutLength());

		Write_Message(ciphertext, ciphertext_path, "Cipher text");
		return mode;
	}

	void Decryption(int mode)
	{
		byte random_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
		byte random_iv[CryptoPP::AES::BLOCKSIZE];

		Open_Message(ciphertext, ciphertext_path);

		decryptedtext.GetData().resize(ciphertext.GetData().size() + CryptoPP::AES::BLOCKSIZE);
		CryptoPP::ArraySink ds(&decryptedtext.GetData()[0], decryptedtext.GetData().size());

		switch (mode)
		{
		case 1:
		{
			Get_Obj(random_key, "Key");
			CryptoPP::ECB_Mode< CryptoPP::AES >::Decryption Dec;
			Dec.SetKey(random_key, sizeof(random_key));
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
			break;
		}
		case 2:
		{
			Get_Obj(random_key, "Key");
			Get_Obj(random_iv, "IV");
			CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption Dec;
			Dec.SetKeyWithIV(random_key, sizeof(random_key), random_iv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
			break;
		}
		case 3:
		{
			Get_Obj(random_key, "Key");
			Get_Obj(random_iv, "IV");
			CryptoPP::CFB_Mode< CryptoPP::AES >::Decryption Dec;
			Dec.SetKeyWithIV(random_key, sizeof(random_key), random_iv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
			break;
		}
		case 4:
		{
			Get_Obj(random_key, "Key");
			Get_Obj(random_iv, "IV");
			CryptoPP::OFB_Mode< CryptoPP::AES >::Decryption Dec;
			Dec.SetKeyWithIV(random_key, sizeof(random_key), random_iv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
			break;
		}
		case 5:
		{
			Get_Obj(random_key, "Key");
			Get_Obj(random_iv, "IV");
			CryptoPP::CTR_Mode< CryptoPP::AES >::Decryption Dec;
			Dec.SetKeyWithIV(random_key, sizeof(random_key), random_iv);
			CryptoPP::ArraySource(ciphertext.GetData().data(), ciphertext.GetData().size(), true,
				new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(ds)));
			break;
		}
		}
		decryptedtext.GetData().resize(ds.TotalPutLength());

		Write_Message(decryptedtext, decryptedtext_path, "Decrypted text ");
	}

	void Get_Obj(byte *random_obj, std::string type)
	{
		MyFile obj;
		std::string obj_path;
		if (type == "Key")
		{
			obj = key;
			obj_path = key_path;
		}
		else if (type == "IV")
		{
			obj = iv;
			obj_path = iv_path;
		}

		Open_Message(obj, obj_path);

		if (type == "Key")
		{
			for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++)
			{
				random_obj[i] = obj.GetData()[i];
			}
		}
		else if (type == "IV")
		{
			for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++)
			{
				random_obj[i] = obj.GetData()[i];
			}
		}
	}

	void Generate_Obj(byte *obj_bytes, std::string type)
	{
		if (type == "Key")
		{
			CryptoPP::AutoSeededRandomPool rand;
			rand.GenerateBlock(obj_bytes, CryptoPP::AES::DEFAULT_KEYLENGTH);
			for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++)
			{
				key.GetData().push_back(obj_bytes[i]);
			}
			Write_Message(key, key_path, "Key");
		}
		else if (type == "IV")
		{
			CryptoPP::AutoSeededRandomPool rand;
			rand.GenerateBlock(obj_bytes, CryptoPP::AES::BLOCKSIZE);
			for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++)
			{
				iv.GetData().push_back(obj_bytes[i]);
			}
			Write_Message(iv, iv_path, "IV");
		}
		else
		{
			std::cout << "'Generate_Obj' function error";
			return;
		}
	}
};


int main()
{
	AES obj;
	int answer = 1;


	while (answer == 1)
	{
		Clear_Screen();
		std::cout << "--AES--" << std::endl;
		int cipher_mode = 0;
		int begin_time;
		int end_time;

		
		begin_time = clock();
		cipher_mode = obj.Encryption();
		obj.Decryption(cipher_mode);
		end_time = clock();
		std::string process_time = std::to_string(Get_Time(begin_time, end_time));
		std::cout << std::endl << "AES encryption and decryption completed. Time = " << process_time << " seconds." << std::endl;

		std::cout << "Again? (1 - Yes, 2 - No)" << std::endl;
		std::cin >> answer;
	}

	system("pause");
	return 0;
}