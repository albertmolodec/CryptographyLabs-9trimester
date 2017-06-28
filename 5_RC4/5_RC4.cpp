#include "MyFile.h"

class RC4
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

	unsigned char s[256];
	int i = 0;
	int j = 0;
	int n;
	unsigned int s_size = 256;

	void Create_S()
	{
		Open_Message(key, key_path);
		for (i = 0; i < s_size; i++)
		{
			s[i] = (unsigned char)i;
		}
		j = 0;
		for (i = 0; i < s_size; i++)
		{
			j = (j + s[i] + key.GetData()[i % key.GetData().size()]) % s_size;
			unsigned char swap_tmp = s[i];
			s[i] = s[j];
			s[j] = swap_tmp;
		}
		i = 0;
		j = 0;
	}

	unsigned char Generate_Key_i()
	{
		i = (i + 1) % s_size;
		j = (j + s[i]) % s_size;
		unsigned char swap_tmp = s[i];
		s[i] = s[j];
		s[j] = swap_tmp;
		return s[(s[i] + s[j]) % s_size];
	}

	int Pow_2(int n)
	{
		int result = 1;
		for (int i = 0; i < n; i++)
		{
			result *= 2;
		}
		return result;
	}
public:
	void Generate_Key(int length)
	{
		for (int i = 0; i < length; i++)
		{
			key.GetData().push_back((unsigned char)rand() % s_size);
		}
		Write_Message(key, key_path, "Key");
	}

	void Encryption()
	{
		Create_S();
		Open_Message(plaintext, plaintext_path);
		for (int m = 0; m < plaintext.GetData().size(); m++)
		{
			ciphertext.GetData().push_back((plaintext.GetData()[m] ^ Generate_Key_i()));
		}
		Write_Message(ciphertext, ciphertext_path, "Cipher text");
	}

	void Decryption()
	{
		Create_S();
		Open_Message(ciphertext, ciphertext_path);
		for (int m = 0; m < ciphertext.GetData().size(); m++)
		{
			decryptedtext.GetData().push_back((ciphertext.GetData()[m] ^ Generate_Key_i()));
		}
		Write_Message(decryptedtext, decryptedtext_path, "Decrypted text");
	}
};



int main()
{
	RC4 obj;
	int key_size;
	std::cout << "Enter key size: ";
	std::cin >> key_size;
	obj.Generate_Key(key_size);
	std::cout << std::endl;
	Clear_Screen();
	obj.Encryption();
	obj.Decryption();
	system("pause");
	return 0;
}

