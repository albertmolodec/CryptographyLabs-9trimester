#include "MyFile.h"


class OTP
{
private:

public:
	OTP()
	{

	}

	void Key_Generator(MyFile &plaintext, std::string &plaintext_path,
		MyFile &key, std::string &key_path)
	{
		if (!plaintext.Open(plaintext_path))
		{
			std::cout << "File plaintext.docx is not exist in this directory: " << plaintext_path << std::endl;
			return;
		}
		else
		{
			srand(time(NULL));
			Clear_Screen();
			int begin_time = clock();
			std::cout << "Key is generating...";
			key.Clear_Data();
			for (int i = 0; i < plaintext.GetData().size(); i++)
			{
				key.GetData().push_back((char)rand() % 256);
			}
			key.Write(key_path);
			int end_time = clock();
			std::string process_time = std::to_string(Get_Time(begin_time, end_time));
			Clear_Screen();
			std::cout << "Key is created. Creation time = " << process_time << " seconds." << std::endl;
			key.Clear_Data();
		}
	}

	void Cipher(MyFile &from, std::string &from_path,
		MyFile &to, std::string &to_path,
		MyFile &key, std::string &key_path, int mode)
	{
		if (!(from.Open(from_path) && key.Open(key_path)))
		{
			std::cout << "Files are not opened" << std::endl;
		}
		else if (from.GetData().size() != key.GetData().size())
		{
			std::cout << "Source text and key have a different size" << std::endl;
		}
		else
		{
			Clear_Screen();
			std::string prefix = "En";
			if (mode == 2)
				prefix = "De";

			std::cout << prefix << "crypted text is generating...";
			int begin_time = clock();
			for (int i = 0; i < from.GetData().size(); i++)
				to.GetData().push_back(from.GetData().at(i) ^ key.GetData().at(i));
			to.Write(to_path);
			int end_time = clock();
			std::string process_time = std::to_string(Get_Time(begin_time, end_time));
			Clear_Screen();
			std::cout << prefix << "crypted text is created. Creation time = " << process_time << " seconds." << std::endl;

			from.Clear_Data();
			to.Clear_Data();
			key.Clear_Data();
			from.Close();
			key.Close();
			to.Close();
		}
	}
};



int main()
{
	MyFile plaintext;
	MyFile ciphertext;
	MyFile decryptedtext;
	MyFile key;
	std::string plaintext_path = "../shared/plaintext.docx";
	std::string ciphertext_path = "../shared/ciphertext.docx";
	std::string decryptedtext_path = "../shared/decryptedtext.docx";
	std::string key_path = "../shared/key.docx";
	OTP workplace;
	int answer = true;

	while (answer == 1)
	{
		Clear_Screen();
		std::cout << "What to do? (1 - Encrypt, 2 - Decrypt)" << std::endl;
		int mode;
		std::cin >> mode;
		if (mode == 1)
		{
			workplace.Key_Generator(plaintext, plaintext_path, key, key_path);
			bool plaintext_check = false;
			plaintext_check = File_Exists(plaintext_path.c_str());
			if (!plaintext_check)
			{
			}
			else
			{
				std::cout << "Press any key to cipher plain text..." << std::endl;
				system("pause");
				workplace.Cipher(plaintext, plaintext_path, ciphertext, ciphertext_path, key, key_path, mode);
			}
		}
		else if (mode == 2)
		{
			bool ciphertext_check = false;
			ciphertext_check = File_Exists(ciphertext_path.c_str());
			if (!ciphertext_check)
			{
				Clear_Screen();
				std::cout << "File ciphertext.docx is not exist in this directory: " << ciphertext_path << std::endl;
			}
			else
			{
				workplace.Cipher(ciphertext, ciphertext_path, decryptedtext, decryptedtext_path, key, key_path, mode);
			}
		}
		std::cout << "Again? (1 - Yes, 2 - No)" << std::endl;
		std::cin >> answer;
	}

	return 0;
}