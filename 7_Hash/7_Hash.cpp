#include "MyFile.h"

class Hash
{
private:
	MyFile plaintext;
	MyFile hash;
	std::string plaintext_path = "../shared/plaintext.docx";
	std::string hash_path = "../shared/hash.txt";
public:
	void Generate_Hash()
	{
		int hash_size = 256;
		int plain_size;
		std::vector<unsigned char> iv;
		
		std::cout << "Hash is generating..." << std::endl;
		Open_Message(plaintext, plaintext_path);
		plain_size = plaintext.GetData().size();

		for (int i = 0; i < hash_size; i++)
		{
			unsigned char perem = i << 2;
			int plain_index = i % plain_size;
			iv.push_back(plaintext.GetData()[plain_index] * perem + 17);
		}

		for (int i = 0; i < hash_size; i++)
		{
			hash.GetData().push_back((iv[i]) ^ (i / 2));
		}
		
		if (plain_size > hash_size)
		{
			for (int i = 0; i < plain_size; i++)
			{
				hash.GetData()[i % hash_size] ^= plaintext.GetData()[i];
			}
		}
		else
		{
			for (int i = 0; i < hash_size; i++)
			{
				hash.GetData()[i] ^= plaintext.GetData()[i % plain_size];
			}
		}		

		Clear_Screen();
		Write_Message(hash, hash_path, "Hash file");
	}	
};

int main()
{
	Hash obj;
	obj.Generate_Hash();
	system("pause");
	return 0;
}