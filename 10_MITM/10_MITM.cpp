#include <MyFile.h>
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\des.h"
#include "..\third-party\src\CryptoPP\modes.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\filters.h"
#include "..\third-party\src\CryptoPP\cbcmac.h"

std::vector <unsigned char> Encryption(std::vector <unsigned char> &plaintext, std::vector <unsigned char> &key)
{
	std::vector <unsigned char> ciphertext;

	byte sub_key[CryptoPP::DES::DEFAULT_KEYLENGTH];
	for (int i = 0; i < CryptoPP::DES::DEFAULT_KEYLENGTH; i++)
	{
		sub_key[i] = key[i];
	}

	ciphertext.resize(plaintext.size() + CryptoPP::DES::DEFAULT_KEYLENGTH);

	CryptoPP::ArraySink cs(&ciphertext[0], ciphertext.size());
	CryptoPP::ECB_Mode <CryptoPP::DES>::Encryption Enc;
	Enc.SetKey(sub_key, sizeof(sub_key));
	CryptoPP::ArraySource(plaintext.data(), plaintext.size(), true,
		new CryptoPP::StreamTransformationFilter(Enc, new CryptoPP::Redirector(cs), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));

	ciphertext.resize(cs.TotalPutLength());
	return ciphertext;
}

std::vector <unsigned char> Decryption(std::vector <unsigned char> &ciphertext, std::vector <unsigned char> &key)
{
	std::vector <unsigned char> plaintext;

	byte sub_key[CryptoPP::DES::DEFAULT_KEYLENGTH];
	for (int i = 0; i < CryptoPP::DES::DEFAULT_KEYLENGTH; i++)
	{
		sub_key[i] = key[i];
	}

	plaintext.resize(ciphertext.size() + CryptoPP::DES::DEFAULT_KEYLENGTH);

	CryptoPP::ArraySink cs(&plaintext[0], plaintext.size());
	CryptoPP::ECB_Mode <CryptoPP::DES>::Decryption Dec;
	Dec.SetKey(sub_key, sizeof(sub_key));
	CryptoPP::ArraySource(ciphertext.data(), ciphertext.size(), true,
		new CryptoPP::StreamTransformationFilter(Dec, new CryptoPP::Redirector(cs), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));

	plaintext.resize(cs.TotalPutLength());
	return plaintext;
}

std::vector <unsigned char> Generate_Key_Abs(int key_size)
{
	srand(time(NULL));
	std::vector <unsigned char> key_abs;
	for (int i = 0; i < key_size; i++)
	{
		key_abs.push_back(rand() % 256);
	}
	return key_abs;
}

std::vector <unsigned char> Generate_Next_Key(std::vector <unsigned char> &prev_key, int key_size)
{
	std::vector <unsigned char> next_key;
	next_key.resize(prev_key.size());
	int j = key_size - 1;
	for (int i = 0; i < key_size; i++)
	{
		next_key[i] = prev_key[i];
	}
	next_key[j] = next_key[j] + 1;
	if (next_key[j] == 0)
	{
		while (next_key[j] == 0)
		{
			j--;
			next_key[j] = next_key[j] + 1;
		}
	}
	return next_key;
}

void Split_Key(std::vector <unsigned char> &key, std::vector <unsigned char> &left_key, std::vector <unsigned char> &right_key, int key_size)
{
	for (int i = 0; i < key_size / 2; i++)
	{
		left_key.push_back(key[i]);
	}
	for (int i = key_size / 2; i < key_size; i++)
	{
		right_key.push_back(key[i]);
	}
}

void Create_Tables(std::vector <unsigned char> &plaintext, std::vector <unsigned char> &ciphertext,
	std::map <std::vector <unsigned char>, std::vector <unsigned char>> &e, std::map <std::vector <unsigned char>, std::vector <unsigned char>> &d,
	std::vector<std::vector <unsigned char>> &left_keys, std::vector<std::vector <unsigned char>> &right_keys,
	int begin, int end)
{
	for (int i = begin; i < end; i++)
	{
		e.insert(std::pair <std::vector <unsigned char>, std::vector <unsigned char>>(left_keys[i], Encryption(plaintext, left_keys[i])));
		d.insert(std::pair <std::vector <unsigned char>, std::vector <unsigned char>>(right_keys[i], Decryption(ciphertext, right_keys[i])));
	}
}

void Print(std::vector<unsigned char> &text)
{
	for (int i = 0; i < text.size(); i++)
	{
		std::cout << text[i];
	}
}

void Full_Print(std::vector<unsigned char> &text, std::string title)
{
	std::cout << title << ": ";
	Print(text);
	std::cout << std::endl;
}





int main()
{
	int begin_time;
	int end_time;


	// open file with plain text
	MyFile plainfile;
	std::string plainfile_path = "../shared/plaintext.txt";
	std::vector <unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> decryptedtext;
	MyFile::Open_Message(plainfile, plainfile_path);
	plaintext = plainfile.GetData();
	int key_size = 16;
	std::cout << "Key size = " << key_size << std::endl;
	std::cout << "Plain text size = " << plaintext.size() << std::endl;
	Full_Print(plaintext, "Plain text");


	// generate abs key and cipher my plain text
	std::vector <unsigned char> key_abs;
	std::vector <unsigned char> left_key_abs;
	std::vector <unsigned char> right_key_abs;
	key_abs = Generate_Key_Abs(key_size);
	std::cout << "Key_abs size = " << key_abs.size() << std::endl;
	Full_Print(key_abs, "Key abs");

	Split_Key(key_abs, left_key_abs, right_key_abs, key_size);
	ciphertext = Encryption(Encryption(plaintext, left_key_abs), right_key_abs);
	Full_Print(ciphertext, "Cipher text");


	// generate array of keys
	begin_time = clock();
	Clear_Screen();
	std::cout << "Attack on 2DES with using of MITM in progress..." << std::endl << std::endl;
	std::cout << "Keys are generating...";
	std::vector<std::vector <unsigned char>> keys;
	int keys_count = pow(2, 20);
	std::vector <unsigned char> next_key = key_abs;
	for (int i = 0; i < keys_count; i++)
	{
		keys.push_back(next_key);
		next_key = Generate_Next_Key(next_key, key_size);
	}


	// split keys
	Clear_Screen();
	std::cout << "Attack on 2DES with using of MITM in progress..." << std::endl << "Number of analysing keys: " << keys_count << std::endl;
	std::cout << "Keys are spliting...";
	std::vector<std::vector <unsigned char>> left_keys;
	std::vector<std::vector <unsigned char>> right_keys;
	left_keys.resize(keys.size());
	right_keys.resize(keys.size());
	for (int i = 0; i < keys.size(); i++)
	{
		Split_Key(keys[i], left_keys[i], right_keys[i], key_size);
	}


	// create pair tables
	Clear_Screen();
	std::map <std::vector <unsigned char>, std::vector <unsigned char>> e;
	std::map <std::vector <unsigned char>, std::vector <unsigned char>> d;
	int threads_count =16;
	std::cout << "Attack on 2DES with using of MITM in progress..." << std::endl << "Number of threads: " << threads_count << std::endl << "Number of analysing keys: " << keys_count << std::endl;
	std::thread *thr = new std::thread[threads_count];
	for (int i = 0; i < threads_count; i++)
	{
		thr[i] = std::thread(Create_Tables, std::ref(plaintext), std::ref(ciphertext), std::ref(e), std::ref(d), std::ref(left_keys), std::ref(right_keys), keys_count / threads_count * i, keys_count / threads_count * (i + 1));
	}
	std::cout << "A table is creating..." << std::endl;
	for (int i = 0; i < threads_count; i++)
	{
		thr[i].join();
	}
	end_time = clock();


	// search in tables 
	std::vector<byte> correct_key_left;
	std::vector<byte> correct_key_right;

	for (auto iter_e : e)
	{
		for (auto iter_d : d)
		{
			if (iter_e.second == iter_d.second)
			{
				correct_key_left = iter_e.first;
				correct_key_right = iter_d.first;
				Clear_Screen();
				std::string process_time = std::to_string(Get_Time(begin_time, end_time));
				decryptedtext = Decryption(Decryption(ciphertext, correct_key_right), correct_key_left);
				std::cout << "Attack on 2DES with using of MITM is completed." << std::endl << "Number of threads: " << threads_count << std::endl << "Number of analysing keys: " << keys_count << std::endl;
				Full_Print(decryptedtext, "Decrypted text");
				std::cout << "Process time = " << process_time << " seconds." << std::endl;
				break;
			}
		}
	}

	system("pause");
	return 0;
}