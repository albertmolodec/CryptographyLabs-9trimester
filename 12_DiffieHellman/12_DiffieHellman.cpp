#pragma comment (lib,"Ws2_32.lib")
#include "mpir.h"
#include "mpirxx.h"
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <time.h>
#include "..\third-party\src\CryptoPP\cryptlib.h"
#include "..\third-party\src\CryptoPP\des.h"
#include "..\third-party\src\CryptoPP\modes.h"
#include "..\third-party\src\CryptoPP\osrng.h"
#include "..\third-party\src\CryptoPP\filters.h"


#define PORT "700"
#define SERVER "127.0.0.1"

#define WHITEONBLUE BACKGROUND_BLUE | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define WHITEONBLACK FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY

std::vector <unsigned char> Encryption(std::vector <unsigned char> &plaintext, std::vector <unsigned char> &key);
std::vector <unsigned char> Decryption(std::vector <unsigned char> &ciphertext, std::vector <unsigned char> &key);
void Fill_Message(std::string &message_str, std::vector<unsigned char> &message_bytes);
void Print(std::vector<unsigned char> &text);
void Full_Print(std::vector<unsigned char> &text, std::string title);
void Print_Title(char *name);
std::string Times_Of_day();



int main()
{
	int client_socket;
	int server_socket;
	bool is_server = true;

	mpz_t a;
	mpz_t b;
	mpz_t P;
	mpz_t N;
	mpz_t A;
	mpz_t B;
	mpz_t key_A;
	mpz_t key_B;

	mpz_init(a);
	mpz_init(b);
	mpz_init(P);
	mpz_init(N);
	mpz_init(A);
	mpz_init(B);
	mpz_init(key_A);
	mpz_init(key_B);

	gmp_randstate_t state;
	gmp_randinit_default(state);

	const int buffer_size = 1024;
	char buf[buffer_size];

	std::string message_str = "The quick brown fox jumps over the lazy dog.";
	std::vector<unsigned char> plain_bytes;
	Fill_Message(message_str, plain_bytes);

	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (result != 0) 
	{
		std::cerr << "WSAStartup failed: " << result << "\n";
		return result;
	}
	struct addrinfo* addr = NULL;

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	result = getaddrinfo(SERVER, PORT, &hints, &addr);
	if (result != 0)
	{
		std::cerr << "getaddrinfo failed: " << result << "\n";
		WSACleanup();
		return 1;
	}

	int listen_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (listen_socket == INVALID_SOCKET)
	{
		std::cerr << "Error at socket: " << WSAGetLastError() << "\n";
		freeaddrinfo(addr);
		WSACleanup();
		return 1;
	}
	result = bind(listen_socket, addr->ai_addr, (int)addr->ai_addrlen);

	if (result == SOCKET_ERROR)
	{
		is_server = false;
	}


	
	
	if (is_server)
	{
		Print_Title("ALICE");

		std::cout << "Waiting Bob...";

		if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR)
		{
			std::cerr << "listen failed with error: " << WSAGetLastError() << "\n";
			closesocket(listen_socket);
			WSACleanup();
			return 1;
		}

		client_socket = accept(listen_socket, NULL, NULL);
		if (client_socket == INVALID_SOCKET) {
			std::cerr << "accept failed: " << WSAGetLastError() << "\n";
			closesocket(listen_socket);
			WSACleanup();
			return 1;
		}

		Print_Title("ALICE");

		std::cout << "Good " << Times_Of_day() << ", Bob.\n\n";

		mpz_urandomb(a, state, 300);
		server_socket = 0;

		server_socket = recv(client_socket, buf, buffer_size, 0);
		mpz_init_set_str(P, buf, 10);

		server_socket = recv(client_socket, buf, buffer_size, 0);
		mpz_init_set_str(N, buf, 10);

		server_socket = recv(client_socket, buf, buffer_size, 0);
		mpz_init_set_str(B, buf, 10);

		mpz_powm(A, P, a, N);
		mpz_get_str(buf, 10, A);
		server_socket = send(client_socket, buf, buffer_size, 0);

		mpz_powm(key_A, B, a, N);

		

		std::cout << "Plain text: " << message_str << std::endl;
		std::cout << std::endl;
		
		std::stringstream ss;
		ss.str(std::string());
		ss << key_A;
		std::vector<unsigned char> key;
		for (int i = 0; i < CryptoPP::DES::DEFAULT_KEYLENGTH; i++)
		{
			key.push_back(ss.str()[i]);
		}
		std::vector<unsigned char> cipher_bytes;
		cipher_bytes = Encryption(plain_bytes, key);
		Full_Print(cipher_bytes, "Cipher text");
		for (int i = 0; i < cipher_bytes.size(); i++)
		{
			buf[i] = cipher_bytes[i];
		}
		server_socket = send(client_socket, buf, cipher_bytes.size(), 0);
	}






	else
	{
		Print_Title("BOB");

		result = connect(listen_socket, addr->ai_addr, (int)addr->ai_addrlen);
		if (result == SOCKET_ERROR)
		{

			std::cerr << "Error connection :( " << WSAGetLastError() << "\n";
			freeaddrinfo(addr);
			closesocket(listen_socket);
			WSACleanup();
			return 1;
		}

		std::cout << "Good " << Times_Of_day() << ", Alice.\n\n" ;

		mpz_urandomb(b, state, 300);
		mpz_urandomb(P, state, 150);
		mpz_urandomb(N, state, 1500);

		client_socket = 0;
		mpz_get_str(buf, 10, P);
		client_socket = send(listen_socket, buf, buffer_size, 0);

		mpz_get_str(buf, 10, N);
		client_socket = send(listen_socket, buf, buffer_size, 0);

		mpz_powm(B, P, b, N);
		mpz_get_str(buf, 10, B);
		client_socket = send(listen_socket, buf, buffer_size, 0);

		client_socket = recv(listen_socket, buf, buffer_size, 0);
		mpz_init_set_str(A, buf, 10);

		mpz_powm(key_B, A, b, N);

		client_socket = recv(listen_socket, buf, buffer_size, 0);
		std::string message = "";
		std::vector<unsigned char> cipher_bytes;
		for (int i = 0; i < client_socket; i++)
		{
			message += buf[i];
		}
		for (int i = 0; i < message.size(); i++)
		{
			cipher_bytes.push_back(message[i]);
		}
		Full_Print(cipher_bytes, "Cipher text");
		std::cout << std::endl;
		std::stringstream ss;
		ss.str(std::string());
		ss << key_B;
		std::vector<unsigned char> key;
		for (int i = 0; i < CryptoPP::DES::DEFAULT_KEYLENGTH; i++)
		{
			key.push_back(ss.str()[i]);
		}
		std::vector<unsigned char> dec_plain;
		dec_plain = Decryption(cipher_bytes, key);
		Full_Print(dec_plain, "Decrypted message");
	}

	closesocket(client_socket);
	closesocket(listen_socket);
	freeaddrinfo(addr);
	WSACleanup();
	std::cout << std::endl;
	system("pause");
	return 0;

}


















std::vector <unsigned char> Encryption(std::vector <unsigned char> &plaintext, std::vector <unsigned char> &key)
{
	std::vector <unsigned char> ciphertext;

	unsigned char sub_key[CryptoPP::DES::DEFAULT_KEYLENGTH];
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

	unsigned char sub_key[CryptoPP::DES::DEFAULT_KEYLENGTH];
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

void Fill_Message(std::string &message_str, std::vector<unsigned char> &message_bytes)
{
	for (int i = 0; i < message_str.size(); i++)
	{
		message_bytes.push_back(message_str[i]);
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

void Print_Title(char *name)
{

	HANDLE hConsoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	system("cls");
	SetConsoleTextAttribute(hConsoleHandle, WHITEONBLUE);
	std::cout << "                              " << name << "                                           \n\n" << std::endl;
	SetConsoleTextAttribute(hConsoleHandle, WHITEONBLACK);
}

std::string Times_Of_day()
{
	time_t t;
	t = time(NULL);
	struct tm *t_m = localtime(&t);
	if (t_m->tm_hour >= 0 && t_m->tm_hour < 6)
		return "night";
	if (t_m->tm_hour >= 6 && t_m->tm_hour < 12)
		return "morning";
	if (t_m->tm_hour >= 12 && t_m->tm_hour < 18)
		return "afternoon";
	else
		return "evening";
}