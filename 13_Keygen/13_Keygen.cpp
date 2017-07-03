#include <iostream>
#include <string>


int main()
{
	std::string plain;
	std::cout << "Enter your text: " << std::endl;
	std::cin >> plain;
	for (int i = 0; i < plain.size(); i++)
		plain[i] = ((plain[i] + i) ^ i) % 26 + 65;
	std::cout << std::endl << "Cipher text: " << std::endl << plain << std::endl;
	system("pause");
	return 0;
}

