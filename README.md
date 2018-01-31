# Cryptography labs

*There are the results of my lab works on cryptographic protocols and standards in the summer of 2017.*

I realized the following algorithms:
1. One-Time Pad
2. DES
3. AES
4. RC4
5. RSA
6. Hash-Table
7. SHA256
8. Entropy calculation
9. Meet-In-The-Middle attack on 2DES
10. Diffie-Hellman key exhange

I used C++ with static library Crypto++ (cryptography algorithms) and MPIR (work with long numbers) for this.


## SOURCES

1_OTP:
  1) ClearConsole using WIN API (System() is evil!):  http://www.cplusplus.com/articles/4z18T05o/
  2) FileExists using WIN API: http://rsdn.org/article/qna/baseserv/fileexist.xml

2_Processes:
  1) Print process list: http://eax.me/winapi-process-list/
  2) Set difference beyond 2 map's: http://ru.cppreference.com/w/cpp/algorithm/set_difference

3_DES:
  1) AES/DES alghs: https://www.cryptopp.com/wiki/Advanced_Encryption_Standard
                    https://www.cryptopp.com/wiki/TripleDES
  2) ArraySink, ArraySource, Redirector: https://www.cryptopp.com/wiki/ArraySource

6_RSA:
  1) General description of RSA: https://www.cryptopp.com/wiki/RSA_Encryption_Schemes#RSA_Encryption_Scheme_.28OAEP_and_SHA.29
  2) Some functions: https://github.com/DF4IAH/xy1en1om/blob/master/Bazaar/tools/encoder/encoder.cpp

7_Hash:
  1) Some simple hash functions with c++ listings and collision histogram: https://habrahabr.ru/post/219139/
  
8_SHA256:
  1) Encryption&Decryption code: http://www.cplusplus.com/forum/beginner/60604/

9_Entropy:
  1) How to create a Zip file from existing files: https://www.codeproject.com/articles/7530/zip-utils-clean-elegant-simple-c-win
  2) Convert string to TCHAR*: http://www.cplusplus.com/forum/general/12245/

11_HashTable: 
  1) File attributes list: http://www.vsokovikov.narod.ru/New_MSDN_API/Menage_files/fn_getfileattributes.htm
  2) How to get attributes of file: http://www.cyberforum.ru/cpp-beginners/thread633547.html
  3) Convert FILETIME to string: http://rextester.com/DDL72539
  4) Recursive search: http://eax.me/winapi-file-search/
  
12_DiffieHellman:
  1) Sockets: http://club.shelek.ru/viewart.php?id=35
  2) Sockets[2]: https://code-live.ru/post/cpp-http-server-over-sockets/
 
## Teacher — Smirnov A.V.
