#ifndef INCLUDE_RSA_H_
#define INCLUDE_RSA_H_

#include <string>
#include <utility>
#include <vector>
typedef std::vector<char> key;

std::pair<key, key> generate_public_key();
std::vector<unsigned char> encrypt_data(const std::string &data,
                                        const key &publicKey);
std::string decrypt_data(const std::vector<unsigned char> &encryptedData,
                         const key &privateKey);

#endif // INCLUDE_RSA_H_
