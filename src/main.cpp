#include "rsa.h"
#include <cstdio>
#include <iomanip>
#include <iostream>

int main() {
  auto [privateKey, publicKey] = generate_public_key();

  if (privateKey.empty() || publicKey.empty()) {
    std::cerr << "Erro ao gerar as chaves.\n";
    return 1;
  }

  std::cout << "Chave privada:\n" << privateKey.data() << "\n";
  std::cout << "Chave pública:\n" << publicKey.data() << "\n";

  std::string data = "Mensagem secreta";
  auto encrypted = encrypt_data(data, publicKey);

  if (encrypted.empty()) {
    std::cerr << "Erro ao criptografar os dados.\n";
    return 1;
  }

  auto decrypted = decrypt_data(encrypted, privateKey);

  if (decrypted.empty()) {
    std::cerr << "Erro ao descriptografar os dados.\n";
    return 1;
  }

  std::cout << "Mensagem original: " << data << "\n";
  std::cout << "Encryptografada: ";
  for (auto &x : encrypted) {
    std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
              << (unsigned int)x << ' ';
  }
  std::cout << std::endl << "Mensagem descriptografada: " << decrypted << "\n";

  return 0;
}
