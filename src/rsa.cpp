#include "rsa.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

std::pair<key, key> generate_public_key() {
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

  if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
      EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  BIO *privateBIO = BIO_new(BIO_s_mem());
  BIO *publicBIO = BIO_new(BIO_s_mem());

  if (!PEM_write_bio_PrivateKey(privateBIO, pkey, NULL, NULL, 0, NULL, NULL) ||
      !PEM_write_bio_PUBKEY(publicBIO, pkey)) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  size_t privateLen = BIO_pending(privateBIO);
  size_t publicLen = BIO_pending(publicBIO);

  key privateKey(privateLen + 1);
  key publicKey(publicLen + 1);

  BIO_read(privateBIO, privateKey.data(), privateLen);
  BIO_read(publicBIO, publicKey.data(), publicLen);

  privateKey[privateLen] = '\0';
  publicKey[publicLen] = '\0';

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  BIO_free(privateBIO);
  BIO_free(publicBIO);

  return std::make_pair(privateKey, publicKey);
}

std::vector<unsigned char> encrypt_data(const std::string &data,
                                        const key &publicKey) {
  BIO *keyBIO = BIO_new_mem_buf(publicKey.data(), -1);
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(keyBIO, NULL, NULL, NULL);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

  if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  size_t outLen;
  if (EVP_PKEY_encrypt(ctx, NULL, &outLen,
                       reinterpret_cast<const unsigned char *>(data.data()),
                       data.size()) <= 0) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  std::vector<unsigned char> encrypted(outLen);
  if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outLen,
                       reinterpret_cast<const unsigned char *>(data.data()),
                       data.size()) <= 0) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  BIO_free(keyBIO);

  return encrypted;
}

std::string decrypt_data(const std::vector<unsigned char> &encryptedData,
                         const key &privateKey) {
  BIO *keyBIO = BIO_new_mem_buf(privateKey.data(), -1);
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keyBIO, NULL, NULL, NULL);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

  if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  size_t outLen;
  if (EVP_PKEY_decrypt(ctx, NULL, &outLen, encryptedData.data(),
                       encryptedData.size()) <= 0) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  std::vector<unsigned char> decrypted(outLen);
  if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outLen, encryptedData.data(),
                       encryptedData.size()) <= 0) {
    ERR_print_errors_fp(stderr);
    return {};
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  BIO_free(keyBIO);

  return std::string(decrypted.begin(), decrypted.end());
}

// Função para verificar erros da OpenSSL
void print_openssl_errors() { ERR_print_errors_fp(stderr); }
