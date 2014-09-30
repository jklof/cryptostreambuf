/*
  Copyright 2014 Janne Lof

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef CRYPTOSTREAMBUF_H
#define CRYPTOSTREAMBUF_H

#include <streambuf>
#include <istream>
#include <cstdint>
#include <array>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define AES_BLOCK_SIZE   16
#define AES256_KEY_SZ    32
#define AES_IV_SZ        16   // same as block size
#define BUFFER_SIZE      256  // can be tuned


typedef std::array<uint8_t, AES256_KEY_SZ> crypto_key;
typedef std::array<uint8_t, AES_IV_SZ>     crypto_iv;

inline crypto_key crypto_generate_key()
{
  crypto_key key;
  RAND_bytes(key.data(), key.size());
  return key;
}
inline crypto_iv crypto_generate_iv()
{
  crypto_iv iv;
  RAND_bytes(iv.data(), iv.size());
  return iv;
}


class icryptostreambuf : public std::streambuf
{

 public:
  explicit icryptostreambuf(std::streambuf *in, const crypto_key& key, const crypto_iv& iv, int enc);
  ~icryptostreambuf();

 private:
  int_type underflow();

  // not implemented
  icryptostreambuf(const icryptostreambuf&);
  icryptostreambuf &operator=(const icryptostreambuf&);


 private:

  EVP_CIPHER_CTX *ctx;

  std::streambuf &input;
  std::array<char,BUFFER_SIZE> in;
  std::array<char,BUFFER_SIZE+AES_BLOCK_SIZE>out;
};

class ocryptostreambuf : public std::streambuf
{

 public:
  explicit ocryptostreambuf(std::streambuf* out, const crypto_key& key, const crypto_iv& iv, int enc);
  ~ocryptostreambuf();

  void finalize();

 private:
  int_type overflow(int_type ch);
  int sync();

  // not implemented
  ocryptostreambuf(const ocryptostreambuf&);
  ocryptostreambuf &operator=(const ocryptostreambuf&);

 private:
  EVP_CIPHER_CTX *ctx;
  std::streambuf &output;
  std::array<char,BUFFER_SIZE> in;
  std::array<char,BUFFER_SIZE+AES_BLOCK_SIZE>out;
};




#endif
