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

#include "cryptostreambuf.h"

#include <algorithm>

icryptostreambuf::icryptostreambuf(std::streambuf *in, const crypto_key& key, const crypto_iv& iv, int enc)
  :ctx(EVP_CIPHER_CTX_new()),
  input(*in)
{
  if (!ctx)
    return;

  if (1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data(), enc))
    {
      // rudimentary error handling
      EVP_CIPHER_CTX_free(ctx);
      ctx = NULL;
    }
  setg(NULL,NULL,NULL);
}

icryptostreambuf::~icryptostreambuf()
{
  std::fill(out.begin(), out.end(), 0);
  std::fill(in.begin(), in.end(), 0);
  EVP_CIPHER_CTX_free(ctx);
  ctx = NULL;
}


std::streambuf::int_type icryptostreambuf::underflow()
{

  if (!ctx)
    {
      // closed crypto stream
      return traits_type::eof();
    }

  // return character pointed to by gptr()
  // without advancing it if charactes are available
  // if there are no charactes return EOF
  if (gptr() < egptr())
    {
      return traits_type::to_int_type(*gptr());
    }

  if (eback() == NULL) // NULL indicates 1st time
    {
      // TODO: put back buffer handling
      // basically done by moving
      // last few bytes to front of the buffer
      // so buffer is always putback+buffer
    }

  // ok, we need to fill buffer, so read from underlying buffer

  // should loop until we are at an end or encrypt/decrypt returns
  // at least some bytes, we are not worrying
  // to fill out buffer completely
  int out_len = 0;
  while (out_len == 0 && input.sgetc() != traits_type::eof())
    {
      int in_len = input.sgetn(in.data(), in.size());
      int outl = 0;

      // TODO: error handling
      EVP_CipherUpdate(ctx,
			(uint8_t*)out.data()+out_len, &outl,
			(uint8_t*)in.data(), in_len);
      out_len += outl;
    }

  // finalise if underlying streambuf is at an end
  if (input.sgetc() == traits_type::eof())
    {
      int outl = 0;
      // TODO: error handling
      EVP_CipherFinal_ex(ctx, (uint8_t*)out.data()+out_len, &outl);
      EVP_CIPHER_CTX_free(ctx); // free does EVP_CIPHER_CTX_cleanup also
      ctx = NULL;
      out_len += outl;
    }

  // zero out here means we don't have any
  // bytes even after possible finalize, must be
  // at an end of stream..
  if (out_len == 0)
    {
      return traits_type::eof();
   }

  // set buffer pointers
  char *start = out.data(); // TODO: + putback_size
  // eback, gptr, egptr
  setg(out.data(), start, start + out_len);

  return traits_type::to_int_type(*gptr());
}


ocryptostreambuf::ocryptostreambuf(std::streambuf* out, const crypto_key& key, const crypto_iv& iv, int enc)
  :ctx(EVP_CIPHER_CTX_new()),
   output(*out)
{
  if (!ctx)
    return;

  // TODO: better error handling
  if (1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data(), enc))
    {
      EVP_CIPHER_CTX_free(ctx);
      ctx = NULL;
    }

  setp(in.data(),in.data()+in.size());
}

ocryptostreambuf::~ocryptostreambuf()
{
  finalize();
  std::fill(out.begin(), out.end(), 0);
  std::fill(in.begin(), in.end(), 0);
}


std::streambuf::int_type ocryptostreambuf::overflow(int_type ch)
{
  // overflow is only ever called when buffer is full
  // i think eof never happens in normal couse of operation?
  if (!ctx || ch == traits_type::eof() )
    {
      return traits_type::eof();
    }

  // sync flushes and crypts buffer
  // todo: to handle output buffer sync
  // it would be better to have update() and
  // sync would call update() and output.sync();
  sync();

  // append remaining char to newly empty buffer
  *pptr() = ch;  pbump(1);

  return ch;
}

void ocryptostreambuf::finalize()
{
  sync();
  if (ctx)
    {
      int outl = 0;
      // TODO: error handling
      EVP_CipherFinal_ex(ctx, (uint8_t*)out.data(), &outl);
      EVP_CIPHER_CTX_free(ctx);
      ctx = NULL;
      output.sputn(out.data(), outl); // write
    }
}


int ocryptostreambuf::sync()
{
  if (!ctx)
    return -1;

  int inl = pptr() - pbase();
  pbump(-inl);
  int outl = 0;
  // TODO: error handling, should sync output buffer?
  EVP_CipherUpdate(ctx, (uint8_t*)out.data(), &outl, (uint8_t*)pbase(), inl);
  return output.sputn(out.data(), outl) == outl ? 0 : -1;
}
