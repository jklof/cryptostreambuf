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

#include <iostream>
#include <fstream>
#include <cstring>

crypto_key null_key = { 0 };
crypto_iv  null_iv  = { 0 };


void icrypt(int enc)
{
  icryptostreambuf ic(std::cin.rdbuf(), null_key, null_iv, enc);
  std::cout << &ic;
}

void ocrypt(int enc)
{
  ocryptostreambuf oc(std::cout.rdbuf(), null_key, null_iv, enc);
  std::ostream os(&oc);
  os << std::cin.rdbuf();
}


int main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "icrypt") == 0)
    icrypt(1);
  else if (argc == 2 && strcmp(argv[1], "idecrypt") == 0)
    icrypt(0);
  else if (argc == 2 && strcmp(argv[1], "ocrypt") == 0)
    ocrypt(1);
  else if (argc == 2 && strcmp(argv[1], "odecrypt") == 0)
    ocrypt(0);
  
  return 0;

}
/* EOF */
