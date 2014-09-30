#   Copyright 2014 Janne Lof


FLAGS = -Wall -std=c++11 -g

KEY = 0000000000000000000000000000000000000000000000000000000000000000
IV  = 00000000000000000000000000000000

cs : cryptostreambuf.o main.o
	g++ $(FLAGS) -o cs cryptostreambuf.o main.o -lcrypto

main.o : main.cpp cryptostreambuf.h
	g++ $(FLAGS) -c  main.cpp

cryptostreambuf.o : cryptostreambuf.cpp cryptostreambuf.h
	g++ $(FLAGS) -c cryptostreambuf.cpp

clean:
	rm -f *.o cs *~

test: cs
	openssl aes-256-cbc -K $(KEY) -iv $(IV) -in main.cpp -out openssl_crypted.tmp
	cat main.cpp | ./cs icrypt > icrypt.tmp
	cat main.cpp | ./cs ocrypt > ocrypt.tmp
	diff openssl_crypted.tmp icrypt.tmp
	diff openssl_crypted.tmp ocrypt.tmp
	cat openssl_crypted.tmp | ./cs idecrypt > idecrypt.tmp
	cat openssl_crypted.tmp | ./cs odecrypt > odecrypt.tmp
	diff idecrypt.tmp main.cpp
	diff odecrypt.tmp main.cpp
	rm idecrypt.tmp odecrypt.tmp icrypt.tmp ocrypt.tmp openssl_crypted.tmp
