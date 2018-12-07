gen32.out: gen32.cpp mt19937ar.c
	g++ $^ -lcrypto -lb64 -Wall -o $@
gen64.out: gen64.cpp mt19937ar.c
	g++ $^ -lcrypto -lb64 -Wall -o $@
