

all:
	g++ -O3 -o clone main.cc -lpcap -std=c++11

clean:
	@rm -f clone
