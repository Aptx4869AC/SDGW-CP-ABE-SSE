CC = g++
# CFLAGS = -Wall
LDFLAGS = -L/usr/local/openssl/lib64 -lssl -lcrypto

all: client

client: client.o
	@$(CC) $(CFLAGS) -o client client.o $(LDFLAGS)

client.o: client.cpp
	@$(CC) $(CFLAGS) -c client.cpp

clean:
	@rm -f client client.o

