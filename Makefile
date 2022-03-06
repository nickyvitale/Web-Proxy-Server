CC = gcc

all: myproxy

myproxy: server.o
	gcc server.o -ggdb3 -lssl -lcrypto -pthread -o ./bin/myproxy
server.o: ./src/server.c
	gcc -c ./src/server.c
clean:
	rm *.o ./bin/myproxy
