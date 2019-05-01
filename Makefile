all:
	gcc -o server server.c -lssl -lcrypto
	gcc -o client client.c -lssl -lcrypto