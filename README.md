# OpenSSL DTLS Example

A simple DTLS echo example using OpenSSL.

This will not compile with OpenSSL versions older than 1.1.1 because of the usage of BIO_bind.

## Usage

> ./server

> ./client word1 word2 word3

The server will echo the args you pass to the client before exiting.