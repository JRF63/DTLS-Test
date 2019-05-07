#pragma once

#ifdef _WIN32
#include <openssl\applink.c>
#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#define PRINT_AND_EXIT(err_str) \
printf(err_str); \
exit(EXIT_FAILURE);

#define PORT "4321"

BIO* init_bio(int is_server)
{
    BIO_ADDRINFO* info;
    BIO_ADDRINFO* p;

    char* node = is_server ? NULL : "localhost";
    enum BIO_lookup_type lookup = is_server ? BIO_LOOKUP_SERVER : BIO_LOOKUP_CLIENT;
    
    if (BIO_lookup(node, PORT, lookup, 0, SOCK_DGRAM, &info) != 1) {
        PRINT_AND_EXIT("BIO_lookup failed\n");
    }
    
    BIO* bio;
    for (p = info; p != NULL; p = BIO_ADDRINFO_next(p)) {
        int sock;
        if ((sock = BIO_socket(BIO_ADDRINFO_family(p), BIO_ADDRINFO_socktype(p),
            BIO_ADDRINFO_protocol(p), 0)) == -1) {
            continue;
        }

        if (is_server) {
            if (BIO_bind(sock, BIO_ADDRINFO_address(p), BIO_SOCK_REUSEADDR) == 0) {
                BIO_closesocket(sock);
                continue;
            }
            
        } else {
            if (BIO_connect(sock, BIO_ADDRINFO_address(p), 0) == 0) {
                BIO_closesocket(sock);
                continue;
            }
        }

        // automatically free socket with BIO_CLOSE
        bio = BIO_new_dgram(sock, BIO_CLOSE);
        if (!is_server) {
            BIO_ctrl_set_connected(bio, BIO_ADDRINFO_address(p));
        }
        break;
    }

    BIO_ADDRINFO_free(info);

    if (p == NULL) {
        PRINT_AND_EXIT("can't bind/connect");
    }

    return bio;
}

SSL_CTX* init_context(int is_server)
{
    SSL_CTX* ctx = SSL_CTX_new(DTLS_method());

    if (SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") != 1) {
        PRINT_AND_EXIT("cannot set cipher list.\n");
    }

    char* keyfile = is_server ? "./keys/server-key.pem" : "./keys/client-key.pem";
    char* certfile = is_server ? "./certs/server-cert.pem" : "./certs/client-cert.pem";

    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
        PRINT_AND_EXIT("failed to load private key.\n");
    }

    if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1) {
        PRINT_AND_EXIT("failed to load certificate.\n");
    }

    return ctx;
}