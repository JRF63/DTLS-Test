#pragma once

#include "common.h"

#define COOKIE_SECRET_LEN 32
unsigned char cookie_secret[COOKIE_SECRET_LEN];
char cookie_version;

// #define DEBUG

// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
int stateless_hmac(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
    // 16 bytes for ip address: [0..15]
    // 2 bytes for port (short): [16,17]
    // 1 byte for socket family: [18]
    // 1 byte for cookie version number: [19]
    unsigned char data[20] = {0};
    
    struct sockaddr_storage peer;
    BIO* bio = SSL_get_rbio(ssl);
    BIO_dgram_get_peer(bio, &peer);

    // write the ip address to the first 16 bytes of data
    size_t ip_len = 16;
    BIO_ADDR_rawaddress((const BIO_ADDR*)&peer, (void*)data, &ip_len);
    
    // copy the 2 bytes of port number to offset 16 of data
    *(unsigned short*)(data + 16) = BIO_ADDR_rawport((const BIO_ADDR*)&peer);

    // copy socket family type to offset 18 of data
    data[18] = BIO_ADDR_family((const BIO_ADDR*)&peer);

    // copy cookie version to offset 19
    data[19] = cookie_version;

    #ifdef DEBUG
    //----- start debug
    printf("IP Addr: ");
    for (size_t i = 0; i < ip_len; i++) {
        printf("%hhu.", data[i]);
    }
    printf("\n");

    printf("FAMILY: ");
    switch (data[18]) {
        case AF_INET:
            printf("AF_INET\n");
            break;
        case AF_INET6:
            printf("AF_INET6\n");
            break;
        case AF_UNIX:
            printf("AF_UNIX\n");
            break;
        case AF_UNSPEC:
            printf("AF_UNSPEC\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }

    printf("PORT: %hu\n", *(unsigned short*)(data + 16));

    printf("data: ");
    for (size_t i = 0; i < 20; i++) {
        printf("%hhu.", data[i]);
    }
    printf("\n");
    //----- end debug
    #endif

    HMAC(EVP_sha256(), (const void*) cookie_secret, COOKIE_SECRET_LEN,
        data, 20, cookie, (unsigned int*)cookie_len);

    #ifdef DEBUG
    printf("digest len: %u\n", *cookie_len);

    printf("digest: ");
    for (size_t i = 0; i < *cookie_len; i++) {
        printf("%hhu.", cookie[i]);
    }
    printf("\n");
    #endif

    return 1;
}

int cookie_gen(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
    #ifdef DEBUG
    printf("-> cookie gen\n");
    #endif
    return stateless_hmac(ssl, cookie, cookie_len);
}

int cookie_verify(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
{
    #ifdef DEBUG
    printf("<- cookie verify\n");
    #endif
    
    // 32 bytes for SHA-256
    unsigned char cookie_check[32];
    unsigned int len_check;

    // if there is an error in doing the HMAC,
    if (stateless_hmac(ssl, cookie_check, &len_check) != 1) {
        return 0;
    }

    if (cookie_len != len_check) {
        return 0;
    }
    return (memcmp(cookie, cookie_check, len_check) == 0);
}