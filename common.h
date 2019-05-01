#pragma once

#include <stdio.h>
#include <netinet/in.h>

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
    enum BIO_lookup_type lookup = is_server ? BIO_LOOKUP_CLIENT : BIO_LOOKUP_SERVER;
    
    if (BIO_lookup(node, PORT, lookup, AF_INET, SOCK_DGRAM, & info) != 1) {
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

SSL_CTX* init_context(const char* keyname, SSL_verify_cb verify_cb)
{
    int result;

    SSL_CTX* ctx = SSL_CTX_new(DTLS_method());
    if (ctx == NULL) {
        PRINT_AND_EXIT("Error: cannot create SSL_CTX.\n");
    }

    result = SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (result != 1) {
        PRINT_AND_EXIT("Error: cannot set the cipher list.\n");
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);

    char certfile[1024];
    char keyfile[1024];
    sprintf(certfile, "./%s-cert.pem", keyname);
    sprintf(keyfile, "./%s-key.pem", keyname);

    result = SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        PRINT_AND_EXIT("Error: cannot load certificate file.\n");
    }

    result = SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        PRINT_AND_EXIT("Error: cannot load private key file.\n");
    }

    return ctx;
}

int server_verify_cb(int preverify_ok, X509_STORE_CTX* x509_ctx)
{
	FILE* fp = fopen("client-cert.pem", "r");
	X509* a = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	X509* b = X509_STORE_CTX_get_current_cert(x509_ctx);
	if (X509_cmp(a, b) == 0) {
		preverify_ok = 1;
	}
	X509_free(a);
    // Don't "X509_free(b);", we don't own the pointer
	printf("Server callback here.\n");
	return preverify_ok;
}

int client_verify_cb(int preverify_ok, X509_STORE_CTX* x509_ctx)
{
	FILE* fp = fopen("server-cert.pem", "r");
	X509* a = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	X509* b = X509_STORE_CTX_get_current_cert(x509_ctx);
	if (X509_cmp(a, b) == 0) {
		preverify_ok = 1;
	}
	X509_free(a);
    // Don't "X509_free(b);", we don't own the pointer
	printf("Client callback here.\n");
	return preverify_ok;
}

# define COOKIE_LEN  20

int cookie_gen(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    printf("Cookie gen.\n");
    unsigned int i;

    for (i = 0; i < COOKIE_LEN; i++, cookie++)
        *cookie = i;
    *cookie_len = COOKIE_LEN;
    
    return 1;
}

int cookie_verify(SSL *ssl, const unsigned char *cookie,
                         unsigned int cookie_len)
{
    printf("Cookie verify.\n");
    unsigned int i;

    if (cookie_len != COOKIE_LEN)
        return 0;

    for (i = 0; i < COOKIE_LEN; i++, cookie++) {
        if (*cookie != i)
            return 0;
    }

    return 1;
}