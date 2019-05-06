#include "common.h"
#include "cookie.h"
#include <openssl/rand.h>

int main()
{
    #ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif

    BIO* bio = init_bio(1);
    SSL_CTX* ctx = init_context(1);

    // set trusted cert
    SSL_CTX_load_verify_locations(ctx, "./certs/server-cert.pem", NULL);
    // verify the client too
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    SSL* ssl = SSL_new(ctx);
    // ssl takes ownership of bio, no need to free
    SSL_set_bio(ssl, bio, bio);

    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(ctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify);
    cookie_version = 0;
    RAND_bytes(cookie_secret, COOKIE_SECRET_LEN);

    printf("waiting for connection...\n");
    
    BIO_ADDR* client_addr = BIO_ADDR_new();

    while (DTLSv1_listen(ssl, client_addr) <= 0);
    
    // SSL_accept requires this bio to be
    // connected to the client's addr
    BIO_ctrl_dgram_connect(bio, client_addr);
    BIO_ADDR_free(client_addr);

    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        printf("%d\n", SSL_get_error(ssl, ret));
        PRINT_AND_EXIT("SSL_accept failed\n");
    }

    printf("\nclient says:\n");

    char buf[1024];
    while (!SSL_get_shutdown(ssl)) {
        int read = SSL_read(ssl, buf, sizeof(buf));
        if (read > 0) {
            printf("%s\n", buf);
        }
    }
    SSL_shutdown(ssl);

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    #ifdef _WIN32
    WSACleanup();
    #endif

    return 0;
}