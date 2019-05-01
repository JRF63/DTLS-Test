#include "common.h"

int main()
{
    BIO* bio = init_bio(1);

    SSL_CTX* ctx = init_context("server", server_verify_cb);
    SSL_CTX_set_cookie_generate_cb(ctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify);

    SSL* ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    printf("Waiting for connection\n");
    struct sockaddr_in client_addr;

    while (DTLSv1_listen(ssl, (BIO_ADDR*) &client_addr) <= 0);
    
    BIO_set_conn_address(bio, (BIO_ADDR*) &client_addr);
    BIO_do_connect(bio);

    if (SSL_accept(ssl) <= 0) {
        PRINT_AND_EXIT("SSL_accept failed\n");
    }

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

    return 0;
}